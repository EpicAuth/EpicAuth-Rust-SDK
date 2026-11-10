# EpicAuth Rust SDK — Architecture & Design

This document details the architectural design, security mechanisms, and design decisions behind the EpicAuth Rust SDK.

---

## 1. Architectural Overview

The SDK is organized into modular components with strict separation of concerns:

```
src/
├── client.rs       # Main EpicAuth client & EpicAuthBuilder implementation
├── crypto.rs       # Ed25519 signature verification and cryptographic hashing
├── error.rs        # Typed errors (EpicAuthError) utilizing thiserror
├── hwid.rs         # Cross-platform hardware ID resolution
├── lib.rs          # Public facade re-exporting client, errors, and models
├── logger.rs       # Optional disk logging with automated field redaction
└── types/
    ├── mod.rs      # Module facade for types
    ├── models.rs   # Data structs (EpicAuthUserData, EpicAuthAppData, etc.)
    ├── options.rs  # Input parameter structs (LicenseOptions, etc.)
    └── responses.rs# Internal JSON deserializers with flexible numeric parsing
```

---

## 2. Security Architecture

### Cryptographic Ed25519 Verification

Every non-exempt server response is cryptographically authenticated using **Ed25519**:

1. **Header Inspection**: The client inspects `x-signature-ed25519` and `x-signature-timestamp`.
2. **Anti-Replay Verification**: The client calculates the time difference between server UTC and local UTC:
   $$\Delta t = |t_{\text{server}} - t_{\text{local}}|$$
   If $\Delta t > 25\text{ seconds}$, the request is rejected with `EpicAuthError::ClockDesync`.
3. **Signature Check**: The signed message is constructed as:
   $$\text{Message} = \text{timestamp} \mathbin{\Vert} \text{raw\_body}$$
   The signature is verified against the official EpicAuth public key:
   `95b38710f40927b16528a073b87d942e03bd4578d49963a19ebae177945f89ac`

### Exempt Endpoints
In alignment with the official server implementation, the following request types bypass Ed25519 verification:
- `file` (binary payload delivery)
- `log` (telemetry submission)
- `2faenable` (two-factor enrollment payload)
- `2fadisable` (two-factor de-enrollment)

---

## 3. Hardware Fingerprinting (HWID)

HWID resolution dynamically identifies the client platform:

1. **Windows**:
   - Primary: Query registry `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
   - Secondary: Query user SID via `wmic useraccount where name='...' get sid`.
2. **Linux**:
   - Primary: Read `/etc/machine-id`.
   - Secondary: Read `/var/lib/dbus/machine-id`.
3. **macOS**:
   - Primary: Execute `ioreg -rd1 -c IOPlatformExpertDevice` to extract `IOPlatformSerialNumber`.
4. **Fallback (All OS)**:
   - Compute SHA-256 of `hostname|username|arch` and truncate to 32 hex characters.

---

## 4. Parity with TypeScript SDK

| Feature | TypeScript SDK (`@epicauth/sdk`) | Rust SDK (`epicauth`) |
|---|---|---|
| Runtime | Node.js / Bun | Tokio / native asynchronous |
| HTTP Transport | Fetch API | `reqwest` (rustls-tls) |
| Cryptography | `@noble/ed25519` + `@noble/hashes` | `ed25519-dalek` + `sha2` |
| Error Handling | `EpicAuthError` class | `EpicAuthError` enum (`thiserror`) |
| Redaction | Regex string replacement | Token-based sanitizer |
| Packaging | npm package (`@epicauth/sdk`) | crates.io package (`epicauth`) |

---

## 5. Client Lifecycle & Concurrency Patterns

### Single-Instance Lifecycle (Singleton Pattern)

The `EpicAuth` client is architected to be instantiated and initialized **once per application process**:

```
[Application Startup]
        │
        ▼
 EpicAuth::builder().build()?
        │
        ▼
   app.init().await?   ──► Acquires cryptographically bound `sessionid`
        │
        ▼
 app.license(...) / app.login(...) ──► Binds HWID & populates `user_data`
        │
        ▼
 [Application Runtime] ──► Reuses `app` across all subsystems (var, check, file, log)
```

#### Why Re-instantiation is an Anti-Pattern:
1. **Session Invalidation**: Each `init()` invocation generates a new cryptographic session token. Overwriting or creating parallel sessions invalidates prior credentials.
2. **Server Rate Limiting**: Repeatedly sending initialization requests from the same client triggers server-side abuse and DDoS throttling.
3. **Loss of Cached State**: User subscription metadata, expiry timestamps, and HWID bindings stored in `app.user_data` are cleared or reset.

### Concurrency and Sharing Strategies in Rust

Because `EpicAuth` maintains internal session state, methods modify fields like `sessionid` and `user_data`. To share the client across asynchronous tasks or OS threads, adopt the following patterns:

#### 1. Thread-Safe Sharing with `Arc<tokio::sync::Mutex<EpicAuth>>`
The recommended pattern for multi-threaded applications, background workers, and GUI frameworks (such as Tauri, Slint, or egui):

```rust
use epicauth::{EpicAuth, LicenseOptions};
use std::sync::Arc;
use tokio::sync::Mutex;

let mut app = EpicAuth::builder()
    .name("MyApp")
    .ownerid("MyOwnerId")
    .version("1.0.0")
    .build()?;

app.init().await?;
app.license(LicenseOptions::new("XXXX-XXXX-XXXX-XXXX")).await?;

// Wrap in thread-safe reference-counting mutex
let shared_client = Arc::new(Mutex::new(app));

// Pass clones into Tokio tasks or GUI event loops
let worker_client = Arc::clone(&shared_client);
tokio::spawn(async move {
    let mut client = worker_client.lock().await;
    let _ = client.log("Worker task started").await;
});
```

#### 2. Global State via `tokio::sync::OnceCell`
For applications where dependency injection or passing handles through UI trees is impractical:

```rust
use epicauth::EpicAuth;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

pub static GLOBAL_AUTH: OnceCell<Arc<Mutex<EpicAuth>>> = OnceCell::const_new();

pub fn auth() -> &'static Arc<Mutex<EpicAuth>> {
    GLOBAL_AUTH.get().expect("EpicAuth has not been initialized!")
}
```
