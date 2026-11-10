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
