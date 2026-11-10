# EpicAuth Rust SDK

[![Crates.io](https://img.shields.io/crates/v/epicauth.svg)](https://crates.io/crates/epicauth)
[![Documentation](https://docs.rs/epicauth/badge.svg)](https://docs.rs/epicauth)
[![CI](https://github.com/EpicAuth/EpicAuth-Rust-SDK/actions/workflows/ci.yml/badge.svg)](https://github.com/EpicAuth/EpicAuth-Rust-SDK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](LICENSE)

Official high-performance Rust SDK for [EpicAuth](https://epicauth.cc) — enterprise licensing, cryptographic software protection, hardware locking, and session authentication.

1:1 parity with the official [EpicAuth TypeScript SDK](https://github.com/EpicAuth/EpicAuth-TS-SDK), re-engineered for Rust with full memory safety, async `tokio` runtime, Ed25519 response verification, and zero unnecessary runtime overhead.

---

## Features

- **Ed25519 Tamper Protection**: Validates cryptographic signatures (`x-signature-ed25519`) and timestamp drift on every server response.
- **Cross-Platform HWID Locking**: Machine GUID / SID on Windows, machine-id on Linux, IOPlatformSerialNumber on macOS, and robust SHA-256 fallback.
- **Complete Parity**: Supports `init`, `license`, `login`, `register`, `upgrade`, `var`, `getvar`, `setvar`, `file`, `webhook`, `check`, `fetch_stats`, `fetch_online`, `chat`, and `2fa`.
- **Sensitive Data Redaction**: Automatic sanitization of session tokens and private parameters in debug logs.
- **Idiomatic Rust**: Strong types, structured `EpicAuthError` with `thiserror`, and builder pattern support.

---

## Installation

Add `epicauth` and `tokio` to your `Cargo.toml`:

```toml
[dependencies]
epicauth = "0.1"
tokio = { version = "1", features = ["full"] }
```

Or using `cargo add`:

```bash
cargo add epicauth
cargo add tokio --features full
```

---

## Quick Start

### 1. License Authentication

```rust
use epicauth::{EpicAuth, LicenseOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourApplication")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    // Initialize application session
    app.init().await?;

    // Authenticate with a license key
    app.license(LicenseOptions::new("XXXX-XXXX-XXXX-XXXX")).await?;

    if let Some(user) = &app.user_data {
        println!("Authenticated as: {}", user.username);
        println!("HWID: {}", user.hwid);
        println!("Subscription: {}", user.subscription);
        println!("Expires at: {}", user.expires);
    }

    Ok(())
}
```

---

### 2. User Login & Registration

```rust
use epicauth::{EpicAuth, LoginOptions, RegisterOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourApplication")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    // Register a new user
    // app.register(RegisterOptions::new("user", "pass", "LICENSE-KEY")).await?;

    // Login existing user
    let mut login_opts = LoginOptions::new("username", "password");
    login_opts.code = Some("123456".into()); // Optional 2FA code

    app.login(login_opts).await?;
    println!("Logged in successfully!");

    Ok(())
}
```

---

### 3. Application Statistics & Online Users

```rust
use epicauth::EpicAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourApplication")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    let stats = app.fetch_stats().await?;
    println!("Total Users: {}", stats.num_users);
    println!("Online Users: {}", stats.online_users);
    println!("Active Keys: {}", stats.num_keys);
    println!("Version: {}", stats.app_ver);
    println!("Panel: {}", stats.customer_panel);

    Ok(())
}
```

---

### 4. Remote Variables & Secure Files

```rust
use epicauth::EpicAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourApplication")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    // Fetch a remote server variable
    let config = app.var("server_config").await?;
    println!("Remote config: {config}");

    // Get and set user-specific variables
    app.setvar("theme", "dark").await?;
    let theme = app.getvar("theme").await?;
    println!("User theme: {theme}");

    // Download protected asset bytes
    let file_bytes = app.file("protected_asset_id").await?;
    println!("Downloaded {} bytes", file_bytes.len());

    Ok(())
}
```

---

### 5. Webhooks & Audit Logs

```rust
use epicauth::{EpicAuth, WebhookOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourApplication")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    // Trigger dashboard webhook
    let resp = app.webhook(WebhookOptions::new("webhook_id", "user_action")).await?;
    println!("Webhook response: {resp}");

    // Send an audit log
    app.log("Admin module unlocked").await?;

    Ok(())
}
```

---

## API Overview

| Method | Parameters | Description |
|---|---|---|
| `init()` | — | Establishes session and verifies app integrity. |
| `license(options)` | `LicenseOptions` | Authenticates using license key and binds HWID. |
| `login(options)` | `LoginOptions` | Authenticates username and password. |
| `register(options)` | `RegisterOptions` | Creates user account with key. |
| `upgrade(options)` | `UpgradeOptions` | Extends user subscription with another key. |
| `var(name)` | `&str` | Retrieves global dashboard variable. |
| `getvar(name)` | `&str` | Retrieves user-scoped variable. |
| `setvar(name, value)` | `&str, &str` | Writes user-scoped variable. |
| `file(id)` | `&str` | Downloads protected binary payload. |
| `webhook(options)` | `WebhookOptions` | Executes configured server-side webhook. |
| `check()` | — | Validates current session status. |
| `checkblacklist()` | — | Checks if the current HWID is blacklisted. |
| `log(message)` | `&str` | Submits security audit log with machine user. |
| `fetch_stats()` | — | Retrieves aggregate application metrics. |
| `fetch_online()` | — | Fetches count of active online users. |
| `chat_get(channel)` | `&str` | Reads messages from an application chat channel. |
| `chat_send(channel, msg)` | `&str, &str` | Sends a message to a chat channel. |
| `change_username(new_name)` | `&str` | Modifies the authenticated username. |
| `logout()` | — | Invalidates server session. |
| `enable_2fa(code)` | `Option<&str>` | Initializes or verifies two-factor authentication. |
| `disable_2fa(code)` | `&str` | Deactivates two-factor authentication. |
| `get_hwid()` | — | Returns platform hardware fingerprint. |

---

## Security Model

1. **Ed25519 Signatures**: EpicAuth signs responses using Ed25519. The SDK verifies all non-exempt payloads using the platform public key (`95b387...`). Tampered or replayed responses trigger `EpicAuthError::SignatureVerificationFailed`.
2. **Anti-Replay Window**: Response timestamps are checked against UTC clock drift. Any drift larger than 25 seconds raises `EpicAuthError::ClockDesync`.
3. **HWID Fingerprinting**: Prevents license sharing by coupling authorization tokens to platform-specific hardware serials.

---

## License

This project is licensed under the [Elastic License 2.0](LICENSE).
