---
name: epicauth
description: Best practices and comprehensive recipes for integrating the EpicAuth Rust SDK (epicauth crate) into Rust applications for enterprise licensing, HWID locking, user authentication, and remote secure variables.
---

# EpicAuth Rust SDK Integration Guide

The `epicauth` crate provides high-performance, cryptographically verified integration with the [EpicAuth](https://epicauth.cc) licensing and anti-piracy platform.

## 1. Dependency Setup

Add `epicauth` and `tokio` to your `Cargo.toml`:

```toml
[dependencies]
epicauth = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## 2. Core Principles & Workflow

1. **Always Call `init()` First**:
   All operations (`license`, `login`, `var`, `file`, etc.) require an active server session. Calling any method before `app.init().await?` will return `EpicAuthError::NotInitialized`.

2. **Mutability**:
   The `EpicAuth` instance must be declared as `mut` (`let mut app = ...`) because authentication and session updates modify internal state (`sessionid`, `user_data`, `app_data`).

3. **Cryptographic Validation**:
   The SDK automatically validates Ed25519 signatures and checks for UTC clock drift ($\le 25\text{s}$) on responses. If users report signature failures, ensure their system time is synchronized.

---

## 3. Standard Patterns

### Pattern A: License Key Protection (Typical CLI / Desktop App)

```rust
use epicauth::{EpicAuth, LicenseOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    let license_key = "XXXX-XXXX-XXXX-XXXX";
    app.license(LicenseOptions::new(license_key)).await?;

    if let Some(user) = &app.user_data {
        println!("Welcome, {}! Subscription: {}", user.username, user.subscription);
    }

    Ok(())
}
```

### Pattern B: Username & Password with Optional 2FA

```rust
use epicauth::{EpicAuth, LoginOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;

    let mut opts = LoginOptions::new("username", "password");
    opts.code = Some("2FA_CODE".into()); // Only if 2FA is active

    app.login(opts).await?;
    println!("User authenticated successfully.");

    Ok(())
}
```

### Pattern C: Fetching Remote Configuration or Protected Assets

```rust
use epicauth::EpicAuth;

async fn load_remote_assets(app: &mut EpicAuth) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Read server-side variable without exposing strings in local binary
    let api_endpoint = app.var("api_endpoint").await?;
    println!("Server endpoint: {api_endpoint}");

    // Download protected asset bytes directly
    let asset = app.file("protected_binary_id").await?;
    Ok(asset)
}
```

---

## 4. Error Handling Reference

Handle errors using standard Rust pattern matching:

```rust
use epicauth::EpicAuthError;

match app.license(options).await {
    Ok(()) => println!("Authorized!"),
    Err(EpicAuthError::InvalidApplication) => eprintln!("Application not found in EpicAuth dashboard."),
    Err(EpicAuthError::OutdatedVersionWithUrl { download_url }) => {
        eprintln!("Please update your app from: {download_url}");
    }
    Err(EpicAuthError::ClockDesync { diff }) => {
        eprintln!("System clock is out of sync by {diff} seconds. Please sync your clock.");
    }
    Err(EpicAuthError::SignatureVerificationFailed) => {
        eprintln!("Security alert: Server response was tampered with!");
    }
    Err(EpicAuthError::ApiError(msg)) => eprintln!("Server error: {msg}"),
    Err(err) => eprintln!("Error: {err}"),
}
```
