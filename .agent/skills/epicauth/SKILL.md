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

1. **Single Instance Lifecycle (Singleton / Shared State)**:
   Create and initialize `EpicAuth` **once** at application startup. Do **not** create separate `EpicAuth` instances or re-run `init()` inside disparate functions or request handlers. Re-initializing creates duplicate server sessions and risks rate-limiting or anti-abuse triggers. Share the initialized instance across your application using references or `Arc<tokio::sync::Mutex<EpicAuth>>`.

2. **Always Call `init()` First**:
   All operations (`license`, `login`, `var`, `file`, etc.) require an active server session. Calling any method before `app.init().await?` will return `EpicAuthError::NotInitialized`.

3. **Mutability & State**:
   The `EpicAuth` instance must be declared as `mut` (`let mut app = ...`) because authentication and session updates modify internal state (`sessionid`, `user_data`, `app_data`).

4. **Cryptographic Validation**:
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

### Pattern D: Sharing EpicAuth Across Tasks, Threads, or GUI (`Arc<Mutex<EpicAuth>>`)

When using EpicAuth across asynchronous Tokio tasks, GUI handlers (Tauri, Slint, egui), or background workers, wrap the initialized client in `Arc<tokio::sync::Mutex<EpicAuth>>`:

```rust
use epicauth::{EpicAuth, LicenseOptions};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize ONCE during app startup
    let mut app = EpicAuth::builder()
        .name("YourAppName")
        .ownerid("YourOwnerId")
        .version("1.0.0")
        .build()?;

    app.init().await?;
    app.license(LicenseOptions::new("XXXX-XXXX-XXXX-XXXX")).await?;

    // 2. Wrap in Arc<Mutex<...>> for application-wide sharing
    let shared_app = Arc::new(Mutex::new(app));

    // 3. Clone handle for background tasks or event handlers
    let task_app = Arc::clone(&shared_app);
    tokio::spawn(async move {
        let mut client = task_app.lock().await;
        let config = client.getvar("remote_config").await;
        println!("Config loaded in background: {:?}", config);
    });

    // 4. Access in the main routine or UI thread
    {
        let client = shared_app.lock().await;
        if let Some(user) = &client.user_data {
            println!("Active user: {}", user.username);
        }
    }

    Ok(())
}
```

### Pattern E: Global Singleton Access (`OnceCell`)

For architectures requiring access from anywhere without explicitly threading references:

```rust
use epicauth::EpicAuth;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

pub static AUTH_CLIENT: OnceCell<Arc<Mutex<EpicAuth>>> = OnceCell::const_new();

pub fn get_auth() -> &'static Arc<Mutex<EpicAuth>> {
    AUTH_CLIENT.get().expect("EpicAuth not initialized")
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
