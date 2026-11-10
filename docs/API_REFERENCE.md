# EpicAuth Rust SDK — API Reference

## Table of Contents
- [Client Configuration](#client-configuration)
  - [EpicAuth](#epicauth)
  - [EpicAuthBuilder](#epicauthbuilder)
  - [EpicAuthOptions](#epicauthoptions)
  - [Lifecycle & Shared State Best Practice](#lifecycle--shared-state-best-practice)
- [Client Methods](#client-methods)
  - [init](#init)
  - [license](#license)
  - [login](#login)
  - [register](#register)
  - [upgrade](#upgrade)
  - [var](#var)
  - [getvar / setvar](#getvar--setvar)
  - [ban](#ban)
  - [file](#file)
  - [webhook](#webhook)
  - [check / checkblacklist](#check--checkblacklist)
  - [log](#log)
  - [fetch_stats / fetch_online](#fetch_stats--fetch_online)
  - [chat_get / chat_send](#chat_get--chat_send)
  - [change_username](#change_username)
  - [enable_2fa / disable_2fa](#enable_2fa--disable_2fa)
  - [logout](#logout)
- [Data Models](#data-models)
  - [EpicAuthUserData](#epicauthuserdata)
  - [EpicAuthSubscription](#epicauthsubscription)
  - [EpicAuthAppData](#epicauthappdata)
  - [ChatMessage](#chatmessage)
- [Error Handling](#error-handling)
  - [EpicAuthError](#epicautherror)

---

## Client Configuration

### `EpicAuth`

The main client struct that manages communication with the EpicAuth licensing server.

```rust
pub struct EpicAuth {
    pub name: String,
    pub ownerid: String,
    pub version: String,
    pub hash_to_check: Option<String>,
    pub url: String,
    pub path: Option<String>,
    pub exit_on_error: bool,
    pub sessionid: Option<String>,
    pub initialized: bool,
    pub public_key: String,
    pub logging_enabled: bool,
    pub user_data: Option<EpicAuthUserData>,
    pub app_data: Option<EpicAuthAppData>,
}
```

### `EpicAuthBuilder`

A builder pattern interface for constructing `EpicAuth` instances.

```rust
let app = EpicAuth::builder()
    .name("MyApp")
    .ownerid("XyZ123")
    .version("1.0.0")
    .url("https://epicauth.cc/api/1.3/") // optional
    .logging_enabled(true)               // optional
    .exit_on_error(false)                // optional
    .build()?;
```

### `EpicAuthOptions`

Direct configuration struct passed to `EpicAuth::new()`.

```rust
use epicauth::EpicAuthOptions;

let options = EpicAuthOptions::new("MyApp", "OwnerID", "1.0.0");
let app = EpicAuth::new(options)?;
```

### Lifecycle & Shared State Best Practice

> [!IMPORTANT]
> **Single Instance Lifecycle**: `EpicAuth` is designed to be built and initialized (`init()`) **only once** per application lifecycle. Do not create new instances in separate functions or HTTP handlers.
>
> To share `EpicAuth` across multiple tasks, threads, or GUI screens, wrap the instance in `Arc<tokio::sync::Mutex<EpicAuth>>`:
>
> ```rust
> use epicauth::{EpicAuth, LicenseOptions};
> use std::sync::Arc;
> use tokio::sync::Mutex;
>
> // 1. Initialize once
> let mut app = EpicAuth::builder()
>     .name("MyApp")
>     .ownerid("MyOwnerId")
>     .version("1.0.0")
>     .build()?;
>
> app.init().await?;
> app.license(LicenseOptions::new("LICENSE-KEY")).await?;
>
> // 2. Wrap for thread-safe concurrent access
> let shared_app = Arc::new(Mutex::new(app));
>
> // 3. Clone handle for tasks or GUI event loops
> let task_app = Arc::clone(&shared_app);
> tokio::spawn(async move {
>     let mut client = task_app.lock().await;
>     let val = client.getvar("secret").await;
> });
> ```

---

## Client Methods

### `init`

```rust
pub async fn init(&mut self) -> Result<(), EpicAuthError>
```

Initializes the application session. Must be called before calling any other methods.
- Validates application presence.
- Sets up `sessionid`.
- Populates `app_data` if returned by server.
- Automatically handles outdated versions (`OutdatedVersionWithUrl` / `OutdatedVersion`).

### `license`

```rust
pub async fn license(&mut self, options: LicenseOptions) -> Result<(), EpicAuthError>
```

Authenticates using a license key and binds the machine HWID to the key.
- `options.license`: The license key string.
- `options.code`: Optional 2FA code.
- `options.hwid`: Optional override for hardware identifier.

Populates `app.user_data` upon success.

### `login`

```rust
pub async fn login(&mut self, options: LoginOptions) -> Result<(), EpicAuthError>
```

Authenticates an existing user using username and password.
- `options.username`: User username.
- `options.password`: User password.
- `options.code`: Optional 2FA code.
- `options.hwid`: Optional HWID override.

Populates `app.user_data` upon success.

### `register`

```rust
pub async fn register(&mut self, options: RegisterOptions) -> Result<(), EpicAuthError>
```

Registers a new user account with a license key.

### `upgrade`

```rust
pub async fn upgrade(&mut self, options: UpgradeOptions) -> Result<String, EpicAuthError>
```

Applies a license key to an existing user to extend their subscription.

### `var`

```rust
pub async fn var(&mut self, name: &str) -> Result<String, EpicAuthError>
```

Retrieves a server-side global variable defined in the EpicAuth dashboard.

### `getvar` / `setvar`

```rust
pub async fn getvar(&mut self, name: &str) -> Result<String, EpicAuthError>
pub async fn setvar(&mut self, name: &str, value: &str) -> Result<(), EpicAuthError>
```

Reads or updates user-specific persistent variables stored in EpicAuth.

### `ban`

```rust
pub async fn ban(&mut self) -> Result<(), EpicAuthError>
```

Bans the currently authenticated user and terminates their session.

### `file`

```rust
pub async fn file(&mut self, id: &str) -> Result<Vec<u8>, EpicAuthError>
```

Downloads a protected binary file or asset by ID directly from EpicAuth file storage.

### `webhook`

```rust
pub async fn webhook(&mut self, options: WebhookOptions) -> Result<String, EpicAuthError>
```

Triggers a server-configured webhook with parameters, custom payload, and content-type.

### `check` / `checkblacklist`

```rust
pub async fn check(&mut self) -> Result<bool, EpicAuthError>
pub async fn checkblacklist(&mut self) -> Result<bool, EpicAuthError>
```

- `check()`: Validates that the current session token remains active on the server.
- `checkblacklist()`: Queries whether the device's hardware ID or IP is blacklisted. If blacklisted, triggers an error with the server message (`"Client is blacklisted"`, and terminates if `exit_on_error` is enabled). If clean, returns `Ok(false)`.

### `log`

```rust
pub async fn log(&mut self, message: &str) -> Result<(), EpicAuthError>
```

Dispatches an audit log message to EpicAuth or configured webhook endpoint with machine user info.

### `fetch_stats` / `fetch_online`

```rust
pub async fn fetch_stats(&mut self) -> Result<EpicAuthAppData, EpicAuthError>
pub async fn fetch_online(&mut self) -> Result<Option<u64>, EpicAuthError>
```

- `fetch_stats()`: Updates and returns application statistics (total users, active keys, online users, etc.).
- `fetch_online()`: Retrieves real-time count of active online users.

### `chat_get` / `chat_send`

```rust
pub async fn chat_get(&mut self, channel: &str) -> Result<Vec<ChatMessage>, EpicAuthError>
pub async fn chat_send(&mut self, channel: &str, message: &str) -> Result<bool, EpicAuthError>
```

Reads and publishes messages to real-time chat channels.

### `change_username`

```rust
pub async fn change_username(&mut self, new_username: &str) -> Result<bool, EpicAuthError>
```

Updates the authenticated user's account name.

### `enable_2fa` / `disable_2fa`

```rust
pub async fn enable_2fa(&mut self, code: Option<&str>) -> Result<Option<TwoFactorData>, EpicAuthError>
pub async fn disable_2fa(&mut self, code: &str) -> Result<(), EpicAuthError>
```

Manages two-factor authentication initialization and confirmation.

### `logout`

```rust
pub async fn logout(&mut self) -> Result<(), EpicAuthError>
```

Terminates the session on the server and clears local authentication state.

---

## Data Models

### `EpicAuthUserData`

```rust
pub struct EpicAuthUserData {
    pub username: String,
    pub ip: String,
    pub hwid: String,
    pub expires: i64,
    pub createdate: i64,
    pub lastlogin: i64,
    pub subscription: String,
    pub subscriptions: Vec<EpicAuthSubscription>,
}
```

### `EpicAuthSubscription`

```rust
pub struct EpicAuthSubscription {
    pub subscription: String,
    pub key: String,
    pub expiry: String,
    pub timeleft: i64,
    pub level: String,
}
```

### `EpicAuthAppData`

```rust
pub struct EpicAuthAppData {
    pub num_users: u64,
    pub num_keys: u64,
    pub app_ver: String,
    pub customer_panel: String,
    pub online_users: u64,
}
```

---

## Error Handling

### `EpicAuthError`

All methods return a standard `Result<T, EpicAuthError>`.

```rust
pub enum EpicAuthError {
    InvalidApplication,
    OutdatedVersionWithUrl { download_url: String },
    OutdatedVersion,
    NotInitialized,
    AlreadyInitialized,
    MissingSignatureHeaders,
    ClockDesync { diff: i64 },
    SignatureVerificationFailed,
    ApiError(String),
    HttpError(reqwest::Error),
    JsonError(serde_json::Error),
    IoError(std::io::Error),
    CryptoError(String),
    MissingSubscriptions,
    ConfigError(String),
}
```
