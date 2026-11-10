use thiserror::Error;

#[derive(Error, Debug)]
pub enum EpicAuthError {
    #[error("This application does not exist")]
    InvalidApplication,

    #[error("Application is outdated. Download update at: {download_url}")]
    OutdatedVersionWithUrl { download_url: String },

    #[error("Your application is outdated and no download link was provided, contact the owner for the latest app version.")]
    OutdatedVersion,

    #[error("You need to run init() before calling any other EpicAuth methods")]
    NotInitialized,

    #[error("Application already initialized")]
    AlreadyInitialized,

    #[error("Missing signature or timestamp in response headers")]
    MissingSignatureHeaders,

    #[error("Time difference is too large: {diff}s, try syncing your date and time settings")]
    ClockDesync { diff: i64 },

    #[error("Signature checksum failed. Request was tampered with or session ended")]
    SignatureVerificationFailed,

    #[error("EpicAuth API error: {0}")]
    ApiError(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Missing or invalid user subscriptions")]
    MissingSubscriptions,

    #[error("Invalid configuration: {0}")]
    ConfigError(String),
}
