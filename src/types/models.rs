use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpicAuthSubscription {
    pub subscription: String,
    pub key: String,
    pub expiry: String,
    pub timeleft: i64,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpicAuthAppData {
    pub num_users: u64,
    pub num_keys: u64,
    pub app_ver: String,
    pub customer_panel: String,
    pub online_users: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub author: String,
    pub message: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorData {
    pub secret_code: String,
    #[serde(rename = "QRCode")]
    pub qr_code: String,
}
