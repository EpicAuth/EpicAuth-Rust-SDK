use crate::types::models::{ChatMessage, TwoFactorData};
use serde::de::{self, Deserializer};
use serde::Deserialize;

pub fn string_or_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrStr {
        Int(i64),
        Str(String),
    }

    match IntOrStr::deserialize(deserializer)? {
        IntOrStr::Int(i) => Ok(i),
        IntOrStr::Str(s) => s.trim().parse::<i64>().map_err(de::Error::custom),
    }
}

pub fn string_or_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum UintOrStr {
        Uint(u64),
        Str(String),
    }

    match UintOrStr::deserialize(deserializer)? {
        UintOrStr::Uint(u) => Ok(u),
        UintOrStr::Str(s) => s.trim().parse::<u64>().map_err(de::Error::custom),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawAppInfo {
    #[serde(deserialize_with = "string_or_u64", rename = "numUsers")]
    pub num_users: u64,
    #[serde(deserialize_with = "string_or_u64", rename = "numOnlineUsers")]
    pub num_online_users: u64,
    #[serde(deserialize_with = "string_or_u64", rename = "numKeys")]
    pub num_keys: u64,
    pub version: String,
    #[serde(rename = "customerPanelLink")]
    pub customer_panel_link: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawSubscriptionInfo {
    pub subscription: String,
    pub key: String,
    pub expiry: String,
    #[serde(deserialize_with = "string_or_i64")]
    pub timeleft: i64,
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawUserInfo {
    pub username: String,
    pub subscriptions: Vec<RawSubscriptionInfo>,
    pub ip: String,
    pub hwid: Option<String>,
    #[serde(deserialize_with = "string_or_i64")]
    pub createdate: i64,
    #[serde(deserialize_with = "string_or_i64")]
    pub lastlogin: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawApiResponse {
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub sessionid: Option<String>,
    #[serde(default)]
    pub download: Option<String>,
    #[serde(default)]
    pub appinfo: Option<RawAppInfo>,
    #[serde(default)]
    pub info: Option<RawUserInfo>,
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub contents: Option<String>,
    #[serde(default)]
    pub users: Option<serde_json::Value>,
    #[serde(default)]
    pub messages: Option<Vec<ChatMessage>>,
    #[serde(rename = "2fa", default)]
    pub two_factor: Option<TwoFactorData>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_raw_init() {
        let json_str = r#"{
            "success": true,
            "message": "Initialized",
            "sessionid": "sess_abc123",
            "appinfo": {
                "numUsers": "150",
                "numOnlineUsers": "42",
                "numKeys": "300",
                "version": "1.0.0",
                "customerPanelLink": "https://epicauth.cc/panel"
            }
        }"#;

        let res: RawApiResponse = serde_json::from_str(json_str).unwrap();
        assert!(res.success);
        assert_eq!(res.sessionid.as_deref(), Some("sess_abc123"));
        let appinfo = res.appinfo.unwrap();
        assert_eq!(appinfo.num_users, 150);
        assert_eq!(appinfo.num_online_users, 42);
        assert_eq!(appinfo.num_keys, 300);
        assert_eq!(appinfo.version, "1.0.0");
    }

    #[test]
    fn test_deserialize_raw_login() {
        let json_str = r#"{
            "success": true,
            "message": "Logged in",
            "info": {
                "username": "coder",
                "subscriptions": [
                    {
                        "subscription": "VIP",
                        "key": "KEY-XYZ",
                        "expiry": "1800000000",
                        "timeleft": "3600",
                        "level": "5"
                    }
                ],
                "ip": "1.1.1.1",
                "hwid": "my-hwid",
                "createdate": "1690000000",
                "lastlogin": 1695000000
            }
        }"#;

        let res: RawApiResponse = serde_json::from_str(json_str).unwrap();
        assert!(res.success);
        let info = res.info.unwrap();
        assert_eq!(info.username, "coder");
        assert_eq!(info.createdate, 1690000000);
        assert_eq!(info.lastlogin, 1695000000);
        assert_eq!(info.subscriptions[0].timeleft, 3600);
    }
}
