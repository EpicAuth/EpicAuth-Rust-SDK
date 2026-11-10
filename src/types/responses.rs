use crate::types::models::{ChatMessage, TwoFactorData};
use serde::de::Deserializer;
use serde::Deserialize;

pub fn string_or_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrStr {
        Int(i64),
        Uint(u64),
        Float(f64),
        Str(String),
        Null,
    }

    match IntOrStr::deserialize(deserializer)? {
        IntOrStr::Int(i) => Ok(i),
        IntOrStr::Uint(u) => Ok(u as i64),
        IntOrStr::Float(f) => Ok(f as i64),
        IntOrStr::Str(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("n/a")
                || trimmed.eq_ignore_ascii_case("null")
            {
                Ok(0)
            } else {
                Ok(trimmed
                    .parse::<i64>()
                    .or_else(|_| trimmed.parse::<f64>().map(|f| f as i64))
                    .unwrap_or(0))
            }
        }
        IntOrStr::Null => Ok(0),
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
        Int(i64),
        Float(f64),
        Str(String),
        Null,
    }

    match UintOrStr::deserialize(deserializer)? {
        UintOrStr::Uint(u) => Ok(u),
        UintOrStr::Int(i) => Ok(i.max(0) as u64),
        UintOrStr::Float(f) => Ok(f.max(0.0) as u64),
        UintOrStr::Str(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("n/a")
                || trimmed.eq_ignore_ascii_case("null")
            {
                Ok(0)
            } else {
                Ok(trimmed
                    .parse::<u64>()
                    .or_else(|_| trimmed.parse::<f64>().map(|f| f.max(0.0) as u64))
                    .unwrap_or(0))
            }
        }
        UintOrStr::Null => Ok(0),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawAppInfo {
    #[serde(deserialize_with = "string_or_u64", rename = "numUsers", default)]
    pub num_users: u64,
    #[serde(deserialize_with = "string_or_u64", rename = "numOnlineUsers", default)]
    pub num_online_users: u64,
    #[serde(deserialize_with = "string_or_u64", rename = "numKeys", default)]
    pub num_keys: u64,
    #[serde(default)]
    pub version: String,
    #[serde(rename = "customerPanelLink", default)]
    pub customer_panel_link: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawSubscriptionInfo {
    #[serde(default)]
    pub subscription: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub expiry: String,
    #[serde(deserialize_with = "string_or_i64", default)]
    pub timeleft: i64,
    #[serde(default)]
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawUserInfo {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub subscriptions: Vec<RawSubscriptionInfo>,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub hwid: Option<String>,
    #[serde(deserialize_with = "string_or_i64", default)]
    pub createdate: i64,
    #[serde(deserialize_with = "string_or_i64", default)]
    pub lastlogin: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawApiResponse {
    #[serde(alias = "sucess", default)]
    pub success: bool,
    #[serde(default)]
    pub code: Option<i64>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(alias = "sessionId", default)]
    pub sessionid: Option<String>,
    #[serde(default)]
    pub download: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(alias = "appInfo", default)]
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
    #[serde(rename = "2fa", alias = "twoFactor", default)]
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

    #[test]
    fn test_deserialize_na_and_sucess_alias() {
        // Test real-world EpicAuth responses where numUsers is "N/A"
        let json_str = r#"{
            "success": true,
            "message": "Initialized",
            "sessionid": "sess_live",
            "appInfo": {
                "numUsers": "N/A",
                "numOnlineUsers": "N/A",
                "numKeys": "N/A",
                "version": "1.0",
                "customerPanelLink": "https://epicauth.cc/panel"
            }
        }"#;

        let res: RawApiResponse = serde_json::from_str(json_str).unwrap();
        assert!(res.success);
        let appinfo = res.appinfo.unwrap();
        assert_eq!(appinfo.num_users, 0);
        assert_eq!(appinfo.num_online_users, 0);
        assert_eq!(appinfo.num_keys, 0);
        assert_eq!(appinfo.version, "1.0");

        // Test server typo "sucess": false
        let typo_json = r#"{"sucess":false,"message":"OwnerID should be 10 characters long."}"#;
        let typo_res: RawApiResponse = serde_json::from_str(typo_json).unwrap();
        assert!(!typo_res.success);
        assert_eq!(
            typo_res.message.as_deref(),
            Some("OwnerID should be 10 characters long.")
        );
    }
}
