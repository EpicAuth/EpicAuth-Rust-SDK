use crate::crypto::{sha256_hex, verify_signature};
use crate::error::EpicAuthError;
use crate::hwid::get_hwid;
use crate::logger::log_event;
use crate::types::models::{
    ChatMessage, EpicAuthAppData, EpicAuthSubscription, EpicAuthUserData, TwoFactorData,
};
use crate::types::options::{
    EpicAuthOptions, LicenseOptions, LoginOptions, RegisterOptions, UpgradeOptions, WebhookOptions,
};
use crate::types::responses::{RawApiResponse, RawUserInfo};
use chrono::Utc;
use std::collections::HashMap;

const DEFAULT_URL: &str = "https://epicauth.cc/api/1.3/";
const DEFAULT_PUBLIC_KEY: &str = "95b38710f40927b16528a073b87d942e03bd4578d49963a19ebae177945f89ac";

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
    http_client: reqwest::Client,
}

pub struct EpicAuthBuilder {
    options: EpicAuthOptions,
}

impl EpicAuthBuilder {
    pub fn new() -> Self {
        Self {
            options: EpicAuthOptions {
                name: String::new(),
                ownerid: String::new(),
                version: String::new(),
                hash_to_check: None,
                url: None,
                path: None,
                exit_on_error: Some(false),
                logging_enabled: Some(false),
                public_key: None,
            },
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.options.name = name.into();
        self
    }

    pub fn ownerid(mut self, ownerid: impl Into<String>) -> Self {
        self.options.ownerid = ownerid.into();
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.options.version = version.into();
        self
    }

    pub fn hash_to_check(mut self, hash: impl Into<String>) -> Self {
        self.options.hash_to_check = Some(hash.into());
        self
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.options.url = Some(url.into());
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.options.path = Some(path.into());
        self
    }

    pub fn exit_on_error(mut self, exit: bool) -> Self {
        self.options.exit_on_error = Some(exit);
        self
    }

    pub fn logging_enabled(mut self, enabled: bool) -> Self {
        self.options.logging_enabled = Some(enabled);
        self
    }

    pub fn public_key(mut self, key: impl Into<String>) -> Self {
        self.options.public_key = Some(key.into());
        self
    }

    pub fn build(self) -> Result<EpicAuth, EpicAuthError> {
        EpicAuth::new(self.options)
    }
}

impl Default for EpicAuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EpicAuth {
    pub fn builder() -> EpicAuthBuilder {
        EpicAuthBuilder::new()
    }

    pub fn new(options: EpicAuthOptions) -> Result<Self, EpicAuthError> {
        if options.name.trim().is_empty() {
            return Err(EpicAuthError::ConfigError("Name is required".to_string()));
        }
        if options.ownerid.trim().is_empty() {
            return Err(EpicAuthError::ConfigError(
                "Owner ID is required".to_string(),
            ));
        }
        if options.version.trim().is_empty() {
            return Err(EpicAuthError::ConfigError(
                "Version is required".to_string(),
            ));
        }

        let url = options.url.unwrap_or_else(|| DEFAULT_URL.to_string());
        let public_key = options
            .public_key
            .unwrap_or_else(|| DEFAULT_PUBLIC_KEY.to_string());
        let exit_on_error = options.exit_on_error.unwrap_or(false);
        let logging_enabled = options.logging_enabled.unwrap_or(false);

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        Ok(Self {
            name: options.name,
            ownerid: options.ownerid,
            version: options.version,
            hash_to_check: options.hash_to_check,
            url,
            path: options.path,
            exit_on_error,
            sessionid: None,
            initialized: false,
            public_key,
            logging_enabled,
            user_data: None,
            app_data: None,
            http_client,
        })
    }

    pub fn checkinit(&self) -> Result<(), EpicAuthError> {
        if !self.initialized || self.sessionid.is_none() {
            return self.fail(EpicAuthError::NotInitialized);
        }
        Ok(())
    }

    pub fn get_hwid(&self) -> String {
        get_hwid()
    }

    pub async fn init(&mut self) -> Result<(), EpicAuthError> {
        if self.initialized && self.sessionid.is_some() {
            return self.fail(EpicAuthError::AlreadyInitialized);
        }

        let mut token = String::new();
        let mut thash = String::new();

        if let Some(ref path) = self.path {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    token = content.trim().to_string();
                    thash = sha256_hex(token.as_bytes());
                }
                Err(err) => {
                    return self.fail(EpicAuthError::IoError(err));
                }
            }
        }

        let mut params = HashMap::new();
        params.insert("type", "init");
        params.insert("ownerid", &self.ownerid);
        params.insert("version", &self.version);
        params.insert("name", &self.name);

        if let Some(ref hash) = self.hash_to_check {
            params.insert("hash", hash);
        }
        if self.path.is_some() {
            params.insert("token", &token);
            params.insert("thash", &thash);
        }

        let response = self.request("init", params).await?;

        if let Some(msg) = &response.message {
            if msg == "invalidver" {
                if let Some(ref dl) = response.download {
                    return self.fail(EpicAuthError::OutdatedVersionWithUrl {
                        download_url: dl.clone(),
                    });
                } else {
                    return self.fail(EpicAuthError::OutdatedVersion);
                }
            }
        }

        if !response.success {
            return self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "Init failed".into()),
            ));
        }

        if let Some(ref sid) = response.sessionid {
            self.sessionid = Some(sid.clone());
            self.initialized = true;
        }

        if let Some(appinfo) = response.appinfo {
            self.app_data = Some(EpicAuthAppData {
                num_users: appinfo.num_users,
                num_keys: appinfo.num_keys,
                app_ver: appinfo.version,
                customer_panel: appinfo.customer_panel_link,
                online_users: appinfo.num_online_users,
            });
        }

        Ok(())
    }

    pub async fn login(&mut self, options: LoginOptions) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let hwid = options.hwid.unwrap_or_else(|| self.get_hwid());
        let sessionid = self.sessionid.as_deref().unwrap_or_default();

        let mut params = HashMap::new();
        params.insert("type", "login");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("username", &options.username);
        params.insert("pass", &options.password);
        params.insert("hwid", &hwid);

        if let Some(ref code) = options.code {
            params.insert("code", code);
        }

        let response = self.request("login", params).await?;
        if response.success {
            if let Some(info) = response.info {
                self.load_user_data(info)?;
                Ok(())
            } else {
                self.fail(EpicAuthError::MissingSubscriptions)
            }
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "Login failed".into()),
            ))
        }
    }

    pub async fn license(&mut self, options: LicenseOptions) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let hwid = options.hwid.unwrap_or_else(|| self.get_hwid());
        let sessionid = self.sessionid.as_deref().unwrap_or_default();

        let mut params = HashMap::new();
        params.insert("type", "license");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("key", &options.license);
        params.insert("hwid", &hwid);

        if let Some(ref code) = options.code {
            params.insert("code", code);
        }

        let response = self.request("license", params).await?;
        if response.success {
            if let Some(info) = response.info {
                self.load_user_data(info)?;
                Ok(())
            } else {
                self.fail(EpicAuthError::MissingSubscriptions)
            }
        } else {
            self.fail(EpicAuthError::ApiError(
                response
                    .message
                    .unwrap_or_else(|| "License verification failed".into()),
            ))
        }
    }

    pub async fn register(&mut self, options: RegisterOptions) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let hwid = options.hwid.unwrap_or_else(|| self.get_hwid());
        let sessionid = self.sessionid.as_deref().unwrap_or_default();

        let mut params = HashMap::new();
        params.insert("type", "register");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("username", &options.username);
        params.insert("pass", &options.password);
        params.insert("key", &options.license);
        params.insert("hwid", &hwid);

        let response = self.request("register", params).await?;
        if response.success {
            if let Some(info) = response.info {
                self.load_user_data(info)?;
                Ok(())
            } else {
                self.fail(EpicAuthError::MissingSubscriptions)
            }
        } else {
            self.fail(EpicAuthError::ApiError(
                response
                    .message
                    .unwrap_or_else(|| "Registration failed".into()),
            ))
        }
    }

    pub async fn upgrade(&mut self, options: UpgradeOptions) -> Result<String, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "upgrade");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("username", &options.username);
        params.insert("key", &options.license);

        let response = self.request("upgrade", params).await?;
        if response.success {
            Ok(response
                .message
                .unwrap_or_else(|| "Restart the application to apply the changes.".to_string()))
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "Upgrade failed".into()),
            ))
        }
    }

    pub async fn var(&mut self, name: &str) -> Result<String, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "var");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("varid", name);

        let response = self.request("var", params).await?;
        if response.success {
            Ok(response.message.unwrap_or_default())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "var error".into()),
            ))
        }
    }

    pub async fn getvar(&mut self, name: &str) -> Result<String, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "getvar");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("var", name);

        let response = self.request("getvar", params).await?;
        if response.success {
            Ok(response.response.unwrap_or_default())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "getvar error".into()),
            ))
        }
    }

    pub async fn setvar(&mut self, name: &str, value: &str) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "setvar");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("varid", name);
        params.insert("data", value);

        let response = self.request("setvar", params).await?;
        if response.success {
            Ok(())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "setvar error".into()),
            ))
        }
    }

    pub async fn ban(&mut self) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "ban");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        let response = self.request("ban", params).await?;
        if response.success {
            Ok(())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "ban error".into()),
            ))
        }
    }

    pub async fn file(&mut self, id: &str) -> Result<Vec<u8>, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "file");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("fileid", id);

        let response = self.request("file", params).await?;
        if response.success {
            let contents = response.contents.unwrap_or_default();
            Ok(contents.into_bytes())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "file error".into()),
            ))
        }
    }

    pub async fn webhook(&mut self, options: WebhookOptions) -> Result<String, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "webhook");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("webid", &options.id);
        params.insert("params", &options.param);

        if let Some(ref body) = options.body {
            params.insert("body", body);
        }
        if let Some(ref conttype) = options.conttype {
            params.insert("conttype", conttype);
        }

        let response = self.request("webhook", params).await?;
        if response.success {
            Ok(response.response.or(response.message).unwrap_or_default())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "webhook error".into()),
            ))
        }
    }

    pub async fn check(&mut self) -> Result<bool, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "check");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        let response = self.request("check", params).await?;
        if response.success {
            Ok(true)
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "check failed".into()),
            ))
        }
    }

    pub async fn checkblacklist(&mut self) -> Result<bool, EpicAuthError> {
        self.checkinit()?;

        let hwid = self.get_hwid();
        let sessionid = self.sessionid.as_deref().unwrap_or_default();

        let mut params = HashMap::new();
        params.insert("type", "checkblacklist");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("hwid", &hwid);

        let response = self.request("checkblacklist", params).await?;

        // In EpicAuth backend:
        // - If blacklisted: success = true, message = "Client is blacklisted"
        // - If clean: success = false, message = "Client is not blacklisted"
        if response.success {
            let msg = response
                .message
                .unwrap_or_else(|| "Client is blacklisted".to_string());
            return self.fail(EpicAuthError::ApiError(msg));
        }

        Ok(false)
    }

    pub async fn log(&mut self, message: &str) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let pcuser = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown".to_string());
        let sessionid = self.sessionid.as_deref().unwrap_or_default();

        let mut params = HashMap::new();
        params.insert("type", "log");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("message", message);
        params.insert("pcuser", &pcuser);

        self.request("log", params).await?;
        Ok(())
    }

    pub async fn fetch_online(&mut self) -> Result<Option<u64>, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "fetchOnline");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        let response = self.request("fetchOnline", params).await?;
        if response.success {
            if let Some(val) = response.users {
                if let Some(num) = val.as_u64() {
                    return Ok(Some(num));
                }
                if let Some(s) = val.as_str() {
                    if let Ok(num) = s.parse::<u64>() {
                        return Ok(Some(num));
                    }
                }
                if let Some(arr) = val.as_array() {
                    return Ok(Some(arr.len() as u64));
                }
            }
            Ok(None)
        } else {
            Ok(None)
        }
    }

    pub async fn fetch_stats(&mut self) -> Result<EpicAuthAppData, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "fetchStats");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        let response = self.request("fetchStats", params).await?;
        if response.success {
            if let Some(appinfo) = response.appinfo {
                let data = EpicAuthAppData {
                    num_users: appinfo.num_users,
                    num_keys: appinfo.num_keys,
                    app_ver: appinfo.version,
                    customer_panel: appinfo.customer_panel_link,
                    online_users: appinfo.num_online_users,
                };
                self.app_data = Some(data.clone());
                return Ok(data);
            }
        }
        self.fail(EpicAuthError::ApiError(
            response
                .message
                .unwrap_or_else(|| "Failed to fetch stats".into()),
        ))
    }

    pub async fn chat_get(&mut self, channel: &str) -> Result<Vec<ChatMessage>, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "chatget");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("channel", channel);

        let response = self.request("chatget", params).await?;
        if response.success {
            Ok(response.messages.unwrap_or_default())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "chatget failed".into()),
            ))
        }
    }

    pub async fn chat_send(&mut self, channel: &str, message: &str) -> Result<bool, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "chatsend");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("channel", channel);
        params.insert("message", message);

        let response = self.request("chatsend", params).await?;
        Ok(response.success)
    }

    pub async fn change_username(&mut self, new_username: &str) -> Result<bool, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "changeUsername");
        params.insert("newUsername", new_username);
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        let response = self.request("changeUsername", params).await?;
        Ok(response.success)
    }

    pub async fn logout(&mut self) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "logout");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        let response = self.request("logout", params).await?;
        self.sessionid = None;
        self.user_data = None;
        self.initialized = false;

        if response.success {
            Ok(())
        } else {
            self.fail(EpicAuthError::ApiError(
                response.message.unwrap_or_else(|| "logout failed".into()),
            ))
        }
    }

    pub async fn enable_2fa(
        &mut self,
        code: Option<&str>,
    ) -> Result<Option<TwoFactorData>, EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "2faenable");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);

        if let Some(c) = code {
            params.insert("code", c);
        }

        let response = self.request("2faenable", params).await?;
        if response.success {
            Ok(response.two_factor)
        } else {
            self.fail(EpicAuthError::ApiError(
                response
                    .message
                    .unwrap_or_else(|| "2faenable failed".into()),
            ))
        }
    }

    pub async fn disable_2fa(&mut self, code: &str) -> Result<(), EpicAuthError> {
        self.checkinit()?;

        let sessionid = self.sessionid.as_deref().unwrap_or_default();
        let mut params = HashMap::new();
        params.insert("type", "2fadisable");
        params.insert("name", &self.name);
        params.insert("ownerid", &self.ownerid);
        params.insert("sessionid", sessionid);
        params.insert("code", code);

        let response = self.request("2fadisable", params).await?;
        if response.success {
            Ok(())
        } else {
            self.fail(EpicAuthError::ApiError(
                response
                    .message
                    .unwrap_or_else(|| "2fadisable failed".into()),
            ))
        }
    }

    fn fail<T>(&self, err: EpicAuthError) -> Result<T, EpicAuthError> {
        if self.exit_on_error {
            eprintln!("{err}");
            std::process::exit(1);
        }
        Err(err)
    }

    fn load_user_data(&mut self, data: RawUserInfo) -> Result<(), EpicAuthError> {
        let first_sub = data
            .subscriptions
            .first()
            .ok_or(EpicAuthError::MissingSubscriptions)?;

        let first_subscription_name = first_sub.subscription.clone();
        let expiry_num = first_sub.expiry.parse::<i64>().unwrap_or(0);

        let subscriptions = data
            .subscriptions
            .into_iter()
            .map(|s| EpicAuthSubscription {
                subscription: s.subscription,
                key: s.key,
                expiry: s.expiry,
                timeleft: s.timeleft,
                level: s.level,
            })
            .collect();

        self.user_data = Some(EpicAuthUserData {
            username: data.username,
            ip: data.ip,
            hwid: data.hwid.unwrap_or_else(|| "N/A".to_string()),
            expires: expiry_num,
            createdate: data.createdate,
            lastlogin: data.lastlogin,
            subscription: first_subscription_name,
            subscriptions,
        });

        Ok(())
    }

    async fn request<'a>(
        &self,
        request_type: &str,
        params: HashMap<&'a str, &'a str>,
    ) -> Result<RawApiResponse, EpicAuthError> {
        let response = self
            .http_client
            .post(&self.url)
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        let headers = response.headers().clone();
        let raw_body = response.text().await?;

        if raw_body == "EpicAuth_Invalid" {
            return self.fail(EpicAuthError::InvalidApplication);
        }

        if !status.is_success() {
            return self.fail(EpicAuthError::ApiError(format!("HTTP {}", status.as_u16())));
        }

        let parsed: RawApiResponse = serde_json::from_str(&raw_body)?;

        let excluded = ["file", "log", "2faenable", "2fadisable"];
        if !excluded.contains(&request_type) {
            let sig_header = headers
                .get("x-signature-ed25519")
                .and_then(|h| h.to_str().ok());
            let time_header = headers
                .get("x-signature-timestamp")
                .and_then(|h| h.to_str().ok());

            match (sig_header, time_header) {
                (Some(signature), Some(timestamp_str)) => {
                    if let Ok(server_timestamp) = timestamp_str.parse::<i64>() {
                        let current_timestamp = Utc::now().timestamp();
                        let diff = (server_timestamp - current_timestamp).abs();
                        if diff > 25 {
                            return self.fail(EpicAuthError::ClockDesync { diff });
                        }
                    }

                    let message = format!("{}{}", timestamp_str, raw_body);
                    let valid = verify_signature(&self.public_key, signature, message.as_bytes())?;
                    if !valid {
                        return self.fail(EpicAuthError::SignatureVerificationFailed);
                    }
                }
                _ => {
                    return self.fail(EpicAuthError::MissingSignatureHeaders);
                }
            }
        }

        if self.logging_enabled {
            log_event(&raw_body);
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_validation() {
        let err = EpicAuth::builder().name("").ownerid("").version("").build();
        assert!(err.is_err());

        let client = EpicAuth::builder()
            .name("TestApp")
            .ownerid("TestOwner")
            .version("1.0.0")
            .build();
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.name, "TestApp");
        assert_eq!(client.ownerid, "TestOwner");
        assert_eq!(client.version, "1.0.0");
        assert!(!client.initialized);
    }

    #[test]
    fn test_uninitialized_check() {
        let client = EpicAuth::builder()
            .name("TestApp")
            .ownerid("TestOwner")
            .version("1.0.0")
            .build()
            .unwrap();

        assert!(client.checkinit().is_err());
    }

    #[test]
    fn test_load_user_data() {
        let mut client = EpicAuth::builder()
            .name("TestApp")
            .ownerid("TestOwner")
            .version("1.0.0")
            .build()
            .unwrap();

        let raw_user = RawUserInfo {
            username: "testuser".to_string(),
            subscriptions: vec![crate::types::responses::RawSubscriptionInfo {
                subscription: "default".to_string(),
                key: "TEST-KEY".to_string(),
                expiry: "1735689600".to_string(),
                timeleft: 86400,
                level: "1".to_string(),
            }],
            ip: "127.0.0.1".to_string(),
            hwid: Some("HWID-12345".to_string()),
            createdate: 1700000000,
            lastlogin: 1700000000,
        };

        client.load_user_data(raw_user).unwrap();
        assert!(client.user_data.is_some());
        let u = client.user_data.as_ref().unwrap();
        assert_eq!(u.username, "testuser");
        assert_eq!(u.hwid, "HWID-12345");
        assert_eq!(u.subscription, "default");
        assert_eq!(u.expires, 1735689600);
    }
}
