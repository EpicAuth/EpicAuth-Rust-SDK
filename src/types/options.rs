use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpicAuthOptions {
    pub name: String,
    pub ownerid: String,
    pub version: String,
    #[serde(default)]
    pub hash_to_check: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub exit_on_error: Option<bool>,
    #[serde(default)]
    pub logging_enabled: Option<bool>,
    #[serde(default)]
    pub public_key: Option<String>,
}

impl EpicAuthOptions {
    pub fn new(
        name: impl Into<String>,
        ownerid: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            ownerid: ownerid.into(),
            version: version.into(),
            hash_to_check: None,
            url: None,
            path: None,
            exit_on_error: Some(false),
            logging_enabled: Some(false),
            public_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginOptions {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub hwid: Option<String>,
}

impl LoginOptions {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            code: None,
            hwid: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseOptions {
    pub license: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub hwid: Option<String>,
}

impl LicenseOptions {
    pub fn new(license: impl Into<String>) -> Self {
        Self {
            license: license.into(),
            code: None,
            hwid: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterOptions {
    pub username: String,
    pub password: String,
    pub license: String,
    #[serde(default)]
    pub hwid: Option<String>,
}

impl RegisterOptions {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        license: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            license: license.into(),
            hwid: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeOptions {
    pub username: String,
    pub license: String,
}

impl UpgradeOptions {
    pub fn new(username: impl Into<String>, license: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            license: license.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookOptions {
    pub id: String,
    pub param: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub conttype: Option<String>,
}

impl WebhookOptions {
    pub fn new(id: impl Into<String>, param: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            param: param.into(),
            body: None,
            conttype: None,
        }
    }
}
