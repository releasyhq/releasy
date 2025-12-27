use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub name: String,
    pub plan: Option<String>,
    pub allowed_prefixes: Option<String>,
    pub created_at: i64,
    pub suspended_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: String,
    pub customer_id: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub name: Option<String>,
    pub key_type: String,
    pub scopes: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyAuthRecord {
    pub id: String,
    pub customer_id: String,
    pub key_type: String,
    pub scopes: String,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyIntrospection {
    pub active: bool,
    pub api_key_id: String,
    pub customer_id: String,
    pub key_type: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub id: String,
    pub product: String,
    pub version: String,
    pub status: String,
    pub created_at: i64,
    pub published_at: Option<i64>,
}

pub const DEFAULT_API_KEY_TYPE: &str = "human";

pub const ALLOWED_SCOPES: &[&str] = &[
    "releases:read",
    "downloads:read",
    "downloads:token",
    "keys:read",
    "keys:write",
    "audit:read",
];

pub const DEFAULT_SCOPES: &[&str] = ALLOWED_SCOPES;

pub fn default_scopes() -> Vec<String> {
    DEFAULT_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect()
}

pub fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for scope in scopes {
        let trimmed = scope.trim();
        if trimmed.is_empty() {
            continue;
        }
        if normalized.iter().any(|existing| existing == trimmed) {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

pub fn scopes_to_json(scopes: &[String]) -> Result<String, serde_json::Error> {
    serde_json::to_string(scopes)
}
