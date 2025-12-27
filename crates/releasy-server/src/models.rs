use serde::{Deserialize, Serialize};

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

#[allow(dead_code)]
pub const DEFAULT_SCOPES: &[&str] = &[
    "releases:read",
    "downloads:read",
    "downloads:token",
    "keys:read",
    "keys:write",
    "audit:read",
];

#[allow(dead_code)]
pub fn default_scopes() -> Vec<String> {
    DEFAULT_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect()
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn scopes_to_json(scopes: &[String]) -> Result<String, serde_json::Error> {
    serde_json::to_string(scopes)
}
