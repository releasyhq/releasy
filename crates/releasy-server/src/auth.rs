use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tracing::error;

use crate::{
    config::Settings, db::Database, errors::ApiError, models::ApiKeyAuthRecord, utils::now_ts,
};

#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    pub api_key_id: String,
    pub customer_id: String,
    pub key_type: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
}

pub async fn authenticate_api_key(
    headers: &HeaderMap,
    settings: &Settings,
    db: &Database,
) -> Result<ApiKeyAuth, ApiError> {
    let raw_key = match api_key_from_headers(headers) {
        Some(raw_key) => raw_key,
        None => {
            record_api_key_audit(db, None, None, "reject", "missing_header").await;
            return Err(ApiError::unauthorized());
        }
    };

    let key_hash = hash_api_key(&raw_key, settings.api_key_pepper.as_deref());
    let record = db.get_api_key_by_hash(&key_hash).await.map_err(|err| {
        error!("api key lookup failed: {err}");
        ApiError::internal("api key lookup failed")
    })?;
    let record = match record {
        Some(record) => record,
        None => {
            record_api_key_audit(db, None, None, "reject", "not_found").await;
            return Err(ApiError::unauthorized());
        }
    };

    if let Err(reason) = validate_api_key(&record) {
        record_api_key_audit(
            db,
            Some(&record.customer_id),
            Some(&record.id),
            "reject",
            reason.as_str(),
        )
        .await;
        return Err(ApiError::unauthorized());
    }

    let scopes = match parse_scopes(&record.scopes) {
        Ok(scopes) => scopes,
        Err(err) => {
            record_api_key_audit(
                db,
                Some(&record.customer_id),
                Some(&record.id),
                "reject",
                "invalid_scopes",
            )
            .await;
            return Err(err);
        }
    };

    record_api_key_audit(
        db,
        Some(&record.customer_id),
        Some(&record.id),
        "accept",
        "ok",
    )
    .await;
    Ok(ApiKeyAuth {
        api_key_id: record.id,
        customer_id: record.customer_id,
        key_type: record.key_type,
        scopes,
        expires_at: record.expires_at,
    })
}

pub fn admin_authorize(headers: &HeaderMap, settings: &Settings) -> Result<(), ApiError> {
    let expected = settings.admin_api_key.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api key not configured",
        )
    })?;
    let candidate = admin_key_from_headers(headers).ok_or_else(ApiError::unauthorized)?;
    if candidate == expected.as_str() {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

pub fn require_scopes(auth: &ApiKeyAuth, required: &[&str]) -> Result<(), ApiError> {
    for scope in required {
        if !auth.scopes.iter().any(|entry| entry == scope) {
            return Err(ApiError::forbidden("missing scope"));
        }
    }
    Ok(())
}

pub fn generate_api_key() -> Result<String, ApiError> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).map_err(|err| {
        error!("failed to generate api key bytes: {err}");
        ApiError::internal("failed to generate api key")
    })?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    Ok(format!("releasy_{token}"))
}

pub fn api_key_prefix(key: &str) -> String {
    key.chars().take(12).collect()
}

pub fn hash_api_key(key: &str, pepper: Option<&str>) -> String {
    hash_secret(key, pepper)
}

fn hash_secret(value: &str, pepper: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    if let Some(pepper) = pepper {
        hasher.update(pepper.as_bytes());
    }
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-releasy-api-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn admin_key_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(bearer) = bearer_token(headers) {
        return Some(bearer);
    }
    headers
        .get("x-releasy-admin-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiKeyInvalidReason {
    Revoked,
    Expired,
}

impl ApiKeyInvalidReason {
    fn as_str(self) -> &'static str {
        match self {
            ApiKeyInvalidReason::Revoked => "revoked",
            ApiKeyInvalidReason::Expired => "expired",
        }
    }
}

fn validate_api_key(record: &ApiKeyAuthRecord) -> Result<(), ApiKeyInvalidReason> {
    if record.revoked_at.is_some() {
        return Err(ApiKeyInvalidReason::Revoked);
    }
    if let Some(expires_at) = record.expires_at
        && expires_at <= now_ts()
    {
        return Err(ApiKeyInvalidReason::Expired);
    }
    Ok(())
}

fn parse_scopes(scopes: &str) -> Result<Vec<String>, ApiError> {
    let values: Vec<serde_json::Value> =
        serde_json::from_str(scopes).map_err(|_| ApiError::internal("invalid scope data"))?;
    let mut parsed = Vec::new();
    for entry in values {
        let scope = entry
            .as_str()
            .ok_or_else(|| ApiError::internal("invalid scope data"))?;
        parsed.push(scope.to_string());
    }
    Ok(parsed)
}

async fn record_api_key_audit(
    db: &Database,
    customer_id: Option<&str>,
    api_key_id: Option<&str>,
    outcome: &str,
    reason: &str,
) {
    let payload = serde_json::json!({
        "outcome": outcome,
        "reason": reason,
        "api_key_id": api_key_id,
    })
    .to_string();
    if let Err(err) = db
        .insert_audit_event(customer_id, "api_key", "api_key.auth", Some(&payload))
        .await
    {
        error!("failed to insert api key audit event: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use axum::http::HeaderMap;

    #[test]
    fn hash_api_key_changes_with_pepper() {
        let no_pepper = hash_api_key("releasy_abc", None);
        let with_pepper = hash_api_key("releasy_abc", Some("pepper"));
        assert_ne!(no_pepper, with_pepper);
    }

    #[test]
    fn generate_api_key_uses_prefix() {
        let key = generate_api_key().expect("api key");
        assert!(key.starts_with("releasy_"));
    }

    #[test]
    fn api_key_from_headers_rejects_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(api_key_from_headers(&headers), None);
    }

    #[test]
    fn validate_api_key_rejects_revoked() {
        let record = ApiKeyAuthRecord {
            id: "key".to_string(),
            customer_id: "customer".to_string(),
            key_type: "human".to_string(),
            scopes: "[]".to_string(),
            expires_at: None,
            revoked_at: Some(1),
        };
        assert_eq!(validate_api_key(&record), Err(ApiKeyInvalidReason::Revoked));
    }

    #[test]
    fn parse_scopes_rejects_invalid_json() {
        let result = parse_scopes("not-json");
        assert!(result.is_err());
    }

    #[test]
    fn admin_authorize_accepts_header() {
        let settings = Settings {
            bind_addr: "127.0.0.1:8080".to_string(),
            log_level: "info".to_string(),
            database_url: "sqlite::memory:".to_string(),
            database_max_connections: 1,
            admin_api_key: Some("secret".to_string()),
            api_key_pepper: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());
        assert!(admin_authorize(&headers, &settings).is_ok());
    }

    #[test]
    fn admin_authorize_rejects_missing_key() {
        let settings = Settings {
            bind_addr: "127.0.0.1:8080".to_string(),
            log_level: "info".to_string(),
            database_url: "sqlite::memory:".to_string(),
            database_max_connections: 1,
            admin_api_key: Some("secret".to_string()),
            api_key_pepper: None,
        };
        let headers = HeaderMap::new();
        assert!(admin_authorize(&headers, &settings).is_err());
    }
}
