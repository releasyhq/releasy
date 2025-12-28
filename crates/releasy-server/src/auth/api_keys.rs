use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::OsRng as PasswordOsRng,
    },
};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

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

    let key_prefix = api_key_prefix(&raw_key);
    let candidates = db
        .get_api_keys_by_prefix(&key_prefix)
        .await
        .map_err(|err| {
            error!("api key lookup failed: {err}");
            ApiError::internal("api key lookup failed")
        })?;
    if candidates.is_empty() {
        record_api_key_audit(db, None, None, "reject", "not_found").await;
        return Err(ApiError::unauthorized());
    }

    let pepper = settings.api_key_pepper.as_deref();
    let input = api_key_input_bytes(&raw_key, pepper);
    let legacy_hash = legacy_hash_from_bytes(&input);
    let mut matched_legacy = false;
    let mut record = None;
    for candidate in candidates {
        if is_argon2_hash(&candidate.key_hash) {
            if verify_argon2_hash(&input, &candidate.key_hash) {
                record = Some(candidate);
                break;
            }
        } else if candidate.key_hash == legacy_hash {
            matched_legacy = true;
            record = Some(candidate);
            break;
        }
    }

    let record = match record {
        Some(record) => record,
        None => {
            record_api_key_audit(db, None, None, "reject", "not_found").await;
            return Err(ApiError::unauthorized());
        }
    };

    let now = match now_ts() {
        Ok(now) => now,
        Err(err) => {
            error!("system time error: {err}");
            record_api_key_audit(
                db,
                Some(&record.customer_id),
                Some(&record.id),
                "reject",
                "time_unavailable",
            )
            .await;
            return Err(ApiError::internal("system time unavailable"));
        }
    };

    if let Err(reason) = validate_api_key(&record, now) {
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

    if matched_legacy {
        let new_hash = hash_api_key(&raw_key, pepper)?;
        let updated = db
            .update_api_key_hash(&record.id, &new_hash)
            .await
            .map_err(|err| {
                error!("failed to update api key hash: {err}");
                ApiError::internal("failed to update api key hash")
            })?;
        if updated == 0 {
            record_api_key_audit(
                db,
                Some(&record.customer_id),
                Some(&record.id),
                "reject",
                "not_found",
            )
            .await;
            return Err(ApiError::unauthorized());
        }
    }

    let updated = db
        .update_api_key_last_used(&record.id, now)
        .await
        .map_err(|err| {
            error!("failed to update api key last_used_at: {err}");
            ApiError::internal("failed to update api key usage")
        })?;
    if updated == 0 {
        record_api_key_audit(
            db,
            Some(&record.customer_id),
            Some(&record.id),
            "reject",
            "not_found",
        )
        .await;
        return Err(ApiError::unauthorized());
    }

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

pub fn generate_download_token() -> Result<String, ApiError> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).map_err(|err| {
        error!("failed to generate download token bytes: {err}");
        ApiError::internal("failed to generate download token")
    })?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    Ok(format!("releasy_dl_{token}"))
}

pub fn api_key_prefix(key: &str) -> String {
    key.chars().take(12).collect()
}

pub fn hash_api_key(key: &str, pepper: Option<&str>) -> Result<String, ApiError> {
    let input = api_key_input_bytes(key, pepper);
    let salt = SaltString::generate(&mut PasswordOsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(&input, &salt)
        .map_err(|err| {
            error!("failed to hash api key: {err}");
            ApiError::internal("failed to hash api key")
        })?
        .to_string();
    Ok(hash)
}

pub fn hash_download_token(token: &str, pepper: Option<&str>) -> String {
    hash_secret(token, pepper)
}

fn hash_secret(value: &str, pepper: Option<&str>) -> String {
    let input = api_key_input_bytes(value, pepper);
    legacy_hash_from_bytes(&input)
}

fn legacy_hash_from_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn api_key_input_bytes(key: &str, pepper: Option<&str>) -> Vec<u8> {
    let extra = pepper.map(|value| value.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(key.len() + extra);
    bytes.extend_from_slice(key.as_bytes());
    if let Some(pepper) = pepper {
        bytes.extend_from_slice(pepper.as_bytes());
    }
    bytes
}

fn is_argon2_hash(value: &str) -> bool {
    value.starts_with("$argon2")
}

fn verify_argon2_hash(input: &[u8], stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!("invalid api key hash: {err}");
            return false;
        }
    };
    Argon2::default().verify_password(input, &parsed).is_ok()
}

fn api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-releasy-api-key")
        .and_then(|value| value.to_str().ok())
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

fn validate_api_key(record: &ApiKeyAuthRecord, now: i64) -> Result<(), ApiKeyInvalidReason> {
    if record.revoked_at.is_some() {
        return Err(ApiKeyInvalidReason::Revoked);
    }
    if let Some(expires_at) = record.expires_at
        && expires_at <= now
    {
        return Err(ApiKeyInvalidReason::Expired);
    }
    Ok(())
}

fn parse_scopes(scopes: &str) -> Result<Vec<String>, ApiError> {
    let values: Vec<Value> = serde_json::from_str(scopes).map_err(|err| {
        warn!("invalid api key scope data: {err}");
        ApiError::unauthorized()
    })?;
    let mut parsed = Vec::new();
    for entry in values {
        let scope = entry.as_str().ok_or_else(|| {
            warn!("invalid api key scope entry");
            ApiError::unauthorized()
        })?;
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
    let created_at = match now_ts() {
        Ok(ts) => ts,
        Err(err) => {
            warn!("system time error, skipping audit event: {err}");
            return;
        }
    };
    let payload = json!({
        "outcome": outcome,
        "reason": reason,
        "api_key_id": api_key_id,
    })
    .to_string();
    if let Err(err) = db
        .insert_audit_event(
            customer_id,
            "api_key",
            "api_key.auth",
            Some(&payload),
            created_at,
        )
        .await
    {
        error!("failed to insert api key audit event: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::db::Database;
    use crate::models::{
        ApiKeyRecord, Customer, DEFAULT_API_KEY_TYPE, default_scopes, scopes_to_json,
    };
    use axum::http::{HeaderMap, StatusCode};

    fn test_settings() -> Settings {
        Settings {
            bind_addr: "127.0.0.1:8080".to_string(),
            log_level: "info".to_string(),
            database_url: "sqlite::memory:".to_string(),
            database_max_connections: 1,
            download_token_ttl_seconds: 600,
            admin_api_key: Some("secret".to_string()),
            api_key_pepper: None,
            operator_jwks_url: None,
            operator_issuer: None,
            operator_audience: None,
            operator_resource: None,
            operator_jwks_ttl_seconds: 300,
            operator_jwt_leeway_seconds: 0,
            artifact_settings: None,
        }
    }

    async fn setup_db(settings: &Settings) -> Database {
        let db = Database::connect(settings).await.expect("db connect");
        db.migrate().await.expect("db migrate");
        db
    }

    async fn fetch_last_used_at(db: &Database, key_id: &str) -> Option<i64> {
        match db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id = ?")
                    .bind(key_id)
                    .fetch_one(pool)
                    .await
                    .expect("last_used_at")
            }
            Database::Postgres(_) => panic!("sqlite expected"),
        }
    }

    async fn fetch_key_hash(db: &Database, key_id: &str) -> String {
        match db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar("SELECT key_hash FROM api_keys WHERE id = ?")
                    .bind(key_id)
                    .fetch_one(pool)
                    .await
                    .expect("key_hash")
            }
            Database::Postgres(_) => panic!("sqlite expected"),
        }
    }

    #[test]
    fn hash_api_key_verifies_matching_key() {
        let hash = hash_api_key("releasy_abc", Some("pepper")).expect("hash");
        let input = api_key_input_bytes("releasy_abc", Some("pepper"));
        assert!(verify_argon2_hash(&input, &hash));
    }

    #[test]
    fn hash_api_key_rejects_wrong_key() {
        let hash = hash_api_key("releasy_abc", None).expect("hash");
        let input = api_key_input_bytes("releasy_wrong", None);
        assert!(!verify_argon2_hash(&input, &hash));
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
            key_hash: "hash".to_string(),
            key_type: "human".to_string(),
            scopes: "[]".to_string(),
            expires_at: None,
            revoked_at: Some(1),
        };
        assert_eq!(
            validate_api_key(&record, 0),
            Err(ApiKeyInvalidReason::Revoked)
        );
    }

    #[tokio::test]
    async fn authenticate_api_key_updates_last_used_at() {
        let settings = test_settings();
        let db = setup_db(&settings).await;

        let customer = Customer {
            id: "customer".to_string(),
            name: "Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: 1,
            suspended_at: None,
        };
        db.insert_customer(&customer).await.expect("customer");

        let raw_key = "releasy_test_key";
        let scopes = default_scopes();
        let record = ApiKeyRecord {
            id: "key".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes"),
            expires_at: None,
            created_at: 1,
            revoked_at: None,
            last_used_at: None,
        };
        let key_id = record.id.clone();
        db.insert_api_key(&record).await.expect("api key");

        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
        let auth = authenticate_api_key(&headers, &settings, &db)
            .await
            .expect("auth");
        assert_eq!(auth.api_key_id, key_id);

        let last_used_at = fetch_last_used_at(&db, &key_id).await;
        assert!(last_used_at.is_some());
    }

    #[tokio::test]
    async fn authenticate_api_key_upgrades_legacy_hash() {
        let settings = test_settings();
        let db = setup_db(&settings).await;

        let customer = Customer {
            id: "customer".to_string(),
            name: "Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: 1,
            suspended_at: None,
        };
        db.insert_customer(&customer).await.expect("customer");

        let raw_key = "releasy_test_key";
        let legacy_hash = legacy_hash_from_bytes(&api_key_input_bytes(raw_key, None));
        let scopes = default_scopes();
        let record = ApiKeyRecord {
            id: "key".to_string(),
            customer_id: customer.id.clone(),
            key_hash: legacy_hash.clone(),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes"),
            expires_at: None,
            created_at: 1,
            revoked_at: None,
            last_used_at: None,
        };
        let key_id = record.id.clone();
        db.insert_api_key(&record).await.expect("api key");

        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
        authenticate_api_key(&headers, &settings, &db)
            .await
            .expect("auth");

        let updated_hash = fetch_key_hash(&db, &key_id).await;
        assert!(updated_hash.starts_with("$argon2"));
        assert_ne!(updated_hash, legacy_hash);
    }

    #[tokio::test]
    async fn authenticate_api_key_does_not_update_last_used_on_failure() {
        let settings = test_settings();
        let db = setup_db(&settings).await;

        let customer = Customer {
            id: "customer".to_string(),
            name: "Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: 1,
            suspended_at: None,
        };
        db.insert_customer(&customer).await.expect("customer");

        let raw_key = "releasy_test_key";
        let scopes = default_scopes();
        let record = ApiKeyRecord {
            id: "key".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes"),
            expires_at: None,
            created_at: 1,
            revoked_at: None,
            last_used_at: None,
        };
        let key_id = record.id.clone();
        db.insert_api_key(&record).await.expect("api key");

        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", "releasy_wrong".parse().unwrap());
        assert!(
            authenticate_api_key(&headers, &settings, &db)
                .await
                .is_err()
        );

        let last_used_at = fetch_last_used_at(&db, &key_id).await;
        assert!(last_used_at.is_none());
    }

    #[tokio::test]
    async fn authenticate_api_key_rejects_invalid_scopes() {
        let settings = test_settings();
        let db = setup_db(&settings).await;

        let customer = Customer {
            id: "customer".to_string(),
            name: "Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: 1,
            suspended_at: None,
        };
        db.insert_customer(&customer).await.expect("customer");

        let raw_key = "releasy_test_key";
        let record = ApiKeyRecord {
            id: "key".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: "not-json".to_string(),
            expires_at: None,
            created_at: 1,
            revoked_at: None,
            last_used_at: None,
        };
        let key_id = record.id.clone();
        db.insert_api_key(&record).await.expect("api key");

        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
        let err = authenticate_api_key(&headers, &settings, &db)
            .await
            .expect_err("auth");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);

        let last_used_at = fetch_last_used_at(&db, &key_id).await;
        assert!(last_used_at.is_none());
    }

    #[test]
    fn parse_scopes_accepts_valid_json() {
        let result = parse_scopes("[\"release:read\", \"release:write\"]").expect("scopes");
        assert_eq!(
            result,
            vec!["release:read".to_string(), "release:write".to_string()]
        );
    }

    #[test]
    fn parse_scopes_rejects_invalid_json() {
        let result = parse_scopes("not-json").expect_err("error");
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
    }
}
