use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    PlatformAdmin,
    PlatformSupport,
    ReleasePublisher,
}

#[derive(Clone)]
pub struct JwksCache {
    jwks_url: String,
    ttl: Duration,
    client: Client,
    state: Arc<RwLock<Option<JwksState>>>,
}

#[derive(Clone)]
struct JwksState {
    fetched_at: Instant,
    jwks: JwkSet,
}

const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(8);
const JWKS_RETRY_BACKOFF: Duration = Duration::from_millis(200);
const JWKS_MAX_RETRIES: usize = 1;
const JWKS_TIMEOUT_MESSAGE: &str = "operator jwks request timed out";

struct JwksFetchFailure {
    api_error: ApiError,
    retryable: bool,
}

impl JwksFetchFailure {
    fn timeout() -> Self {
        Self {
            api_error: ApiError::new(StatusCode::SERVICE_UNAVAILABLE, JWKS_TIMEOUT_MESSAGE),
            retryable: false,
        }
    }

    fn unavailable(retryable: bool) -> Self {
        Self {
            api_error: ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "operator jwks unavailable"),
            retryable,
        }
    }
}

impl JwksCache {
    pub fn new(settings: &Settings) -> Option<Self> {
        let jwks_url = settings.operator_jwks_url.clone()?;
        let ttl = Duration::from_secs(settings.operator_jwks_ttl_seconds as u64);
        let client = Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .expect("failed to build jwks client");
        Some(Self {
            jwks_url,
            ttl,
            client,
            state: Arc::new(RwLock::new(None)),
        })
    }

    async fn get_jwks(&self) -> Result<JwkSet, ApiError> {
        let now = Instant::now();
        if let Some(cached) = self.state.read().await.clone()
            && now.duration_since(cached.fetched_at) <= self.ttl
        {
            return Ok(cached.jwks);
        }

        let jwks = self.fetch_jwks().await?;
        let mut guard = self.state.write().await;
        *guard = Some(JwksState {
            fetched_at: now,
            jwks: jwks.clone(),
        });
        Ok(jwks)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, ApiError> {
        let mut attempt = 0;
        let mut backoff = JWKS_RETRY_BACKOFF;
        loop {
            match self.fetch_jwks_once().await {
                Ok(jwks) => return Ok(jwks),
                Err(failure) => {
                    if !failure.retryable || attempt >= JWKS_MAX_RETRIES {
                        return Err(failure.api_error);
                    }
                    warn!(
                        "jwks fetch failed, retrying in {:?} (attempt {}/{})",
                        backoff,
                        attempt + 1,
                        JWKS_MAX_RETRIES + 1
                    );
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                    attempt += 1;
                }
            }
        }
    }

    async fn fetch_jwks_once(&self) -> Result<JwkSet, JwksFetchFailure> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    warn!("jwks request timed out: {err}");
                    return JwksFetchFailure::timeout();
                }
                error!("failed to fetch jwks: {err}");
                JwksFetchFailure::unavailable(err.is_connect())
            })?;
        let response = response.error_for_status().map_err(|err| {
            let retryable = err
                .status()
                .map(|status| status.is_server_error())
                .unwrap_or(false);
            error!("jwks returned error status: {err}");
            JwksFetchFailure::unavailable(retryable)
        })?;
        response.json::<JwkSet>().await.map_err(|err| {
            if err.is_timeout() {
                warn!("jwks response timed out: {err}");
                return JwksFetchFailure::timeout();
            }
            error!("failed to parse jwks: {err}");
            JwksFetchFailure::unavailable(false)
        })
    }
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

pub async fn admin_authorize_with_role(
    headers: &HeaderMap,
    settings: &Settings,
    jwks_cache: &Option<JwksCache>,
) -> Result<AdminRole, ApiError> {
    let has_admin_key = admin_key_from_headers(headers).is_some();
    if let Some(token) = bearer_token(headers)
        && looks_like_jwt(&token)
    {
        let jwks_cache = match jwks_cache.as_ref() {
            Some(cache) => cache,
            None => {
                if has_admin_key {
                    warn!("operator jwks not configured, falling back to admin key");
                    admin_authorize(headers, settings)?;
                    return Ok(AdminRole::PlatformAdmin);
                }
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "operator jwks not configured",
                ));
            }
        };
        match authorize_operator_jwt(&token, settings, jwks_cache).await {
            Ok(role) => return Ok(role),
            Err(err) => {
                if has_admin_key {
                    warn!("operator jwt auth failed, falling back to admin key");
                    admin_authorize(headers, settings)?;
                    return Ok(AdminRole::PlatformAdmin);
                }
                return Err(err);
            }
        }
    }

    admin_authorize(headers, settings)?;
    Ok(AdminRole::PlatformAdmin)
}

pub fn require_admin(role: AdminRole) -> Result<(), ApiError> {
    if role == AdminRole::PlatformAdmin {
        Ok(())
    } else {
        Err(ApiError::forbidden("admin role required"))
    }
}

pub fn require_support_or_admin(role: AdminRole) -> Result<(), ApiError> {
    match role {
        AdminRole::PlatformAdmin | AdminRole::PlatformSupport => Ok(()),
        _ => Err(ApiError::forbidden("platform_support role required")),
    }
}

pub fn require_release_publisher(role: AdminRole) -> Result<(), ApiError> {
    match role {
        AdminRole::PlatformAdmin | AdminRole::ReleasePublisher => Ok(()),
        _ => Err(ApiError::forbidden("release_publisher role required")),
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
    if let Some(bearer) = bearer_token(headers)
        && !looks_like_jwt(&bearer)
    {
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

fn looks_like_jwt(token: &str) -> bool {
    token.matches('.').count() == 2
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
    let values: Vec<serde_json::Value> = serde_json::from_str(scopes).map_err(|err| {
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

async fn authorize_operator_jwt(
    token: &str,
    settings: &Settings,
    jwks_cache: &JwksCache,
) -> Result<AdminRole, ApiError> {
    let header = decode_header(token).map_err(|err| {
        error!("jwt header decode failed: {err}");
        ApiError::unauthorized()
    })?;
    let kid = header.kid.ok_or_else(ApiError::unauthorized)?;
    let jwks = jwks_cache.get_jwks().await?;
    let jwk = jwks.find(&kid).ok_or_else(ApiError::unauthorized)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|err| {
        error!("jwt jwk decode failed: {err}");
        ApiError::unauthorized()
    })?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = settings.operator_jwt_leeway_seconds as u64;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    let token_data = decode::<Value>(token, &key, &validation).map_err(|err| {
        error!("jwt decode failed: {err}");
        ApiError::unauthorized()
    })?;

    let claims = token_data.claims;
    if let Some(expected) = settings.operator_issuer.as_deref() {
        let issuer = claims
            .get("iss")
            .and_then(|value| value.as_str())
            .ok_or_else(ApiError::unauthorized)?;
        if issuer != expected {
            return Err(ApiError::unauthorized());
        }
    }

    if let Some(expected) = settings.operator_audience.as_deref()
        && !audience_matches(&claims, expected)
    {
        return Err(ApiError::unauthorized());
    }

    let roles = extract_roles(&claims, settings.operator_resource.as_deref());
    let role = admin_role_from_roles(&roles)
        .ok_or_else(|| ApiError::forbidden("missing operator role"))?;
    Ok(role)
}

fn audience_matches(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|entry| entry.as_str() == Some(expected)),
        _ => false,
    }
}

fn extract_roles(claims: &Value, resource: Option<&str>) -> HashSet<String> {
    let mut roles = HashSet::new();
    collect_roles(&mut roles, claims.get("roles"));
    collect_roles(
        &mut roles,
        claims
            .get("realm_access")
            .and_then(|value| value.get("roles")),
    );
    if let Some(resource) = resource {
        collect_roles(
            &mut roles,
            claims
                .get("resource_access")
                .and_then(|value| value.get(resource))
                .and_then(|value| value.get("roles")),
        );
    }
    roles
}

fn collect_roles(target: &mut HashSet<String>, value: Option<&Value>) {
    match value {
        Some(Value::String(role)) => {
            target.insert(role.to_string());
        }
        Some(Value::Array(roles)) => {
            for entry in roles {
                if let Some(role) = entry.as_str() {
                    target.insert(role.to_string());
                }
            }
        }
        _ => {}
    }
}

fn admin_role_from_roles(roles: &HashSet<String>) -> Option<AdminRole> {
    if roles.contains("platform_admin") {
        Some(AdminRole::PlatformAdmin)
    } else if roles.contains("platform_support") {
        Some(AdminRole::PlatformSupport)
    } else if roles.contains("release_publisher") {
        Some(AdminRole::ReleasePublisher)
    } else {
        None
    }
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
    let payload = serde_json::json!({
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
    use serde_json::json;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn test_settings() -> Settings {
        Settings {
            bind_addr: "127.0.0.1:8080".to_string(),
            log_level: "info".to_string(),
            database_url: "sqlite::memory:".to_string(),
            database_max_connections: 1,
            admin_api_key: Some("secret".to_string()),
            api_key_pepper: None,
            operator_jwks_url: None,
            operator_issuer: None,
            operator_audience: None,
            operator_resource: None,
            operator_jwks_ttl_seconds: 300,
            operator_jwt_leeway_seconds: 0,
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
            key_hash: hash_api_key(raw_key, None),
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
            key_hash: hash_api_key(raw_key, None),
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
            key_hash: hash_api_key(raw_key, None),
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

    #[test]
    fn admin_authorize_accepts_header() {
        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());
        assert!(admin_authorize(&headers, &settings).is_ok());
    }

    #[test]
    fn admin_authorize_rejects_missing_key() {
        let settings = test_settings();
        let headers = HeaderMap::new();
        assert!(admin_authorize(&headers, &settings).is_err());
    }

    #[tokio::test]
    async fn admin_authorize_with_role_falls_back_without_jwks() {
        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer a.b.c".parse().unwrap());
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());

        let role = admin_authorize_with_role(&headers, &settings, &None)
            .await
            .expect("role");
        assert_eq!(role, AdminRole::PlatformAdmin);
    }

    #[tokio::test]
    async fn admin_authorize_with_role_falls_back_on_jwt_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let cache = JwksCache {
            jwks_url: format!("http://{addr}/jwks"),
            ttl: Duration::from_secs(30),
            client: Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .expect("client"),
            state: Arc::new(RwLock::new(None)),
        };

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"missing"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"operator"}"#);
        let token = format!("{header}.{payload}.signature");

        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());

        let role = admin_authorize_with_role(&headers, &settings, &Some(cache))
            .await
            .expect("role");
        assert_eq!(role, AdminRole::PlatformAdmin);
        server.await.expect("server");
    }

    #[test]
    fn extract_roles_collects_multiple_sources() {
        let claims = json!({
            "roles": ["release_publisher"],
            "realm_access": { "roles": ["platform_support"] },
            "resource_access": {
                "releasy": { "roles": ["platform_admin"] }
            }
        });
        let roles = extract_roles(&claims, Some("releasy"));
        assert!(roles.contains("release_publisher"));
        assert!(roles.contains("platform_support"));
        assert!(roles.contains("platform_admin"));
    }

    #[test]
    fn extract_roles_returns_empty_without_roles() {
        let claims = json!({ "sub": "operator" });
        let roles = extract_roles(&claims, Some("releasy"));
        assert!(roles.is_empty());
    }

    #[test]
    fn admin_role_from_roles_prefers_admin() {
        let roles = HashSet::from([
            "release_publisher".to_string(),
            "platform_admin".to_string(),
        ]);
        assert_eq!(
            admin_role_from_roles(&roles),
            Some(AdminRole::PlatformAdmin)
        );
    }

    #[test]
    fn admin_role_from_roles_rejects_unknown() {
        let roles = HashSet::from(["other".to_string()]);
        assert_eq!(admin_role_from_roles(&roles), None);
    }

    #[test]
    fn looks_like_jwt_detects_format() {
        assert!(looks_like_jwt("a.b.c"));
        assert!(!looks_like_jwt("not-a-jwt"));
    }

    #[tokio::test]
    async fn jwks_cache_fetches_jwks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let cache = JwksCache {
            jwks_url: format!("http://{addr}/jwks"),
            ttl: Duration::from_secs(30),
            client: Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .expect("client"),
            state: Arc::new(RwLock::new(None)),
        };

        let jwks = cache.fetch_jwks().await.expect("jwks");
        assert!(jwks.keys.is_empty());
        server.await.expect("server");
    }

    #[tokio::test]
    async fn jwks_cache_timeout_returns_service_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(socket);
        });

        let cache = JwksCache {
            jwks_url: format!("http://{addr}/jwks"),
            ttl: Duration::from_secs(30),
            client: Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .expect("client"),
            state: Arc::new(RwLock::new(None)),
        };

        let result = tokio::time::timeout(Duration::from_secs(2), cache.fetch_jwks()).await;
        let err = result
            .expect("fetch timed out")
            .expect_err("expected timeout");
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.message(), JWKS_TIMEOUT_MESSAGE);
        server.await.expect("server");
    }
}
