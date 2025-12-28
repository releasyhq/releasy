pub(crate) mod admin;
pub(crate) mod artifacts;
pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod downloads;
pub(crate) mod entitlements;
pub(crate) mod keys;
pub(crate) mod releases;

pub(crate) use admin::{
    AdminCreateCustomerRequest, AdminCreateCustomerResponse, admin_create_customer,
};
pub(crate) use artifacts::{
    ArtifactPresignRequest, ArtifactPresignResponse, ArtifactRegisterRequest,
    ArtifactRegisterResponse, presign_release_artifact_upload, register_release_artifact,
};
pub(crate) use audit::{
    AuditEventListQuery, AuditEventListResponse, AuditEventResponse, list_audit_events,
};
pub(crate) use auth::auth_introspect;
pub(crate) use downloads::{
    DownloadTokenRequest, DownloadTokenResponse, create_download_token, resolve_download_token,
};
pub(crate) use entitlements::{
    EntitlementCreateRequest, EntitlementListQuery, EntitlementListResponse, EntitlementResponse,
    EntitlementUpdateRequest, create_entitlement, delete_entitlement, list_entitlements,
    update_entitlement,
};
pub(crate) use keys::{
    AdminCreateKeyRequest, AdminCreateKeyResponse, AdminRevokeKeyRequest, AdminRevokeKeyResponse,
    admin_create_key, admin_revoke_key,
};
pub(crate) use releases::{
    ArtifactSummary, ReleaseCreateRequest, ReleaseListQuery, ReleaseListResponse, ReleaseResponse,
    create_release, delete_release, list_releases, publish_release, unpublish_release,
};

use axum::extract::Json;
use axum::http::{HeaderMap, StatusCode, header};
use hex::encode as hex_encode;
use s3::Bucket;
use s3::Region;
use s3::creds::Credentials;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::future::Future;
#[cfg(test)]
use std::sync::{Arc, Mutex};
use tracing::error;
#[cfg(test)]
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{AdminRole, admin_authorize_with_role, require_admin, require_release_publisher};
use crate::config::ArtifactSettings;
use crate::errors::ApiError;
use crate::models::{ALLOWED_SCOPES, DEFAULT_API_KEY_TYPE, EntitlementRecord, ReleaseRecord};
use crate::release::{ReleaseAction, ReleaseStatus, ReleaseTransitionError, apply_release_action};
use crate::utils::now_ts;

#[cfg(test)]
use crate::auth::{api_key_prefix, hash_api_key};
#[cfg(test)]
use crate::models::default_scopes;
#[cfg(test)]
use axum::extract::{Path, State};
#[cfg(test)]
use axum::response::IntoResponse;
#[cfg(test)]
use tokio::sync::Barrier;

#[cfg(test)]
static RELEASE_UPDATE_BARRIER: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);
fn artifact_settings(settings: &crate::config::Settings) -> Result<&ArtifactSettings, ApiError> {
    settings.artifact_settings.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact storage not configured",
        )
    })
}

fn build_artifact_bucket(settings: &ArtifactSettings) -> Result<Box<Bucket>, ApiError> {
    let region = match &settings.endpoint {
        Some(endpoint) => Region::Custom {
            region: settings.region.clone(),
            endpoint: endpoint.clone(),
        },
        None => settings
            .region
            .parse()
            .map_err(|_| ApiError::bad_request("invalid artifact region"))?,
    };
    let credentials = Credentials::new(
        Some(settings.access_key.as_str()),
        Some(settings.secret_key.as_str()),
        None,
        None,
        None,
    )
    .map_err(|err| {
        error!("invalid artifact credentials: {err}");
        ApiError::internal("invalid artifact credentials")
    })?;
    let bucket = Bucket::new(settings.bucket.as_str(), region, credentials).map_err(|err| {
        error!("failed to build artifact bucket: {err}");
        ApiError::internal("failed to build artifact bucket")
    })?;
    let bucket = if settings.path_style {
        bucket.with_path_style()
    } else {
        bucket
    };
    Ok(bucket)
}

fn artifact_object_key_prefix(
    release: &ReleaseRecord,
    platform: &str,
    artifact_id: &str,
) -> Result<String, ApiError> {
    let product = normalize_object_key_segment("product", &release.product)?;
    let version = normalize_object_key_segment("version", &release.version)?;
    let platform = normalize_object_key_segment("platform", platform)?;
    Ok(format!(
        "releases/{product}/{version}/{platform}/{artifact_id}/"
    ))
}

fn build_artifact_object_key(
    release: &ReleaseRecord,
    platform: &str,
    artifact_id: &str,
    filename: &str,
) -> Result<String, ApiError> {
    let prefix = artifact_object_key_prefix(release, platform, artifact_id)?;
    let filename = normalize_object_key_segment("filename", filename)?;
    Ok(format!("{prefix}{filename}"))
}

fn normalize_required(field: &str, value: String) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(format!("{field} is required")));
    }
    Ok(trimmed.to_string())
}

fn normalize_optional(field: &str, value: Option<String>) -> Result<Option<String>, ApiError> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(ApiError::bad_request(format!("{field} must not be empty")))
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        None => Ok(None),
    }
}

async fn ensure_customer_exists(state: &AppState, customer_id: &str) -> Result<(), ApiError> {
    let exists = state.db.customer_exists(customer_id).await.map_err(|err| {
        error!("failed to lookup customer: {err}");
        ApiError::internal("customer lookup failed")
    })?;
    if !exists {
        return Err(ApiError::not_found("customer not found"));
    }
    Ok(())
}

fn metadata_to_string(metadata: Value) -> Result<String, ApiError> {
    serde_json::to_string(&metadata).map_err(|err| {
        error!("failed to serialize entitlement metadata: {err}");
        ApiError::bad_request("metadata must be valid JSON")
    })
}

fn normalize_object_key_segment(field: &str, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(format!("{field} is required")));
    }
    let mut normalized = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            normalized.push(ch.to_ascii_lowercase());
        } else {
            normalized.push('_');
        }
    }
    if normalized.trim_matches('_').is_empty() {
        return Err(ApiError::bad_request(format!("{field} is invalid")));
    }
    Ok(normalized)
}

fn normalize_checksum(checksum: &str) -> Result<String, ApiError> {
    let trimmed = checksum.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "checksum must be a 64 character hex string",
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn validate_artifact_size(size: i64) -> Result<i64, ApiError> {
    if size <= 0 {
        return Err(ApiError::bad_request("size must be positive"));
    }
    Ok(size)
}

fn now_ts_or_internal() -> Result<i64, ApiError> {
    now_ts().map_err(|err| {
        error!("system time error: {err}");
        ApiError::internal("system time unavailable")
    })
}

fn resolve_pagination(limit: Option<u32>, offset: Option<u32>) -> Result<(i64, i64), ApiError> {
    const DEFAULT_LIMIT: u32 = 50;
    const MAX_LIMIT: u32 = 200;

    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 {
        return Err(ApiError::bad_request("limit must be positive"));
    }
    if limit > MAX_LIMIT {
        return Err(ApiError::bad_request(format!(
            "limit must be <= {MAX_LIMIT}"
        )));
    }

    let offset = offset.unwrap_or(0);
    Ok((limit as i64, offset as i64))
}

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const IDEMPOTENCY_TTL_SECONDS: i64 = 86_400;
const IDEMPOTENCY_STATE_IN_PROGRESS: &str = "in_progress";
const IDEMPOTENCY_STATE_COMPLETED: &str = "completed";

struct IdempotencyContext {
    key: String,
    endpoint: &'static str,
    request_hash: String,
    created_at: i64,
    expires_at: i64,
}

struct IdempotencyStart<R> {
    existing: Option<R>,
    context: Option<IdempotencyContext>,
}

async fn idempotency_start<P, R>(
    state: &AppState,
    headers: &HeaderMap,
    endpoint: &'static str,
    extra: &str,
    payload: &P,
) -> Result<IdempotencyStart<R>, ApiError>
where
    P: Serialize,
    R: DeserializeOwned,
{
    let key = match extract_idempotency_key(headers)? {
        Some(key) => key,
        None => {
            return Ok(IdempotencyStart {
                existing: None,
                context: None,
            });
        }
    };
    let request_hash = hash_idempotency_payload(extra, payload)?;
    let now = now_ts_or_internal()?;

    loop {
        let record = crate::models::IdempotencyRecord {
            key: key.clone(),
            endpoint: endpoint.to_string(),
            request_hash: request_hash.clone(),
            response_status: None,
            response_body: None,
            state: IDEMPOTENCY_STATE_IN_PROGRESS.to_string(),
            created_at: now,
            expires_at: now + IDEMPOTENCY_TTL_SECONDS,
        };
        let inserted = state
            .db
            .insert_idempotency_key(&record)
            .await
            .map_err(|err| {
                error!("failed to reserve idempotency key: {err}");
                ApiError::internal("failed to reserve idempotency key")
            })?;
        if inserted > 0 {
            return Ok(IdempotencyStart {
                existing: None,
                context: Some(IdempotencyContext {
                    key,
                    endpoint,
                    request_hash,
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                }),
            });
        }

        let existing = state
            .db
            .get_idempotency_key(&key, endpoint)
            .await
            .map_err(|err| {
                error!("failed to lookup idempotency key: {err}");
                ApiError::internal("failed to lookup idempotency key")
            })?;
        let Some(existing) = existing else {
            continue;
        };

        if existing.expires_at <= now {
            let _ = state.db.delete_idempotency_key(&key, endpoint).await;
            continue;
        }

        if existing.request_hash != request_hash {
            return Err(ApiError::new_with_code(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "idempotency key already used",
            ));
        }

        if existing.state != IDEMPOTENCY_STATE_COMPLETED {
            return Err(ApiError::new_with_code(
                StatusCode::CONFLICT,
                "idempotency_in_progress",
                "idempotency key already in progress",
            ));
        }

        let body = existing
            .response_body
            .ok_or_else(|| ApiError::internal("idempotency response missing"))?;
        let response = serde_json::from_str(&body).map_err(|err| {
            error!("failed to decode idempotency response: {err}");
            ApiError::internal("failed to decode idempotency response")
        })?;
        return Ok(IdempotencyStart {
            existing: Some(response),
            context: None,
        });
    }
}

async fn idempotency_finish<R>(
    state: &AppState,
    context: IdempotencyContext,
    response: &R,
) -> Result<(), ApiError>
where
    R: Serialize,
{
    let body = serde_json::to_string(response).map_err(|err| {
        error!("failed to encode idempotency response: {err}");
        ApiError::internal("failed to encode idempotency response")
    })?;
    let record = crate::models::IdempotencyRecord {
        key: context.key,
        endpoint: context.endpoint.to_string(),
        request_hash: context.request_hash,
        response_status: Some(i32::from(StatusCode::OK.as_u16())),
        response_body: Some(body),
        state: IDEMPOTENCY_STATE_COMPLETED.to_string(),
        created_at: context.created_at,
        expires_at: context.expires_at,
    };

    state
        .db
        .update_idempotency_key(&record)
        .await
        .map_err(|err| {
            error!("failed to store idempotency response: {err}");
            ApiError::internal("failed to store idempotency response")
        })?;
    Ok(())
}

async fn idempotency_abort(state: &AppState, context: IdempotencyContext) {
    let _ = state
        .db
        .delete_idempotency_key(&context.key, context.endpoint)
        .await;
}

fn extract_idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let value = match headers.get(IDEMPOTENCY_KEY_HEADER) {
        Some(value) => value,
        None => return Ok(None),
    };
    let value = value
        .to_str()
        .map_err(|_| ApiError::bad_request("idempotency-key must be valid ASCII"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("idempotency-key must not be empty"));
    }
    if trimmed.len() > 128 {
        return Err(ApiError::bad_request("idempotency-key is too long"));
    }
    Ok(Some(trimmed.to_string()))
}

fn hash_idempotency_payload<P>(extra: &str, payload: &P) -> Result<String, ApiError>
where
    P: Serialize,
{
    let payload_json = serde_json::to_string(payload).map_err(|err| {
        error!("failed to encode idempotency payload: {err}");
        ApiError::internal("failed to encode idempotency payload")
    })?;
    let mut hasher = Sha256::new();
    hasher.update(extra.as_bytes());
    hasher.update(b":");
    hasher.update(payload_json.as_bytes());
    Ok(hex_encode(hasher.finalize()))
}

async fn with_idempotency<P, R, F, Fut>(
    state: &AppState,
    headers: &HeaderMap,
    endpoint: &'static str,
    extra: &str,
    payload: &P,
    handler: F,
) -> Result<R, ApiError>
where
    P: Serialize,
    R: Serialize + DeserializeOwned,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R, ApiError>>,
{
    let start = idempotency_start::<P, R>(state, headers, endpoint, extra, payload).await?;
    if let Some(existing) = start.existing {
        return Ok(existing);
    }

    let result = handler().await;
    match result {
        Ok(response) => {
            if let Some(context) = start.context
                && let Err(err) = idempotency_finish(state, context, &response).await
            {
                error!("idempotency finish failed: {err:?}");
            }
            Ok(response)
        }
        Err(err) => {
            if let Some(context) = start.context {
                idempotency_abort(state, context).await;
            }
            Err(err)
        }
    }
}

fn normalize_key_type(value: Option<String>) -> Result<String, ApiError> {
    let value = value.unwrap_or_else(|| DEFAULT_API_KEY_TYPE.to_string());
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("key_type is required"));
    }
    let normalized = trimmed.to_ascii_lowercase();
    match normalized.as_str() {
        "human" | "ci" | "integration" => Ok(normalized),
        _ => Err(ApiError::bad_request("invalid key_type")),
    }
}

fn validate_expires_at(expires_at: Option<i64>) -> Result<Option<i64>, ApiError> {
    const MAX_EXPIRES_AT_SECONDS: i64 = 10_000_000_000;
    if let Some(expires_at) = expires_at {
        if !(0..=MAX_EXPIRES_AT_SECONDS).contains(&expires_at) {
            return Err(ApiError::bad_request(
                "expires_at must be a unix timestamp in seconds",
            ));
        }
        let now = now_ts_or_internal()?;
        if expires_at <= now {
            return Err(ApiError::bad_request("expires_at must be in the future"));
        }
    }
    Ok(expires_at)
}

fn validate_scopes(scopes: &[String]) -> Result<(), ApiError> {
    for scope in scopes {
        if !ALLOWED_SCOPES.iter().any(|allowed| allowed == scope) {
            return Err(ApiError::bad_request("invalid scope"));
        }
    }
    Ok(())
}

fn resolve_requested_ttl(requested: Option<u32>, max: u32, field: &str) -> Result<u32, ApiError> {
    let ttl = requested.unwrap_or(max);
    if ttl == 0 {
        return Err(ApiError::bad_request(format!("{field} must be positive")));
    }
    if ttl > max {
        return Err(ApiError::bad_request(format!("{field} must be <= {max}")));
    }
    Ok(ttl)
}

fn build_download_url(headers: &HeaderMap, token: &str) -> Result<String, ApiError> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing Host header"))?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("https");
    Ok(format!("{proto}://{host}/v1/downloads/{token}"))
}

fn is_product_entitled(entitlements: &[EntitlementRecord], product: &str, now: i64) -> bool {
    entitlements.iter().any(|entitlement| {
        entitlement.product == product
            && entitlement.starts_at <= now
            && entitlement
                .ends_at
                .map(|ends_at| ends_at >= now)
                .unwrap_or(true)
    })
}

fn require_release_list_role(role: AdminRole) -> Result<(), ApiError> {
    match role {
        AdminRole::PlatformAdmin | AdminRole::PlatformSupport | AdminRole::ReleasePublisher => {
            Ok(())
        }
    }
}

async fn apply_release_action_with_rbac(
    state: &AppState,
    headers: &HeaderMap,
    release_id: &str,
    action: ReleaseAction,
) -> Result<Json<ReleaseResponse>, ApiError> {
    let role = admin_authorize_with_role(headers, &state.settings, &state.jwks_cache).await?;
    match action {
        ReleaseAction::Publish => require_release_publisher(role)?,
        ReleaseAction::Unpublish => require_admin(role)?,
    }

    let mut release = state
        .db
        .get_release(release_id)
        .await
        .map_err(|err| {
            error!("failed to get release: {err}");
            ApiError::internal("failed to get release")
        })?
        .ok_or_else(|| ApiError::not_found("release not found"))?;

    let current = ReleaseStatus::parse(&release.status)
        .ok_or_else(|| ApiError::internal("invalid status"))?;
    let next = apply_release_action(current, action).map_err(|err| {
        let message = match err {
            ReleaseTransitionError::AlreadyPublished => "release already published",
            ReleaseTransitionError::AlreadyDraft => "release already draft",
        };
        ApiError::bad_request(message)
    })?;

    let published_at = if next == ReleaseStatus::Published {
        Some(now_ts_or_internal()?)
    } else {
        None
    };

    #[cfg(test)]
    {
        let barrier = RELEASE_UPDATE_BARRIER
            .lock()
            .expect("release update barrier")
            .clone();
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
    }

    let rows = state
        .db
        .update_release_status(
            release_id,
            next.as_str(),
            published_at,
            Some(current.as_str()),
        )
        .await
        .map_err(|err| {
            error!("failed to update release status: {err}");
            ApiError::internal("failed to update release status")
        })?;
    if rows == 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "release status changed, retry",
        ));
    }

    release.status = next.as_str().to_string();
    release.published_at = published_at;
    Ok(Json(ReleaseResponse::from_record(release, None)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ArtifactSettings, Settings};
    use crate::db::Database;
    use crate::models::{
        ApiKeyRecord, ArtifactRecord, Customer, EntitlementRecord, ReleaseRecord, scopes_to_json,
    };
    use crate::release::ReleaseStatus;
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use serde_json::json;

    #[test]
    fn normalize_key_type_accepts_known_values() {
        let value = Some("  Human ".to_string());
        assert_eq!(normalize_key_type(value).expect("key type"), "human");
    }

    #[test]
    fn normalize_key_type_rejects_empty() {
        let value = Some("   ".to_string());
        assert!(normalize_key_type(value).is_err());
    }

    #[test]
    fn normalize_key_type_rejects_unknown() {
        let value = Some("other".to_string());
        assert!(normalize_key_type(value).is_err());
    }

    #[test]
    fn validate_expires_at_rejects_past() {
        let now = now_ts_or_internal().expect("now");
        let expires_at = Some(now - 1);
        assert!(validate_expires_at(expires_at).is_err());
    }

    #[test]
    fn validate_expires_at_rejects_too_large() {
        let expires_at = Some(10_000_000_001);
        assert!(validate_expires_at(expires_at).is_err());
    }

    #[test]
    fn validate_expires_at_accepts_future() {
        let now = now_ts_or_internal().expect("now");
        let expires_at = Some(now + 60);
        assert_eq!(
            validate_expires_at(expires_at).expect("expires"),
            expires_at
        );
    }

    #[test]
    fn validate_scopes_accepts_allowed() {
        let scopes = default_scopes();
        assert!(validate_scopes(&scopes).is_ok());
    }

    #[test]
    fn validate_scopes_rejects_unknown() {
        let scopes = vec!["keys:read".to_string(), "other:scope".to_string()];
        assert!(validate_scopes(&scopes).is_err());
    }

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

    async fn setup_state_with_settings(settings: Settings) -> AppState {
        let db = Database::connect(&settings).await.expect("db connect");
        db.migrate().await.expect("db migrate");
        AppState {
            db,
            settings,
            jwks_cache: None,
        }
    }

    async fn setup_state() -> AppState {
        setup_state_with_settings(test_settings()).await
    }

    fn admin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());
        headers
    }

    fn api_headers(raw_key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
        headers
    }

    fn test_artifact_settings() -> ArtifactSettings {
        ArtifactSettings {
            bucket: "releasy-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint: Some("https://s3.example.invalid".to_string()),
            access_key: "access".to_string(),
            secret_key: "secret".to_string(),
            path_style: true,
            presign_expires_seconds: 300,
        }
    }

    fn test_settings_with_artifacts() -> Settings {
        let mut settings = test_settings();
        settings.artifact_settings = Some(test_artifact_settings());
        settings
    }

    async fn with_release_update_barrier<F, Fut, T>(barrier: Arc<Barrier>, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        loop {
            let should_wait = {
                let mut guard = RELEASE_UPDATE_BARRIER
                    .lock()
                    .expect("release update barrier");
                if guard.is_none() {
                    *guard = Some(Arc::clone(&barrier));
                    false
                } else {
                    true
                }
            };
            if !should_wait {
                break;
            }
            tokio::task::yield_now().await;
        }

        let result = f().await;

        let mut guard = RELEASE_UPDATE_BARRIER
            .lock()
            .expect("release update barrier");
        *guard = None;

        result
    }

    #[tokio::test]
    async fn apply_release_action_with_rbac_conflicts_on_stale_publish() {
        let state = setup_state().await;
        let release = ReleaseRecord {
            id: "release-1".to_string(),
            product: "releasy".to_string(),
            version: "1.0.0".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: 1,
            published_at: None,
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let barrier = Arc::new(Barrier::new(2));

        let headers = admin_headers();
        let state_a = state.clone();
        let state_b = state.clone();
        let headers_a = headers.clone();
        let headers_b = headers.clone();

        let (result_a, result_b) = with_release_update_barrier(barrier, || async move {
            tokio::join!(
                apply_release_action_with_rbac(
                    &state_a,
                    &headers_a,
                    &release.id,
                    ReleaseAction::Publish
                ),
                apply_release_action_with_rbac(
                    &state_b,
                    &headers_b,
                    &release.id,
                    ReleaseAction::Publish
                ),
            )
        })
        .await;

        let results = [result_a, result_b];
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let conflicts = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|err| err.status() == StatusCode::CONFLICT)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(conflicts, 1);
    }

    #[tokio::test]
    async fn apply_release_action_with_rbac_conflicts_on_stale_unpublish() {
        let state = setup_state().await;
        let release = ReleaseRecord {
            id: "release-2".to_string(),
            product: "releasy".to_string(),
            version: "1.0.1".to_string(),
            status: ReleaseStatus::Published.as_str().to_string(),
            created_at: 1,
            published_at: Some(1),
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let barrier = Arc::new(Barrier::new(2));

        let headers = admin_headers();
        let state_a = state.clone();
        let state_b = state.clone();
        let headers_a = headers.clone();
        let headers_b = headers.clone();

        let (result_a, result_b) = with_release_update_barrier(barrier, || async move {
            tokio::join!(
                apply_release_action_with_rbac(
                    &state_a,
                    &headers_a,
                    &release.id,
                    ReleaseAction::Unpublish
                ),
                apply_release_action_with_rbac(
                    &state_b,
                    &headers_b,
                    &release.id,
                    ReleaseAction::Unpublish
                ),
            )
        })
        .await;

        let results = [result_a, result_b];
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let conflicts = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|err| err.status() == StatusCode::CONFLICT)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(conflicts, 1);
    }

    #[tokio::test]
    async fn create_release_rejects_duplicate_version() {
        let state = setup_state().await;
        let headers = admin_headers();

        let first = ReleaseCreateRequest {
            product: "releasy".to_string(),
            version: "1.0.0".to_string(),
        };
        let _ = create_release(State(state.clone()), headers.clone(), Json(first))
            .await
            .expect("first release");

        let second = ReleaseCreateRequest {
            product: "releasy".to_string(),
            version: "1.0.0".to_string(),
        };
        let err = create_release(State(state), headers, Json(second))
            .await
            .expect_err("duplicate release");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_release_is_idempotent() {
        let state = setup_state().await;
        let mut headers = admin_headers();
        headers.insert(IDEMPOTENCY_KEY_HEADER, "release-idem-1".parse().unwrap());

        let request = ReleaseCreateRequest {
            product: "releasy".to_string(),
            version: "9.9.9".to_string(),
        };

        let Json(first) =
            create_release(State(state.clone()), headers.clone(), Json(request.clone()))
                .await
                .expect("first release");

        let Json(second) = create_release(State(state), headers, Json(request))
            .await
            .expect("second release");

        assert_eq!(first.id, second.id);
    }

    #[tokio::test]
    async fn create_release_rejects_idempotency_conflict() {
        let state = setup_state().await;
        let mut headers = admin_headers();
        headers.insert(IDEMPOTENCY_KEY_HEADER, "release-idem-2".parse().unwrap());

        let first = ReleaseCreateRequest {
            product: "releasy".to_string(),
            version: "10.0.0".to_string(),
        };
        let _ = create_release(State(state.clone()), headers.clone(), Json(first))
            .await
            .expect("first release");

        let second = ReleaseCreateRequest {
            product: "releasy".to_string(),
            version: "10.0.1".to_string(),
        };
        let err = create_release(State(state), headers, Json(second))
            .await
            .expect_err("idempotency conflict");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn presign_release_artifact_upload_returns_url() {
        let state = setup_state_with_settings(test_settings_with_artifacts()).await;
        let release = ReleaseRecord {
            id: "release-artifact-1".to_string(),
            product: "releasy".to_string(),
            version: "1.0.0".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: 1,
            published_at: None,
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let request = ArtifactPresignRequest {
            filename: "linux.tar.gz".to_string(),
            platform: "linux-x86_64".to_string(),
        };
        let response = presign_release_artifact_upload(
            State(state),
            admin_headers(),
            Path(release.id.clone()),
            Json(request),
        )
        .await
        .expect("presign");
        assert!(response.upload_url.contains(&response.object_key));
        assert!(response.expires_at > 0);
    }

    #[tokio::test]
    async fn presign_release_artifact_upload_requires_config() {
        let state = setup_state().await;
        let release = ReleaseRecord {
            id: "release-artifact-2".to_string(),
            product: "releasy".to_string(),
            version: "1.0.1".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: 1,
            published_at: None,
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let request = ArtifactPresignRequest {
            filename: "linux.tar.gz".to_string(),
            platform: "linux-x86_64".to_string(),
        };
        let err = presign_release_artifact_upload(
            State(state),
            admin_headers(),
            Path(release.id.clone()),
            Json(request),
        )
        .await
        .expect_err("presign");
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn register_release_artifact_persists_record() {
        let state = setup_state_with_settings(test_settings_with_artifacts()).await;
        let release = ReleaseRecord {
            id: "release-artifact-3".to_string(),
            product: "releasy".to_string(),
            version: "1.0.2".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: 1,
            published_at: None,
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let artifact_id = Uuid::new_v4().to_string();
        let object_key =
            build_artifact_object_key(&release, "linux-x86_64", &artifact_id, "bundle.tar.gz")
                .expect("object key");
        let request = ArtifactRegisterRequest {
            artifact_id: artifact_id.clone(),
            object_key: object_key.clone(),
            checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
                .to_string(),
            size: 1024,
            platform: "linux-x86_64".to_string(),
        };

        let response = register_release_artifact(
            State(state.clone()),
            admin_headers(),
            Path(release.id.clone()),
            Json(request),
        )
        .await
        .expect("register");
        assert_eq!(response.id, artifact_id);

        let pool = match &state.db {
            Database::Sqlite(pool) => pool,
            Database::Postgres(_) => panic!("sqlite expected"),
        };
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE release_id = ? AND object_key = ?",
        )
        .bind(&release.id)
        .bind(&object_key)
        .fetch_one(pool)
        .await
        .expect("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn register_release_artifact_rejects_invalid_checksum() {
        let state = setup_state_with_settings(test_settings_with_artifacts()).await;
        let release = ReleaseRecord {
            id: "release-artifact-4".to_string(),
            product: "releasy".to_string(),
            version: "1.0.3".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: 1,
            published_at: None,
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let artifact_id = Uuid::new_v4().to_string();
        let object_key =
            build_artifact_object_key(&release, "linux-x86_64", &artifact_id, "bundle.tar.gz")
                .expect("object key");
        let request = ArtifactRegisterRequest {
            artifact_id,
            object_key,
            checksum: "not-a-checksum".to_string(),
            size: 1024,
            platform: "linux-x86_64".to_string(),
        };

        let err = register_release_artifact(
            State(state),
            admin_headers(),
            Path(release.id.clone()),
            Json(request),
        )
        .await
        .expect_err("register");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_release_artifact_rejects_mismatched_object_key() {
        let state = setup_state_with_settings(test_settings_with_artifacts()).await;
        let release = ReleaseRecord {
            id: "release-artifact-5".to_string(),
            product: "releasy".to_string(),
            version: "1.0.4".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: 1,
            published_at: None,
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let artifact_id = Uuid::new_v4().to_string();
        let request = ArtifactRegisterRequest {
            artifact_id,
            object_key: "releases/other/1.2.3/linux-x86_64/file.tar.gz".to_string(),
            checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
                .to_string(),
            size: 2048,
            platform: "linux-x86_64".to_string(),
        };

        let err = register_release_artifact(
            State(state),
            admin_headers(),
            Path(release.id.clone()),
            Json(request),
        )
        .await
        .expect_err("register");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn download_token_flow_redirects() {
        let state = setup_state_with_settings(test_settings_with_artifacts()).await;
        let now = now_ts_or_internal().expect("now");

        let customer = Customer {
            id: "customer-download".to_string(),
            name: "Download Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: now,
            suspended_at: None,
        };
        state
            .db
            .insert_customer(&customer)
            .await
            .expect("insert customer");

        let raw_key = "releasy_test_key";
        let scopes = vec!["downloads:token".to_string()];
        let api_key = ApiKeyRecord {
            id: "api-key-download".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash api key"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes json"),
            expires_at: None,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
        };
        state
            .db
            .insert_api_key(&api_key)
            .await
            .expect("insert api key");

        let release = ReleaseRecord {
            id: "release-download".to_string(),
            product: "releasy".to_string(),
            version: "1.2.3".to_string(),
            status: ReleaseStatus::Published.as_str().to_string(),
            created_at: now,
            published_at: Some(now),
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let artifact_id = Uuid::new_v4().to_string();
        let object_key =
            build_artifact_object_key(&release, "linux-x86_64", &artifact_id, "bundle.tar.gz")
                .expect("object key");
        let artifact = ArtifactRecord {
            id: artifact_id.clone(),
            release_id: release.id.clone(),
            object_key,
            checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
                .to_string(),
            size: 1024,
            platform: "linux-x86_64".to_string(),
            created_at: now,
        };
        state
            .db
            .insert_artifact(&artifact)
            .await
            .expect("insert artifact");

        let entitlement = EntitlementRecord {
            id: "entitlement-download".to_string(),
            customer_id: customer.id.clone(),
            product: release.product.clone(),
            starts_at: now - 10,
            ends_at: None,
            metadata: None,
        };
        state
            .db
            .insert_entitlement(&entitlement)
            .await
            .expect("insert entitlement");

        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
        headers.insert(header::HOST, "downloads.test".parse().unwrap());

        let request = DownloadTokenRequest {
            artifact_id,
            purpose: Some("ci".to_string()),
            expires_in_seconds: None,
        };
        let Json(response) = create_download_token(State(state.clone()), headers, Json(request))
            .await
            .expect("create token");
        assert!(response.download_url.contains("/v1/downloads/"));

        let token = response
            .download_url
            .split("/v1/downloads/")
            .nth(1)
            .expect("token");
        assert!(!token.is_empty());

        let response = resolve_download_token(State(state), Path(token.to_string()))
            .await
            .expect("resolve token")
            .into_response();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(!location.is_empty());
        let cache_control = response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert_eq!(cache_control, "no-store");
    }

    #[tokio::test]
    async fn create_download_token_rejects_missing_entitlement() {
        let state = setup_state_with_settings(test_settings_with_artifacts()).await;
        let now = now_ts_or_internal().expect("now");

        let customer = Customer {
            id: "customer-no-entitlement".to_string(),
            name: "Missing Entitlement".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: now,
            suspended_at: None,
        };
        state
            .db
            .insert_customer(&customer)
            .await
            .expect("insert customer");

        let raw_key = "releasy_test_key_2";
        let scopes = vec!["downloads:token".to_string()];
        let api_key = ApiKeyRecord {
            id: "api-key-no-entitlement".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash api key"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes json"),
            expires_at: None,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
        };
        state
            .db
            .insert_api_key(&api_key)
            .await
            .expect("insert api key");

        let release = ReleaseRecord {
            id: "release-no-entitlement".to_string(),
            product: "releasy".to_string(),
            version: "2.0.0".to_string(),
            status: ReleaseStatus::Published.as_str().to_string(),
            created_at: now,
            published_at: Some(now),
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let artifact = ArtifactRecord {
            id: Uuid::new_v4().to_string(),
            release_id: release.id.clone(),
            object_key: "releases/releasy/2.0.0/linux-x86_64/bundle.tar.gz".to_string(),
            checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
                .to_string(),
            size: 512,
            platform: "linux-x86_64".to_string(),
            created_at: now,
        };
        state
            .db
            .insert_artifact(&artifact)
            .await
            .expect("insert artifact");

        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
        headers.insert(header::HOST, "downloads.test".parse().unwrap());

        let request = DownloadTokenRequest {
            artifact_id: artifact.id.clone(),
            purpose: None,
            expires_in_seconds: None,
        };
        let err = create_download_token(State(state), headers, Json(request))
            .await
            .expect_err("missing entitlement");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_entitlement_persists_and_lists() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        let customer = Customer {
            id: "entitlement-customer".to_string(),
            name: "Entitlement Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: now,
            suspended_at: None,
        };
        state
            .db
            .insert_customer(&customer)
            .await
            .expect("insert customer");

        let payload = EntitlementCreateRequest {
            product: "releasy".to_string(),
            starts_at: now - 10,
            ends_at: Some(now + 1000),
            metadata: Some(json!({"tier": "pro"})),
        };

        let Json(response) = create_entitlement(
            State(state.clone()),
            admin_headers(),
            Path(customer.id.clone()),
            Json(payload),
        )
        .await
        .expect("create entitlement");
        assert_eq!(response.customer_id, customer.id);
        assert_eq!(response.product, "releasy");
        assert_eq!(response.metadata, Some(json!({"tier": "pro"})));

        let query = EntitlementListQuery {
            product: None,
            limit: None,
            offset: None,
        };
        let Json(list_response) = list_entitlements(
            State(state),
            admin_headers(),
            Path(customer.id),
            Query(query),
        )
        .await
        .expect("list entitlements");
        assert_eq!(list_response.entitlements.len(), 1);
        assert_eq!(list_response.entitlements[0].product, "releasy");
    }

    #[tokio::test]
    async fn create_entitlement_rejects_invalid_dates() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        let customer = Customer {
            id: "entitlement-invalid".to_string(),
            name: "Entitlement Invalid".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: now,
            suspended_at: None,
        };
        state
            .db
            .insert_customer(&customer)
            .await
            .expect("insert customer");

        let payload = EntitlementCreateRequest {
            product: "releasy".to_string(),
            starts_at: now + 10,
            ends_at: Some(now),
            metadata: None,
        };

        let err = create_entitlement(
            State(state),
            admin_headers(),
            Path(customer.id),
            Json(payload),
        )
        .await
        .expect_err("invalid dates");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_audit_events_requires_admin() {
        let state = setup_state().await;

        let query = AuditEventListQuery {
            customer_id: None,
            actor: None,
            event: None,
            created_from: None,
            created_to: None,
            limit: None,
            offset: None,
        };

        let err = list_audit_events(State(state), HeaderMap::new(), Query(query))
            .await
            .expect_err("missing admin auth");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_audit_events_filters_by_customer() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        let payload = json!({
            "outcome": "accept",
            "reason": "ok",
            "api_key_id": null
        })
        .to_string();
        state
            .db
            .insert_audit_event(
                Some("audit-customer-1"),
                "api_key",
                "api_key.auth",
                Some(&payload),
                now - 10,
            )
            .await
            .expect("insert audit event");
        state
            .db
            .insert_audit_event(
                Some("audit-customer-2"),
                "api_key",
                "api_key.auth",
                None,
                now,
            )
            .await
            .expect("insert audit event");

        let query = AuditEventListQuery {
            customer_id: Some("audit-customer-1".to_string()),
            actor: None,
            event: None,
            created_from: None,
            created_to: None,
            limit: None,
            offset: None,
        };
        let Json(response) = list_audit_events(State(state), admin_headers(), Query(query))
            .await
            .expect("list audit events");
        assert_eq!(response.events.len(), 1);
        assert_eq!(
            response.events[0].customer_id,
            Some("audit-customer-1".to_string())
        );
        assert_eq!(response.events[0].event, "api_key.auth");
        assert_eq!(
            response.events[0].payload,
            Some(json!({"outcome": "accept", "reason": "ok", "api_key_id": null}))
        );
    }

    #[tokio::test]
    async fn list_audit_events_filters_by_created_at() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        state
            .db
            .insert_audit_event(
                Some("audit-created-1"),
                "api_key",
                "api_key.auth",
                None,
                now - 120,
            )
            .await
            .expect("insert audit event");
        state
            .db
            .insert_audit_event(
                Some("audit-created-2"),
                "api_key",
                "api_key.auth",
                None,
                now - 10,
            )
            .await
            .expect("insert audit event");

        let query = AuditEventListQuery {
            customer_id: None,
            actor: None,
            event: None,
            created_from: Some(now - 30),
            created_to: Some(now),
            limit: None,
            offset: None,
        };
        let Json(response) = list_audit_events(State(state), admin_headers(), Query(query))
            .await
            .expect("list audit events");
        assert_eq!(response.events.len(), 1);
        assert_eq!(
            response.events[0].customer_id,
            Some("audit-created-2".to_string())
        );
    }

    #[tokio::test]
    async fn list_audit_events_rejects_invalid_range() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        let query = AuditEventListQuery {
            customer_id: None,
            actor: None,
            event: None,
            created_from: Some(now),
            created_to: Some(now - 10),
            limit: None,
            offset: None,
        };
        let err = list_audit_events(State(state), admin_headers(), Query(query))
            .await
            .expect_err("invalid range");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_releases_filters_by_entitlement() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        let customer = Customer {
            id: "release-entitlement".to_string(),
            name: "Release Entitled".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: now,
            suspended_at: None,
        };
        state
            .db
            .insert_customer(&customer)
            .await
            .expect("insert customer");

        let raw_key = "releasy_release_key";
        let scopes = vec!["releases:read".to_string()];
        let api_key = ApiKeyRecord {
            id: "api-release-key".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash api key"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes json"),
            expires_at: None,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
        };
        state
            .db
            .insert_api_key(&api_key)
            .await
            .expect("insert api key");

        let entitlement = EntitlementRecord {
            id: "entitlement-release".to_string(),
            customer_id: customer.id.clone(),
            product: "releasy".to_string(),
            starts_at: now - 10,
            ends_at: None,
            metadata: None,
        };
        state
            .db
            .insert_entitlement(&entitlement)
            .await
            .expect("insert entitlement");

        let published = ReleaseRecord {
            id: "release-published".to_string(),
            product: "releasy".to_string(),
            version: "1.0.0".to_string(),
            status: ReleaseStatus::Published.as_str().to_string(),
            created_at: now,
            published_at: Some(now),
        };
        state
            .db
            .insert_release(&published)
            .await
            .expect("insert release");

        let draft = ReleaseRecord {
            id: "release-draft".to_string(),
            product: "releasy".to_string(),
            version: "1.1.0".to_string(),
            status: ReleaseStatus::Draft.as_str().to_string(),
            created_at: now,
            published_at: None,
        };
        state
            .db
            .insert_release(&draft)
            .await
            .expect("insert release");

        let other = ReleaseRecord {
            id: "release-other".to_string(),
            product: "other".to_string(),
            version: "2.0.0".to_string(),
            status: ReleaseStatus::Published.as_str().to_string(),
            created_at: now,
            published_at: Some(now),
        };
        state
            .db
            .insert_release(&other)
            .await
            .expect("insert release");

        let query = ReleaseListQuery {
            product: None,
            status: None,
            version: None,
            include_artifacts: None,
            limit: None,
            offset: None,
        };
        let Json(response) = list_releases(State(state), api_headers(raw_key), Query(query))
            .await
            .expect("list releases");
        assert_eq!(response.releases.len(), 1);
        assert_eq!(response.releases[0].product, "releasy");
        assert_eq!(response.releases[0].status, "published");
    }

    #[tokio::test]
    async fn list_releases_returns_empty_without_entitlement() {
        let state = setup_state().await;
        let now = now_ts_or_internal().expect("now");

        let customer = Customer {
            id: "release-no-entitlement".to_string(),
            name: "Release No Entitlement".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: now,
            suspended_at: None,
        };
        state
            .db
            .insert_customer(&customer)
            .await
            .expect("insert customer");

        let raw_key = "releasy_release_key_2";
        let scopes = vec!["releases:read".to_string()];
        let api_key = ApiKeyRecord {
            id: "api-release-key-2".to_string(),
            customer_id: customer.id.clone(),
            key_hash: hash_api_key(raw_key, None).expect("hash api key"),
            key_prefix: api_key_prefix(raw_key),
            name: None,
            key_type: DEFAULT_API_KEY_TYPE.to_string(),
            scopes: scopes_to_json(&scopes).expect("scopes json"),
            expires_at: None,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
        };
        state
            .db
            .insert_api_key(&api_key)
            .await
            .expect("insert api key");

        let release = ReleaseRecord {
            id: "release-visible".to_string(),
            product: "releasy".to_string(),
            version: "3.0.0".to_string(),
            status: ReleaseStatus::Published.as_str().to_string(),
            created_at: now,
            published_at: Some(now),
        };
        state
            .db
            .insert_release(&release)
            .await
            .expect("insert release");

        let query = ReleaseListQuery {
            product: None,
            status: None,
            version: None,
            include_artifacts: None,
            limit: None,
            offset: None,
        };
        let Json(response) = list_releases(State(state), api_headers(raw_key), Query(query))
            .await
            .expect("list releases");
        assert!(response.releases.is_empty());
    }
}
