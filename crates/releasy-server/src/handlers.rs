pub(crate) mod admin;
pub(crate) mod artifacts;
pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod downloads;
pub(crate) mod entitlements;
pub(crate) mod health;
pub(crate) mod keys;
pub(crate) mod releases;

pub(crate) use admin::{
    AdminCreateCustomerRequest, AdminCreateCustomerResponse, AdminCustomerListQuery,
    AdminCustomerListResponse, AdminCustomerResponse, AdminUpdateCustomerRequest,
    admin_create_customer, get_customer, list_customers, update_customer,
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
pub(crate) use health::{HealthResponse, health_check, live_check, ready_check};
pub(crate) use keys::{
    AdminCreateKeyRequest, AdminCreateKeyResponse, AdminRevokeKeyRequest, AdminRevokeKeyResponse,
    admin_create_key, admin_revoke_key,
};
pub(crate) use releases::{
    ArtifactSummary, ReleaseCreateRequest, ReleaseListQuery, ReleaseListResponse, ReleaseResponse,
    create_release, delete_release, list_releases, publish_release, unpublish_release,
};

use axum::extract::Json;
use axum::http::{HeaderMap, StatusCode};
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

use crate::app::AppState;
use crate::auth::{AdminRole, admin_authorize_with_role, require_admin, require_release_publisher};
use crate::config::{ArtifactSettings, Settings};
use crate::errors::ApiError;
use crate::models::{ALLOWED_SCOPES, DEFAULT_API_KEY_TYPE, EntitlementRecord, ReleaseRecord};
use crate::release::{ReleaseAction, ReleaseStatus, ReleaseTransitionError, apply_release_action};
use crate::utils::now_ts;

#[cfg(test)]
use tokio::sync::Barrier;

#[cfg(test)]
static RELEASE_UPDATE_BARRIER: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);
fn artifact_settings(settings: &Settings) -> Result<&ArtifactSettings, ApiError> {
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

fn build_download_url(settings: &Settings, token: &str) -> Result<String, ApiError> {
    let base = settings.public_base_url.trim_end_matches('/');
    if base.is_empty() {
        return Err(ApiError::internal("public base url missing"));
    }
    Ok(format!("{base}/v1/downloads/{token}"))
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
mod test_support;
#[cfg(test)]
mod tests;
