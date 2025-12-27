use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{
    AdminRole, admin_authorize_with_role, api_key_prefix, authenticate_api_key, generate_api_key,
    hash_api_key, require_admin, require_release_publisher, require_scopes,
    require_support_or_admin,
};
use crate::errors::ApiError;
use crate::models::{
    ALLOWED_SCOPES, ApiKeyIntrospection, ApiKeyRecord, Customer, DEFAULT_API_KEY_TYPE,
    ReleaseRecord, default_scopes, normalize_scopes, scopes_to_json,
};
use crate::release::{ReleaseAction, ReleaseStatus, ReleaseTransitionError, apply_release_action};
use crate::utils::now_ts;

#[derive(Debug, Deserialize)]
pub(crate) struct AdminCreateCustomerRequest {
    name: String,
    plan: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminCreateCustomerResponse {
    id: String,
    name: String,
    plan: Option<String>,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminCreateKeyRequest {
    customer_id: String,
    name: Option<String>,
    scopes: Option<Vec<String>>,
    expires_at: Option<i64>,
    key_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminCreateKeyResponse {
    api_key_id: String,
    api_key: String,
    customer_id: String,
    key_type: String,
    scopes: Vec<String>,
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminRevokeKeyRequest {
    api_key_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminRevokeKeyResponse {
    api_key_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReleaseCreateRequest {
    product: String,
    version: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReleaseListQuery {
    product: Option<String>,
    status: Option<String>,
    version: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReleaseResponse {
    id: String,
    product: String,
    version: String,
    status: String,
    created_at: i64,
    published_at: Option<i64>,
}

impl ReleaseResponse {
    fn from_record(record: ReleaseRecord) -> Self {
        Self {
            id: record.id,
            product: record.product,
            version: record.version,
            status: record.status,
            created_at: record.created_at,
            published_at: record.published_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ReleaseListResponse {
    releases: Vec<ReleaseResponse>,
    limit: i64,
    offset: i64,
}

pub async fn admin_create_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminCreateCustomerRequest>,
) -> Result<Json<AdminCreateCustomerResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let name = payload.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }

    let plan = payload
        .plan
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let customer = Customer {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        plan,
        allowed_prefixes: None,
        created_at: now_ts_or_internal()?,
        suspended_at: None,
    };

    state.db.insert_customer(&customer).await.map_err(|err| {
        error!("failed to insert customer: {err}");
        ApiError::internal("failed to create customer")
    })?;

    Ok(Json(AdminCreateCustomerResponse {
        id: customer.id,
        name: customer.name,
        plan: customer.plan,
        created_at: customer.created_at,
    }))
}

pub async fn admin_create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminCreateKeyRequest>,
) -> Result<Json<AdminCreateKeyResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let customer_id = payload.customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }

    let exists = state.db.customer_exists(customer_id).await.map_err(|err| {
        error!("failed to lookup customer: {err}");
        ApiError::internal("customer lookup failed")
    })?;
    if !exists {
        return Err(ApiError::not_found("customer not found"));
    }

    let scopes = match payload.scopes {
        Some(scopes) => {
            let normalized = normalize_scopes(scopes);
            if normalized.is_empty() {
                return Err(ApiError::bad_request("scopes must not be empty"));
            }
            normalized
        }
        None => default_scopes(),
    };
    validate_scopes(&scopes)?;
    let scopes_json =
        scopes_to_json(&scopes).map_err(|_| ApiError::internal("failed to encode scopes"))?;

    let key_type = normalize_key_type(payload.key_type)?;

    let raw_key = generate_api_key()?;
    let key_hash = hash_api_key(&raw_key, state.settings.api_key_pepper.as_deref());
    let key_prefix = api_key_prefix(&raw_key);

    let expires_at = validate_expires_at(payload.expires_at)?;
    let record = ApiKeyRecord {
        id: Uuid::new_v4().to_string(),
        customer_id: customer_id.to_string(),
        key_hash,
        key_prefix,
        name: payload.name,
        key_type: key_type.clone(),
        scopes: scopes_json,
        expires_at,
        created_at: now_ts_or_internal()?,
        revoked_at: None,
        last_used_at: None,
    };

    state.db.insert_api_key(&record).await.map_err(|err| {
        error!("failed to create api key: {err}");
        ApiError::internal("failed to create api key")
    })?;

    Ok(Json(AdminCreateKeyResponse {
        api_key_id: record.id,
        api_key: raw_key,
        customer_id: record.customer_id,
        key_type,
        scopes,
        expires_at: record.expires_at,
    }))
}

pub async fn admin_revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminRevokeKeyRequest>,
) -> Result<Json<AdminRevokeKeyResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_support_or_admin(role)?;

    let key_id = payload.api_key_id.trim();
    if key_id.is_empty() {
        return Err(ApiError::bad_request("api_key_id is required"));
    }

    let updated = state
        .db
        .revoke_api_key(key_id, now_ts_or_internal()?)
        .await
        .map_err(|err| {
            error!("failed to revoke api key: {err}");
            ApiError::internal("failed to revoke api key")
        })?;
    if updated == 0 {
        return Err(ApiError::not_found("api key not found or already revoked"));
    }

    Ok(Json(AdminRevokeKeyResponse {
        api_key_id: key_id.to_string(),
    }))
}

pub async fn create_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ReleaseCreateRequest>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_publisher(role)?;

    let product = normalize_required("product", payload.product)?;
    let version = normalize_required("version", payload.version)?;

    let record = ReleaseRecord {
        id: Uuid::new_v4().to_string(),
        product,
        version,
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: now_ts_or_internal()?,
        published_at: None,
    };

    state.db.insert_release(&record).await.map_err(|err| {
        error!("failed to create release: {err}");
        ApiError::internal("failed to create release")
    })?;

    Ok(Json(ReleaseResponse::from_record(record)))
}

pub async fn list_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReleaseListQuery>,
) -> Result<Json<ReleaseListResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_list_role(role)?;

    let product = normalize_optional("product", query.product)?;
    let version = normalize_optional("version", query.version)?;
    let status = match normalize_optional("status", query.status)? {
        Some(status) => {
            let parsed = ReleaseStatus::parse(&status)
                .ok_or_else(|| ApiError::bad_request("invalid status"))?;
            Some(parsed.as_str().to_string())
        }
        None => None,
    };

    let (limit, offset) = resolve_pagination(query.limit, query.offset)?;
    let releases = state
        .db
        .list_releases(
            product.as_deref(),
            status.as_deref(),
            version.as_deref(),
            limit,
            offset,
        )
        .await
        .map_err(|err| {
            error!("failed to list releases: {err}");
            ApiError::internal("failed to list releases")
        })?;

    let responses = releases
        .into_iter()
        .map(ReleaseResponse::from_record)
        .collect();
    Ok(Json(ReleaseListResponse {
        releases: responses,
        limit,
        offset,
    }))
}

pub async fn publish_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    apply_release_action_with_rbac(&state, &headers, &release_id, ReleaseAction::Publish).await
}

pub async fn unpublish_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    apply_release_action_with_rbac(&state, &headers, &release_id, ReleaseAction::Unpublish).await
}

pub async fn delete_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let rows = state.db.delete_release(&release_id).await.map_err(|err| {
        error!("failed to delete release: {err}");
        ApiError::internal("failed to delete release")
    })?;
    if rows == 0 {
        return Err(ApiError::not_found("release not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn auth_introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiKeyIntrospection>, ApiError> {
    let auth = authenticate_api_key(&headers, &state.settings, &state.db).await?;
    require_scopes(&auth, &["keys:read"])?;

    Ok(Json(ApiKeyIntrospection {
        active: true,
        api_key_id: auth.api_key_id,
        customer_id: auth.customer_id,
        key_type: auth.key_type,
        scopes: auth.scopes,
        expires_at: auth.expires_at,
    }))
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

    let rows = state
        .db
        .update_release_status(release_id, next.as_str(), published_at)
        .await
        .map_err(|err| {
            error!("failed to update release status: {err}");
            ApiError::internal("failed to update release status")
        })?;
    if rows == 0 {
        return Err(ApiError::not_found("release not found"));
    }

    release.status = next.as_str().to_string();
    release.published_at = published_at;
    Ok(Json(ReleaseResponse::from_record(release)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
