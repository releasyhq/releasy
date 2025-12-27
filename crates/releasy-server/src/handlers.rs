use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use s3::Bucket;
use s3::Region;
use s3::creds::Credentials;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::{Arc, Mutex};
#[cfg(test)]
use tokio::sync::Barrier;
use tracing::error;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{
    AdminRole, admin_authorize_with_role, api_key_prefix, authenticate_api_key, generate_api_key,
    generate_download_token, hash_api_key, hash_download_token, require_admin,
    require_release_publisher, require_scopes, require_support_or_admin,
};
use crate::config::ArtifactSettings;
use crate::errors::ApiError;
use crate::models::{
    ALLOWED_SCOPES, ApiKeyIntrospection, ApiKeyRecord, ArtifactRecord, Customer,
    DEFAULT_API_KEY_TYPE, DownloadTokenRecord, EntitlementRecord, ReleaseRecord, default_scopes,
    normalize_scopes, scopes_to_json,
};
use crate::release::{ReleaseAction, ReleaseStatus, ReleaseTransitionError, apply_release_action};
use crate::utils::now_ts;

#[cfg(test)]
static RELEASE_UPDATE_BARRIER: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);

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

#[derive(Debug, Deserialize)]
pub(crate) struct ArtifactPresignRequest {
    filename: String,
    platform: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ArtifactPresignResponse {
    artifact_id: String,
    object_key: String,
    upload_url: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ArtifactRegisterRequest {
    artifact_id: String,
    object_key: String,
    checksum: String,
    size: i64,
    platform: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ArtifactRegisterResponse {
    id: String,
    release_id: String,
    object_key: String,
    checksum: String,
    size: i64,
    platform: String,
    created_at: i64,
}

impl ArtifactRegisterResponse {
    fn from_record(record: ArtifactRecord) -> Self {
        Self {
            id: record.id,
            release_id: record.release_id,
            object_key: record.object_key,
            checksum: record.checksum,
            size: record.size,
            platform: record.platform,
            created_at: record.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DownloadTokenRequest {
    artifact_id: String,
    purpose: Option<String>,
    expires_in_seconds: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DownloadTokenResponse {
    download_url: String,
    expires_at: i64,
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
        if let sqlx::Error::Database(db_err) = &err
            && db_err.is_unique_violation()
        {
            return ApiError::new(StatusCode::CONFLICT, "release already exists");
        }
        error!("failed to create release: {err}");
        ApiError::internal("failed to create release")
    })?;

    Ok(Json(ReleaseResponse::from_record(record)))
}

pub async fn presign_release_artifact_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
    Json(payload): Json<ArtifactPresignRequest>,
) -> Result<Json<ArtifactPresignResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_publisher(role)?;

    let artifact_settings = artifact_settings(&state.settings)?;
    let release = state
        .db
        .get_release(&release_id)
        .await
        .map_err(|err| {
            error!("failed to get release: {err}");
            ApiError::internal("failed to get release")
        })?
        .ok_or_else(|| ApiError::not_found("release not found"))?;

    let filename = normalize_required("filename", payload.filename)?;
    let platform = normalize_required("platform", payload.platform)?;
    let artifact_id = Uuid::new_v4().to_string();
    let object_key = build_artifact_object_key(&release, &platform, &artifact_id, &filename)?;

    let bucket = build_artifact_bucket(artifact_settings)?;
    let upload_url = bucket
        .presign_put(
            &object_key,
            artifact_settings.presign_expires_seconds,
            None,
            None,
        )
        .await
        .map_err(|err| {
            error!("failed to presign artifact upload: {err}");
            ApiError::internal("failed to presign upload")
        })?;
    let expires_at = now_ts_or_internal()? + i64::from(artifact_settings.presign_expires_seconds);

    Ok(Json(ArtifactPresignResponse {
        artifact_id,
        object_key,
        upload_url,
        expires_at,
    }))
}

pub async fn register_release_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
    Json(payload): Json<ArtifactRegisterRequest>,
) -> Result<Json<ArtifactRegisterResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_publisher(role)?;

    let _artifact_settings = artifact_settings(&state.settings)?;
    let release = state
        .db
        .get_release(&release_id)
        .await
        .map_err(|err| {
            error!("failed to get release: {err}");
            ApiError::internal("failed to get release")
        })?
        .ok_or_else(|| ApiError::not_found("release not found"))?;

    let artifact_id = normalize_required("artifact_id", payload.artifact_id)?;
    let artifact_uuid = Uuid::parse_str(&artifact_id)
        .map_err(|_| ApiError::bad_request("artifact_id must be a valid UUID"))?;
    let platform = normalize_required("platform", payload.platform)?;
    let object_key = normalize_required("object_key", payload.object_key)?;
    let checksum = normalize_checksum(&payload.checksum)?;
    let size = validate_artifact_size(payload.size)?;

    let expected_prefix =
        artifact_object_key_prefix(&release, &platform, &artifact_uuid.to_string())?;
    if !object_key.starts_with(&expected_prefix) {
        return Err(ApiError::bad_request(
            "object_key does not match release or platform",
        ));
    }

    let record = ArtifactRecord {
        id: artifact_uuid.to_string(),
        release_id: release.id,
        object_key,
        checksum,
        size,
        platform,
        created_at: now_ts_or_internal()?,
    };

    state.db.insert_artifact(&record).await.map_err(|err| {
        if let sqlx::Error::Database(db_err) = &err
            && db_err.is_unique_violation()
        {
            return ApiError::new(StatusCode::CONFLICT, "artifact already exists");
        }
        error!("failed to register artifact: {err}");
        ApiError::internal("failed to register artifact")
    })?;

    Ok(Json(ArtifactRegisterResponse::from_record(record)))
}

pub async fn create_download_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DownloadTokenRequest>,
) -> Result<Json<DownloadTokenResponse>, ApiError> {
    let auth = authenticate_api_key(&headers, &state.settings, &state.db).await?;
    require_scopes(&auth, &["downloads:token"])?;

    let artifact_id = normalize_required("artifact_id", payload.artifact_id)?;
    let artifact_uuid = Uuid::parse_str(&artifact_id)
        .map_err(|_| ApiError::bad_request("artifact_id must be a valid UUID"))?;

    let artifact = state
        .db
        .get_artifact(&artifact_uuid.to_string())
        .await
        .map_err(|err| {
            error!("failed to get artifact: {err}");
            ApiError::internal("failed to lookup artifact")
        })?
        .ok_or_else(|| ApiError::not_found("artifact not found"))?;

    let release = state
        .db
        .get_release(&artifact.release_id)
        .await
        .map_err(|err| {
            error!("failed to get release: {err}");
            ApiError::internal("failed to lookup release")
        })?
        .ok_or_else(|| ApiError::not_found("release not found"))?;

    let status = ReleaseStatus::parse(&release.status)
        .ok_or_else(|| ApiError::internal("invalid status"))?;
    if status != ReleaseStatus::Published {
        return Err(ApiError::forbidden("release not published"));
    }

    let entitlements = state
        .db
        .list_entitlements_by_customer(&auth.customer_id)
        .await
        .map_err(|err| {
            error!("failed to list entitlements: {err}");
            ApiError::internal("failed to list entitlements")
        })?;

    let now = now_ts_or_internal()?;
    if !is_product_entitled(&entitlements, &release.product, now) {
        return Err(ApiError::forbidden("entitlement required"));
    }

    let ttl = resolve_requested_ttl(
        payload.expires_in_seconds,
        state.settings.download_token_ttl_seconds,
        "expires_in_seconds",
    )?;
    let token = generate_download_token()?;
    let token_hash = hash_download_token(&token, state.settings.api_key_pepper.as_deref());
    let expires_at = now + i64::from(ttl);
    let purpose = payload
        .purpose
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let record = DownloadTokenRecord {
        token_hash,
        artifact_id: artifact.id,
        customer_id: auth.customer_id,
        purpose,
        expires_at,
        created_at: now,
    };

    state
        .db
        .insert_download_token(&record)
        .await
        .map_err(|err| {
            error!("failed to create download token: {err}");
            ApiError::internal("failed to create download token")
        })?;

    let download_url = build_download_url(&headers, &token)?;

    Ok(Json(DownloadTokenResponse {
        download_url,
        expires_at,
    }))
}

pub async fn resolve_download_token(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::bad_request("token is required"));
    }

    let token_hash = hash_download_token(token, state.settings.api_key_pepper.as_deref());
    let record = state
        .db
        .get_download_token_by_hash(&token_hash)
        .await
        .map_err(|err| {
            error!("failed to lookup download token: {err}");
            ApiError::internal("failed to lookup download token")
        })?
        .ok_or_else(|| ApiError::not_found("download token not found"))?;

    let customer = state
        .db
        .get_customer(&record.customer_id)
        .await
        .map_err(|err| {
            error!("failed to lookup download token customer: {err}");
            ApiError::internal("failed to lookup customer")
        })?
        .ok_or_else(|| ApiError::not_found("download token not found"))?;
    if customer.suspended_at.is_some() {
        return Err(ApiError::not_found("download token not found"));
    }

    let now = now_ts_or_internal()?;
    if record.expires_at <= now {
        return Err(ApiError::not_found("download token expired"));
    }

    let artifact = state
        .db
        .get_artifact(&record.artifact_id)
        .await
        .map_err(|err| {
            error!("failed to get artifact: {err}");
            ApiError::internal("failed to lookup artifact")
        })?
        .ok_or_else(|| ApiError::not_found("artifact not found"))?;

    let release = state
        .db
        .get_release(&artifact.release_id)
        .await
        .map_err(|err| {
            error!("failed to get release: {err}");
            ApiError::internal("failed to lookup release")
        })?
        .ok_or_else(|| ApiError::not_found("release not found"))?;

    let status = ReleaseStatus::parse(&release.status)
        .ok_or_else(|| ApiError::internal("invalid status"))?;
    if status != ReleaseStatus::Published {
        return Err(ApiError::not_found("release not available"));
    }

    let entitlements = state
        .db
        .list_entitlements_by_customer(&record.customer_id)
        .await
        .map_err(|err| {
            error!("failed to list entitlements: {err}");
            ApiError::internal("failed to list entitlements")
        })?;
    if !is_product_entitled(&entitlements, &release.product, now) {
        return Err(ApiError::not_found("release not available"));
    }

    let remaining = record.expires_at.saturating_sub(now);
    if remaining == 0 {
        return Err(ApiError::not_found("download token expired"));
    }

    let artifact_settings = artifact_settings(&state.settings)?;
    let bucket = build_artifact_bucket(artifact_settings)?;
    let presigned_url = bucket
        .presign_get(
            &artifact.object_key,
            remaining.min(i64::from(u32::MAX)) as u32,
            None,
        )
        .await
        .map_err(|err| {
            error!("failed to presign download: {err}");
            ApiError::internal("failed to presign download")
        })?;

    let mut response = (StatusCode::FOUND, [(header::LOCATION, presigned_url)]).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
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
    Ok(Json(ReleaseResponse::from_record(release)))
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
    use axum::http::HeaderMap;

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
        {
            let mut guard = RELEASE_UPDATE_BARRIER
                .lock()
                .expect("release update barrier");
            *guard = Some(barrier);
        }

        let headers = admin_headers();
        let state_a = state.clone();
        let state_b = state.clone();
        let headers_a = headers.clone();
        let headers_b = headers.clone();

        let (result_a, result_b) = tokio::join!(
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
        );

        {
            let mut guard = RELEASE_UPDATE_BARRIER
                .lock()
                .expect("release update barrier");
            *guard = None;
        }

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
        {
            let mut guard = RELEASE_UPDATE_BARRIER
                .lock()
                .expect("release update barrier");
            *guard = Some(barrier);
        }

        let headers = admin_headers();
        let state_a = state.clone();
        let state_b = state.clone();
        let headers_a = headers.clone();
        let headers_b = headers.clone();

        let (result_a, result_b) = tokio::join!(
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
        );

        {
            let mut guard = RELEASE_UPDATE_BARRIER
                .lock()
                .expect("release update barrier");
            *guard = None;
        }

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
            key_hash: hash_api_key(raw_key, None),
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
            key_hash: hash_api_key(raw_key, None),
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
}
