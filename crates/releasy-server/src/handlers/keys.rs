use axum::extract::{Json, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{
    admin_authorize_with_role, api_key_prefix, generate_api_key, hash_api_key, require_admin,
    require_support_or_admin,
};
use crate::errors::{ApiError, ErrorBody};
use crate::models::{ApiKeyRecord, default_scopes, normalize_scopes, scopes_to_json};

use super::{extract_idempotency_key, normalize_key_type, validate_expires_at, validate_scopes};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct AdminCreateKeyRequest {
    customer_id: String,
    name: Option<String>,
    scopes: Option<Vec<String>>,
    expires_at: Option<i64>,
    key_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AdminCreateKeyResponse {
    api_key_id: String,
    api_key: String,
    customer_id: String,
    key_type: String,
    scopes: Vec<String>,
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct AdminRevokeKeyRequest {
    api_key_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AdminRevokeKeyResponse {
    api_key_id: String,
}

#[utoipa::path(
    post,
    path = "/v1/admin/keys",
    tag = "keys",
    summary = "Create an API key",
    description = "Creates an API key for a customer. Requires platform_admin role.",
    request_body = AdminCreateKeyRequest,
    responses(
        (status = 200, description = "API key created", body = AdminCreateKeyResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Customer not found", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn admin_create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminCreateKeyRequest>,
) -> Result<Json<AdminCreateKeyResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    if extract_idempotency_key(&headers)?.is_some() {
        return Err(ApiError::bad_request(
            "idempotency-key not supported for admin key creation",
        ));
    }

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
    let key_hash = hash_api_key(&raw_key, state.settings.api_key_pepper.as_deref())?;
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
        created_at: super::now_ts_or_internal()?,
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

#[utoipa::path(
    post,
    path = "/v1/admin/keys/revoke",
    tag = "keys",
    summary = "Revoke an API key",
    description = "Revokes an API key for a customer. Requires platform_support or platform_admin.",
    request_body = AdminRevokeKeyRequest,
    responses(
        (status = 200, description = "API key revoked", body = AdminRevokeKeyResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "API key not found", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
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
        .revoke_api_key(key_id, super::now_ts_or_internal()?)
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
