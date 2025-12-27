use axum::extract::{Json, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{
    admin_authorize, api_key_prefix, authenticate_api_key, generate_api_key, hash_api_key,
    require_scopes,
};
use crate::errors::ApiError;
use crate::models::{
    ApiKeyIntrospection, ApiKeyRecord, Customer, DEFAULT_API_KEY_TYPE, default_scopes,
    normalize_scopes, scopes_to_json,
};
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

pub async fn admin_create_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminCreateCustomerRequest>,
) -> Result<Json<AdminCreateCustomerResponse>, ApiError> {
    admin_authorize(&headers, &state.settings)?;

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
        created_at: now_ts(),
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
    admin_authorize(&headers, &state.settings)?;

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
    let scopes_json =
        scopes_to_json(&scopes).map_err(|_| ApiError::internal("failed to encode scopes"))?;

    let key_type = payload
        .key_type
        .unwrap_or_else(|| DEFAULT_API_KEY_TYPE.to_string());

    let raw_key = generate_api_key()?;
    let key_hash = hash_api_key(&raw_key, state.settings.api_key_pepper.as_deref());
    let key_prefix = api_key_prefix(&raw_key);

    let record = ApiKeyRecord {
        id: Uuid::new_v4().to_string(),
        customer_id: customer_id.to_string(),
        key_hash,
        key_prefix,
        name: payload.name,
        key_type: key_type.clone(),
        scopes: scopes_json,
        expires_at: payload.expires_at,
        created_at: now_ts(),
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
    admin_authorize(&headers, &state.settings)?;

    let key_id = payload.api_key_id.trim();
    if key_id.is_empty() {
        return Err(ApiError::bad_request("api_key_id is required"));
    }

    let updated = state
        .db
        .revoke_api_key(key_id, now_ts())
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
