use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{admin_authorize_with_role, require_admin, require_support_or_admin};
use crate::errors::{ApiError, ErrorBody};
use crate::models::EntitlementRecord;

use super::{
    ensure_customer_exists, metadata_to_string, normalize_optional, normalize_required,
    resolve_pagination, with_idempotency,
};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct EntitlementCreateRequest {
    pub(crate) product: String,
    pub(crate) starts_at: i64,
    pub(crate) ends_at: Option<i64>,
    pub(crate) metadata: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct EntitlementUpdateRequest {
    pub(crate) product: Option<String>,
    pub(crate) starts_at: Option<i64>,
    #[serde(default)]
    pub(crate) ends_at: Option<Option<i64>>,
    #[serde(default)]
    pub(crate) metadata: Option<Option<Value>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct EntitlementResponse {
    pub(crate) id: String,
    pub(crate) customer_id: String,
    pub(crate) product: String,
    pub(crate) starts_at: i64,
    pub(crate) ends_at: Option<i64>,
    pub(crate) metadata: Option<Value>,
}

impl EntitlementResponse {
    fn try_from_record(record: EntitlementRecord) -> Result<Self, ApiError> {
        let metadata = match record.metadata {
            Some(metadata) => Some(serde_json::from_str(&metadata).map_err(|err| {
                error!("failed to parse entitlement metadata: {err}");
                ApiError::internal("invalid entitlement metadata")
            })?),
            None => None,
        };
        Ok(Self {
            id: record.id,
            customer_id: record.customer_id,
            product: record.product,
            starts_at: record.starts_at,
            ends_at: record.ends_at,
            metadata,
        })
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EntitlementListResponse {
    pub(crate) entitlements: Vec<EntitlementResponse>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct EntitlementListQuery {
    pub(crate) product: Option<String>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/v1/admin/customers/{customer_id}/entitlements",
    tag = "entitlements",
    summary = "List customer entitlements",
    description = "Lists entitlements for a customer with optional product filtering.",
    params(
        ("customer_id" = String, Path, description = "Customer identifier"),
        ("product" = Option<String>, Query, description = "Optional product filter"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)")
    ),
    responses(
        (status = 200, description = "Entitlements list", body = EntitlementListResponse),
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
pub async fn list_entitlements(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<String>,
    Query(query): Query<EntitlementListQuery>,
) -> Result<Json<EntitlementListResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_support_or_admin(role)?;

    let customer_id = customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }
    ensure_customer_exists(&state, customer_id).await?;

    let product = normalize_optional("product", query.product)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset)?;
    let entitlements = state
        .db
        .list_entitlements_by_customer(customer_id, product.as_deref(), Some(limit), Some(offset))
        .await
        .map_err(|err| {
            error!("failed to list entitlements: {err}");
            ApiError::internal("failed to list entitlements")
        })?;

    let mut responses = Vec::with_capacity(entitlements.len());
    for entitlement in entitlements {
        responses.push(EntitlementResponse::try_from_record(entitlement)?);
    }

    Ok(Json(EntitlementListResponse {
        entitlements: responses,
        limit,
        offset,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/customers/{customer_id}/entitlements",
    tag = "entitlements",
    summary = "Create an entitlement",
    description = "Creates an entitlement for a customer. Requires platform_admin role.",
    request_body = EntitlementCreateRequest,
    params(
        ("customer_id" = String, Path, description = "Customer identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Idempotency key for safe retries.")
    ),
    responses(
        (status = 200, description = "Entitlement created", body = EntitlementResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Customer not found", body = ErrorBody),
        (status = 409, description = "Idempotency conflict", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn create_entitlement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<String>,
    Json(payload): Json<EntitlementCreateRequest>,
) -> Result<Json<EntitlementResponse>, ApiError> {
    let customer_id = customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }

    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    ensure_customer_exists(&state, customer_id).await?;

    let payload_for_idempotency = payload.clone();
    let response = with_idempotency(
        &state,
        &headers,
        "create_entitlement",
        customer_id,
        &payload_for_idempotency,
        || async {
            let product = normalize_required("product", payload.product)?;
            if payload.starts_at <= 0 {
                return Err(ApiError::bad_request("starts_at must be positive"));
            }
            if let Some(ends_at) = payload.ends_at
                && ends_at < payload.starts_at
            {
                return Err(ApiError::bad_request(
                    "ends_at must be greater than or equal to starts_at",
                ));
            }

            let metadata = payload.metadata.map(metadata_to_string).transpose()?;

            let record = EntitlementRecord {
                id: Uuid::new_v4().to_string(),
                customer_id: customer_id.to_string(),
                product,
                starts_at: payload.starts_at,
                ends_at: payload.ends_at,
                metadata,
            };

            state.db.insert_entitlement(&record).await.map_err(|err| {
                error!("failed to create entitlement: {err}");
                ApiError::internal("failed to create entitlement")
            })?;

            EntitlementResponse::try_from_record(record)
        },
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    patch,
    path = "/v1/admin/customers/{customer_id}/entitlements/{entitlement_id}",
    tag = "entitlements",
    summary = "Update an entitlement",
    description = "Updates an existing entitlement for a customer. Requires platform_admin role.",
    request_body = EntitlementUpdateRequest,
    params(
        ("customer_id" = String, Path, description = "Customer identifier"),
        ("entitlement_id" = String, Path, description = "Entitlement identifier")
    ),
    responses(
        (status = 200, description = "Entitlement updated", body = EntitlementResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Entitlement not found", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn update_entitlement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((customer_id, entitlement_id)): Path<(String, String)>,
    Json(payload): Json<EntitlementUpdateRequest>,
) -> Result<Json<EntitlementResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let customer_id = customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }
    ensure_customer_exists(&state, customer_id).await?;

    let mut record = state
        .db
        .get_entitlement(customer_id, &entitlement_id)
        .await
        .map_err(|err| {
            error!("failed to get entitlement: {err}");
            ApiError::internal("failed to get entitlement")
        })?
        .ok_or_else(|| ApiError::not_found("entitlement not found"))?;

    if let Some(product) = normalize_optional("product", payload.product)? {
        record.product = product;
    }

    if let Some(starts_at) = payload.starts_at {
        if starts_at <= 0 {
            return Err(ApiError::bad_request("starts_at must be positive"));
        }
        record.starts_at = starts_at;
    }

    if let Some(ends_at) = payload.ends_at {
        if let Some(value) = ends_at
            && value < record.starts_at
        {
            return Err(ApiError::bad_request(
                "ends_at must be greater than or equal to starts_at",
            ));
        }
        record.ends_at = ends_at;
    } else if let Some(current) = record.ends_at
        && current < record.starts_at
    {
        return Err(ApiError::bad_request(
            "ends_at must be greater than or equal to starts_at",
        ));
    }

    if let Some(metadata) = payload.metadata {
        record.metadata = metadata.map(metadata_to_string).transpose()?;
    }

    let rows = state.db.update_entitlement(&record).await.map_err(|err| {
        error!("failed to update entitlement: {err}");
        ApiError::internal("failed to update entitlement")
    })?;
    if rows == 0 {
        return Err(ApiError::not_found("entitlement not found"));
    }

    Ok(Json(EntitlementResponse::try_from_record(record)?))
}

#[utoipa::path(
    delete,
    path = "/v1/admin/customers/{customer_id}/entitlements/{entitlement_id}",
    tag = "entitlements",
    summary = "Delete an entitlement",
    description = "Deletes an entitlement for a customer. Requires platform_admin role.",
    params(
        ("customer_id" = String, Path, description = "Customer identifier"),
        ("entitlement_id" = String, Path, description = "Entitlement identifier")
    ),
    responses(
        (status = 204, description = "Entitlement deleted"),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Entitlement not found", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn delete_entitlement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((customer_id, entitlement_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let customer_id = customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }
    ensure_customer_exists(&state, customer_id).await?;

    let rows = state
        .db
        .delete_entitlement(customer_id, &entitlement_id)
        .await
        .map_err(|err| {
            error!("failed to delete entitlement: {err}");
            ApiError::internal("failed to delete entitlement")
        })?;
    if rows == 0 {
        return Err(ApiError::not_found("entitlement not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}
