use axum::extract::{Json, Path, Query, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{admin_authorize_with_role, require_admin, require_support_or_admin};
use crate::db::CustomerUpdate;
use crate::errors::{ApiError, ErrorBody};
use crate::models::Customer;

use super::{normalize_optional, now_ts_or_internal, resolve_pagination, with_idempotency};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct AdminCreateCustomerRequest {
    pub(crate) name: String,
    pub(crate) plan: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AdminCreateCustomerResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) plan: Option<String>,
    pub(crate) created_at: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct AdminUpdateCustomerRequest {
    pub(crate) name: Option<String>,
    pub(crate) plan: Option<Option<String>>,
    pub(crate) suspended: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AdminCustomerResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) plan: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) suspended_at: Option<i64>,
}

impl AdminCustomerResponse {
    fn from_customer(customer: Customer) -> Self {
        Self {
            id: customer.id,
            name: customer.name,
            plan: customer.plan,
            created_at: customer.created_at,
            suspended_at: customer.suspended_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AdminCustomerListResponse {
    pub(crate) customers: Vec<AdminCustomerResponse>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct AdminCustomerListQuery {
    pub(crate) customer_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) plan: Option<String>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
}

#[utoipa::path(
    post,
    path = "/v1/admin/customers",
    tag = "admin",
    summary = "Create a customer",
    description = "Creates a new customer record. Requires platform_admin role.",
    request_body = AdminCreateCustomerRequest,
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Idempotency key for safe retries.")
    ),
    responses(
        (status = 200, description = "Customer created", body = AdminCreateCustomerResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Idempotency conflict", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn admin_create_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminCreateCustomerRequest>,
) -> Result<Json<AdminCreateCustomerResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let payload_for_idempotency = payload.clone();
    let response = with_idempotency(
        &state,
        &headers,
        "admin_create_customer",
        "",
        &payload_for_idempotency,
        || async {
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

            Ok(AdminCreateCustomerResponse {
                id: customer.id,
                name: customer.name,
                plan: customer.plan,
                created_at: customer.created_at,
            })
        },
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/v1/admin/customers",
    tag = "admin",
    summary = "List customers",
    description = "Lists customers with optional filters. Requires platform_support or platform_admin role.",
    params(
        ("customer_id" = Option<String>, Query, description = "Optional exact customer id filter"),
        ("name" = Option<String>, Query, description = "Optional name filter (case-insensitive contains)"),
        ("plan" = Option<String>, Query, description = "Optional plan filter (case-insensitive exact match)"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)")
    ),
    responses(
        (status = 200, description = "Customers list", body = AdminCustomerListResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn list_customers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminCustomerListQuery>,
) -> Result<Json<AdminCustomerListResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_support_or_admin(role)?;

    let customer_id = normalize_optional("customer_id", query.customer_id)?;
    let name = normalize_optional("name", query.name)?;
    let plan = normalize_optional("plan", query.plan)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset)?;

    let customers = state
        .db
        .list_customers(
            customer_id.as_deref(),
            name.as_deref(),
            plan.as_deref(),
            limit,
            offset,
        )
        .await
        .map_err(|err| {
            error!("failed to list customers: {err}");
            ApiError::internal("failed to list customers")
        })?;

    let responses = customers
        .into_iter()
        .map(AdminCustomerResponse::from_customer)
        .collect();

    Ok(Json(AdminCustomerListResponse {
        customers: responses,
        limit,
        offset,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/admin/customers/{customer_id}",
    tag = "admin",
    summary = "Get a customer",
    description = "Fetches a customer record. Requires platform_support or platform_admin role.",
    params(
        ("customer_id" = String, Path, description = "Customer identifier")
    ),
    responses(
        (status = 200, description = "Customer detail", body = AdminCustomerResponse),
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
pub async fn get_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<String>,
) -> Result<Json<AdminCustomerResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_support_or_admin(role)?;

    let customer_id = customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }

    let customer = state
        .db
        .get_customer(customer_id)
        .await
        .map_err(|err| {
            error!("failed to get customer: {err}");
            ApiError::internal("failed to get customer")
        })?
        .ok_or_else(|| ApiError::not_found("customer not found"))?;

    Ok(Json(AdminCustomerResponse::from_customer(customer)))
}

#[utoipa::path(
    patch,
    path = "/v1/admin/customers/{customer_id}",
    tag = "admin",
    summary = "Update a customer",
    description = "Updates customer name, plan, or suspension. Requires platform_admin role.",
    request_body = AdminUpdateCustomerRequest,
    params(
        ("customer_id" = String, Path, description = "Customer identifier")
    ),
    responses(
        (status = 200, description = "Customer updated", body = AdminCustomerResponse),
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
pub async fn update_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<String>,
    Json(payload): Json<AdminUpdateCustomerRequest>,
) -> Result<Json<AdminCustomerResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let customer_id = customer_id.trim();
    if customer_id.is_empty() {
        return Err(ApiError::bad_request("customer_id is required"));
    }

    let mut has_update = false;

    let name = if let Some(value) = payload.name {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ApiError::bad_request("name must not be empty"));
        }
        has_update = true;
        Some(trimmed.to_string())
    } else {
        None
    };

    let plan = match payload.plan {
        Some(Some(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ApiError::bad_request("plan must not be empty"));
            }
            has_update = true;
            Some(Some(trimmed.to_string()))
        }
        Some(None) => {
            has_update = true;
            Some(None)
        }
        None => None,
    };

    let suspended_at = match payload.suspended {
        Some(true) => {
            has_update = true;
            Some(Some(now_ts_or_internal()?))
        }
        Some(false) => {
            has_update = true;
            Some(None)
        }
        None => None,
    };

    if !has_update {
        return Err(ApiError::bad_request("at least one field must be provided"));
    }

    let update = CustomerUpdate {
        name,
        plan,
        suspended_at,
    };

    let customer = state
        .db
        .update_customer(customer_id, &update)
        .await
        .map_err(|err| {
            error!("failed to update customer: {err}");
            ApiError::internal("failed to update customer")
        })?
        .ok_or_else(|| ApiError::not_found("customer not found"))?;

    Ok(Json(AdminCustomerResponse::from_customer(customer)))
}
