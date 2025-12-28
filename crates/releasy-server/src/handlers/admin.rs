use axum::extract::{Json, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{admin_authorize_with_role, require_admin};
use crate::errors::{ApiError, ErrorBody};
use crate::models::Customer;

use super::{now_ts_or_internal, with_idempotency};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct AdminCreateCustomerRequest {
    name: String,
    plan: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AdminCreateCustomerResponse {
    id: String,
    name: String,
    plan: Option<String>,
    created_at: i64,
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
