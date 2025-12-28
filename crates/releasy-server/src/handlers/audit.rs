use axum::extract::{Json, Query, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::{admin_authorize_with_role, require_support_or_admin};
use crate::db::AuditEventFilter;
use crate::errors::{ApiError, ErrorBody};
use crate::models::AuditEventRecord;

use super::{normalize_optional, resolve_pagination};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AuditEventResponse {
    pub(crate) id: String,
    pub(crate) customer_id: Option<String>,
    pub(crate) actor: String,
    pub(crate) event: String,
    pub(crate) payload: Option<Value>,
    pub(crate) created_at: i64,
}

impl AuditEventResponse {
    fn try_from_record(record: AuditEventRecord) -> Result<Self, ApiError> {
        let payload = match record.payload {
            Some(payload) => Some(serde_json::from_str(&payload).map_err(|err| {
                error!("failed to parse audit payload: {err}");
                ApiError::internal("invalid audit payload")
            })?),
            None => None,
        };
        Ok(Self {
            id: record.id,
            customer_id: record.customer_id,
            actor: record.actor,
            event: record.event,
            payload,
            created_at: record.created_at,
        })
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AuditEventListResponse {
    pub(crate) events: Vec<AuditEventResponse>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct AuditEventListQuery {
    pub(crate) customer_id: Option<String>,
    pub(crate) actor: Option<String>,
    pub(crate) event: Option<String>,
    pub(crate) created_from: Option<i64>,
    pub(crate) created_to: Option<i64>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/v1/admin/audit-events",
    tag = "audit",
    summary = "List audit events",
    description = "Lists audit events with optional filters and pagination.",
    params(
        ("customer_id" = Option<String>, Query, description = "Filter by customer id"),
        ("actor" = Option<String>, Query, description = "Filter by actor"),
        ("event" = Option<String>, Query, description = "Filter by event name"),
        ("created_from" = Option<i64>, Query, description = "Filter events created at or after timestamp"),
        ("created_to" = Option<i64>, Query, description = "Filter events created at or before timestamp"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)")
    ),
    responses(
        (status = 200, description = "Audit events list", body = AuditEventListResponse),
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
pub async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditEventListQuery>,
) -> Result<Json<AuditEventListResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_support_or_admin(role)?;

    let customer_id = normalize_optional("customer_id", query.customer_id)?;
    let actor = normalize_optional("actor", query.actor)?;
    let event = normalize_optional("event", query.event)?;
    let created_from = query.created_from;
    let created_to = query.created_to;
    if let Some(created_from) = created_from
        && created_from < 0
    {
        return Err(ApiError::bad_request("created_from must be >= 0"));
    }
    if let Some(created_to) = created_to
        && created_to < 0
    {
        return Err(ApiError::bad_request("created_to must be >= 0"));
    }
    if let (Some(created_from), Some(created_to)) = (created_from, created_to)
        && created_from > created_to
    {
        return Err(ApiError::bad_request("created_from must be <= created_to"));
    }

    let (limit, offset) = resolve_pagination(query.limit, query.offset)?;

    let filter = AuditEventFilter {
        customer_id: customer_id.as_deref(),
        actor: actor.as_deref(),
        event: event.as_deref(),
        created_from,
        created_to,
    };

    let events = state
        .db
        .list_audit_events(filter, limit, offset)
        .await
        .map_err(|err| {
            error!("failed to list audit events: {err}");
            ApiError::internal("failed to list audit events")
        })?;

    let mut responses = Vec::with_capacity(events.len());
    for event in events {
        responses.push(AuditEventResponse::try_from_record(event)?);
    }

    Ok(Json(AuditEventListResponse {
        events: responses,
        limit,
        offset,
    }))
}
