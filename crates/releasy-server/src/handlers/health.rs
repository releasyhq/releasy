use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

use crate::app::AppState;
use crate::errors::{ApiError, ErrorBody};

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    status: String,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "meta",
    summary = "Service health check",
    description = "Returns ok when the API and database are reachable.",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service unavailable", body = ErrorBody)
    )
)]
pub async fn health_check(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    state.db.ping().await.map_err(|err| {
        error!("health check failed: {err}");
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
    })?;

    Ok(Json(HealthResponse {
        status: "ok".to_string(),
    }))
}
