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

fn ok_response() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

async fn require_database(state: &AppState) -> Result<(), ApiError> {
    state.db.ping().await.map_err(|err| {
        error!("health check failed: {err}");
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
    })
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
    require_database(&state).await?;
    Ok(ok_response())
}

#[utoipa::path(
    get,
    path = "/ready",
    tag = "meta",
    summary = "Readiness check",
    description = "Returns ok when the API is ready to serve requests.",
    responses(
        (status = 200, description = "Service is ready", body = HealthResponse),
        (status = 503, description = "Service unavailable", body = ErrorBody)
    )
)]
pub async fn ready_check(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    require_database(&state).await?;
    Ok(ok_response())
}

#[utoipa::path(
    get,
    path = "/live",
    tag = "meta",
    summary = "Liveness check",
    description = "Returns ok when the API process is running.",
    responses(
        (status = 200, description = "Service is live", body = HealthResponse)
    )
)]
pub async fn live_check() -> Json<HealthResponse> {
    ok_response()
}
