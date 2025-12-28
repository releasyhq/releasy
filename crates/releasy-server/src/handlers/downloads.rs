use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{
    authenticate_api_key, generate_download_token, hash_download_token, require_scopes,
};
use crate::errors::{ApiError, ErrorBody};
use crate::models::DownloadTokenRecord;
use crate::release::ReleaseStatus;

use super::{
    artifact_settings, build_artifact_bucket, build_download_url, is_product_entitled,
    normalize_required, now_ts_or_internal, resolve_requested_ttl, with_idempotency,
};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct DownloadTokenRequest {
    pub(crate) artifact_id: String,
    pub(crate) purpose: Option<String>,
    pub(crate) expires_in_seconds: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct DownloadTokenResponse {
    pub(crate) download_url: String,
    pub(crate) expires_at: i64,
}

#[utoipa::path(
    post,
    path = "/v1/downloads/token",
    tag = "downloads",
    summary = "Create download token",
    description = "Creates a download token for an artifact. Requires API key with downloads:token scope.",
    request_body = DownloadTokenRequest,
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Idempotency key for safe retries.")
    ),
    responses(
        (status = 200, description = "Download token created", body = DownloadTokenResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Artifact or release not found", body = ErrorBody),
        (status = 409, description = "Idempotency conflict", body = ErrorBody)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create_download_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DownloadTokenRequest>,
) -> Result<Json<DownloadTokenResponse>, ApiError> {
    let auth = authenticate_api_key(&headers, &state.settings, &state.db).await?;
    require_scopes(&auth, &["downloads:token"])?;

    let artifact_id = normalize_required("artifact_id", payload.artifact_id.clone())?;
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
        .list_entitlements_by_customer(&auth.customer_id, Some(&release.product), None, None)
        .await
        .map_err(|err| {
            error!("failed to list entitlements: {err}");
            ApiError::internal("failed to list entitlements")
        })?;

    let now = now_ts_or_internal()?;
    if !is_product_entitled(&entitlements, &release.product, now) {
        return Err(ApiError::forbidden("entitlement required"));
    }

    let payload_for_idempotency = payload.clone();
    let response = with_idempotency(
        &state,
        &headers,
        "create_download_token",
        &auth.customer_id,
        &payload_for_idempotency,
        || async {
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
                customer_id: auth.customer_id.clone(),
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

            Ok(DownloadTokenResponse {
                download_url,
                expires_at,
            })
        },
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/v1/downloads/{token}",
    tag = "downloads",
    summary = "Resolve download token",
    description = "Resolves a download token and redirects to the artifact download URL.",
    params(
        ("token" = String, Path, description = "Download token")
    ),
    responses(
        (status = 302, description = "Redirect to artifact download"),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 404, description = "Token not found or expired", body = ErrorBody)
    )
)]
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
        .list_entitlements_by_customer(&record.customer_id, Some(&release.product), None, None)
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
