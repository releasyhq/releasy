use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{admin_authorize_with_role, require_release_publisher};
use crate::errors::{ApiError, ErrorBody};
use crate::models::ArtifactRecord;

use super::{
    artifact_object_key_prefix, artifact_settings, build_artifact_bucket,
    build_artifact_object_key, normalize_checksum, normalize_required, now_ts_or_internal,
    validate_artifact_size, with_idempotency,
};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct ArtifactPresignRequest {
    pub(crate) filename: String,
    pub(crate) platform: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct ArtifactPresignResponse {
    pub(crate) artifact_id: String,
    pub(crate) object_key: String,
    pub(crate) upload_url: String,
    pub(crate) expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct ArtifactRegisterRequest {
    pub(crate) artifact_id: String,
    pub(crate) object_key: String,
    pub(crate) checksum: String,
    pub(crate) size: i64,
    pub(crate) platform: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct ArtifactRegisterResponse {
    pub(crate) id: String,
    pub(crate) release_id: String,
    pub(crate) object_key: String,
    pub(crate) checksum: String,
    pub(crate) size: i64,
    pub(crate) platform: String,
    pub(crate) created_at: i64,
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

#[utoipa::path(
    post,
    path = "/v1/releases/{release_id}/artifacts/presign",
    tag = "artifacts",
    summary = "Presign artifact upload",
    description = "Returns a presigned URL for uploading an artifact. Requires platform_admin or release_publisher.",
    request_body = ArtifactPresignRequest,
    params(
        ("release_id" = String, Path, description = "Release identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Idempotency key for safe retries.")
    ),
    responses(
        (status = 200, description = "Presigned upload created", body = ArtifactPresignResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Release not found", body = ErrorBody),
        (status = 409, description = "Idempotency conflict", body = ErrorBody),
        (status = 503, description = "Artifact storage not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn presign_release_artifact_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
    Json(payload): Json<ArtifactPresignRequest>,
) -> Result<Json<ArtifactPresignResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_publisher(role)?;

    let payload_for_idempotency = payload.clone();
    let response = with_idempotency(
        &state,
        &headers,
        "presign_release_artifact_upload",
        &release_id,
        &payload_for_idempotency,
        || async {
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
            let object_key =
                build_artifact_object_key(&release, &platform, &artifact_id, &filename)?;

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
            let expires_at =
                now_ts_or_internal()? + i64::from(artifact_settings.presign_expires_seconds);

            Ok(ArtifactPresignResponse {
                artifact_id,
                object_key,
                upload_url,
                expires_at,
            })
        },
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/v1/releases/{release_id}/artifacts",
    tag = "artifacts",
    summary = "Register artifact",
    description = "Registers an uploaded artifact. Requires platform_admin or release_publisher.",
    request_body = ArtifactRegisterRequest,
    params(
        ("release_id" = String, Path, description = "Release identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Idempotency key for safe retries.")
    ),
    responses(
        (status = 200, description = "Artifact registered", body = ArtifactRegisterResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Release not found", body = ErrorBody),
        (status = 409, description = "Artifact already exists or idempotency conflict", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn register_release_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
    Json(payload): Json<ArtifactRegisterRequest>,
) -> Result<Json<ArtifactRegisterResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_publisher(role)?;

    let payload_for_idempotency = payload.clone();
    let response = with_idempotency(
        &state,
        &headers,
        "register_release_artifact",
        &release_id,
        &payload_for_idempotency,
        || async {
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

            Ok(ArtifactRegisterResponse::from_record(record))
        },
    )
    .await?;

    Ok(Json(response))
}
