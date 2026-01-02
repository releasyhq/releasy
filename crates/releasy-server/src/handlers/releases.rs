use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{
    admin_authorize_with_role, authenticate_api_key, require_admin, require_release_publisher,
    require_scopes,
};
use crate::errors::{ApiError, ErrorBody};
use crate::models::{ArtifactRecord, ReleaseRecord};
use crate::release::{ReleaseAction, ReleaseStatus};

use super::{
    apply_release_action_with_rbac, normalize_optional, normalize_required, now_ts_or_internal,
    require_release_list_role, resolve_pagination, with_idempotency,
};

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub(crate) struct ReleaseCreateRequest {
    pub(crate) product: String,
    pub(crate) version: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ReleaseListQuery {
    pub(crate) product: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) include_artifacts: Option<bool>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct ReleaseResponse {
    pub(crate) id: String,
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) status: String,
    pub(crate) created_at: i64,
    pub(crate) published_at: Option<i64>,
    pub(crate) artifacts: Option<Vec<ArtifactSummary>>,
}

impl ReleaseResponse {
    pub(super) fn from_record(
        record: ReleaseRecord,
        artifacts: Option<Vec<ArtifactSummary>>,
    ) -> Self {
        Self {
            id: record.id,
            product: record.product,
            version: record.version,
            status: record.status,
            created_at: record.created_at,
            published_at: record.published_at,
            artifacts,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub(crate) struct ArtifactSummary {
    pub(crate) id: String,
    pub(crate) object_key: String,
    pub(crate) platform: String,
    pub(crate) checksum: String,
    pub(crate) size: i64,
}

impl ArtifactSummary {
    fn from_record(record: ArtifactRecord) -> Self {
        Self {
            id: record.id,
            object_key: record.object_key,
            platform: record.platform,
            checksum: record.checksum,
            size: record.size,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ReleaseListResponse {
    pub(crate) releases: Vec<ReleaseResponse>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

#[utoipa::path(
    post,
    path = "/v1/releases",
    tag = "releases",
    summary = "Create a release",
    description = "Creates a draft release. Requires platform_admin or release_publisher.",
    request_body = ReleaseCreateRequest,
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Idempotency key for safe retries.")
    ),
    responses(
        (status = 200, description = "Release created", body = ReleaseResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Release already exists or idempotency conflict", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn create_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ReleaseCreateRequest>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_release_publisher(role)?;

    let payload_for_idempotency = payload.clone();
    let response = with_idempotency(
        &state,
        &headers,
        "create_release",
        "",
        &payload_for_idempotency,
        || async {
            let product = normalize_required("product", payload.product)?;
            let version = normalize_required("version", payload.version)?;

            let record = ReleaseRecord {
                id: Uuid::new_v4().to_string(),
                product,
                version,
                status: ReleaseStatus::Draft.as_str().to_string(),
                created_at: now_ts_or_internal()?,
                published_at: None,
            };

            state.db.insert_release(&record).await.map_err(|err| {
                if let sqlx::Error::Database(db_err) = &err
                    && db_err.is_unique_violation()
                {
                    return ApiError::new(StatusCode::CONFLICT, "release already exists");
                }
                error!("failed to create release: {err}");
                ApiError::internal("failed to create release")
            })?;

            Ok(ReleaseResponse::from_record(record, None))
        },
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/v1/releases",
    tag = "releases",
    summary = "List releases",
    description = "Lists releases. Admins can filter all statuses; API keys only see published releases for entitled products.",
    params(
        ("product" = Option<String>, Query, description = "Optional product filter"),
        ("version" = Option<String>, Query, description = "Optional version filter"),
        ("status" = Option<String>, Query, description = "Optional status filter"),
        ("include_artifacts" = Option<bool>, Query, description = "Include artifact summaries"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("offset" = Option<u32>, Query, description = "Page offset (default 0)")
    ),
    responses(
        (status = 200, description = "Releases list", body = ReleaseListResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = []),
        ("api_key" = [])
    )
)]
pub async fn list_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReleaseListQuery>,
) -> Result<Json<ReleaseListResponse>, ApiError> {
    if headers.contains_key("x-releasy-api-key") {
        return list_releases_for_customer(&state, &headers, query).await;
    }
    list_releases_for_admin(&state, &headers, query).await
}

async fn list_releases_for_admin(
    state: &AppState,
    headers: &HeaderMap,
    query: ReleaseListQuery,
) -> Result<Json<ReleaseListResponse>, ApiError> {
    let role = admin_authorize_with_role(headers, &state.settings, &state.jwks_cache).await?;
    require_release_list_role(role)?;

    let product = normalize_optional("product", query.product)?;
    let version = normalize_optional("version", query.version)?;
    let status = match normalize_optional("status", query.status)? {
        Some(status) => {
            let parsed = ReleaseStatus::parse(&status)
                .ok_or_else(|| ApiError::bad_request("invalid status"))?;
            Some(parsed.as_str().to_string())
        }
        None => None,
    };

    let include_artifacts = query.include_artifacts.unwrap_or(false);
    let (limit, offset) = resolve_pagination(query.limit, query.offset)?;
    let releases = state
        .db
        .list_releases(
            product.as_deref(),
            status.as_deref(),
            version.as_deref(),
            limit,
            offset,
        )
        .await
        .map_err(|err| {
            error!("failed to list releases: {err}");
            ApiError::internal("failed to list releases")
        })?;

    let artifacts_by_release = if include_artifacts {
        Some(load_artifacts_for_releases(state, &releases).await?)
    } else {
        None
    };

    let mut responses = Vec::with_capacity(releases.len());
    for record in releases {
        let artifacts = artifacts_by_release
            .as_ref()
            .map(|map| map.get(&record.id).cloned().unwrap_or_default());
        responses.push(ReleaseResponse::from_record(record, artifacts));
    }

    Ok(Json(ReleaseListResponse {
        releases: responses,
        limit,
        offset,
    }))
}

async fn list_releases_for_customer(
    state: &AppState,
    headers: &HeaderMap,
    query: ReleaseListQuery,
) -> Result<Json<ReleaseListResponse>, ApiError> {
    let auth = authenticate_api_key(headers, &state.settings, &state.db).await?;
    require_scopes(&auth, &["releases:read"])?;

    let product = normalize_optional("product", query.product)?;
    let version = normalize_optional("version", query.version)?;
    if let Some(status) = normalize_optional("status", query.status)? {
        let parsed =
            ReleaseStatus::parse(&status).ok_or_else(|| ApiError::bad_request("invalid status"))?;
        if parsed != ReleaseStatus::Published {
            return Err(ApiError::bad_request("status must be published"));
        }
    }

    let include_artifacts = query.include_artifacts.unwrap_or(false);
    let (limit, offset) = resolve_pagination(query.limit, query.offset)?;

    let entitlements = state
        .db
        .list_entitlements_by_customer(&auth.customer_id, None, None, None)
        .await
        .map_err(|err| {
            error!("failed to list entitlements: {err}");
            ApiError::internal("failed to list entitlements")
        })?;

    let now = now_ts_or_internal()?;
    let mut products = HashSet::new();
    for entitlement in entitlements {
        if entitlement.starts_at > now {
            continue;
        }
        if let Some(ends_at) = entitlement.ends_at
            && ends_at < now
        {
            continue;
        }
        products.insert(entitlement.product);
    }

    if let Some(product) = product {
        if products.contains(&product) {
            products.clear();
            products.insert(product);
        } else {
            return Ok(Json(ReleaseListResponse {
                releases: Vec::new(),
                limit,
                offset,
            }));
        }
    }

    if products.is_empty() {
        return Ok(Json(ReleaseListResponse {
            releases: Vec::new(),
            limit,
            offset,
        }));
    }

    let mut product_list: Vec<String> = products.into_iter().collect();
    product_list.sort();

    let releases = state
        .db
        .list_published_releases_for_products(&product_list, version.as_deref(), limit, offset)
        .await
        .map_err(|err| {
            error!("failed to list releases: {err}");
            ApiError::internal("failed to list releases")
        })?;

    let artifacts_by_release = if include_artifacts {
        Some(load_artifacts_for_releases(state, &releases).await?)
    } else {
        None
    };

    let mut responses = Vec::with_capacity(releases.len());
    for record in releases {
        let artifacts = artifacts_by_release
            .as_ref()
            .map(|map| map.get(&record.id).cloned().unwrap_or_default());
        responses.push(ReleaseResponse::from_record(record, artifacts));
    }

    Ok(Json(ReleaseListResponse {
        releases: responses,
        limit,
        offset,
    }))
}

async fn load_artifacts_for_releases(
    state: &AppState,
    releases: &[ReleaseRecord],
) -> Result<HashMap<String, Vec<ArtifactSummary>>, ApiError> {
    let release_ids: Vec<String> = releases.iter().map(|release| release.id.clone()).collect();
    if release_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let artifacts = state
        .db
        .list_artifacts_by_releases(&release_ids)
        .await
        .map_err(|err| {
            error!("failed to list artifacts: {err}");
            ApiError::internal("failed to list artifacts")
        })?;

    let mut grouped: HashMap<String, Vec<ArtifactSummary>> = HashMap::new();
    for artifact in artifacts {
        grouped
            .entry(artifact.release_id.clone())
            .or_default()
            .push(ArtifactSummary::from_record(artifact));
    }

    for release_id in release_ids {
        grouped.entry(release_id).or_default();
    }

    Ok(grouped)
}

#[utoipa::path(
    post,
    path = "/v1/releases/{release_id}/publish",
    tag = "releases",
    summary = "Publish a release",
    description = "Publishes a draft release. Requires platform_admin or release_publisher.",
    params(
        ("release_id" = String, Path, description = "Release identifier")
    ),
    responses(
        (status = 200, description = "Release published", body = ReleaseResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Release not found", body = ErrorBody),
        (status = 409, description = "Release status changed", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn publish_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    apply_release_action_with_rbac(&state, &headers, &release_id, ReleaseAction::Publish).await
}

#[utoipa::path(
    post,
    path = "/v1/releases/{release_id}/unpublish",
    tag = "releases",
    summary = "Unpublish a release",
    description = "Unpublishes a release. Requires platform_admin.",
    params(
        ("release_id" = String, Path, description = "Release identifier")
    ),
    responses(
        (status = 200, description = "Release unpublished", body = ReleaseResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Release not found", body = ErrorBody),
        (status = 409, description = "Release status changed", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn unpublish_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    apply_release_action_with_rbac(&state, &headers, &release_id, ReleaseAction::Unpublish).await
}

#[utoipa::path(
    delete,
    path = "/v1/releases/{release_id}",
    tag = "releases",
    summary = "Delete a release",
    description = "Deletes a release. Requires platform_admin.",
    params(
        ("release_id" = String, Path, description = "Release identifier")
    ),
    responses(
        (status = 204, description = "Release deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Release not found", body = ErrorBody),
        (status = 503, description = "Admin auth not configured", body = ErrorBody)
    ),
    security(
        ("admin_key" = []),
        ("operator_jwt" = [])
    )
)]
pub async fn delete_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(release_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let role = admin_authorize_with_role(&headers, &state.settings, &state.jwks_cache).await?;
    require_admin(role)?;

    let rows = state.db.delete_release(&release_id).await.map_err(|err| {
        error!("failed to delete release: {err}");
        ApiError::internal("failed to delete release")
    })?;
    if rows == 0 {
        return Err(ApiError::not_found("release not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}
