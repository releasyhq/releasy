use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;

use crate::app::AppState;
use crate::auth::{authenticate_api_key, require_scopes};
use crate::errors::{ApiError, ErrorBody};
use crate::models::ApiKeyIntrospection;

#[utoipa::path(
    post,
    path = "/v1/auth/introspect",
    tag = "auth",
    summary = "Introspect API key",
    description = "Returns API key metadata when the key is valid and authorized.",
    responses(
        (status = 200, description = "Introspection result", body = ApiKeyIntrospection),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 503, description = "Auth not configured", body = ErrorBody)
    ),
    security(
        ("api_key" = [])
    )
)]
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
