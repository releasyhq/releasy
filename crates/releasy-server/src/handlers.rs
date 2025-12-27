use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;

use crate::app::AppState;
use crate::auth::{authenticate_api_key, require_scopes};
use crate::errors::ApiError;
use crate::models::ApiKeyIntrospection;

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
