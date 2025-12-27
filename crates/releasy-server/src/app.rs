use axum::Router;
use axum::routing::{delete, post};

use crate::auth::JwksCache;
use crate::handlers::{
    admin_create_customer, admin_create_key, admin_revoke_key, auth_introspect, create_release,
    delete_release, list_releases, presign_release_artifact_upload, publish_release,
    register_release_artifact, unpublish_release,
};

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub settings: crate::config::Settings,
    pub jwks_cache: Option<JwksCache>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/customers", post(admin_create_customer))
        .route("/v1/admin/keys", post(admin_create_key))
        .route("/v1/admin/keys/revoke", post(admin_revoke_key))
        .route("/v1/releases", post(create_release).get(list_releases))
        .route("/v1/releases/{release_id}", delete(delete_release))
        .route("/v1/releases/{release_id}/publish", post(publish_release))
        .route(
            "/v1/releases/{release_id}/unpublish",
            post(unpublish_release),
        )
        .route(
            "/v1/releases/{release_id}/artifacts/presign",
            post(presign_release_artifact_upload),
        )
        .route(
            "/v1/releases/{release_id}/artifacts",
            post(register_release_artifact),
        )
        .route("/v1/auth/introspect", post(auth_introspect))
        .with_state(state)
}
