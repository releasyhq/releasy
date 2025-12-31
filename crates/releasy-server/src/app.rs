use axum::Router;
use axum::routing::{delete, get, patch, post};

use crate::auth::JwksCache;
use crate::handlers::{
    admin_create_customer, admin_create_key, admin_revoke_key, auth_introspect,
    create_download_token, create_entitlement, create_release, delete_entitlement, delete_release,
    health_check, list_audit_events, list_entitlements, list_releases,
    presign_release_artifact_upload, publish_release, register_release_artifact,
    resolve_download_token, unpublish_release, update_entitlement,
};
use crate::openapi;

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub settings: crate::config::Settings,
    pub jwks_cache: Option<JwksCache>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/openapi.json", get(openapi::openapi_json))
        .route("/v1/admin/customers", post(admin_create_customer))
        .route(
            "/v1/admin/customers/{customer_id}/entitlements",
            get(list_entitlements).post(create_entitlement),
        )
        .route("/v1/admin/audit-events", get(list_audit_events))
        .route(
            "/v1/admin/customers/{customer_id}/entitlements/{entitlement_id}",
            patch(update_entitlement).delete(delete_entitlement),
        )
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
        .route("/v1/downloads/token", post(create_download_token))
        .route("/v1/downloads/{token}", get(resolve_download_token))
        .route("/v1/auth/introspect", post(auth_introspect))
        .with_state(state)
}
