use axum::Router;
use axum::routing::{delete, get, patch, post};

use crate::auth::JwksCache;
use crate::handlers::{
    admin_create_customer, admin_create_key, admin_revoke_key, auth_introspect,
    create_download_token, create_entitlement, create_release, delete_entitlement, delete_release,
    get_customer, health_check, list_audit_events, list_customers, list_entitlements,
    list_releases, live_check, presign_release_artifact_upload, publish_release, ready_check,
    register_release_artifact, resolve_download_token, unpublish_release, update_customer,
    update_entitlement,
};
use crate::openapi;

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub settings: crate::config::Settings,
    pub jwks_cache: Option<JwksCache>,
}

pub fn router(state: AppState) -> Router {
    base_router(state.clone())
        .merge(admin_routes(state.clone()))
        .merge(publisher_routes(state))
}

/// Publisher-only router (no admin routes).
pub fn publisher_router(state: AppState) -> Router {
    base_router(state.clone()).merge(publisher_routes(state))
}

/// Admin-only router (no publisher routes).
pub fn admin_router(state: AppState) -> Router {
    base_router(state.clone()).merge(admin_routes(state))
}

fn base_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/live", get(live_check))
        .route("/openapi.json", get(openapi::openapi_json))
        .route("/v1/auth/introspect", post(auth_introspect))
        .with_state(state)
}

fn admin_routes(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/admin/customers",
            post(admin_create_customer).get(list_customers),
        )
        .route(
            "/v1/admin/customers/{customer_id}",
            get(get_customer).patch(update_customer),
        )
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
        .with_state(state)
}

fn publisher_routes(state: AppState) -> Router {
    Router::new()
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
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{setup_db, test_settings_with_admin_key};

    async fn test_state() -> AppState {
        let settings = test_settings_with_admin_key();
        let db = setup_db(&settings).await;
        AppState {
            db,
            settings,
            jwks_cache: None,
        }
    }

    #[tokio::test]
    async fn publisher_router_excludes_admin_routes() {
        let state = test_state().await;
        let app = publisher_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/releases")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::get("/v1/admin/customers")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_router_excludes_publisher_routes() {
        let state = test_state().await;
        let app = admin_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/admin/customers")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::get("/v1/releases")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
