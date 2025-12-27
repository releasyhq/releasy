use axum::Router;
use axum::routing::post;

use crate::handlers::{admin_create_customer, admin_create_key, admin_revoke_key, auth_introspect};

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub settings: crate::config::Settings,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/customers", post(admin_create_customer))
        .route("/v1/admin/keys", post(admin_create_key))
        .route("/v1/admin/keys/revoke", post(admin_revoke_key))
        .route("/v1/auth/introspect", post(auth_introspect))
        .with_state(state)
}
