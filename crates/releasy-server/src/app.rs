use axum::Router;
use axum::routing::post;

use crate::handlers::auth_introspect;

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub settings: crate::config::Settings,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/auth/introspect", post(auth_introspect))
        .with_state(state)
}
