mod app;
mod auth;
mod config;
mod db;
mod errors;
mod handlers;
mod models;
mod utils;

use crate::config::Settings;
use crate::db::Database;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), String> {
    let settings = Settings::from_env()?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(settings.log_level.clone()));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let addr: SocketAddr = settings
        .bind_addr
        .parse()
        .map_err(|_| format!("invalid RELEASY_BIND_ADDR: {}", settings.bind_addr))?;
    let db = Database::connect(&settings).await?;
    db.migrate().await?;

    let jwks_cache = auth::JwksCache::new(&settings);
    let state = app::AppState {
        db,
        settings,
        jwks_cache,
    };
    let app = app::router(state);

    tracing::info!("releasy-server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| format!("bind failed: {err}"))?;
    axum::serve(listener, app)
        .await
        .map_err(|err| format!("server error: {err}"))?;
    Ok(())
}
