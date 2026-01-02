use sqlx::SqlitePool;

use crate::config::Settings;
use crate::db::Database;

pub(crate) const ADMIN_TEST_KEY: &str = "secret";

pub(crate) fn base_test_settings() -> Settings {
    Settings {
        bind_addr: "127.0.0.1:8080".to_string(),
        log_level: "info".to_string(),
        database_url: "sqlite::memory:".to_string(),
        database_max_connections: 1,
        download_token_ttl_seconds: 600,
        public_base_url: "http://127.0.0.1:8080".to_string(),
        admin_api_key: None,
        api_key_pepper: None,
        operator_jwks_url: None,
        operator_issuer: None,
        operator_audience: None,
        operator_resource: None,
        operator_jwks_ttl_seconds: 300,
        operator_jwt_leeway_seconds: 0,
        artifact_settings: None,
    }
}

pub(crate) fn test_settings_with_admin_key() -> Settings {
    let mut settings = base_test_settings();
    settings.admin_api_key = Some(ADMIN_TEST_KEY.to_string());
    settings
}

pub(crate) async fn setup_db(settings: &Settings) -> Database {
    let db = Database::connect(settings).await.expect("db connect");
    db.migrate().await.expect("db migrate");
    db
}

pub(crate) async fn setup_default_db() -> Database {
    let settings = base_test_settings();
    setup_db(&settings).await
}

pub(crate) fn sqlite_pool(db: &Database) -> &SqlitePool {
    match db {
        Database::Sqlite(pool) => pool,
        Database::Postgres(_) => panic!("sqlite expected"),
    }
}
