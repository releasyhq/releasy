use axum::{body::Body, http::Request, http::StatusCode};
use releasy_server::{app, config::Settings, db::Database};
use tower::ServiceExt;

fn test_settings() -> Settings {
    Settings {
        bind_addr: "127.0.0.1:0".to_string(),
        log_level: "info".to_string(),
        database_url: "sqlite::memory:".to_string(),
        database_max_connections: 1,
        download_token_ttl_seconds: 600,
        admin_api_key: Some("secret".to_string()),
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

async fn setup_app() -> (axum::Router, Database) {
    let settings = test_settings();
    let db = Database::connect(&settings).await.expect("db connect");
    db.migrate().await.expect("db migrate");

    let state = app::AppState {
        db: db.clone(),
        settings,
        jwks_cache: None,
    };

    (app::router(state), db)
}

#[tokio::test]
async fn create_release_requires_admin_key() {
    let (app, db) = setup_app().await;

    let request = Request::builder()
        .method("POST")
        .uri("/v1/releases")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"product":"releasy","version":"1.0.0"}"#))
        .unwrap();

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let releases = db
        .list_releases(Some("releasy"), None, Some("1.0.0"), 10, 0)
        .await
        .expect("list releases");
    assert!(releases.is_empty());
}

#[tokio::test]
async fn create_release_inserts_release() {
    let (app, db) = setup_app().await;

    let request = Request::builder()
        .method("POST")
        .uri("/v1/releases")
        .header("content-type", "application/json")
        .header("x-releasy-admin-key", "secret")
        .body(Body::from(r#"{"product":"releasy","version":"1.2.3"}"#))
        .unwrap();

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let releases = db
        .list_releases(Some("releasy"), None, Some("1.2.3"), 10, 0)
        .await
        .expect("list releases");
    assert_eq!(releases.len(), 1);

    let release = &releases[0];
    assert_eq!(release.product, "releasy");
    assert_eq!(release.version, "1.2.3");
    assert_eq!(release.status, "draft");
}
