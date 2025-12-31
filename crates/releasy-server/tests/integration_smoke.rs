use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt;
use releasy_server::{app, auth, config::Settings, db::Database};
use serde_json::{Value, json};
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN_KEY_HEADER: (&str, &str) = ("x-releasy-admin-key", "secret");

fn now_ts() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time");
    now.as_secs() as i64
}

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

fn sqlite_pool(db: &Database) -> &sqlx::SqlitePool {
    match db {
        Database::Sqlite(pool) => pool,
        Database::Postgres(_) => panic!("sqlite expected"),
    }
}

async fn response_json(response: Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = Body::from(serde_json::to_vec(&body).expect("serialize body"));
    let request = builder
        .header("content-type", "application/json")
        .body(body)
        .expect("request");
    app.clone().oneshot(request).await.expect("response")
}

async fn send_empty(
    app: &axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Body::empty()).expect("request");
    app.clone().oneshot(request).await.expect("response")
}

async fn create_customer(app: &axum::Router, name: &str) -> String {
    let response = send_json(
        app,
        "POST",
        "/v1/admin/customers",
        &[ADMIN_KEY_HEADER],
        json!({ "name": name }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    body.get("id")
        .and_then(Value::as_str)
        .expect("customer id")
        .to_string()
}

async fn create_entitlement(app: &axum::Router, customer_id: &str, product: &str, starts_at: i64) {
    let uri = format!("/v1/admin/customers/{customer_id}/entitlements",);
    let response = send_json(
        app,
        "POST",
        &uri,
        &[ADMIN_KEY_HEADER],
        json!({
            "product": product,
            "starts_at": starts_at,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

async fn create_release(app: &axum::Router, product: &str, version: &str) -> String {
    let response = send_json(
        app,
        "POST",
        "/v1/releases",
        &[ADMIN_KEY_HEADER],
        json!({ "product": product, "version": version }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    body.get("id")
        .and_then(Value::as_str)
        .expect("release id")
        .to_string()
}

async fn publish_release(app: &axum::Router, release_id: &str) {
    let uri = format!("/v1/releases/{release_id}/publish");
    let response = send_empty(app, "POST", &uri, &[ADMIN_KEY_HEADER]).await;
    assert_eq!(response.status(), StatusCode::OK);
}

async fn insert_api_key(db: &Database, customer_id: &str, scopes: &[&str]) -> (String, String) {
    let raw_key = auth::generate_api_key().expect("api key");
    let key_hash = auth::hash_api_key(&raw_key, None).expect("key hash");
    let key_prefix = auth::api_key_prefix(&raw_key);
    let scopes_json = serde_json::to_string(
        &scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>(),
    )
    .expect("scopes json");
    let key_id = Uuid::new_v4().to_string();
    let created_at = now_ts();

    sqlx::query(
        "INSERT INTO api_keys (id, customer_id, key_hash, key_prefix, name, key_type, scopes, \
         expires_at, created_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&key_id)
    .bind(customer_id)
    .bind(&key_hash)
    .bind(&key_prefix)
    .bind(None::<String>)
    .bind("human")
    .bind(&scopes_json)
    .bind(None::<i64>)
    .bind(created_at)
    .bind(None::<i64>)
    .bind(None::<i64>)
    .execute(sqlite_pool(db))
    .await
    .expect("insert api key");

    (key_id, raw_key)
}

async fn api_key_count(db: &Database, customer_id: &str) -> i64 {
    let row = sqlx::query("SELECT COUNT(*) AS count FROM api_keys WHERE customer_id = ?")
        .bind(customer_id)
        .fetch_one(sqlite_pool(db))
        .await
        .expect("api key count");
    row.get("count")
}

async fn api_key_last_used(db: &Database, key_id: &str) -> Option<i64> {
    let row = sqlx::query("SELECT last_used_at FROM api_keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(sqlite_pool(db))
        .await
        .expect("api key last_used_at");
    row.get("last_used_at")
}

#[tokio::test]
async fn admin_endpoints_require_admin_key() {
    let (app, db) = setup_app().await;

    let response = send_json(
        &app,
        "POST",
        "/v1/admin/customers",
        &[],
        json!({ "name": "No Auth" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = send_json(
        &app,
        "POST",
        "/v1/admin/customers",
        &[("x-releasy-admin-key", "wrong")],
        json!({ "name": "Bad Auth" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = send_json(
        &app,
        "POST",
        "/v1/admin/customers",
        &[ADMIN_KEY_HEADER],
        json!({ "name": "Good Auth" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    let customer_id = body.get("id").and_then(Value::as_str).expect("customer id");
    let customer = db.get_customer(customer_id).await.expect("get customer");
    assert!(customer.is_some());
}

#[tokio::test]
async fn create_release_requires_admin_key() {
    let (app, db) = setup_app().await;

    let response = send_json(
        &app,
        "POST",
        "/v1/releases",
        &[],
        json!({ "product": "releasy", "version": "1.0.0" }),
    )
    .await;
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

    let response = send_json(
        &app,
        "POST",
        "/v1/releases",
        &[ADMIN_KEY_HEADER],
        json!({ "product": "releasy", "version": "1.2.3" }),
    )
    .await;
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

#[tokio::test]
async fn create_release_idempotency_reuses_response() {
    let (app, db) = setup_app().await;
    let headers = [ADMIN_KEY_HEADER, ("idempotency-key", "release-idem-1")];

    let response = send_json(
        &app,
        "POST",
        "/v1/releases",
        &headers,
        json!({ "product": "releasy", "version": "3.1.0" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let first = response_json(response).await;
    let first_id = first.get("id").and_then(Value::as_str).expect("id");

    let response = send_json(
        &app,
        "POST",
        "/v1/releases",
        &headers,
        json!({ "product": "releasy", "version": "3.1.0" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let second = response_json(response).await;
    let second_id = second.get("id").and_then(Value::as_str).expect("id");
    assert_eq!(first_id, second_id);

    let releases = db
        .list_releases(Some("releasy"), None, Some("3.1.0"), 10, 0)
        .await
        .expect("list releases");
    assert_eq!(releases.len(), 1);
}

#[tokio::test]
async fn create_release_idempotency_conflict() {
    let (app, _db) = setup_app().await;
    let headers = [ADMIN_KEY_HEADER, ("idempotency-key", "release-idem-2")];

    let response = send_json(
        &app,
        "POST",
        "/v1/releases",
        &headers,
        json!({ "product": "releasy", "version": "3.2.0" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send_json(
        &app,
        "POST",
        "/v1/releases",
        &headers,
        json!({ "product": "releasy", "version": "3.2.1" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn list_releases_requires_scope() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Scope Co").await;
    let (_key_id, api_key) = insert_api_key(&db, &customer_id, &["downloads:token"]).await;
    let api_key_headers = [("x-releasy-api-key", api_key.as_str())];

    let response = send_empty(&app, "GET", "/v1/releases", &api_key_headers).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_releases_respects_entitlement_window() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Entitled Customer").await;
    let release_id = create_release(&app, "releasy", "3.3.0").await;
    publish_release(&app, &release_id).await;

    let (_key_id, api_key) = insert_api_key(&db, &customer_id, &["releases:read"]).await;
    let api_key_headers = [("x-releasy-api-key", api_key.as_str())];

    let now = now_ts();
    create_entitlement(&app, &customer_id, "releasy", now + 3_600).await;

    let response = send_empty(
        &app,
        "GET",
        "/v1/releases?status=published",
        &api_key_headers,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let releases = body
        .get("releases")
        .and_then(Value::as_array)
        .expect("releases list");
    assert!(releases.is_empty());

    create_entitlement(&app, &customer_id, "releasy", now - 60).await;

    let response = send_empty(
        &app,
        "GET",
        "/v1/releases?status=published",
        &api_key_headers,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let releases = body
        .get("releases")
        .and_then(Value::as_array)
        .expect("releases list");
    assert_eq!(releases.len(), 1);
}

#[tokio::test]
async fn release_publish_and_unpublish_flow() {
    let (app, db) = setup_app().await;

    let release_id = create_release(&app, "releasy", "3.4.0").await;

    let publish_uri = format!("/v1/releases/{release_id}/publish");
    let response = send_empty(&app, "POST", &publish_uri, &[ADMIN_KEY_HEADER]).await;
    assert_eq!(response.status(), StatusCode::OK);

    let release = db.get_release(&release_id).await.expect("get release");
    assert_eq!(release.expect("release").status, "published");

    let unpublish_uri = format!("/v1/releases/{release_id}/unpublish");
    let response = send_empty(&app, "POST", &unpublish_uri, &[ADMIN_KEY_HEADER]).await;
    assert_eq!(response.status(), StatusCode::OK);

    let release = db.get_release(&release_id).await.expect("get release");
    assert_eq!(release.expect("release").status, "draft");
}

#[tokio::test]
async fn admin_create_customer_and_list_entitlements() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Acme Co").await;
    create_entitlement(&app, &customer_id, "releasy", now_ts() - 60).await;

    let uri = format!("/v1/admin/customers/{customer_id}/entitlements",);
    let response = send_empty(&app, "GET", &uri, &[ADMIN_KEY_HEADER]).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    let entitlements = body
        .get("entitlements")
        .and_then(Value::as_array)
        .expect("entitlements list");
    assert_eq!(entitlements.len(), 1);
    assert_eq!(
        entitlements[0].get("product").and_then(Value::as_str),
        Some("releasy")
    );

    let stored = db
        .list_entitlements_by_customer(&customer_id, None, None, None)
        .await
        .expect("list entitlements");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].product, "releasy");
}

#[tokio::test]
async fn admin_create_key_persists_record() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Key Customer").await;
    let before = api_key_count(&db, &customer_id).await;

    let response = send_json(
        &app,
        "POST",
        "/v1/admin/keys",
        &[ADMIN_KEY_HEADER],
        json!({
            "customer_id": customer_id.as_str(),
            "scopes": ["keys:read"],
            "key_type": "human",
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(
        body.get("customer_id").and_then(Value::as_str),
        Some(customer_id.as_str())
    );

    let after = api_key_count(&db, &customer_id).await;
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn auth_introspect_returns_key_details() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Introspect Co").await;
    let (key_id, api_key) = insert_api_key(&db, &customer_id, &["keys:read"]).await;

    let api_key_headers = [("x-releasy-api-key", api_key.as_str())];
    let response = send_empty(&app, "POST", "/v1/auth/introspect", &api_key_headers).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body.get("active").and_then(Value::as_bool), Some(true));
    assert_eq!(
        body.get("customer_id").and_then(Value::as_str),
        Some(customer_id.as_str())
    );
    let scopes = body
        .get("scopes")
        .and_then(Value::as_array)
        .expect("scopes");
    assert!(
        scopes
            .iter()
            .any(|value| value.as_str() == Some("keys:read"))
    );

    let last_used_at = api_key_last_used(&db, &key_id).await;
    assert!(last_used_at.is_some());
}

#[tokio::test]
async fn auth_introspect_rejects_missing_scope() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Scope Co").await;
    let (_key_id, api_key) = insert_api_key(&db, &customer_id, &["downloads:token"]).await;

    let api_key_headers = [("x-releasy-api-key", api_key.as_str())];
    let response = send_empty(&app, "POST", "/v1/auth/introspect", &api_key_headers).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_releases_for_customer_includes_published_release() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Release Customer").await;
    let release_id = create_release(&app, "releasy", "2.0.0").await;
    publish_release(&app, &release_id).await;
    create_entitlement(&app, &customer_id, "releasy", now_ts() - 60).await;

    let (_key_id, api_key) = insert_api_key(&db, &customer_id, &["releases:read"]).await;
    let api_key_headers = [("x-releasy-api-key", api_key.as_str())];

    let response = send_empty(
        &app,
        "GET",
        "/v1/releases?status=published",
        &api_key_headers,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    let releases = body
        .get("releases")
        .and_then(Value::as_array)
        .expect("releases list");
    assert_eq!(releases.len(), 1);
    assert_eq!(
        releases[0].get("product").and_then(Value::as_str),
        Some("releasy")
    );
    assert_eq!(
        releases[0].get("version").and_then(Value::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        releases[0].get("status").and_then(Value::as_str),
        Some("published")
    );
}

#[tokio::test]
async fn download_token_expired_returns_not_found() {
    let (app, db) = setup_app().await;

    let customer_id = create_customer(&app, "Download Customer").await;
    let release_id = create_release(&app, "releasy", "4.0.0").await;

    sqlx::query(
        "INSERT INTO artifacts (id, release_id, object_key, checksum, size, platform, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("artifact-1")
    .bind(&release_id)
    .bind("releasy/4.0.0/artifact-1.tar.gz")
    .bind("deadbeef")
    .bind(123_i64)
    .bind("linux-x86_64")
    .bind(now_ts())
    .execute(sqlite_pool(&db))
    .await
    .expect("insert artifact");

    let token = auth::generate_download_token().expect("download token");
    let token_hash = auth::hash_download_token(&token, None);
    let expires_at = now_ts() - 30;
    let created_at = expires_at - 60;

    sqlx::query(
        "INSERT INTO download_tokens (token_hash, artifact_id, customer_id, purpose, \
         expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&token_hash)
    .bind("artifact-1")
    .bind(&customer_id)
    .bind(None::<String>)
    .bind(expires_at)
    .bind(created_at)
    .execute(sqlite_pool(&db))
    .await
    .expect("insert download token");

    let uri = format!("/v1/downloads/{token}");
    let response = send_empty(&app, "GET", &uri, &[]).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (app, _db) = setup_app().await;

    let response = send_empty(&app, "GET", "/health", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body.get("status").and_then(Value::as_str), Some("ok"));
}

#[tokio::test]
async fn health_endpoint_reports_db_unavailable() {
    let (app, db) = setup_app().await;

    match &db {
        Database::Sqlite(pool) => {
            pool.close().await;
        }
        Database::Postgres(_) => panic!("sqlite expected"),
    }

    let response = send_empty(&app, "GET", "/health", &[]).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    let error = body.get("error").and_then(Value::as_object).expect("error");
    assert_eq!(
        error.get("code").and_then(Value::as_str),
        Some("service_unavailable")
    );
}

#[tokio::test]
async fn ready_endpoint_returns_ok() {
    let (app, _db) = setup_app().await;

    let response = send_empty(&app, "GET", "/ready", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body.get("status").and_then(Value::as_str), Some("ok"));
}

#[tokio::test]
async fn ready_endpoint_reports_db_unavailable() {
    let (app, db) = setup_app().await;

    match &db {
        Database::Sqlite(pool) => {
            pool.close().await;
        }
        Database::Postgres(_) => panic!("sqlite expected"),
    }

    let response = send_empty(&app, "GET", "/ready", &[]).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    let error = body.get("error").and_then(Value::as_object).expect("error");
    assert_eq!(
        error.get("code").and_then(Value::as_str),
        Some("service_unavailable")
    );
}

#[tokio::test]
async fn live_endpoint_returns_ok_without_db() {
    let (app, db) = setup_app().await;

    match &db {
        Database::Sqlite(pool) => {
            pool.close().await;
        }
        Database::Postgres(_) => panic!("sqlite expected"),
    }

    let response = send_empty(&app, "GET", "/live", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body.get("status").and_then(Value::as_str), Some("ok"));
}
