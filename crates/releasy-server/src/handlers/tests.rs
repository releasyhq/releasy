use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use serde_json::json;
use uuid::Uuid;

use super::test_support::{
    admin_headers, api_headers, setup_state, setup_state_with_settings,
    test_settings_with_artifacts, with_release_update_barrier,
};
use super::*;
use crate::auth::{api_key_prefix, hash_api_key};
use crate::models::{
    ApiKeyRecord, ArtifactRecord, Customer, EntitlementRecord, ReleaseRecord, default_scopes,
    scopes_to_json,
};
use crate::release::ReleaseStatus;

#[test]
fn normalize_key_type_accepts_known_values() {
    let value = Some("  Human ".to_string());
    assert_eq!(normalize_key_type(value).expect("key type"), "human");
}

#[test]
fn normalize_key_type_rejects_empty() {
    let value = Some("   ".to_string());
    assert!(normalize_key_type(value).is_err());
}

#[test]
fn normalize_key_type_rejects_unknown() {
    let value = Some("other".to_string());
    assert!(normalize_key_type(value).is_err());
}

#[test]
fn validate_expires_at_rejects_past() {
    let now = now_ts_or_internal().expect("now");
    let expires_at = Some(now - 1);
    assert!(validate_expires_at(expires_at).is_err());
}

#[test]
fn validate_expires_at_rejects_too_large() {
    let expires_at = Some(10_000_000_001);
    assert!(validate_expires_at(expires_at).is_err());
}

#[test]
fn validate_expires_at_accepts_future() {
    let now = now_ts_or_internal().expect("now");
    let expires_at = Some(now + 60);
    assert_eq!(
        validate_expires_at(expires_at).expect("expires"),
        expires_at
    );
}

#[test]
fn validate_scopes_accepts_allowed() {
    let scopes = default_scopes();
    assert!(validate_scopes(&scopes).is_ok());
}

#[test]
fn validate_scopes_rejects_unknown() {
    let scopes = vec!["keys:read".to_string(), "other:scope".to_string()];
    assert!(validate_scopes(&scopes).is_err());
}

#[tokio::test]
async fn apply_release_action_with_rbac_conflicts_on_stale_publish() {
    let state = setup_state().await;
    let release = ReleaseRecord {
        id: "release-1".to_string(),
        product: "releasy".to_string(),
        version: "1.0.0".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: 1,
        published_at: None,
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let headers = admin_headers();
    let state_a = state.clone();
    let state_b = state.clone();
    let headers_a = headers.clone();
    let headers_b = headers.clone();

    let (result_a, result_b) = with_release_update_barrier(barrier, || async move {
        tokio::join!(
            apply_release_action_with_rbac(
                &state_a,
                &headers_a,
                &release.id,
                ReleaseAction::Publish
            ),
            apply_release_action_with_rbac(
                &state_b,
                &headers_b,
                &release.id,
                ReleaseAction::Publish
            ),
        )
    })
    .await;

    let results = [result_a, result_b];
    let successes = results.iter().filter(|result| result.is_ok()).count();
    let conflicts = results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .filter(|err| err.status() == StatusCode::CONFLICT)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(conflicts, 1);
}

#[tokio::test]
async fn apply_release_action_with_rbac_conflicts_on_stale_unpublish() {
    let state = setup_state().await;
    let release = ReleaseRecord {
        id: "release-2".to_string(),
        product: "releasy".to_string(),
        version: "1.0.1".to_string(),
        status: ReleaseStatus::Published.as_str().to_string(),
        created_at: 1,
        published_at: Some(1),
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let headers = admin_headers();
    let state_a = state.clone();
    let state_b = state.clone();
    let headers_a = headers.clone();
    let headers_b = headers.clone();

    let (result_a, result_b) = with_release_update_barrier(barrier, || async move {
        tokio::join!(
            apply_release_action_with_rbac(
                &state_a,
                &headers_a,
                &release.id,
                ReleaseAction::Unpublish
            ),
            apply_release_action_with_rbac(
                &state_b,
                &headers_b,
                &release.id,
                ReleaseAction::Unpublish
            ),
        )
    })
    .await;

    let results = [result_a, result_b];
    let successes = results.iter().filter(|result| result.is_ok()).count();
    let conflicts = results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .filter(|err| err.status() == StatusCode::CONFLICT)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(conflicts, 1);
}

#[tokio::test]
async fn create_release_rejects_duplicate_version() {
    let state = setup_state().await;
    let headers = admin_headers();

    let first = ReleaseCreateRequest {
        product: "releasy".to_string(),
        version: "1.0.0".to_string(),
    };
    let _ = create_release(State(state.clone()), headers.clone(), Json(first))
        .await
        .expect("first release");

    let second = ReleaseCreateRequest {
        product: "releasy".to_string(),
        version: "1.0.0".to_string(),
    };
    let err = create_release(State(state), headers, Json(second))
        .await
        .expect_err("duplicate release");
    assert_eq!(err.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn list_customers_filters_by_name_and_plan() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "customer-acme".to_string(),
        name: "Acme Corp".to_string(),
        plan: Some("Pro".to_string()),
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    let other = Customer {
        id: "customer-beta".to_string(),
        name: "Beta LLC".to_string(),
        plan: Some("Starter".to_string()),
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };

    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");
    state
        .db
        .insert_customer(&other)
        .await
        .expect("insert customer");

    let query = AdminCustomerListQuery {
        customer_id: None,
        name: Some("acme".to_string()),
        plan: Some("pro".to_string()),
        limit: Some(10),
        offset: Some(0),
    };

    let Json(response) = list_customers(State(state), admin_headers(), Query(query))
        .await
        .expect("list customers");

    assert_eq!(response.customers.len(), 1);
    assert_eq!(response.customers[0].id, "customer-acme");
}

#[tokio::test]
async fn get_customer_returns_customer() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "customer-detail".to_string(),
        name: "Customer Detail".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let Json(response) = get_customer(State(state), admin_headers(), Path(customer.id.clone()))
        .await
        .expect("get customer");

    assert_eq!(response.id, customer.id);
    assert_eq!(response.name, customer.name);
}

#[tokio::test]
async fn get_customer_returns_not_found() {
    let state = setup_state().await;

    let err = get_customer(
        State(state),
        admin_headers(),
        Path("missing-customer".to_string()),
    )
    .await
    .expect_err("missing customer");

    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_release_is_idempotent() {
    let state = setup_state().await;
    let mut headers = admin_headers();
    headers.insert(IDEMPOTENCY_KEY_HEADER, "release-idem-1".parse().unwrap());

    let request = ReleaseCreateRequest {
        product: "releasy".to_string(),
        version: "9.9.9".to_string(),
    };

    let Json(first) = create_release(State(state.clone()), headers.clone(), Json(request.clone()))
        .await
        .expect("first release");

    let Json(second) = create_release(State(state), headers, Json(request))
        .await
        .expect("second release");

    assert_eq!(first.id, second.id);
}

#[tokio::test]
async fn create_release_rejects_idempotency_conflict() {
    let state = setup_state().await;
    let mut headers = admin_headers();
    headers.insert(IDEMPOTENCY_KEY_HEADER, "release-idem-2".parse().unwrap());

    let first = ReleaseCreateRequest {
        product: "releasy".to_string(),
        version: "10.0.0".to_string(),
    };
    let _ = create_release(State(state.clone()), headers.clone(), Json(first))
        .await
        .expect("first release");

    let second = ReleaseCreateRequest {
        product: "releasy".to_string(),
        version: "10.0.1".to_string(),
    };
    let err = create_release(State(state), headers, Json(second))
        .await
        .expect_err("idempotency conflict");
    assert_eq!(err.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn presign_release_artifact_upload_returns_url() {
    let state = setup_state_with_settings(test_settings_with_artifacts()).await;
    let release = ReleaseRecord {
        id: "release-artifact-1".to_string(),
        product: "releasy".to_string(),
        version: "1.0.0".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: 1,
        published_at: None,
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let request = ArtifactPresignRequest {
        filename: "linux.tar.gz".to_string(),
        platform: "linux-x86_64".to_string(),
    };
    let response = presign_release_artifact_upload(
        State(state),
        admin_headers(),
        Path(release.id.clone()),
        Json(request),
    )
    .await
    .expect("presign");
    assert!(response.upload_url.contains(&response.object_key));
    assert!(response.expires_at > 0);
}

#[tokio::test]
async fn presign_release_artifact_upload_requires_config() {
    let state = setup_state().await;
    let release = ReleaseRecord {
        id: "release-artifact-2".to_string(),
        product: "releasy".to_string(),
        version: "1.0.1".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: 1,
        published_at: None,
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let request = ArtifactPresignRequest {
        filename: "linux.tar.gz".to_string(),
        platform: "linux-x86_64".to_string(),
    };
    let err = presign_release_artifact_upload(
        State(state),
        admin_headers(),
        Path(release.id.clone()),
        Json(request),
    )
    .await
    .expect_err("presign");
    assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn register_release_artifact_persists_record() {
    let state = setup_state_with_settings(test_settings_with_artifacts()).await;
    let release = ReleaseRecord {
        id: "release-artifact-3".to_string(),
        product: "releasy".to_string(),
        version: "1.0.2".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: 1,
        published_at: None,
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let artifact_id = Uuid::new_v4().to_string();
    let object_key =
        build_artifact_object_key(&release, "linux-x86_64", &artifact_id, "bundle.tar.gz")
            .expect("object key");
    let request = ArtifactRegisterRequest {
        artifact_id: artifact_id.clone(),
        object_key: object_key.clone(),
        checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string(),
        size: 1024,
        platform: "linux-x86_64".to_string(),
    };

    let response = register_release_artifact(
        State(state.clone()),
        admin_headers(),
        Path(release.id.clone()),
        Json(request),
    )
    .await
    .expect("register");
    assert_eq!(response.id, artifact_id);

    let pool = crate::test_support::sqlite_pool(&state.db);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifacts WHERE release_id = ? AND object_key = ?",
    )
    .bind(&release.id)
    .bind(&object_key)
    .fetch_one(pool)
    .await
    .expect("count");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn register_release_artifact_rejects_invalid_checksum() {
    let state = setup_state_with_settings(test_settings_with_artifacts()).await;
    let release = ReleaseRecord {
        id: "release-artifact-4".to_string(),
        product: "releasy".to_string(),
        version: "1.0.3".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: 1,
        published_at: None,
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let artifact_id = Uuid::new_v4().to_string();
    let object_key =
        build_artifact_object_key(&release, "linux-x86_64", &artifact_id, "bundle.tar.gz")
            .expect("object key");
    let request = ArtifactRegisterRequest {
        artifact_id,
        object_key,
        checksum: "not-a-checksum".to_string(),
        size: 1024,
        platform: "linux-x86_64".to_string(),
    };

    let err = register_release_artifact(
        State(state),
        admin_headers(),
        Path(release.id.clone()),
        Json(request),
    )
    .await
    .expect_err("register");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_release_artifact_rejects_mismatched_object_key() {
    let state = setup_state_with_settings(test_settings_with_artifacts()).await;
    let release = ReleaseRecord {
        id: "release-artifact-5".to_string(),
        product: "releasy".to_string(),
        version: "1.0.4".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: 1,
        published_at: None,
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let artifact_id = Uuid::new_v4().to_string();
    let request = ArtifactRegisterRequest {
        artifact_id,
        object_key: "releases/other/1.2.3/linux-x86_64/file.tar.gz".to_string(),
        checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string(),
        size: 2048,
        platform: "linux-x86_64".to_string(),
    };

    let err = register_release_artifact(
        State(state),
        admin_headers(),
        Path(release.id.clone()),
        Json(request),
    )
    .await
    .expect_err("register");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn download_token_flow_redirects() {
    let state = setup_state_with_settings(test_settings_with_artifacts()).await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "customer-download".to_string(),
        name: "Download Customer".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let raw_key = "releasy_test_key";
    let scopes = vec!["downloads:token".to_string()];
    let api_key = ApiKeyRecord {
        id: "api-key-download".to_string(),
        customer_id: customer.id.clone(),
        key_hash: hash_api_key(raw_key, None).expect("hash api key"),
        key_prefix: api_key_prefix(raw_key),
        name: None,
        key_type: DEFAULT_API_KEY_TYPE.to_string(),
        scopes: scopes_to_json(&scopes).expect("scopes json"),
        expires_at: None,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    state
        .db
        .insert_api_key(&api_key)
        .await
        .expect("insert api key");

    let release = ReleaseRecord {
        id: "release-download".to_string(),
        product: "releasy".to_string(),
        version: "1.2.3".to_string(),
        status: ReleaseStatus::Published.as_str().to_string(),
        created_at: now,
        published_at: Some(now),
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let artifact_id = Uuid::new_v4().to_string();
    let object_key =
        build_artifact_object_key(&release, "linux-x86_64", &artifact_id, "bundle.tar.gz")
            .expect("object key");
    let artifact = ArtifactRecord {
        id: artifact_id.clone(),
        release_id: release.id.clone(),
        object_key,
        checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string(),
        size: 1024,
        platform: "linux-x86_64".to_string(),
        created_at: now,
    };
    state
        .db
        .insert_artifact(&artifact)
        .await
        .expect("insert artifact");

    let entitlement = EntitlementRecord {
        id: "entitlement-download".to_string(),
        customer_id: customer.id.clone(),
        product: release.product.clone(),
        starts_at: now - 10,
        ends_at: None,
        metadata: None,
    };
    state
        .db
        .insert_entitlement(&entitlement)
        .await
        .expect("insert entitlement");

    let mut headers = HeaderMap::new();
    headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
    headers.insert(header::HOST, "downloads.test".parse().unwrap());

    let request = DownloadTokenRequest {
        artifact_id,
        purpose: Some("ci".to_string()),
        expires_in_seconds: None,
    };
    let Json(response) = create_download_token(State(state.clone()), headers, Json(request))
        .await
        .expect("create token");
    assert!(response.download_url.contains("/v1/downloads/"));

    let token = response
        .download_url
        .split("/v1/downloads/")
        .nth(1)
        .expect("token");
    assert!(!token.is_empty());

    let response = resolve_download_token(State(state), Path(token.to_string()))
        .await
        .expect("resolve token")
        .into_response();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(!location.is_empty());
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert_eq!(cache_control, "no-store");
}

#[tokio::test]
async fn create_download_token_rejects_missing_entitlement() {
    let state = setup_state_with_settings(test_settings_with_artifacts()).await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "customer-no-entitlement".to_string(),
        name: "Missing Entitlement".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let raw_key = "releasy_test_key_2";
    let scopes = vec!["downloads:token".to_string()];
    let api_key = ApiKeyRecord {
        id: "api-key-no-entitlement".to_string(),
        customer_id: customer.id.clone(),
        key_hash: hash_api_key(raw_key, None).expect("hash api key"),
        key_prefix: api_key_prefix(raw_key),
        name: None,
        key_type: DEFAULT_API_KEY_TYPE.to_string(),
        scopes: scopes_to_json(&scopes).expect("scopes json"),
        expires_at: None,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    state
        .db
        .insert_api_key(&api_key)
        .await
        .expect("insert api key");

    let release = ReleaseRecord {
        id: "release-no-entitlement".to_string(),
        product: "releasy".to_string(),
        version: "2.0.0".to_string(),
        status: ReleaseStatus::Published.as_str().to_string(),
        created_at: now,
        published_at: Some(now),
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let artifact = ArtifactRecord {
        id: Uuid::new_v4().to_string(),
        release_id: release.id.clone(),
        object_key: "releases/releasy/2.0.0/linux-x86_64/bundle.tar.gz".to_string(),
        checksum: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string(),
        size: 512,
        platform: "linux-x86_64".to_string(),
        created_at: now,
    };
    state
        .db
        .insert_artifact(&artifact)
        .await
        .expect("insert artifact");

    let mut headers = HeaderMap::new();
    headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
    headers.insert(header::HOST, "downloads.test".parse().unwrap());

    let request = DownloadTokenRequest {
        artifact_id: artifact.id.clone(),
        purpose: None,
        expires_in_seconds: None,
    };
    let err = create_download_token(State(state), headers, Json(request))
        .await
        .expect_err("missing entitlement");
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_entitlement_persists_and_lists() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "entitlement-customer".to_string(),
        name: "Entitlement Customer".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let payload = EntitlementCreateRequest {
        product: "releasy".to_string(),
        starts_at: now - 10,
        ends_at: Some(now + 1000),
        metadata: Some(json!({"tier": "pro"})),
    };

    let Json(response) = create_entitlement(
        State(state.clone()),
        admin_headers(),
        Path(customer.id.clone()),
        Json(payload),
    )
    .await
    .expect("create entitlement");
    assert_eq!(response.customer_id, customer.id);
    assert_eq!(response.product, "releasy");
    assert_eq!(response.metadata, Some(json!({"tier": "pro"})));

    let query = EntitlementListQuery {
        product: None,
        limit: None,
        offset: None,
    };
    let Json(list_response) = list_entitlements(
        State(state),
        admin_headers(),
        Path(customer.id),
        Query(query),
    )
    .await
    .expect("list entitlements");
    assert_eq!(list_response.entitlements.len(), 1);
    assert_eq!(list_response.entitlements[0].product, "releasy");
}

#[tokio::test]
async fn create_entitlement_rejects_invalid_dates() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "entitlement-invalid".to_string(),
        name: "Entitlement Invalid".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let payload = EntitlementCreateRequest {
        product: "releasy".to_string(),
        starts_at: now + 10,
        ends_at: Some(now),
        metadata: None,
    };

    let err = create_entitlement(
        State(state),
        admin_headers(),
        Path(customer.id),
        Json(payload),
    )
    .await
    .expect_err("invalid dates");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_audit_events_requires_admin() {
    let state = setup_state().await;

    let query = AuditEventListQuery {
        customer_id: None,
        actor: None,
        event: None,
        created_from: None,
        created_to: None,
        limit: None,
        offset: None,
    };

    let err = list_audit_events(State(state), HeaderMap::new(), Query(query))
        .await
        .expect_err("missing admin auth");
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_audit_events_filters_by_customer() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let payload = json!({
        "outcome": "accept",
        "reason": "ok",
        "api_key_id": null
    })
    .to_string();
    state
        .db
        .insert_audit_event(
            Some("audit-customer-1"),
            "api_key",
            "api_key.auth",
            Some(&payload),
            now - 10,
        )
        .await
        .expect("insert audit event");
    state
        .db
        .insert_audit_event(
            Some("audit-customer-2"),
            "api_key",
            "api_key.auth",
            None,
            now,
        )
        .await
        .expect("insert audit event");

    let query = AuditEventListQuery {
        customer_id: Some("audit-customer-1".to_string()),
        actor: None,
        event: None,
        created_from: None,
        created_to: None,
        limit: None,
        offset: None,
    };
    let Json(response) = list_audit_events(State(state), admin_headers(), Query(query))
        .await
        .expect("list audit events");
    assert_eq!(response.events.len(), 1);
    assert_eq!(
        response.events[0].customer_id,
        Some("audit-customer-1".to_string())
    );
    assert_eq!(response.events[0].event, "api_key.auth");
    assert_eq!(
        response.events[0].payload,
        Some(json!({"outcome": "accept", "reason": "ok", "api_key_id": null}))
    );
}

#[tokio::test]
async fn list_audit_events_filters_by_created_at() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    state
        .db
        .insert_audit_event(
            Some("audit-created-1"),
            "api_key",
            "api_key.auth",
            None,
            now - 120,
        )
        .await
        .expect("insert audit event");
    state
        .db
        .insert_audit_event(
            Some("audit-created-2"),
            "api_key",
            "api_key.auth",
            None,
            now - 10,
        )
        .await
        .expect("insert audit event");

    let query = AuditEventListQuery {
        customer_id: None,
        actor: None,
        event: None,
        created_from: Some(now - 30),
        created_to: Some(now),
        limit: None,
        offset: None,
    };
    let Json(response) = list_audit_events(State(state), admin_headers(), Query(query))
        .await
        .expect("list audit events");
    assert_eq!(response.events.len(), 1);
    assert_eq!(
        response.events[0].customer_id,
        Some("audit-created-2".to_string())
    );
}

#[tokio::test]
async fn list_audit_events_rejects_invalid_range() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let query = AuditEventListQuery {
        customer_id: None,
        actor: None,
        event: None,
        created_from: Some(now),
        created_to: Some(now - 10),
        limit: None,
        offset: None,
    };
    let err = list_audit_events(State(state), admin_headers(), Query(query))
        .await
        .expect_err("invalid range");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_releases_filters_by_entitlement() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "release-entitlement".to_string(),
        name: "Release Entitled".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let raw_key = "releasy_release_key";
    let scopes = vec!["releases:read".to_string()];
    let api_key = ApiKeyRecord {
        id: "api-release-key".to_string(),
        customer_id: customer.id.clone(),
        key_hash: hash_api_key(raw_key, None).expect("hash api key"),
        key_prefix: api_key_prefix(raw_key),
        name: None,
        key_type: DEFAULT_API_KEY_TYPE.to_string(),
        scopes: scopes_to_json(&scopes).expect("scopes json"),
        expires_at: None,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    state
        .db
        .insert_api_key(&api_key)
        .await
        .expect("insert api key");

    let entitlement = EntitlementRecord {
        id: "entitlement-release".to_string(),
        customer_id: customer.id.clone(),
        product: "releasy".to_string(),
        starts_at: now - 10,
        ends_at: None,
        metadata: None,
    };
    state
        .db
        .insert_entitlement(&entitlement)
        .await
        .expect("insert entitlement");

    let published = ReleaseRecord {
        id: "release-published".to_string(),
        product: "releasy".to_string(),
        version: "1.0.0".to_string(),
        status: ReleaseStatus::Published.as_str().to_string(),
        created_at: now,
        published_at: Some(now),
    };
    state
        .db
        .insert_release(&published)
        .await
        .expect("insert release");

    let draft = ReleaseRecord {
        id: "release-draft".to_string(),
        product: "releasy".to_string(),
        version: "1.1.0".to_string(),
        status: ReleaseStatus::Draft.as_str().to_string(),
        created_at: now,
        published_at: None,
    };
    state
        .db
        .insert_release(&draft)
        .await
        .expect("insert release");

    let other = ReleaseRecord {
        id: "release-other".to_string(),
        product: "other".to_string(),
        version: "2.0.0".to_string(),
        status: ReleaseStatus::Published.as_str().to_string(),
        created_at: now,
        published_at: Some(now),
    };
    state
        .db
        .insert_release(&other)
        .await
        .expect("insert release");

    let query = ReleaseListQuery {
        product: None,
        status: None,
        version: None,
        include_artifacts: None,
        limit: None,
        offset: None,
    };
    let Json(response) = list_releases(State(state), api_headers(raw_key), Query(query))
        .await
        .expect("list releases");
    assert_eq!(response.releases.len(), 1);
    assert_eq!(response.releases[0].product, "releasy");
    assert_eq!(response.releases[0].status, "published");
}

#[tokio::test]
async fn list_releases_returns_empty_without_entitlement() {
    let state = setup_state().await;
    let now = now_ts_or_internal().expect("now");

    let customer = Customer {
        id: "release-no-entitlement".to_string(),
        name: "Release No Entitlement".to_string(),
        plan: None,
        allowed_prefixes: None,
        created_at: now,
        suspended_at: None,
    };
    state
        .db
        .insert_customer(&customer)
        .await
        .expect("insert customer");

    let raw_key = "releasy_release_key_2";
    let scopes = vec!["releases:read".to_string()];
    let api_key = ApiKeyRecord {
        id: "api-release-key-2".to_string(),
        customer_id: customer.id.clone(),
        key_hash: hash_api_key(raw_key, None).expect("hash api key"),
        key_prefix: api_key_prefix(raw_key),
        name: None,
        key_type: DEFAULT_API_KEY_TYPE.to_string(),
        scopes: scopes_to_json(&scopes).expect("scopes json"),
        expires_at: None,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    state
        .db
        .insert_api_key(&api_key)
        .await
        .expect("insert api key");

    let release = ReleaseRecord {
        id: "release-visible".to_string(),
        product: "releasy".to_string(),
        version: "3.0.0".to_string(),
        status: ReleaseStatus::Published.as_str().to_string(),
        created_at: now,
        published_at: Some(now),
    };
    state
        .db
        .insert_release(&release)
        .await
        .expect("insert release");

    let query = ReleaseListQuery {
        product: None,
        status: None,
        version: None,
        include_artifacts: None,
        limit: None,
        offset: None,
    };
    let Json(response) = list_releases(State(state), api_headers(raw_key), Query(query))
        .await
        .expect("list releases");
    assert!(response.releases.is_empty());
}
