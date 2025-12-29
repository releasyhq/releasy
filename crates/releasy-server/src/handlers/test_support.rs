use std::future::Future;
use std::sync::Arc;

use axum::http::HeaderMap;
use tokio::sync::Barrier;

use super::RELEASE_UPDATE_BARRIER;
use crate::app::AppState;
use crate::config::{ArtifactSettings, Settings};
use crate::test_support::{ADMIN_TEST_KEY, setup_db, test_settings_with_admin_key};

pub(crate) fn test_settings() -> Settings {
    test_settings_with_admin_key()
}

pub(crate) async fn setup_state_with_settings(settings: Settings) -> AppState {
    let db = setup_db(&settings).await;
    AppState {
        db,
        settings,
        jwks_cache: None,
    }
}

pub(crate) async fn setup_state() -> AppState {
    setup_state_with_settings(test_settings()).await
}

pub(crate) fn admin_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-releasy-admin-key", ADMIN_TEST_KEY.parse().unwrap());
    headers
}

pub(crate) fn api_headers(raw_key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-releasy-api-key", raw_key.parse().unwrap());
    headers
}

pub(crate) fn test_artifact_settings() -> ArtifactSettings {
    ArtifactSettings {
        bucket: "releasy-test".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("https://s3.example.invalid".to_string()),
        access_key: "access".to_string(),
        secret_key: "secret".to_string(),
        path_style: true,
        presign_expires_seconds: 300,
    }
}

pub(crate) fn test_settings_with_artifacts() -> Settings {
    let mut settings = test_settings();
    settings.artifact_settings = Some(test_artifact_settings());
    settings
}

pub(crate) async fn with_release_update_barrier<F, Fut, T>(barrier: Arc<Barrier>, f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    loop {
        let should_wait = {
            let mut guard = RELEASE_UPDATE_BARRIER
                .lock()
                .expect("release update barrier");
            if guard.is_none() {
                *guard = Some(Arc::clone(&barrier));
                false
            } else {
                true
            }
        };
        if !should_wait {
            break;
        }
        tokio::task::yield_now().await;
    }

    let result = f().await;

    let mut guard = RELEASE_UPDATE_BARRIER
        .lock()
        .expect("release update barrier");
    *guard = None;

    result
}
