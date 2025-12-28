use axum::http::StatusCode;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{error, warn};

use crate::{config::Settings, errors::ApiError};

#[derive(Clone)]
pub struct JwksCache {
    jwks_url: String,
    ttl: Duration,
    client: Client,
    state: Arc<RwLock<Option<JwksState>>>,
}

#[derive(Clone)]
struct JwksState {
    fetched_at: Instant,
    jwks: JwkSet,
}

const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(8);
const JWKS_RETRY_BACKOFF: Duration = Duration::from_millis(200);
const JWKS_MAX_RETRIES: usize = 1;
const JWKS_TIMEOUT_MESSAGE: &str = "operator jwks request timed out";

struct JwksFetchFailure {
    api_error: ApiError,
    retryable: bool,
}

impl JwksFetchFailure {
    fn timeout() -> Self {
        Self {
            api_error: ApiError::new(StatusCode::SERVICE_UNAVAILABLE, JWKS_TIMEOUT_MESSAGE),
            retryable: false,
        }
    }

    fn unavailable(retryable: bool) -> Self {
        Self {
            api_error: ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "operator jwks unavailable"),
            retryable,
        }
    }
}

impl JwksCache {
    pub fn new(settings: &Settings) -> Option<Self> {
        let jwks_url = settings.operator_jwks_url.clone()?;
        let ttl = Duration::from_secs(settings.operator_jwks_ttl_seconds as u64);
        let client = Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .expect("failed to build jwks client");
        Some(Self {
            jwks_url,
            ttl,
            client,
            state: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn get_jwks(&self) -> Result<JwkSet, ApiError> {
        let now = Instant::now();
        if let Some(cached) = self.state.read().await.clone()
            && now.duration_since(cached.fetched_at) <= self.ttl
        {
            return Ok(cached.jwks);
        }

        let jwks = self.fetch_jwks().await?;
        let mut guard = self.state.write().await;
        *guard = Some(JwksState {
            fetched_at: now,
            jwks: jwks.clone(),
        });
        Ok(jwks)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, ApiError> {
        let mut attempt = 0;
        let mut backoff = JWKS_RETRY_BACKOFF;
        loop {
            match self.fetch_jwks_once().await {
                Ok(jwks) => return Ok(jwks),
                Err(failure) => {
                    if !failure.retryable || attempt >= JWKS_MAX_RETRIES {
                        return Err(failure.api_error);
                    }
                    warn!(
                        "jwks fetch failed, retrying in {:?} (attempt {}/{})",
                        backoff,
                        attempt + 1,
                        JWKS_MAX_RETRIES + 1
                    );
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                    attempt += 1;
                }
            }
        }
    }

    async fn fetch_jwks_once(&self) -> Result<JwkSet, JwksFetchFailure> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    warn!("jwks request timed out: {err}");
                    return JwksFetchFailure::timeout();
                }
                error!("failed to fetch jwks: {err}");
                JwksFetchFailure::unavailable(err.is_connect())
            })?;
        let response = response.error_for_status().map_err(|err| {
            let retryable = err
                .status()
                .map(|status| status.is_server_error())
                .unwrap_or(false);
            error!("jwks returned error status: {err}");
            JwksFetchFailure::unavailable(retryable)
        })?;
        response.json::<JwkSet>().await.map_err(|err| {
            if err.is_timeout() {
                warn!("jwks response timed out: {err}");
                return JwksFetchFailure::timeout();
            }
            error!("failed to parse jwks: {err}");
            JwksFetchFailure::unavailable(false)
        })
    }
}

#[cfg(test)]
impl JwksCache {
    pub(crate) fn new_for_tests(jwks_url: String, ttl: Duration, client: Client) -> Self {
        Self {
            jwks_url,
            ttl,
            client,
            state: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn jwks_cache_fetches_jwks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let cache = JwksCache::new_for_tests(
            format!("http://{addr}/jwks"),
            Duration::from_secs(30),
            Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .expect("client"),
        );

        let jwks = cache.fetch_jwks().await.expect("jwks");
        assert!(jwks.keys.is_empty());
        server.await.expect("server");
    }

    #[tokio::test]
    async fn jwks_cache_timeout_returns_service_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(socket);
        });

        let cache = JwksCache::new_for_tests(
            format!("http://{addr}/jwks"),
            Duration::from_secs(30),
            Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .expect("client"),
        );

        let result = tokio::time::timeout(Duration::from_secs(2), cache.fetch_jwks()).await;
        let err = result
            .expect("fetch timed out")
            .expect_err("expected timeout");
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.message(), JWKS_TIMEOUT_MESSAGE);
        server.await.expect("server");
    }
}
