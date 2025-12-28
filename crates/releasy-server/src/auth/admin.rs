use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::HashSet;
use tracing::{error, info};

use crate::{config::Settings, errors::ApiError};

use super::jwks::JwksCache;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    PlatformAdmin,
    PlatformSupport,
    ReleasePublisher,
}

pub fn admin_authorize(headers: &HeaderMap, settings: &Settings) -> Result<(), ApiError> {
    let expected = settings.admin_api_key.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api key not configured",
        )
    })?;
    let candidate = admin_key_from_headers(headers).ok_or_else(ApiError::unauthorized)?;
    if candidate == expected.as_str() {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

pub async fn admin_authorize_with_role(
    headers: &HeaderMap,
    settings: &Settings,
    jwks_cache: &Option<JwksCache>,
) -> Result<AdminRole, ApiError> {
    if admin_key_from_headers(headers).is_some() {
        admin_authorize(headers, settings)?;
        info!("admin authorization via admin key");
        return Ok(AdminRole::PlatformAdmin);
    }

    if let (Some(token), Some(jwks_cache)) = (bearer_token(headers), jwks_cache.as_ref())
        && looks_like_jwt(&token)
    {
        let role = authorize_operator_jwt(&token, settings, jwks_cache).await?;
        info!("admin authorization via operator jwt");
        return Ok(role);
    }

    admin_authorize(headers, settings)?;
    Ok(AdminRole::PlatformAdmin)
}

pub fn require_admin(role: AdminRole) -> Result<(), ApiError> {
    if role == AdminRole::PlatformAdmin {
        Ok(())
    } else {
        Err(ApiError::forbidden("admin role required"))
    }
}

pub fn require_support_or_admin(role: AdminRole) -> Result<(), ApiError> {
    match role {
        AdminRole::PlatformAdmin | AdminRole::PlatformSupport => Ok(()),
        _ => Err(ApiError::forbidden("platform_support role required")),
    }
}

pub fn require_release_publisher(role: AdminRole) -> Result<(), ApiError> {
    match role {
        AdminRole::PlatformAdmin | AdminRole::ReleasePublisher => Ok(()),
        _ => Err(ApiError::forbidden("release_publisher role required")),
    }
}

async fn authorize_operator_jwt(
    token: &str,
    settings: &Settings,
    jwks_cache: &JwksCache,
) -> Result<AdminRole, ApiError> {
    let header = decode_header(token).map_err(|err| {
        error!("jwt header decode failed: {err}");
        ApiError::unauthorized()
    })?;
    let kid = header.kid.ok_or_else(ApiError::unauthorized)?;
    let jwks = jwks_cache.get_jwks().await?;
    let jwk = jwks.find(&kid).ok_or_else(ApiError::unauthorized)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|err| {
        error!("jwt jwk decode failed: {err}");
        ApiError::unauthorized()
    })?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = settings.operator_jwt_leeway_seconds as u64;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    let token_data = decode::<Value>(token, &key, &validation).map_err(|err| {
        error!("jwt decode failed: {err}");
        ApiError::unauthorized()
    })?;

    let claims = token_data.claims;
    if let Some(expected) = settings.operator_issuer.as_deref() {
        let issuer = claims
            .get("iss")
            .and_then(|value| value.as_str())
            .ok_or_else(ApiError::unauthorized)?;
        if issuer != expected {
            return Err(ApiError::unauthorized());
        }
    }

    if let Some(expected) = settings.operator_audience.as_deref()
        && !audience_matches(&claims, expected)
    {
        return Err(ApiError::unauthorized());
    }

    let roles = extract_roles(&claims, settings.operator_resource.as_deref());
    let role = admin_role_from_roles(&roles)
        .ok_or_else(|| ApiError::forbidden("missing operator role"))?;
    Ok(role)
}

fn admin_key_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(bearer) = bearer_token(headers)
        && !looks_like_jwt(&bearer)
    {
        return Some(bearer);
    }
    headers
        .get("x-releasy-admin-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn looks_like_jwt(token: &str) -> bool {
    token.matches('.').count() == 2
}

fn audience_matches(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|entry| entry.as_str() == Some(expected)),
        _ => false,
    }
}

fn extract_roles(claims: &Value, resource: Option<&str>) -> HashSet<String> {
    let mut roles = HashSet::new();
    collect_roles(&mut roles, claims.get("roles"));
    collect_roles(
        &mut roles,
        claims
            .get("realm_access")
            .and_then(|value| value.get("roles")),
    );
    if let Some(resource) = resource {
        collect_roles(
            &mut roles,
            claims
                .get("resource_access")
                .and_then(|value| value.get(resource))
                .and_then(|value| value.get("roles")),
        );
    }
    roles
}

fn collect_roles(target: &mut HashSet<String>, value: Option<&Value>) {
    match value {
        Some(Value::String(role)) => {
            target.insert(role.to_string());
        }
        Some(Value::Array(roles)) => {
            for entry in roles {
                if let Some(role) = entry.as_str() {
                    target.insert(role.to_string());
                }
            }
        }
        _ => {}
    }
}

fn admin_role_from_roles(roles: &HashSet<String>) -> Option<AdminRole> {
    if roles.contains("platform_admin") {
        Some(AdminRole::PlatformAdmin)
    } else if roles.contains("platform_support") {
        Some(AdminRole::PlatformSupport)
    } else if roles.contains("release_publisher") {
        Some(AdminRole::ReleasePublisher)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use reqwest::Client;
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn test_settings() -> Settings {
        Settings {
            bind_addr: "127.0.0.1:8080".to_string(),
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

    #[test]
    fn admin_authorize_accepts_header() {
        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());
        assert!(admin_authorize(&headers, &settings).is_ok());
    }

    #[test]
    fn admin_authorize_rejects_missing_key() {
        let settings = test_settings();
        let headers = HeaderMap::new();
        assert!(admin_authorize(&headers, &settings).is_err());
    }

    #[tokio::test]
    async fn admin_authorize_with_role_falls_back_without_jwks() {
        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer a.b.c".parse().unwrap());
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());

        let role = admin_authorize_with_role(&headers, &settings, &None)
            .await
            .expect("role");
        assert_eq!(role, AdminRole::PlatformAdmin);
    }

    #[tokio::test]
    async fn admin_authorize_with_role_rejects_invalid_jwt_without_admin_key() {
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

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"missing"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"operator"}"#);
        let token = format!("{header}.{payload}.signature");

        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());

        let err = admin_authorize_with_role(&headers, &settings, &Some(cache))
            .await
            .expect_err("role");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn admin_authorize_with_role_prefers_admin_key_over_jwt() {
        let cache = JwksCache::new_for_tests(
            "http://127.0.0.1:0/jwks".to_string(),
            Duration::from_secs(30),
            Client::builder()
                .timeout(Duration::from_millis(50))
                .build()
                .expect("client"),
        );

        let settings = test_settings();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer a.b.c".parse().unwrap());
        headers.insert("x-releasy-admin-key", "secret".parse().unwrap());

        let role = admin_authorize_with_role(&headers, &settings, &Some(cache))
            .await
            .expect("role");
        assert_eq!(role, AdminRole::PlatformAdmin);
    }

    #[test]
    fn extract_roles_collects_multiple_sources() {
        let claims = json!({
            "roles": ["release_publisher"],
            "realm_access": { "roles": ["platform_support"] },
            "resource_access": {
                "releasy": { "roles": ["platform_admin"] }
            }
        });
        let roles = extract_roles(&claims, Some("releasy"));
        assert!(roles.contains("release_publisher"));
        assert!(roles.contains("platform_support"));
        assert!(roles.contains("platform_admin"));
    }

    #[test]
    fn extract_roles_returns_empty_without_roles() {
        let claims = json!({ "sub": "operator" });
        let roles = extract_roles(&claims, Some("releasy"));
        assert!(roles.is_empty());
    }

    #[test]
    fn admin_role_from_roles_prefers_admin() {
        let roles = HashSet::from([
            "release_publisher".to_string(),
            "platform_admin".to_string(),
        ]);
        assert_eq!(
            admin_role_from_roles(&roles),
            Some(AdminRole::PlatformAdmin)
        );
    }

    #[test]
    fn admin_role_from_roles_rejects_unknown() {
        let roles = HashSet::from(["other".to_string()]);
        assert_eq!(admin_role_from_roles(&roles), None);
    }

    #[test]
    fn looks_like_jwt_detects_format() {
        assert!(looks_like_jwt("a.b.c"));
        assert!(!looks_like_jwt("not-a-jwt"));
    }
}
