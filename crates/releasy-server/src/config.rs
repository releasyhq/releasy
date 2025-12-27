use std::env;

#[derive(Clone)]
pub struct Settings {
    pub bind_addr: String,
    pub log_level: String,
    pub database_url: String,
    pub database_max_connections: u32,
    pub admin_api_key: Option<String>,
    pub api_key_pepper: Option<String>,
    pub operator_jwks_url: Option<String>,
    pub operator_issuer: Option<String>,
    pub operator_audience: Option<String>,
    pub operator_resource: Option<String>,
    pub operator_jwks_ttl_seconds: u32,
    pub operator_jwt_leeway_seconds: u32,
}

impl Settings {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr =
            env::var("RELEASY_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let log_level = env::var("RELEASY_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let database_url = required_env("RELEASY_DATABASE_URL")?;
        let database_max_connections = env::var("RELEASY_DATABASE_MAX_CONNECTIONS")
            .ok()
            .map(|value| parse_u32("RELEASY_DATABASE_MAX_CONNECTIONS", &value))
            .transpose()?
            .unwrap_or(5);
        let admin_api_key = optional_env("RELEASY_ADMIN_API_KEY");
        let api_key_pepper = optional_env("RELEASY_API_KEY_PEPPER");
        let operator_jwks_url = optional_env("RELEASY_OPERATOR_JWKS_URL");
        let operator_issuer = optional_env("RELEASY_OPERATOR_ISSUER");
        let operator_audience = optional_env("RELEASY_OPERATOR_AUDIENCE");
        let operator_resource = optional_env("RELEASY_OPERATOR_RESOURCE");
        let operator_jwks_ttl_seconds = env::var("RELEASY_OPERATOR_JWKS_TTL_SECONDS")
            .ok()
            .map(|value| parse_u32("RELEASY_OPERATOR_JWKS_TTL_SECONDS", &value))
            .transpose()?
            .unwrap_or(300);
        let operator_jwt_leeway_seconds = env::var("RELEASY_OPERATOR_JWT_LEEWAY_SECONDS")
            .ok()
            .map(|value| parse_u32("RELEASY_OPERATOR_JWT_LEEWAY_SECONDS", &value))
            .transpose()?
            .unwrap_or(0);

        Ok(Self {
            bind_addr,
            log_level,
            database_url,
            database_max_connections,
            admin_api_key,
            api_key_pepper,
            operator_jwks_url,
            operator_issuer,
            operator_audience,
            operator_resource,
            operator_jwks_ttl_seconds,
            operator_jwt_leeway_seconds,
        })
    }
}

fn optional_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_env(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("missing required env var: {key}"))
}

fn parse_u32(key: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{key} must be an integer"))
}
