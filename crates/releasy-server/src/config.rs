use std::env;

#[derive(Clone)]
pub struct Settings {
    pub bind_addr: String,
    pub log_level: String,
    pub database_url: String,
    pub database_max_connections: u32,
    pub api_key_pepper: Option<String>,
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
        let api_key_pepper = env::var("RELEASY_API_KEY_PEPPER").ok();

        Ok(Self {
            bind_addr,
            log_level,
            database_url,
            database_max_connections,
            api_key_pepper,
        })
    }
}

fn required_env(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("missing required env var: {key}"))
}

fn parse_u32(key: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{key} must be an integer"))
}
