use sqlx::{PgPool, Row, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use uuid::Uuid;

use crate::{config::Settings, models::ApiKeyAuthRecord, utils::now_ts};

#[derive(Clone)]
pub enum Database {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

impl Database {
    pub async fn connect(settings: &Settings) -> Result<Self, String> {
        let url = settings.database_url.as_str();
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pool = PgPoolOptions::new()
                .max_connections(settings.database_max_connections)
                .connect(url)
                .await
                .map_err(|err| format!("database connect failed: {err}"))?;
            Ok(Self::Postgres(pool))
        } else if url.starts_with("sqlite:") {
            let pool = SqlitePoolOptions::new()
                .max_connections(settings.database_max_connections)
                .connect(url)
                .await
                .map_err(|err| format!("database connect failed: {err}"))?;
            Ok(Self::Sqlite(pool))
        } else {
            Err("RELEASY_DATABASE_URL must start with postgres:// or sqlite:".to_string())
        }
    }

    pub async fn migrate(&self) -> Result<(), String> {
        let migrator = sqlx::migrate!("../../migrations");
        match self {
            Database::Postgres(pool) => migrator
                .run(pool)
                .await
                .map_err(|err| format!("database migration failed: {err}")),
            Database::Sqlite(pool) => migrator
                .run(pool)
                .await
                .map_err(|err| format!("database migration failed: {err}")),
        }
    }

    pub async fn get_api_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<ApiKeyAuthRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, customer_id, key_type, scopes, expires_at, revoked_at \
                     FROM api_keys WHERE key_hash = $1",
                )
                .bind(key_hash)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| ApiKeyAuthRecord {
                    id: row.get("id"),
                    customer_id: row.get("customer_id"),
                    key_type: row.get("key_type"),
                    scopes: row.get("scopes"),
                    expires_at: row.get("expires_at"),
                    revoked_at: row.get("revoked_at"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, customer_id, key_type, scopes, expires_at, revoked_at \
                     FROM api_keys WHERE key_hash = ?",
                )
                .bind(key_hash)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| ApiKeyAuthRecord {
                    id: row.get("id"),
                    customer_id: row.get("customer_id"),
                    key_type: row.get("key_type"),
                    scopes: row.get("scopes"),
                    expires_at: row.get("expires_at"),
                    revoked_at: row.get("revoked_at"),
                }))
            }
        }
    }

    pub async fn insert_audit_event(
        &self,
        customer_id: Option<&str>,
        actor: &str,
        event: &str,
        payload: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let id = Uuid::new_v4().to_string();
        let created_at = now_ts();
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO audit_events (id, customer_id, actor, event, payload, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&id)
                .bind(customer_id)
                .bind(actor)
                .bind(event)
                .bind(payload)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO audit_events (id, customer_id, actor, event, payload, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&id)
                .bind(customer_id)
                .bind(actor)
                .bind(event)
                .bind(payload)
                .bind(created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }
}
