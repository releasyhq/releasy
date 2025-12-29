use sqlx::{PgPool, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};

use crate::config::Settings;

trait DbDialect {
    const IS_SQLITE: bool;
}

impl DbDialect for sqlx::Postgres {
    const IS_SQLITE: bool = false;
}

impl DbDialect for sqlx::Sqlite {
    const IS_SQLITE: bool = true;
}

macro_rules! with_db {
    ($db:expr, |$pool:ident| $body:block) => {{
        match $db {
            $crate::db::Database::Postgres($pool) => $body,
            $crate::db::Database::Sqlite($pool) => $body,
        }
    }};
    ($db:expr, |$pool:ident, $db_ty:ident| $body:block) => {{
        match $db {
            $crate::db::Database::Postgres($pool) => {
                type $db_ty = sqlx::Postgres;
                $body
            }
            $crate::db::Database::Sqlite($pool) => {
                type $db_ty = sqlx::Sqlite;
                $body
            }
        }
    }};
}

mod api_keys;
mod artifacts;
mod audit;
mod customers;
mod download_tokens;
mod entitlements;
mod idempotency;
mod releases;
mod sql;

#[derive(Clone)]
pub enum Database {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AuditEventFilter<'a> {
    pub customer_id: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub event: Option<&'a str>,
    pub created_from: Option<i64>,
    pub created_to: Option<i64>,
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
        with_db!(self, |pool| {
            migrator
                .run(pool)
                .await
                .map_err(|err| format!("database migration failed: {err}"))
        })
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
