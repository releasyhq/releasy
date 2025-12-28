use sqlx::{PgPool, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};

use crate::config::Settings;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::models::{ApiKeyRecord, Customer};
    use sqlx::Execute;
    use sqlx::Row;
    use uuid::Uuid;

    fn test_settings() -> Settings {
        Settings {
            bind_addr: "127.0.0.1:8080".to_string(),
            log_level: "info".to_string(),
            database_url: "sqlite::memory:".to_string(),
            database_max_connections: 1,
            download_token_ttl_seconds: 600,
            admin_api_key: None,
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

    async fn setup_db() -> Database {
        let settings = test_settings();
        let db = Database::connect(&settings).await.expect("db connect");
        db.migrate().await.expect("db migrate");
        db
    }

    fn api_key_record(customer_id: &str) -> ApiKeyRecord {
        let key_id = Uuid::new_v4().to_string();
        ApiKeyRecord {
            id: key_id.clone(),
            customer_id: customer_id.to_string(),
            key_hash: format!("hash-{key_id}"),
            key_prefix: "releasy_test".to_string(),
            name: None,
            key_type: "human".to_string(),
            scopes: "[]".to_string(),
            expires_at: None,
            created_at: 1,
            revoked_at: None,
            last_used_at: None,
        }
    }

    fn normalize_sql(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    struct Case {
        product: Option<&'static str>,
        status: Option<&'static str>,
        version: Option<&'static str>,
        expected_postgres: &'static str,
        expected_sqlite: &'static str,
    }

    fn cases() -> Vec<Case> {
        vec![
            Case {
                product: Some("releasy"),
                status: Some("published"),
                version: Some("1.2.3"),
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 AND status = $2 AND version = $3 ORDER BY created_at DESC \
LIMIT $4 OFFSET $5",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? AND status = ? AND version = ? ORDER BY created_at DESC \
LIMIT ? OFFSET ?",
            },
            Case {
                product: Some("releasy"),
                status: Some("published"),
                version: None,
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? AND status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
            Case {
                product: Some("releasy"),
                status: None,
                version: Some("1.2.3"),
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 AND version = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? AND version = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
            Case {
                product: Some("releasy"),
                status: None,
                version: None,
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
            Case {
                product: None,
                status: Some("published"),
                version: Some("1.2.3"),
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = $1 AND version = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = ? AND version = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
            Case {
                product: None,
                status: Some("published"),
                version: None,
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
            Case {
                product: None,
                status: None,
                version: Some("1.2.3"),
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE version = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE version = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
            Case {
                product: None,
                status: None,
                version: None,
                expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases ORDER BY created_at DESC LIMIT ? OFFSET ?",
            },
        ]
    }

    #[test]
    fn list_releases_query_postgres_all_combinations() {
        for case in cases() {
            let mut builder = Database::build_list_releases_query::<sqlx::Postgres>(
                case.product,
                case.status,
                case.version,
                10,
                20,
            );
            let sql = builder.build().sql().to_string();
            assert_eq!(normalize_sql(&sql), normalize_sql(case.expected_postgres));
        }
    }

    #[test]
    fn list_releases_query_sqlite_all_combinations() {
        for case in cases() {
            let mut builder = Database::build_list_releases_query::<sqlx::Sqlite>(
                case.product,
                case.status,
                case.version,
                10,
                20,
            );
            let sql = builder.build().sql().to_string();
            assert_eq!(normalize_sql(&sql), normalize_sql(case.expected_sqlite));
        }
    }

    #[tokio::test]
    async fn release_index_used_for_product_status_filter() {
        let db = setup_db().await;
        let pool = match &db {
            Database::Sqlite(pool) => pool,
            Database::Postgres(_) => panic!("sqlite expected"),
        };

        sqlx::query(
            "INSERT INTO releases (id, product, version, status, created_at, published_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("release-1")
        .bind("releasy")
        .bind("1.0.0")
        .bind("published")
        .bind(1_i64)
        .bind(None::<i64>)
        .execute(pool)
        .await
        .expect("insert release");

        let rows = sqlx::query(
            "EXPLAIN QUERY PLAN SELECT id FROM releases \
             WHERE product = ? AND status = ? ORDER BY created_at DESC",
        )
        .bind("releasy")
        .bind("published")
        .fetch_all(pool)
        .await
        .expect("plan");

        let details: Vec<String> = rows.into_iter().map(|row| row.get("detail")).collect();
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("releases_product_status_created_at_idx")),
            "plan details: {details:?}"
        );
    }

    #[tokio::test]
    async fn release_index_hint_rejects_unknown_index() {
        let db = setup_db().await;
        let pool = match &db {
            Database::Sqlite(pool) => pool,
            Database::Postgres(_) => panic!("sqlite expected"),
        };

        let result = sqlx::query(
            "EXPLAIN QUERY PLAN SELECT id FROM releases \
             INDEXED BY releases_missing_idx WHERE product = ?",
        )
        .bind("releasy")
        .fetch_all(pool)
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn api_keys_fk_allows_existing_customer() {
        let db = setup_db().await;
        let customer = Customer {
            id: "customer".to_string(),
            name: "Customer".to_string(),
            plan: None,
            allowed_prefixes: None,
            created_at: 1,
            suspended_at: None,
        };
        db.insert_customer(&customer).await.expect("customer");

        let record = api_key_record(&customer.id);
        db.insert_api_key(&record).await.expect("api key");
    }

    #[tokio::test]
    async fn api_keys_fk_rejects_missing_customer() {
        let db = setup_db().await;

        let record = api_key_record("missing-customer");
        let result = db.insert_api_key(&record).await;

        assert!(result.is_err());
    }
}
