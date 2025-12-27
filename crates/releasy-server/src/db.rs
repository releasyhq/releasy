use sqlx::{PgPool, Row, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use uuid::Uuid;

use crate::{
    config::Settings,
    models::{
        ApiKeyAuthRecord, ApiKeyRecord, ArtifactRecord, Customer, DownloadTokenRecord,
        EntitlementRecord, IdempotencyRecord, ReleaseRecord,
    },
};

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

    pub async fn get_api_keys_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<ApiKeyAuthRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT id, customer_id, key_hash, key_type, scopes, expires_at, revoked_at \
                     FROM api_keys WHERE key_prefix = $1",
                )
                .bind(key_prefix)
                .fetch_all(pool)
                .await?;
                Ok(rows
                    .into_iter()
                    .map(|row| ApiKeyAuthRecord {
                        id: row.get("id"),
                        customer_id: row.get("customer_id"),
                        key_hash: row.get("key_hash"),
                        key_type: row.get("key_type"),
                        scopes: row.get("scopes"),
                        expires_at: row.get("expires_at"),
                        revoked_at: row.get("revoked_at"),
                    })
                    .collect())
            }
            Database::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT id, customer_id, key_hash, key_type, scopes, expires_at, revoked_at \
                     FROM api_keys WHERE key_prefix = ?",
                )
                .bind(key_prefix)
                .fetch_all(pool)
                .await?;
                Ok(rows
                    .into_iter()
                    .map(|row| ApiKeyAuthRecord {
                        id: row.get("id"),
                        customer_id: row.get("customer_id"),
                        key_hash: row.get("key_hash"),
                        key_type: row.get("key_type"),
                        scopes: row.get("scopes"),
                        expires_at: row.get("expires_at"),
                        revoked_at: row.get("revoked_at"),
                    })
                    .collect())
            }
        }
    }

    pub async fn customer_exists(&self, customer_id: &str) -> Result<bool, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query("SELECT 1 FROM customers WHERE id = $1 LIMIT 1")
                    .bind(customer_id)
                    .fetch_optional(pool)
                    .await?;
                Ok(row.is_some())
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query("SELECT 1 FROM customers WHERE id = ? LIMIT 1")
                    .bind(customer_id)
                    .fetch_optional(pool)
                    .await?;
                Ok(row.is_some())
            }
        }
    }

    pub async fn insert_customer(&self, customer: &Customer) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO customers (id, name, plan, allowed_prefixes, created_at, suspended_at) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&customer.id)
                .bind(&customer.name)
                .bind(&customer.plan)
                .bind(&customer.allowed_prefixes)
                .bind(customer.created_at)
                .bind(customer.suspended_at)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO customers (id, name, plan, allowed_prefixes, created_at, suspended_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&customer.id)
                .bind(&customer.name)
                .bind(&customer.plan)
                .bind(&customer.allowed_prefixes)
                .bind(customer.created_at)
                .bind(customer.suspended_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn get_customer(&self, customer_id: &str) -> Result<Option<Customer>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, name, plan, allowed_prefixes, created_at, suspended_at \
                     FROM customers WHERE id = $1",
                )
                .bind(customer_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| Customer {
                    id: row.get("id"),
                    name: row.get("name"),
                    plan: row.get("plan"),
                    allowed_prefixes: row.get("allowed_prefixes"),
                    created_at: row.get("created_at"),
                    suspended_at: row.get("suspended_at"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, name, plan, allowed_prefixes, created_at, suspended_at \
                     FROM customers WHERE id = ?",
                )
                .bind(customer_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| Customer {
                    id: row.get("id"),
                    name: row.get("name"),
                    plan: row.get("plan"),
                    allowed_prefixes: row.get("allowed_prefixes"),
                    created_at: row.get("created_at"),
                    suspended_at: row.get("suspended_at"),
                }))
            }
        }
    }

    pub async fn list_entitlements_by_customer(
        &self,
        customer_id: &str,
        product: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<EntitlementRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let rows = Self::build_list_entitlements_query::<sqlx::Postgres>(
                    customer_id,
                    product,
                    limit,
                    offset,
                )
                .build()
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(EntitlementRecord {
                            id: row.try_get("id")?,
                            customer_id: row.try_get("customer_id")?,
                            product: row.try_get("product")?,
                            starts_at: row.try_get("starts_at")?,
                            ends_at: row.try_get("ends_at")?,
                            metadata: row.try_get("metadata")?,
                        })
                    })
                    .collect()
            }
            Database::Sqlite(pool) => {
                let rows = Self::build_list_entitlements_query::<sqlx::Sqlite>(
                    customer_id,
                    product,
                    limit,
                    offset,
                )
                .build()
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(EntitlementRecord {
                            id: row.try_get("id")?,
                            customer_id: row.try_get("customer_id")?,
                            product: row.try_get("product")?,
                            starts_at: row.try_get("starts_at")?,
                            ends_at: row.try_get("ends_at")?,
                            metadata: row.try_get("metadata")?,
                        })
                    })
                    .collect()
            }
        }
    }

    fn build_list_entitlements_query<'args, DB>(
        customer_id: &'args str,
        product: Option<&'args str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> sqlx::QueryBuilder<'args, DB>
    where
        DB: sqlx::Database,
        &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
        i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    {
        let mut builder = sqlx::QueryBuilder::<DB>::new(
            "SELECT id, customer_id, product, starts_at, ends_at, metadata \
             FROM entitlements WHERE customer_id = ",
        );
        builder.push_bind(customer_id);

        if let Some(product) = product {
            builder.push(" AND product = ").push_bind(product);
        }

        builder.push(" ORDER BY starts_at ASC");

        if let Some(limit) = limit {
            builder
                .push(" LIMIT ")
                .push_bind(limit)
                .push(" OFFSET ")
                .push_bind(offset.unwrap_or(0));
        }

        builder
    }

    pub async fn get_entitlement(
        &self,
        customer_id: &str,
        entitlement_id: &str,
    ) -> Result<Option<EntitlementRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, customer_id, product, starts_at, ends_at, metadata \
                     FROM entitlements WHERE customer_id = $1 AND id = $2",
                )
                .bind(customer_id)
                .bind(entitlement_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| EntitlementRecord {
                    id: row.get("id"),
                    customer_id: row.get("customer_id"),
                    product: row.get("product"),
                    starts_at: row.get("starts_at"),
                    ends_at: row.get("ends_at"),
                    metadata: row.get("metadata"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, customer_id, product, starts_at, ends_at, metadata \
                     FROM entitlements WHERE customer_id = ? AND id = ?",
                )
                .bind(customer_id)
                .bind(entitlement_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| EntitlementRecord {
                    id: row.get("id"),
                    customer_id: row.get("customer_id"),
                    product: row.get("product"),
                    starts_at: row.get("starts_at"),
                    ends_at: row.get("ends_at"),
                    metadata: row.get("metadata"),
                }))
            }
        }
    }

    #[allow(dead_code)]
    pub async fn insert_entitlement(
        &self,
        entitlement: &EntitlementRecord,
    ) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO entitlements (id, customer_id, product, starts_at, ends_at, metadata) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&entitlement.id)
                .bind(&entitlement.customer_id)
                .bind(&entitlement.product)
                .bind(entitlement.starts_at)
                .bind(entitlement.ends_at)
                .bind(&entitlement.metadata)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO entitlements (id, customer_id, product, starts_at, ends_at, metadata) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&entitlement.id)
                .bind(&entitlement.customer_id)
                .bind(&entitlement.product)
                .bind(entitlement.starts_at)
                .bind(entitlement.ends_at)
                .bind(&entitlement.metadata)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn update_entitlement(
        &self,
        entitlement: &EntitlementRecord,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query(
                    "UPDATE entitlements SET product = $1, starts_at = $2, ends_at = $3, metadata = $4 \
                     WHERE customer_id = $5 AND id = $6",
                )
                .bind(&entitlement.product)
                .bind(entitlement.starts_at)
                .bind(entitlement.ends_at)
                .bind(&entitlement.metadata)
                .bind(&entitlement.customer_id)
                .bind(&entitlement.id)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query(
                    "UPDATE entitlements SET product = ?, starts_at = ?, ends_at = ?, metadata = ? \
                     WHERE customer_id = ? AND id = ?",
                )
                .bind(&entitlement.product)
                .bind(entitlement.starts_at)
                .bind(entitlement.ends_at)
                .bind(&entitlement.metadata)
                .bind(&entitlement.customer_id)
                .bind(&entitlement.id)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn delete_entitlement(
        &self,
        customer_id: &str,
        entitlement_id: &str,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result =
                    sqlx::query("DELETE FROM entitlements WHERE customer_id = $1 AND id = $2")
                        .bind(customer_id)
                        .bind(entitlement_id)
                        .execute(pool)
                        .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result =
                    sqlx::query("DELETE FROM entitlements WHERE customer_id = ? AND id = ?")
                        .bind(customer_id)
                        .bind(entitlement_id)
                        .execute(pool)
                        .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn insert_api_key(&self, api_key: &ApiKeyRecord) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO api_keys (id, customer_id, key_hash, key_prefix, name, key_type, scopes, expires_at, created_at, revoked_at, last_used_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                )
                .bind(&api_key.id)
                .bind(&api_key.customer_id)
                .bind(&api_key.key_hash)
                .bind(&api_key.key_prefix)
                .bind(&api_key.name)
                .bind(&api_key.key_type)
                .bind(&api_key.scopes)
                .bind(api_key.expires_at)
                .bind(api_key.created_at)
                .bind(api_key.revoked_at)
                .bind(api_key.last_used_at)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO api_keys (id, customer_id, key_hash, key_prefix, name, key_type, scopes, expires_at, created_at, revoked_at, last_used_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&api_key.id)
                .bind(&api_key.customer_id)
                .bind(&api_key.key_hash)
                .bind(&api_key.key_prefix)
                .bind(&api_key.name)
                .bind(&api_key.key_type)
                .bind(&api_key.scopes)
                .bind(api_key.expires_at)
                .bind(api_key.created_at)
                .bind(api_key.revoked_at)
                .bind(api_key.last_used_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn revoke_api_key(&self, key_id: &str, timestamp: i64) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query(
                    "UPDATE api_keys SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
                )
                .bind(timestamp)
                .bind(key_id)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query(
                    "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                )
                .bind(timestamp)
                .bind(key_id)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn update_api_key_hash(
        &self,
        key_id: &str,
        key_hash: &str,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query("UPDATE api_keys SET key_hash = $1 WHERE id = $2")
                    .bind(key_hash)
                    .bind(key_id)
                    .execute(pool)
                    .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query("UPDATE api_keys SET key_hash = ? WHERE id = ?")
                    .bind(key_hash)
                    .bind(key_id)
                    .execute(pool)
                    .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn update_api_key_last_used(
        &self,
        key_id: &str,
        timestamp: i64,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query("UPDATE api_keys SET last_used_at = $1 WHERE id = $2")
                    .bind(timestamp)
                    .bind(key_id)
                    .execute(pool)
                    .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
                    .bind(timestamp)
                    .bind(key_id)
                    .execute(pool)
                    .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn insert_release(&self, release: &ReleaseRecord) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO releases (id, product, version, status, created_at, published_at) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&release.id)
                .bind(&release.product)
                .bind(&release.version)
                .bind(&release.status)
                .bind(release.created_at)
                .bind(release.published_at)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO releases (id, product, version, status, created_at, published_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&release.id)
                .bind(&release.product)
                .bind(&release.version)
                .bind(&release.status)
                .bind(release.created_at)
                .bind(release.published_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn insert_artifact(&self, artifact: &ArtifactRecord) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO artifacts \
                     (id, release_id, object_key, checksum, size, platform, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(&artifact.id)
                .bind(&artifact.release_id)
                .bind(&artifact.object_key)
                .bind(&artifact.checksum)
                .bind(artifact.size)
                .bind(&artifact.platform)
                .bind(artifact.created_at)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO artifacts \
                     (id, release_id, object_key, checksum, size, platform, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&artifact.id)
                .bind(&artifact.release_id)
                .bind(&artifact.object_key)
                .bind(&artifact.checksum)
                .bind(artifact.size)
                .bind(&artifact.platform)
                .bind(artifact.created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn list_artifacts_by_release(
        &self,
        release_id: &str,
    ) -> Result<Vec<ArtifactRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT id, release_id, object_key, checksum, size, platform, created_at \
                     FROM artifacts WHERE release_id = $1 ORDER BY created_at ASC",
                )
                .bind(release_id)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(ArtifactRecord {
                            id: row.try_get("id")?,
                            release_id: row.try_get("release_id")?,
                            object_key: row.try_get("object_key")?,
                            checksum: row.try_get("checksum")?,
                            size: row.try_get("size")?,
                            platform: row.try_get("platform")?,
                            created_at: row.try_get("created_at")?,
                        })
                    })
                    .collect()
            }
            Database::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT id, release_id, object_key, checksum, size, platform, created_at \
                     FROM artifacts WHERE release_id = ? ORDER BY created_at ASC",
                )
                .bind(release_id)
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(ArtifactRecord {
                            id: row.try_get("id")?,
                            release_id: row.try_get("release_id")?,
                            object_key: row.try_get("object_key")?,
                            checksum: row.try_get("checksum")?,
                            size: row.try_get("size")?,
                            platform: row.try_get("platform")?,
                            created_at: row.try_get("created_at")?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn get_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, release_id, object_key, checksum, size, platform, created_at \
                     FROM artifacts WHERE id = $1",
                )
                .bind(artifact_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| ArtifactRecord {
                    id: row.get("id"),
                    release_id: row.get("release_id"),
                    object_key: row.get("object_key"),
                    checksum: row.get("checksum"),
                    size: row.get("size"),
                    platform: row.get("platform"),
                    created_at: row.get("created_at"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, release_id, object_key, checksum, size, platform, created_at \
                     FROM artifacts WHERE id = ?",
                )
                .bind(artifact_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| ArtifactRecord {
                    id: row.get("id"),
                    release_id: row.get("release_id"),
                    object_key: row.get("object_key"),
                    checksum: row.get("checksum"),
                    size: row.get("size"),
                    platform: row.get("platform"),
                    created_at: row.get("created_at"),
                }))
            }
        }
    }

    pub async fn get_release(
        &self,
        release_id: &str,
    ) -> Result<Option<ReleaseRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, product, version, status, created_at, published_at \
                     FROM releases WHERE id = $1",
                )
                .bind(release_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| ReleaseRecord {
                    id: row.get("id"),
                    product: row.get("product"),
                    version: row.get("version"),
                    status: row.get("status"),
                    created_at: row.get("created_at"),
                    published_at: row.get("published_at"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, product, version, status, created_at, published_at \
                     FROM releases WHERE id = ?",
                )
                .bind(release_id)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| ReleaseRecord {
                    id: row.get("id"),
                    product: row.get("product"),
                    version: row.get("version"),
                    status: row.get("status"),
                    created_at: row.get("created_at"),
                    published_at: row.get("published_at"),
                }))
            }
        }
    }

    pub async fn insert_download_token(
        &self,
        token: &DownloadTokenRecord,
    ) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO download_tokens \
                     (token_hash, artifact_id, customer_id, purpose, expires_at, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&token.token_hash)
                .bind(&token.artifact_id)
                .bind(&token.customer_id)
                .bind(&token.purpose)
                .bind(token.expires_at)
                .bind(token.created_at)
                .execute(pool)
                .await?;
            }
            Database::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO download_tokens \
                     (token_hash, artifact_id, customer_id, purpose, expires_at, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&token.token_hash)
                .bind(&token.artifact_id)
                .bind(&token.customer_id)
                .bind(&token.purpose)
                .bind(token.expires_at)
                .bind(token.created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn get_download_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<DownloadTokenRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT token_hash, artifact_id, customer_id, purpose, expires_at, created_at \
                     FROM download_tokens WHERE token_hash = $1",
                )
                .bind(token_hash)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| DownloadTokenRecord {
                    token_hash: row.get("token_hash"),
                    artifact_id: row.get("artifact_id"),
                    customer_id: row.get("customer_id"),
                    purpose: row.get("purpose"),
                    expires_at: row.get("expires_at"),
                    created_at: row.get("created_at"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT token_hash, artifact_id, customer_id, purpose, expires_at, created_at \
                     FROM download_tokens WHERE token_hash = ?",
                )
                .bind(token_hash)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| DownloadTokenRecord {
                    token_hash: row.get("token_hash"),
                    artifact_id: row.get("artifact_id"),
                    customer_id: row.get("customer_id"),
                    purpose: row.get("purpose"),
                    expires_at: row.get("expires_at"),
                    created_at: row.get("created_at"),
                }))
            }
        }
    }

    pub async fn get_idempotency_key(
        &self,
        key: &str,
        endpoint: &str,
    ) -> Result<Option<IdempotencyRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT idempotency_key, endpoint, request_hash, response_status, response_body, \
                     state, created_at, expires_at FROM idempotency_keys \
                     WHERE idempotency_key = $1 AND endpoint = $2",
                )
                .bind(key)
                .bind(endpoint)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| IdempotencyRecord {
                    key: row.get("idempotency_key"),
                    endpoint: row.get("endpoint"),
                    request_hash: row.get("request_hash"),
                    response_status: row.get("response_status"),
                    response_body: row.get("response_body"),
                    state: row.get("state"),
                    created_at: row.get("created_at"),
                    expires_at: row.get("expires_at"),
                }))
            }
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT idempotency_key, endpoint, request_hash, response_status, response_body, \
                     state, created_at, expires_at FROM idempotency_keys \
                     WHERE idempotency_key = ? AND endpoint = ?",
                )
                .bind(key)
                .bind(endpoint)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|row| IdempotencyRecord {
                    key: row.get("idempotency_key"),
                    endpoint: row.get("endpoint"),
                    request_hash: row.get("request_hash"),
                    response_status: row.get("response_status"),
                    response_body: row.get("response_body"),
                    state: row.get("state"),
                    created_at: row.get("created_at"),
                    expires_at: row.get("expires_at"),
                }))
            }
        }
    }

    pub async fn insert_idempotency_key(
        &self,
        record: &IdempotencyRecord,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query(
                    "INSERT INTO idempotency_keys \
                     (idempotency_key, endpoint, request_hash, response_status, response_body, \
                      state, created_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (idempotency_key, endpoint) DO NOTHING",
                )
                .bind(&record.key)
                .bind(&record.endpoint)
                .bind(&record.request_hash)
                .bind(record.response_status)
                .bind(&record.response_body)
                .bind(&record.state)
                .bind(record.created_at)
                .bind(record.expires_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO idempotency_keys \
                     (idempotency_key, endpoint, request_hash, response_status, response_body, \
                      state, created_at, expires_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&record.key)
                .bind(&record.endpoint)
                .bind(&record.request_hash)
                .bind(record.response_status)
                .bind(&record.response_body)
                .bind(&record.state)
                .bind(record.created_at)
                .bind(record.expires_at)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn update_idempotency_key(
        &self,
        record: &IdempotencyRecord,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query(
                    "UPDATE idempotency_keys SET response_status = $1, response_body = $2, \
                     state = $3, expires_at = $4 WHERE idempotency_key = $5 AND endpoint = $6",
                )
                .bind(record.response_status)
                .bind(&record.response_body)
                .bind(&record.state)
                .bind(record.expires_at)
                .bind(&record.key)
                .bind(&record.endpoint)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query(
                    "UPDATE idempotency_keys SET response_status = ?, response_body = ?, \
                     state = ?, expires_at = ? WHERE idempotency_key = ? AND endpoint = ?",
                )
                .bind(record.response_status)
                .bind(&record.response_body)
                .bind(&record.state)
                .bind(record.expires_at)
                .bind(&record.key)
                .bind(&record.endpoint)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn delete_idempotency_key(
        &self,
        key: &str,
        endpoint: &str,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let result = sqlx::query(
                    "DELETE FROM idempotency_keys WHERE idempotency_key = $1 AND endpoint = $2",
                )
                .bind(key)
                .bind(endpoint)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let result = sqlx::query(
                    "DELETE FROM idempotency_keys WHERE idempotency_key = ? AND endpoint = ?",
                )
                .bind(key)
                .bind(endpoint)
                .execute(pool)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn list_releases(
        &self,
        product: Option<&str>,
        status: Option<&str>,
        version: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ReleaseRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let rows = Self::build_list_releases_query::<sqlx::Postgres>(
                    product, status, version, limit, offset,
                )
                .build()
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(ReleaseRecord {
                            id: row.try_get("id")?,
                            product: row.try_get("product")?,
                            version: row.try_get("version")?,
                            status: row.try_get("status")?,
                            created_at: row.try_get("created_at")?,
                            published_at: row.try_get("published_at")?,
                        })
                    })
                    .collect()
            }
            Database::Sqlite(pool) => {
                let rows = Self::build_list_releases_query::<sqlx::Sqlite>(
                    product, status, version, limit, offset,
                )
                .build()
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(ReleaseRecord {
                            id: row.try_get("id")?,
                            product: row.try_get("product")?,
                            version: row.try_get("version")?,
                            status: row.try_get("status")?,
                            created_at: row.try_get("created_at")?,
                            published_at: row.try_get("published_at")?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn list_published_releases_for_products(
        &self,
        products: &[String],
        version: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ReleaseRecord>, sqlx::Error> {
        if products.is_empty() {
            return Ok(Vec::new());
        }

        match self {
            Database::Postgres(pool) => {
                let rows =
                    Self::build_list_published_releases_for_products_query::<sqlx::Postgres>(
                        products, version, limit, offset,
                    )
                    .build()
                    .fetch_all(pool)
                    .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(ReleaseRecord {
                            id: row.try_get("id")?,
                            product: row.try_get("product")?,
                            version: row.try_get("version")?,
                            status: row.try_get("status")?,
                            created_at: row.try_get("created_at")?,
                            published_at: row.try_get("published_at")?,
                        })
                    })
                    .collect()
            }
            Database::Sqlite(pool) => {
                let rows = Self::build_list_published_releases_for_products_query::<sqlx::Sqlite>(
                    products, version, limit, offset,
                )
                .build()
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|row| {
                        Ok(ReleaseRecord {
                            id: row.try_get("id")?,
                            product: row.try_get("product")?,
                            version: row.try_get("version")?,
                            status: row.try_get("status")?,
                            created_at: row.try_get("created_at")?,
                            published_at: row.try_get("published_at")?,
                        })
                    })
                    .collect()
            }
        }
    }

    fn build_list_releases_query<'args, DB>(
        product: Option<&'args str>,
        status: Option<&'args str>,
        version: Option<&'args str>,
        limit: i64,
        offset: i64,
    ) -> sqlx::QueryBuilder<'args, DB>
    where
        DB: sqlx::Database,
        &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
        i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    {
        let mut builder = sqlx::QueryBuilder::<DB>::new(
            "SELECT id, product, version, status, created_at, published_at FROM releases",
        );
        let mut has_where = false;

        if let Some(product) = product {
            if !has_where {
                builder.push(" WHERE ");
                has_where = true;
            } else {
                builder.push(" AND ");
            }
            builder.push("product = ").push_bind(product);
        }

        if let Some(status) = status {
            if !has_where {
                builder.push(" WHERE ");
                has_where = true;
            } else {
                builder.push(" AND ");
            }
            builder.push("status = ").push_bind(status);
        }

        if let Some(version) = version {
            if !has_where {
                builder.push(" WHERE ");
            } else {
                builder.push(" AND ");
            }
            builder.push("version = ").push_bind(version);
        }

        builder
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);

        builder
    }

    fn build_list_published_releases_for_products_query<'args, DB>(
        products: &'args [String],
        version: Option<&'args str>,
        limit: i64,
        offset: i64,
    ) -> sqlx::QueryBuilder<'args, DB>
    where
        DB: sqlx::Database,
        &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
        i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    {
        let mut builder = sqlx::QueryBuilder::<DB>::new(
            "SELECT id, product, version, status, created_at, published_at FROM releases \
             WHERE status = ",
        );
        builder.push_bind("published");
        builder.push(" AND product IN (");
        let mut separated = builder.separated(", ");
        for product in products {
            separated.push_bind(product.as_str());
        }
        builder.push(")");

        if let Some(version) = version {
            builder.push(" AND version = ").push_bind(version);
        }

        builder
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);

        builder
    }

    pub async fn update_release_status(
        &self,
        release_id: &str,
        status: &str,
        published_at: Option<i64>,
        expected_status: Option<&str>,
    ) -> Result<u64, sqlx::Error> {
        let rows = match self {
            Database::Postgres(pool) => match expected_status {
                Some(expected) => sqlx::query(
                    "UPDATE releases SET status = $1, published_at = $2 \
                     WHERE id = $3 AND status = $4",
                )
                .bind(status)
                .bind(published_at)
                .bind(release_id)
                .bind(expected)
                .execute(pool)
                .await?
                .rows_affected(),
                None => {
                    sqlx::query("UPDATE releases SET status = $1, published_at = $2 WHERE id = $3")
                        .bind(status)
                        .bind(published_at)
                        .bind(release_id)
                        .execute(pool)
                        .await?
                        .rows_affected()
                }
            },
            Database::Sqlite(pool) => match expected_status {
                Some(expected) => sqlx::query(
                    "UPDATE releases SET status = ?, published_at = ? \
                     WHERE id = ? AND status = ?",
                )
                .bind(status)
                .bind(published_at)
                .bind(release_id)
                .bind(expected)
                .execute(pool)
                .await?
                .rows_affected(),
                None => {
                    sqlx::query("UPDATE releases SET status = ?, published_at = ? WHERE id = ?")
                        .bind(status)
                        .bind(published_at)
                        .bind(release_id)
                        .execute(pool)
                        .await?
                        .rows_affected()
                }
            },
        };
        Ok(rows)
    }

    pub async fn delete_release(&self, release_id: &str) -> Result<u64, sqlx::Error> {
        let rows = match self {
            Database::Postgres(pool) => sqlx::query("DELETE FROM releases WHERE id = $1")
                .bind(release_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Sqlite(pool) => sqlx::query("DELETE FROM releases WHERE id = ?")
                .bind(release_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(rows)
    }

    pub async fn insert_audit_event(
        &self,
        customer_id: Option<&str>,
        actor: &str,
        event: &str,
        payload: Option<&str>,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let id = Uuid::new_v4().to_string();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use sqlx::Execute;
    use sqlx::Row;

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
            assert_eq!(sql, case.expected_postgres);
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
            assert_eq!(sql, case.expected_sqlite);
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
