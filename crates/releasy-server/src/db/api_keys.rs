use sqlx::QueryBuilder;

use crate::models::{ApiKeyAuthRecord, ApiKeyRecord};

use super::{Database, sql};

impl Database {
    pub async fn get_api_keys_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<ApiKeyAuthRecord>, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_get_api_keys_by_prefix_query::<Db>(key_prefix);
            let rows = builder.build().fetch_all(pool).await?;
            rows.into_iter().map(map_api_key_auth).collect()
        })
    }

    pub async fn insert_api_key(&self, api_key: &ApiKeyRecord) -> Result<(), sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_insert_api_key_query::<Db>(api_key);
            builder.build().execute(pool).await?;
            Ok(())
        })
    }

    pub async fn revoke_api_key(&self, key_id: &str, timestamp: i64) -> Result<u64, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_revoke_api_key_query::<Db>(key_id, timestamp);
            let result = builder.build().execute(pool).await?;
            Ok(result.rows_affected())
        })
    }

    pub async fn update_api_key_hash(
        &self,
        key_id: &str,
        key_hash: &str,
    ) -> Result<u64, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_update_api_key_hash_query::<Db>(key_id, key_hash);
            let result = builder.build().execute(pool).await?;
            Ok(result.rows_affected())
        })
    }

    pub async fn update_api_key_last_used(
        &self,
        key_id: &str,
        timestamp: i64,
    ) -> Result<u64, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_update_api_key_last_used_query::<Db>(key_id, timestamp);
            let result = builder.build().execute(pool).await?;
            Ok(result.rows_affected())
        })
    }
}

fn build_get_api_keys_by_prefix_query<'args, DB>(key_prefix: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::api_keys::GET_BY_PREFIX);
    builder.push(" ").push_bind(key_prefix);
    builder
}

fn build_insert_api_key_query<'args, DB>(api_key: &'args ApiKeyRecord) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::api_keys::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(api_key.id.as_str());
    separated.push_bind(api_key.customer_id.as_str());
    separated.push_bind(api_key.key_hash.as_str());
    separated.push_bind(api_key.key_prefix.as_str());
    separated.push_bind(&api_key.name);
    separated.push_bind(api_key.key_type.as_str());
    separated.push_bind(api_key.scopes.as_str());
    separated.push_bind(api_key.expires_at);
    separated.push_bind(api_key.created_at);
    separated.push_bind(api_key.revoked_at);
    separated.push_bind(api_key.last_used_at);
    builder.push(")");
    builder
}

fn build_revoke_api_key_query<'args, DB>(
    key_id: &'args str,
    timestamp: i64,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::api_keys::REVOKE);
    builder.push(" ").push_bind(timestamp);
    builder.push(" WHERE id = ").push_bind(key_id);
    builder.push(" AND revoked_at IS NULL");
    builder
}

fn build_update_api_key_hash_query<'args, DB>(
    key_id: &'args str,
    key_hash: &'args str,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::api_keys::UPDATE_HASH);
    builder.push(" ").push_bind(key_hash);
    builder.push(" WHERE id = ").push_bind(key_id);
    builder
}

fn build_update_api_key_last_used_query<'args, DB>(
    key_id: &'args str,
    timestamp: i64,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::api_keys::UPDATE_LAST_USED);
    builder.push(" ").push_bind(timestamp);
    builder.push(" WHERE id = ").push_bind(key_id);
    builder
}

fn map_api_key_auth<R>(row: R) -> Result<ApiKeyAuthRecord, sqlx::Error>
where
    R: sqlx::Row,
    for<'r> &'r str: sqlx::ColumnIndex<R>,
    for<'r> String:
        sqlx::Decode<'r, <R as sqlx::Row>::Database> + sqlx::Type<<R as sqlx::Row>::Database>,
    for<'r> Option<String>:
        sqlx::Decode<'r, <R as sqlx::Row>::Database> + sqlx::Type<<R as sqlx::Row>::Database>,
    for<'r> i64:
        sqlx::Decode<'r, <R as sqlx::Row>::Database> + sqlx::Type<<R as sqlx::Row>::Database>,
    for<'r> Option<i64>:
        sqlx::Decode<'r, <R as sqlx::Row>::Database> + sqlx::Type<<R as sqlx::Row>::Database>,
    for<'r> Option<i32>:
        sqlx::Decode<'r, <R as sqlx::Row>::Database> + sqlx::Type<<R as sqlx::Row>::Database>,
{
    Ok(ApiKeyAuthRecord {
        id: row.try_get("id")?,
        customer_id: row.try_get("customer_id")?,
        key_hash: row.try_get("key_hash")?,
        key_type: row.try_get("key_type")?,
        scopes: row.try_get("scopes")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}
