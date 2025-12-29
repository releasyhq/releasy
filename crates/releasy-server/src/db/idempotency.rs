use sqlx::QueryBuilder;
use std::borrow::Cow;

use crate::models::IdempotencyRecord;

use super::{Database, sql};

impl Database {
    pub async fn get_idempotency_key(
        &self,
        key: &str,
        endpoint: &str,
    ) -> Result<Option<IdempotencyRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_get_idempotency_query::<sqlx::Postgres>(key, endpoint);
                let row = builder.build().fetch_optional(pool).await?;
                row.map(map_idempotency).transpose()
            }
            Database::Sqlite(pool) => {
                let mut builder = build_get_idempotency_query::<sqlx::Sqlite>(key, endpoint);
                let row = builder.build().fetch_optional(pool).await?;
                row.map(map_idempotency).transpose()
            }
        }
    }

    pub async fn insert_idempotency_key(
        &self,
        record: &IdempotencyRecord,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let base_sql = insert_idempotency_base_sql(false);
                let mut builder =
                    build_insert_idempotency_query::<sqlx::Postgres>(base_sql.as_ref(), record);
                builder.push(sql::idempotency::INSERT_CONFLICT_SUFFIX);
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let base_sql = insert_idempotency_base_sql(true);
                let mut builder =
                    build_insert_idempotency_query::<sqlx::Sqlite>(base_sql.as_ref(), record);
                builder.push(")");
                let result = builder.build().execute(pool).await?;
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
                let mut builder = build_update_idempotency_query::<sqlx::Postgres>(record);
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let mut builder = build_update_idempotency_query::<sqlx::Sqlite>(record);
                let result = builder.build().execute(pool).await?;
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
                let mut builder = build_delete_idempotency_query::<sqlx::Postgres>(key, endpoint);
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let mut builder = build_delete_idempotency_query::<sqlx::Sqlite>(key, endpoint);
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
        }
    }
}

fn build_get_idempotency_query<'args, DB>(
    key: &'args str,
    endpoint: &'args str,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::idempotency::GET);
    builder.push(" ").push_bind(key);
    builder.push(" AND endpoint = ").push_bind(endpoint);
    builder
}

fn build_insert_idempotency_query<'args, DB>(
    base_sql: &'args str,
    record: &'args IdempotencyRecord,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i32>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(base_sql);
    let mut separated = builder.separated(", ");
    separated.push_bind(record.key.as_str());
    separated.push_bind(record.endpoint.as_str());
    separated.push_bind(record.request_hash.as_str());
    separated.push_bind(record.response_status);
    separated.push_bind(&record.response_body);
    separated.push_bind(record.state.as_str());
    separated.push_bind(record.created_at);
    separated.push_bind(record.expires_at);
    builder
}

fn insert_idempotency_base_sql(ignore_conflicts: bool) -> Cow<'static, str> {
    if ignore_conflicts {
        Cow::Owned(sql::idempotency::INSERT_BASE.replacen(
            "INSERT INTO",
            "INSERT OR IGNORE INTO",
            1,
        ))
    } else {
        Cow::Borrowed(sql::idempotency::INSERT_BASE)
    }
}

fn build_update_idempotency_query<'args, DB>(
    record: &'args IdempotencyRecord,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i32>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::idempotency::UPDATE);
    builder.push(" ").push_bind(record.response_status);
    builder
        .push(", response_body = ")
        .push_bind(&record.response_body);
    builder.push(", state = ").push_bind(record.state.as_str());
    builder.push(", expires_at = ").push_bind(record.expires_at);
    builder
        .push(" WHERE idempotency_key = ")
        .push_bind(record.key.as_str());
    builder
        .push(" AND endpoint = ")
        .push_bind(record.endpoint.as_str());
    builder
}

fn build_delete_idempotency_query<'args, DB>(
    key: &'args str,
    endpoint: &'args str,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::idempotency::DELETE);
    builder.push(" ").push_bind(key);
    builder.push(" AND endpoint = ").push_bind(endpoint);
    builder
}

fn map_idempotency<R>(row: R) -> Result<IdempotencyRecord, sqlx::Error>
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
    Ok(IdempotencyRecord {
        key: row.try_get("idempotency_key")?,
        endpoint: row.try_get("endpoint")?,
        request_hash: row.try_get("request_hash")?,
        response_status: row.try_get("response_status")?,
        response_body: row.try_get("response_body")?,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}
