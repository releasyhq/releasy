use sqlx::QueryBuilder;

use crate::models::DownloadTokenRecord;

use super::{Database, sql};

impl Database {
    pub async fn insert_download_token(
        &self,
        token: &DownloadTokenRecord,
    ) -> Result<(), sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_insert_download_token_query::<Db>(token);
            builder.build().execute(pool).await?;
            Ok(())
        })
    }

    pub async fn get_download_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<DownloadTokenRecord>, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_get_download_token_query::<Db>(token_hash);
            let row = builder.build().fetch_optional(pool).await?;
            row.map(map_download_token).transpose()
        })
    }
}

fn build_insert_download_token_query<'args, DB>(
    token: &'args DownloadTokenRecord,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::download_tokens::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(token.token_hash.as_str());
    separated.push_bind(token.artifact_id.as_str());
    separated.push_bind(token.customer_id.as_str());
    separated.push_bind(&token.purpose);
    separated.push_bind(token.expires_at);
    separated.push_bind(token.created_at);
    builder.push(")");
    builder
}

fn build_get_download_token_query<'args, DB>(token_hash: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::download_tokens::GET_BY_HASH);
    builder.push(" ").push_bind(token_hash);
    builder
}

fn map_download_token<R>(row: R) -> Result<DownloadTokenRecord, sqlx::Error>
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
    Ok(DownloadTokenRecord {
        token_hash: row.try_get("token_hash")?,
        artifact_id: row.try_get("artifact_id")?,
        customer_id: row.try_get("customer_id")?,
        purpose: row.try_get("purpose")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
    })
}
