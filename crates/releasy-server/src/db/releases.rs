use sqlx::QueryBuilder;

use crate::models::ReleaseRecord;

use super::{Database, sql};

impl Database {
    pub async fn insert_release(&self, release: &ReleaseRecord) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_insert_release_query::<sqlx::Postgres>(release);
                builder.build().execute(pool).await?;
            }
            Database::Sqlite(pool) => {
                let mut builder = build_insert_release_query::<sqlx::Sqlite>(release);
                builder.build().execute(pool).await?;
            }
        }
        Ok(())
    }

    pub async fn get_release(
        &self,
        release_id: &str,
    ) -> Result<Option<ReleaseRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_get_release_query::<sqlx::Postgres>(release_id);
                let row = builder.build().fetch_optional(pool).await?;
                row.map(map_release).transpose()
            }
            Database::Sqlite(pool) => {
                let mut builder = build_get_release_query::<sqlx::Sqlite>(release_id);
                let row = builder.build().fetch_optional(pool).await?;
                row.map(map_release).transpose()
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
                let mut builder = Database::build_list_releases_query::<sqlx::Postgres>(
                    product, status, version, limit, offset,
                );
                let rows = builder.build().fetch_all(pool).await?;
                rows.into_iter().map(map_release).collect()
            }
            Database::Sqlite(pool) => {
                let mut builder = Database::build_list_releases_query::<sqlx::Sqlite>(
                    product, status, version, limit, offset,
                );
                let rows = builder.build().fetch_all(pool).await?;
                rows.into_iter().map(map_release).collect()
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
                let mut builder = build_list_published_releases_for_products_query::<sqlx::Postgres>(
                    products, version, limit, offset,
                );
                let rows = builder.build().fetch_all(pool).await?;
                rows.into_iter().map(map_release).collect()
            }
            Database::Sqlite(pool) => {
                let mut builder = build_list_published_releases_for_products_query::<sqlx::Sqlite>(
                    products, version, limit, offset,
                );
                let rows = builder.build().fetch_all(pool).await?;
                rows.into_iter().map(map_release).collect()
            }
        }
    }

    pub async fn update_release_status(
        &self,
        release_id: &str,
        status: &str,
        published_at: Option<i64>,
        expected_status: Option<&str>,
    ) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_update_release_status_query::<sqlx::Postgres>(
                    release_id,
                    status,
                    published_at,
                    expected_status,
                );
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let mut builder = build_update_release_status_query::<sqlx::Sqlite>(
                    release_id,
                    status,
                    published_at,
                    expected_status,
                );
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub async fn delete_release(&self, release_id: &str) -> Result<u64, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_delete_release_query::<sqlx::Postgres>(release_id);
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
            Database::Sqlite(pool) => {
                let mut builder = build_delete_release_query::<sqlx::Sqlite>(release_id);
                let result = builder.build().execute(pool).await?;
                Ok(result.rows_affected())
            }
        }
    }

    pub(super) fn build_list_releases_query<'args, DB>(
        product: Option<&'args str>,
        status: Option<&'args str>,
        version: Option<&'args str>,
        limit: i64,
        offset: i64,
    ) -> QueryBuilder<'args, DB>
    where
        DB: sqlx::Database,
        &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
        i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    {
        let mut builder = QueryBuilder::<DB>::new(sql::releases::LIST_BASE);
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
}

fn build_insert_release_query<'args, DB>(release: &'args ReleaseRecord) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::releases::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(release.id.as_str());
    separated.push_bind(release.product.as_str());
    separated.push_bind(release.version.as_str());
    separated.push_bind(release.status.as_str());
    separated.push_bind(release.created_at);
    separated.push_bind(release.published_at);
    builder.push(")");
    builder
}

fn build_get_release_query<'args, DB>(release_id: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::releases::GET);
    builder.push(" ").push_bind(release_id);
    builder
}

fn build_list_published_releases_for_products_query<'args, DB>(
    products: &'args [String],
    version: Option<&'args str>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::releases::LIST_PUBLISHED_BASE);
    builder.push(" ").push_bind("published");
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

fn build_update_release_status_query<'args, DB>(
    release_id: &'args str,
    status: &'args str,
    published_at: Option<i64>,
    expected_status: Option<&'args str>,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::releases::UPDATE_STATUS);
    builder.push(" ").push_bind(status);
    builder.push(", published_at = ").push_bind(published_at);
    builder.push(" WHERE id = ").push_bind(release_id);
    if let Some(expected_status) = expected_status {
        builder.push(" AND status = ").push_bind(expected_status);
    }
    builder
}

fn build_delete_release_query<'args, DB>(release_id: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::releases::DELETE);
    builder.push(" ").push_bind(release_id);
    builder
}

fn map_release<R>(row: R) -> Result<ReleaseRecord, sqlx::Error>
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
    Ok(ReleaseRecord {
        id: row.try_get("id")?,
        product: row.try_get("product")?,
        version: row.try_get("version")?,
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
        published_at: row.try_get("published_at")?,
    })
}
