use sqlx::QueryBuilder;

use crate::models::EntitlementRecord;

use super::{Database, sql};

impl Database {
    pub async fn list_entitlements_by_customer(
        &self,
        customer_id: &str,
        product: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<EntitlementRecord>, sqlx::Error> {
        crate::with_db!(self, |pool, Db| {
            let mut builder =
                build_list_entitlements_query::<Db>(customer_id, product, limit, offset);
            let rows = builder.build().fetch_all(pool).await?;
            rows.into_iter().map(map_entitlement).collect()
        })
    }

    pub async fn get_entitlement(
        &self,
        customer_id: &str,
        entitlement_id: &str,
    ) -> Result<Option<EntitlementRecord>, sqlx::Error> {
        crate::with_db!(self, |pool, Db| {
            let mut builder = build_get_entitlement_query::<Db>(customer_id, entitlement_id);
            let row = builder.build().fetch_optional(pool).await?;
            row.map(map_entitlement).transpose()
        })
    }

    #[allow(dead_code)]
    pub async fn insert_entitlement(
        &self,
        entitlement: &EntitlementRecord,
    ) -> Result<(), sqlx::Error> {
        crate::with_db!(self, |pool, Db| {
            let mut builder = build_insert_entitlement_query::<Db>(entitlement);
            builder.build().execute(pool).await?;
            Ok(())
        })
    }

    pub async fn update_entitlement(
        &self,
        entitlement: &EntitlementRecord,
    ) -> Result<u64, sqlx::Error> {
        crate::with_db!(self, |pool, Db| {
            let mut builder = build_update_entitlement_query::<Db>(entitlement);
            let result = builder.build().execute(pool).await?;
            Ok(result.rows_affected())
        })
    }

    pub async fn delete_entitlement(
        &self,
        customer_id: &str,
        entitlement_id: &str,
    ) -> Result<u64, sqlx::Error> {
        crate::with_db!(self, |pool, Db| {
            let mut builder = build_delete_entitlement_query::<Db>(customer_id, entitlement_id);
            let result = builder.build().execute(pool).await?;
            Ok(result.rows_affected())
        })
    }
}

fn build_list_entitlements_query<'args, DB>(
    customer_id: &'args str,
    product: Option<&'args str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::entitlements::LIST_BY_CUSTOMER);
    builder.push(" ").push_bind(customer_id);

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

fn build_get_entitlement_query<'args, DB>(
    customer_id: &'args str,
    entitlement_id: &'args str,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::entitlements::GET);
    builder.push(" ").push_bind(customer_id);
    builder.push(" AND id = ").push_bind(entitlement_id);
    builder
}

fn build_insert_entitlement_query<'args, DB>(
    entitlement: &'args EntitlementRecord,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::entitlements::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(entitlement.id.as_str());
    separated.push_bind(entitlement.customer_id.as_str());
    separated.push_bind(entitlement.product.as_str());
    separated.push_bind(entitlement.starts_at);
    separated.push_bind(entitlement.ends_at);
    separated.push_bind(&entitlement.metadata);
    builder.push(")");
    builder
}

fn build_update_entitlement_query<'args, DB>(
    entitlement: &'args EntitlementRecord,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::entitlements::UPDATE);
    builder.push(" ").push_bind(entitlement.product.as_str());
    builder
        .push(", starts_at = ")
        .push_bind(entitlement.starts_at);
    builder.push(", ends_at = ").push_bind(entitlement.ends_at);
    builder
        .push(", metadata = ")
        .push_bind(&entitlement.metadata);
    builder
        .push(" WHERE customer_id = ")
        .push_bind(entitlement.customer_id.as_str());
    builder
        .push(" AND id = ")
        .push_bind(entitlement.id.as_str());
    builder
}

fn build_delete_entitlement_query<'args, DB>(
    customer_id: &'args str,
    entitlement_id: &'args str,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::entitlements::DELETE);
    builder.push(" ").push_bind(customer_id);
    builder.push(" AND id = ").push_bind(entitlement_id);
    builder
}

fn map_entitlement<R>(row: R) -> Result<EntitlementRecord, sqlx::Error>
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
    Ok(EntitlementRecord {
        id: row.try_get("id")?,
        customer_id: row.try_get("customer_id")?,
        product: row.try_get("product")?,
        starts_at: row.try_get("starts_at")?,
        ends_at: row.try_get("ends_at")?,
        metadata: row.try_get("metadata")?,
    })
}
