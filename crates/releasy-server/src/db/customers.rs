use sqlx::QueryBuilder;

use crate::models::Customer;

use super::{Database, sql};

impl Database {
    pub async fn customer_exists(&self, customer_id: &str) -> Result<bool, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_customer_exists_query::<Db>(customer_id);
            let row = builder.build().fetch_optional(pool).await?;
            Ok(row.is_some())
        })
    }

    pub async fn insert_customer(&self, customer: &Customer) -> Result<(), sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_insert_customer_query::<Db>(customer);
            builder.build().execute(pool).await?;
            Ok(())
        })
    }

    pub async fn get_customer(&self, customer_id: &str) -> Result<Option<Customer>, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let mut builder = build_get_customer_query::<Db>(customer_id);
            let row = builder.build().fetch_optional(pool).await?;
            row.map(map_customer).transpose()
        })
    }
}

fn build_customer_exists_query<'args, DB>(customer_id: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::customers::EXISTS);
    builder.push(" ").push_bind(customer_id);
    builder.push(" LIMIT 1");
    builder
}

fn build_get_customer_query<'args, DB>(customer_id: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::customers::GET);
    builder.push(" ").push_bind(customer_id);
    builder
}

fn build_insert_customer_query<'args, DB>(customer: &'args Customer) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::customers::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(customer.id.as_str());
    separated.push_bind(customer.name.as_str());
    separated.push_bind(&customer.plan);
    separated.push_bind(&customer.allowed_prefixes);
    separated.push_bind(customer.created_at);
    separated.push_bind(customer.suspended_at);
    builder.push(")");
    builder
}

fn map_customer<R>(row: R) -> Result<Customer, sqlx::Error>
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
    Ok(Customer {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        plan: row.try_get("plan")?,
        allowed_prefixes: row.try_get("allowed_prefixes")?,
        created_at: row.try_get("created_at")?,
        suspended_at: row.try_get("suspended_at")?,
    })
}
