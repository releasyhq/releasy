use sqlx::QueryBuilder;

use crate::models::Customer;

use super::{Database, sql};

#[derive(Debug, Default, Clone)]
pub struct CustomerUpdate {
    pub name: Option<String>,
    pub plan: Option<Option<String>>,
    pub suspended_at: Option<Option<i64>>,
}

impl CustomerUpdate {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.plan.is_none() && self.suspended_at.is_none()
    }
}

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

    pub async fn list_customers(
        &self,
        customer_id: Option<&str>,
        name: Option<&str>,
        plan: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Customer>, sqlx::Error> {
        with_db!(self, |pool, Db| {
            let name_filter = name.map(|value| format!("%{}%", value.to_ascii_lowercase()));
            let plan_filter = plan.map(|value| value.to_ascii_lowercase());
            let mut builder = build_list_customers_query::<Db>(
                customer_id,
                name_filter.as_deref(),
                plan_filter.as_deref(),
                limit,
                offset,
            );
            let rows = builder.build().fetch_all(pool).await?;
            rows.into_iter().map(map_customer).collect()
        })
    }

    pub async fn update_customer(
        &self,
        customer_id: &str,
        update: &CustomerUpdate,
    ) -> Result<Option<Customer>, sqlx::Error> {
        with_db!(self, |pool, Db| {
            if update.is_empty() {
                return Ok(None);
            }

            let mut builder = build_update_customer_query::<Db>(customer_id, update);
            let result = builder.build().execute(pool).await?;
            if result.rows_affected() == 0 {
                return Ok(None);
            }

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

fn build_update_customer_query<'args, DB>(
    customer_id: &'args str,
    update: &'args CustomerUpdate,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<String>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    &'args Option<i64>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::customers::UPDATE);
    let mut separated = builder.separated(", ");

    if let Some(name) = update.name.as_deref() {
        separated.push("name = ");
        separated.push_bind_unseparated(name);
    }

    if let Some(plan) = &update.plan {
        separated.push("plan = ");
        separated.push_bind_unseparated(plan);
    }

    if let Some(suspended_at) = &update.suspended_at {
        separated.push("suspended_at = ");
        separated.push_bind_unseparated(suspended_at);
    }

    builder.push(" WHERE id = ").push_bind(customer_id);
    builder
}

fn build_list_customers_query<'args, DB>(
    customer_id: Option<&'args str>,
    name_like: Option<&'args str>,
    plan: Option<&'args str>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::customers::LIST_BASE);
    let mut has_where = false;

    if let Some(customer_id) = customer_id {
        if !has_where {
            builder.push(" WHERE ");
            has_where = true;
        }
        builder.push("id = ").push_bind(customer_id);
    }

    if let Some(name_like) = name_like {
        if !has_where {
            builder.push(" WHERE ");
            has_where = true;
        } else {
            builder.push(" AND ");
        }
        builder.push("LOWER(name) LIKE ").push_bind(name_like);
    }

    if let Some(plan) = plan {
        if !has_where {
            builder.push(" WHERE ");
        } else {
            builder.push(" AND ");
        }
        builder.push("LOWER(plan) = ").push_bind(plan);
    }

    builder
        .push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);

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
