use sqlx::QueryBuilder;
use uuid::Uuid;

use crate::models::AuditEventRecord;

use super::{AuditEventFilter, Database, sql};

impl Database {
    pub async fn list_audit_events(
        &self,
        filter: AuditEventFilter<'_>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
        crate::with_db!(self, |pool, Db| {
            let mut builder = build_list_audit_events_query::<Db>(filter, limit, offset);
            let rows = builder.build().fetch_all(pool).await?;
            rows.into_iter().map(map_audit_event).collect()
        })
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
        crate::with_db!(self, |pool, Db| {
            let mut builder = build_insert_audit_event_query::<Db>(
                &id,
                customer_id,
                actor,
                event,
                payload,
                created_at,
            );
            builder.build().execute(pool).await?;
            Ok(())
        })
    }
}

fn build_list_audit_events_query<'args, DB>(
    filter: AuditEventFilter<'args>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::audit::LIST_BASE);

    if let Some(customer_id) = filter.customer_id {
        builder.push(" AND customer_id = ").push_bind(customer_id);
    }
    if let Some(actor) = filter.actor {
        builder.push(" AND actor = ").push_bind(actor);
    }
    if let Some(event) = filter.event {
        builder.push(" AND event = ").push_bind(event);
    }
    if let Some(created_from) = filter.created_from {
        builder.push(" AND created_at >= ").push_bind(created_from);
    }
    if let Some(created_to) = filter.created_to {
        builder.push(" AND created_at <= ").push_bind(created_to);
    }

    builder
        .push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);

    builder
}

fn build_insert_audit_event_query<'args, DB>(
    id: &'args str,
    customer_id: Option<&'args str>,
    actor: &'args str,
    event: &'args str,
    payload: Option<&'args str>,
    created_at: i64,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    Option<&'args str>: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::audit::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(id);
    separated.push_bind(customer_id);
    separated.push_bind(actor);
    separated.push_bind(event);
    separated.push_bind(payload);
    separated.push_bind(created_at);
    builder.push(")");
    builder
}

fn map_audit_event<R>(row: R) -> Result<AuditEventRecord, sqlx::Error>
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
    Ok(AuditEventRecord {
        id: row.try_get("id")?,
        customer_id: row.try_get("customer_id")?,
        actor: row.try_get("actor")?,
        event: row.try_get("event")?,
        payload: row.try_get("payload")?,
        created_at: row.try_get("created_at")?,
    })
}
