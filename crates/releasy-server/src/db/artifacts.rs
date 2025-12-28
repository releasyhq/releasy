use sqlx::QueryBuilder;

use crate::models::ArtifactRecord;

use super::{Database, sql};

impl Database {
    pub async fn insert_artifact(&self, artifact: &ArtifactRecord) -> Result<(), sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_insert_artifact_query::<sqlx::Postgres>(artifact);
                builder.build().execute(pool).await?;
            }
            Database::Sqlite(pool) => {
                let mut builder = build_insert_artifact_query::<sqlx::Sqlite>(artifact);
                builder.build().execute(pool).await?;
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
                let mut builder =
                    build_list_artifacts_by_release_query::<sqlx::Postgres>(release_id);
                let rows = builder.build().fetch_all(pool).await?;
                rows.into_iter().map(map_artifact).collect()
            }
            Database::Sqlite(pool) => {
                let mut builder = build_list_artifacts_by_release_query::<sqlx::Sqlite>(release_id);
                let rows = builder.build().fetch_all(pool).await?;
                rows.into_iter().map(map_artifact).collect()
            }
        }
    }

    pub async fn get_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactRecord>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => {
                let mut builder = build_get_artifact_query::<sqlx::Postgres>(artifact_id);
                let row = builder.build().fetch_optional(pool).await?;
                row.map(map_artifact).transpose()
            }
            Database::Sqlite(pool) => {
                let mut builder = build_get_artifact_query::<sqlx::Sqlite>(artifact_id);
                let row = builder.build().fetch_optional(pool).await?;
                row.map(map_artifact).transpose()
            }
        }
    }
}

fn build_insert_artifact_query<'args, DB>(
    artifact: &'args ArtifactRecord,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::artifacts::INSERT);
    let mut separated = builder.separated(", ");
    separated.push_bind(artifact.id.as_str());
    separated.push_bind(artifact.release_id.as_str());
    separated.push_bind(artifact.object_key.as_str());
    separated.push_bind(artifact.checksum.as_str());
    separated.push_bind(artifact.size);
    separated.push_bind(artifact.platform.as_str());
    separated.push_bind(artifact.created_at);
    builder.push(")");
    builder
}

fn build_list_artifacts_by_release_query<'args, DB>(
    release_id: &'args str,
) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::artifacts::LIST_BY_RELEASE);
    builder.push(" ").push_bind(release_id);
    builder.push(" ORDER BY created_at ASC");
    builder
}

fn build_get_artifact_query<'args, DB>(artifact_id: &'args str) -> QueryBuilder<'args, DB>
where
    DB: sqlx::Database,
    &'args str: sqlx::Encode<'args, DB> + sqlx::Type<DB>,
{
    let mut builder = QueryBuilder::<DB>::new(sql::artifacts::GET);
    builder.push(" ").push_bind(artifact_id);
    builder
}

fn map_artifact<R>(row: R) -> Result<ArtifactRecord, sqlx::Error>
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
    Ok(ArtifactRecord {
        id: row.try_get("id")?,
        release_id: row.try_get("release_id")?,
        object_key: row.try_get("object_key")?,
        checksum: row.try_get("checksum")?,
        size: row.try_get("size")?,
        platform: row.try_get("platform")?,
        created_at: row.try_get("created_at")?,
    })
}
