use sqlx::{Execute, Row};

use super::Database;
use super::test_support::{api_key_record, cases, normalize_sql};
use crate::models::Customer;
use crate::test_support::{setup_default_db, sqlite_pool};

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
        assert_eq!(normalize_sql(&sql), normalize_sql(case.expected_postgres));
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
        assert_eq!(normalize_sql(&sql), normalize_sql(case.expected_sqlite));
    }
}

#[tokio::test]
async fn release_index_used_for_product_status_filter() {
    let db = setup_default_db().await;
    let pool = sqlite_pool(&db);

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
    let db = setup_default_db().await;
    let pool = sqlite_pool(&db);

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
    let db = setup_default_db().await;
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
    let db = setup_default_db().await;

    let record = api_key_record("missing-customer");
    let result = db.insert_api_key(&record).await;

    assert!(result.is_err());
}
