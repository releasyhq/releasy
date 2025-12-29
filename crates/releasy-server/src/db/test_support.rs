use uuid::Uuid;

use crate::models::ApiKeyRecord;

pub(crate) fn api_key_record(customer_id: &str) -> ApiKeyRecord {
    let key_id = Uuid::new_v4().to_string();
    ApiKeyRecord {
        id: key_id.clone(),
        customer_id: customer_id.to_string(),
        key_hash: format!("hash-{key_id}"),
        key_prefix: "releasy_test".to_string(),
        name: None,
        key_type: "human".to_string(),
        scopes: "[]".to_string(),
        expires_at: None,
        created_at: 1,
        revoked_at: None,
        last_used_at: None,
    }
}

pub(crate) fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) struct Case {
    pub(crate) product: Option<&'static str>,
    pub(crate) status: Option<&'static str>,
    pub(crate) version: Option<&'static str>,
    pub(crate) expected_postgres: &'static str,
    pub(crate) expected_sqlite: &'static str,
}

pub(crate) fn cases() -> Vec<Case> {
    vec![
        Case {
            product: Some("releasy"),
            status: Some("published"),
            version: Some("1.2.3"),
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 AND status = $2 AND version = $3 ORDER BY created_at DESC \
LIMIT $4 OFFSET $5",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? AND status = ? AND version = ? ORDER BY created_at DESC \
LIMIT ? OFFSET ?",
        },
        Case {
            product: Some("releasy"),
            status: Some("published"),
            version: None,
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? AND status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
        Case {
            product: Some("releasy"),
            status: None,
            version: Some("1.2.3"),
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 AND version = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? AND version = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
        Case {
            product: Some("releasy"),
            status: None,
            version: None,
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE product = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
        Case {
            product: None,
            status: Some("published"),
            version: Some("1.2.3"),
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = $1 AND version = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = ? AND version = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
        Case {
            product: None,
            status: Some("published"),
            version: None,
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
        Case {
            product: None,
            status: None,
            version: Some("1.2.3"),
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE version = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases WHERE version = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
        Case {
            product: None,
            status: None,
            version: None,
            expected_postgres: "SELECT id, product, version, status, created_at, published_at \
FROM releases ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            expected_sqlite: "SELECT id, product, version, status, created_at, published_at \
FROM releases ORDER BY created_at DESC LIMIT ? OFFSET ?",
        },
    ]
}
