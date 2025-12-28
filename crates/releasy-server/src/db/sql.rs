pub(in crate::db) mod api_keys {
    pub(in crate::db) const GET_BY_PREFIX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/api_keys/get_by_prefix.sql"
    ));
    pub(in crate::db) const INSERT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/api_keys/insert.sql"
    ));
    pub(in crate::db) const REVOKE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/api_keys/revoke.sql"
    ));
    pub(in crate::db) const UPDATE_HASH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/api_keys/update_hash.sql"
    ));
    pub(in crate::db) const UPDATE_LAST_USED: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/api_keys/update_last_used.sql"
    ));
}

pub(in crate::db) mod artifacts {
    pub(in crate::db) const INSERT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/artifacts/insert.sql"
    ));
    pub(in crate::db) const LIST_BY_RELEASE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/artifacts/list_by_release.sql"
    ));
    pub(in crate::db) const GET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/artifacts/get.sql"
    ));
}

pub(in crate::db) mod audit {
    pub(in crate::db) const LIST_BASE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/audit/list_base.sql"
    ));
    pub(in crate::db) const INSERT: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/sql/audit/insert.sql"));
}

pub(in crate::db) mod customers {
    pub(in crate::db) const EXISTS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/customers/exists.sql"
    ));
    pub(in crate::db) const GET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/customers/get.sql"
    ));
    pub(in crate::db) const INSERT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/customers/insert.sql"
    ));
}

pub(in crate::db) mod download_tokens {
    pub(in crate::db) const INSERT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/download_tokens/insert.sql"
    ));
    pub(in crate::db) const GET_BY_HASH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/download_tokens/get_by_hash.sql"
    ));
}

pub(in crate::db) mod entitlements {
    pub(in crate::db) const LIST_BY_CUSTOMER: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/entitlements/list_by_customer.sql"
    ));
    pub(in crate::db) const GET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/entitlements/get.sql"
    ));
    pub(in crate::db) const INSERT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/entitlements/insert.sql"
    ));
    pub(in crate::db) const UPDATE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/entitlements/update.sql"
    ));
    pub(in crate::db) const DELETE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/entitlements/delete.sql"
    ));
}

pub(in crate::db) mod idempotency {
    pub(in crate::db) const GET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/idempotency/get.sql"
    ));
    pub(in crate::db) const INSERT_POSTGRES: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/idempotency/insert_postgres.sql"
    ));
    pub(in crate::db) const INSERT_POSTGRES_SUFFIX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/idempotency/insert_postgres_suffix.sql"
    ));
    pub(in crate::db) const INSERT_SQLITE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/idempotency/insert_sqlite.sql"
    ));
    pub(in crate::db) const UPDATE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/idempotency/update.sql"
    ));
    pub(in crate::db) const DELETE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/idempotency/delete.sql"
    ));
}

pub(in crate::db) mod releases {
    pub(in crate::db) const INSERT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/releases/insert.sql"
    ));
    pub(in crate::db) const GET: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/sql/releases/get.sql"));
    pub(in crate::db) const LIST_BASE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/releases/list_base.sql"
    ));
    pub(in crate::db) const LIST_PUBLISHED_BASE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/releases/list_published_base.sql"
    ));
    pub(in crate::db) const UPDATE_STATUS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/releases/update_status.sql"
    ));
    pub(in crate::db) const DELETE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sql/releases/delete.sql"
    ));
}
