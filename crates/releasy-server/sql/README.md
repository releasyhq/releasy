# SQL Conventions

These .sql files are intentionally partial. They are base fragments that
get finished in Rust with sqlx::QueryBuilder. This keeps bind handling
in Rust and avoids DB-specific placeholder syntax in the files.

## Naming

- *_base.sql: start of a statement that is extended in Rust.
- get.sql/insert.sql/update.sql/delete.sql: base statement; WHERE/VALUES
  may be appended in Rust.

## Binding and placeholders

- Do not use $1 or ? placeholders in .sql files.
- Rust appends binds with QueryBuilder push_bind().
- Some files end with "WHERE column =" so Rust can append a bind and
  additional predicates.

## Dialect differences

- SQLite vs Postgres differences live in Rust.
- Example: idempotency inserts switch between INSERT OR IGNORE and
  ON CONFLICT in db/idempotency.rs.

## Notes

- These files are included verbatim and are sometimes used in SQL string
  comparisons in tests. Avoid adding comments to the SQL files unless the
  expected SQL strings are updated too.
- The include list lives in crates/releasy-server/src/db/sql.rs.

## Examples

Base fragment extended in Rust:

SQL file (crates/releasy-server/sql/entitlements/get.sql):

```sql
SELECT id, customer_id, product, starts_at, ends_at, metadata
FROM entitlements
WHERE customer_id =
```

Rust extension (crates/releasy-server/src/db/entitlements.rs):

```rust
let mut builder = QueryBuilder::<DB>::new(sql::entitlements::GET);
builder.push(" ").push_bind(customer_id);
builder.push(" AND id = ").push_bind(entitlement_id);
```

Dialect-specific insert handling:

SQL file (crates/releasy-server/sql/idempotency/insert_base.sql):

```sql
INSERT INTO idempotency
  (idempotency_key, endpoint, request_hash, response_status, response_body,
   state, created_at, expires_at)
VALUES
```

Rust extension (crates/releasy-server/src/db/idempotency.rs):

```rust
let base_sql = insert_idempotency_base_sql(ignore_conflicts);
let mut builder = QueryBuilder::<Db>::new(base_sql.as_ref());
// push_bind(...) calls
if ignore_conflicts {
    builder.push(")");
} else {
    builder.push(sql::idempotency::INSERT_CONFLICT_SUFFIX);
}
```
