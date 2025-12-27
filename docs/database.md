# Database Support

Releasy officially supports PostgreSQL and SQLite through SQLx. The
selected driver is determined by the scheme of `RELEASY_DATABASE_URL`.

## Connection URLs

Set `RELEASY_DATABASE_URL` using one of the supported schemes:

- PostgreSQL: `postgres://user:pass@host:5432/dbname`
- PostgreSQL (alt): `postgresql://user:pass@host:5432/dbname`
- SQLite (file): `sqlite://relative/path.db` or `sqlite:///absolute/path.db`
- SQLite (memory): `sqlite::memory:` (dev/tests only)

Control pool sizing with `RELEASY_DATABASE_MAX_CONNECTIONS`.

## Migrations

- Migrations live in `migrations/` and use a zero-padded numeric prefix
  for ordering (for example: `0001_init.sql`).
- Migrations are embedded at build time and executed on server startup
  before the HTTP listener is bound.
- Adding or changing migrations requires rebuilding the server binary.

Compatibility rules:

- Migrations must run on both PostgreSQL and SQLite.
- Prefer portable SQL types (TEXT, INTEGER) and avoid vendor-specific
  syntax unless the statement is compatible on both databases.

## Operational Guidance

- Production: Use PostgreSQL for durability and multi-instance
  deployments. Tune `RELEASY_DATABASE_MAX_CONNECTIONS` to match your
  database limits.
- Development: SQLite is suitable for local evaluation or single-node
  setups. Use a local disk path for file-backed databases.
