# Migrations

Database migration files live here.

## Strategy

- Migrations are versioned, forward-only SQL files.
- Filenames use a zero-padded numeric prefix to define order
  (for example: `0001_init.sql`).
- Migrations are embedded at build time and executed on server startup.

## Compatibility

Releasy supports PostgreSQL and SQLite, so every migration must run on
both databases. Prefer portable SQL types (TEXT, INTEGER) and avoid
database-specific syntax unless it is guarded or applied in a compatible
way.
