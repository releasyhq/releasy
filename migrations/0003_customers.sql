CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT,
  allowed_prefixes TEXT,
  created_at INTEGER NOT NULL,
  suspended_at INTEGER
);
