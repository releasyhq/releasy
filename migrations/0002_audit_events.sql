CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  customer_id TEXT,
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  payload TEXT,
  created_at INTEGER NOT NULL
);
