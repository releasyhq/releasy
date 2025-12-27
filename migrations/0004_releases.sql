CREATE TABLE IF NOT EXISTS releases (
  id TEXT PRIMARY KEY,
  product TEXT NOT NULL,
  version TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER
);
