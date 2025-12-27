CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  checksum TEXT NOT NULL,
  size INTEGER NOT NULL,
  platform TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS artifacts_release_object_key_idx
  ON artifacts (release_id, object_key);

CREATE INDEX IF NOT EXISTS artifacts_release_id_idx
  ON artifacts (release_id);
