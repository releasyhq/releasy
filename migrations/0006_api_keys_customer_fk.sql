DELETE FROM api_keys
WHERE customer_id NOT IN (SELECT id FROM customers);

CREATE TABLE api_keys_new (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  name TEXT,
  key_type TEXT NOT NULL,
  scopes TEXT NOT NULL,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_used_at INTEGER,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

INSERT INTO api_keys_new (
  id,
  customer_id,
  key_hash,
  key_prefix,
  name,
  key_type,
  scopes,
  expires_at,
  created_at,
  revoked_at,
  last_used_at
)
SELECT
  id,
  customer_id,
  key_hash,
  key_prefix,
  name,
  key_type,
  scopes,
  expires_at,
  created_at,
  revoked_at,
  last_used_at
FROM api_keys;

DROP TABLE api_keys;

ALTER TABLE api_keys_new RENAME TO api_keys;

CREATE INDEX IF NOT EXISTS api_keys_customer_id_idx ON api_keys (customer_id);
