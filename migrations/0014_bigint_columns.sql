CREATE TABLE customers_new (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT,
  allowed_prefixes TEXT,
  created_at BIGINT NOT NULL,
  suspended_at BIGINT
);

CREATE TABLE releases_new (
  id TEXT PRIMARY KEY,
  product TEXT NOT NULL,
  version TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  published_at BIGINT
);

CREATE TABLE artifacts_new (
  id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  checksum TEXT NOT NULL,
  size BIGINT NOT NULL,
  platform TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  FOREIGN KEY (release_id) REFERENCES releases_new(id) ON DELETE CASCADE
);

CREATE TABLE download_tokens_new (
  token_hash TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  purpose TEXT,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES artifacts_new(id) ON DELETE CASCADE,
  FOREIGN KEY (customer_id) REFERENCES customers_new(id) ON DELETE CASCADE
);

CREATE TABLE api_keys_new (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  name TEXT,
  key_type TEXT NOT NULL,
  scopes TEXT NOT NULL,
  expires_at BIGINT,
  created_at BIGINT NOT NULL,
  revoked_at BIGINT,
  last_used_at BIGINT,
  FOREIGN KEY (customer_id) REFERENCES customers_new(id) ON DELETE CASCADE
);

CREATE TABLE entitlements_new (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  product TEXT NOT NULL,
  starts_at BIGINT NOT NULL,
  ends_at BIGINT,
  metadata TEXT,
  FOREIGN KEY (customer_id) REFERENCES customers_new(id) ON DELETE CASCADE
);

CREATE TABLE audit_events_new (
  id TEXT PRIMARY KEY,
  customer_id TEXT,
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  payload TEXT,
  created_at BIGINT NOT NULL
);

CREATE TABLE idempotency_keys_new (
  idempotency_key TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response_status INTEGER,
  response_body TEXT,
  state TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  PRIMARY KEY (idempotency_key, endpoint)
);

INSERT INTO customers_new (
  id,
  name,
  plan,
  allowed_prefixes,
  created_at,
  suspended_at
)
SELECT
  id,
  name,
  plan,
  allowed_prefixes,
  created_at,
  suspended_at
FROM customers;

INSERT INTO releases_new (
  id,
  product,
  version,
  status,
  created_at,
  published_at
)
SELECT
  id,
  product,
  version,
  status,
  created_at,
  published_at
FROM releases;

INSERT INTO artifacts_new (
  id,
  release_id,
  object_key,
  checksum,
  size,
  platform,
  created_at
)
SELECT
  id,
  release_id,
  object_key,
  checksum,
  size,
  platform,
  created_at
FROM artifacts;

INSERT INTO download_tokens_new (
  token_hash,
  artifact_id,
  customer_id,
  purpose,
  expires_at,
  created_at
)
SELECT
  token_hash,
  artifact_id,
  customer_id,
  purpose,
  expires_at,
  created_at
FROM download_tokens;

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

INSERT INTO entitlements_new (
  id,
  customer_id,
  product,
  starts_at,
  ends_at,
  metadata
)
SELECT
  id,
  customer_id,
  product,
  starts_at,
  ends_at,
  metadata
FROM entitlements;

INSERT INTO audit_events_new (
  id,
  customer_id,
  actor,
  event,
  payload,
  created_at
)
SELECT
  id,
  customer_id,
  actor,
  event,
  payload,
  created_at
FROM audit_events;

INSERT INTO idempotency_keys_new (
  idempotency_key,
  endpoint,
  request_hash,
  response_status,
  response_body,
  state,
  created_at,
  expires_at
)
SELECT
  idempotency_key,
  endpoint,
  request_hash,
  response_status,
  response_body,
  state,
  created_at,
  expires_at
FROM idempotency_keys;

DROP TABLE download_tokens;
DROP TABLE artifacts;
DROP TABLE api_keys;
DROP TABLE entitlements;
DROP TABLE releases;
DROP TABLE customers;
DROP TABLE audit_events;
DROP TABLE idempotency_keys;

ALTER TABLE customers_new RENAME TO customers;
ALTER TABLE releases_new RENAME TO releases;
ALTER TABLE artifacts_new RENAME TO artifacts;
ALTER TABLE download_tokens_new RENAME TO download_tokens;
ALTER TABLE api_keys_new RENAME TO api_keys;
ALTER TABLE entitlements_new RENAME TO entitlements;
ALTER TABLE audit_events_new RENAME TO audit_events;
ALTER TABLE idempotency_keys_new RENAME TO idempotency_keys;

CREATE INDEX IF NOT EXISTS api_keys_customer_id_idx ON api_keys (customer_id);
CREATE INDEX IF NOT EXISTS api_keys_key_prefix_idx ON api_keys (key_prefix);
CREATE INDEX IF NOT EXISTS releases_product_status_created_at_idx
  ON releases (product, status, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS releases_product_version_idx
  ON releases (product, version);
CREATE UNIQUE INDEX IF NOT EXISTS artifacts_release_object_key_idx
  ON artifacts (release_id, object_key);
CREATE INDEX IF NOT EXISTS artifacts_release_id_idx
  ON artifacts (release_id);
CREATE INDEX IF NOT EXISTS entitlements_customer_id_idx ON entitlements(customer_id);
CREATE INDEX IF NOT EXISTS entitlements_customer_product_idx
  ON entitlements(customer_id, product);
CREATE INDEX IF NOT EXISTS download_tokens_artifact_id_idx
  ON download_tokens(artifact_id);
CREATE INDEX IF NOT EXISTS download_tokens_customer_id_idx
  ON download_tokens(customer_id);
CREATE INDEX IF NOT EXISTS download_tokens_expires_at_idx
  ON download_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idempotency_keys_expires_at_idx
  ON idempotency_keys (expires_at);
