ALTER TABLE entitlements RENAME TO entitlements_old;

CREATE TABLE entitlements (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  product TEXT NOT NULL,
  starts_at BIGINT NOT NULL,
  ends_at BIGINT,
  metadata TEXT,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

INSERT INTO entitlements (id, customer_id, product, starts_at, ends_at, metadata)
SELECT id, customer_id, product, starts_at, ends_at, metadata
FROM entitlements_old;

DROP TABLE entitlements_old;

CREATE INDEX IF NOT EXISTS entitlements_customer_id_idx ON entitlements(customer_id);
CREATE INDEX IF NOT EXISTS entitlements_customer_product_idx
  ON entitlements(customer_id, product);
