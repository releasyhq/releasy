CREATE TABLE IF NOT EXISTS entitlements (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  product TEXT NOT NULL,
  starts_at INTEGER NOT NULL,
  ends_at INTEGER,
  metadata TEXT,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS entitlements_customer_id_idx ON entitlements(customer_id);
CREATE INDEX IF NOT EXISTS entitlements_customer_product_idx
  ON entitlements(customer_id, product);
