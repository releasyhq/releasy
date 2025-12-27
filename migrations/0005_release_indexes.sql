CREATE INDEX IF NOT EXISTS releases_product_status_created_at_idx
  ON releases (product, status, created_at DESC);

CREATE INDEX IF NOT EXISTS releases_product_version_idx
  ON releases (product, version);
