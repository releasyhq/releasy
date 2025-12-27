DROP INDEX IF EXISTS releases_product_version_idx;
CREATE UNIQUE INDEX IF NOT EXISTS releases_product_version_idx
  ON releases (product, version);
