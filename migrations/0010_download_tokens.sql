CREATE TABLE IF NOT EXISTS download_tokens (
  token_hash TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  purpose TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS download_tokens_artifact_id_idx
  ON download_tokens(artifact_id);
CREATE INDEX IF NOT EXISTS download_tokens_customer_id_idx
  ON download_tokens(customer_id);
CREATE INDEX IF NOT EXISTS download_tokens_expires_at_idx
  ON download_tokens(expires_at);
