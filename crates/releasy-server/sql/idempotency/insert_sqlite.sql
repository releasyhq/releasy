INSERT OR IGNORE INTO idempotency_keys (idempotency_key, endpoint, request_hash, response_status, response_body, state, created_at, expires_at)
VALUES (
