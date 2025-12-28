SELECT id, customer_id, key_hash, key_type, scopes, expires_at, revoked_at
FROM api_keys
WHERE key_prefix =
