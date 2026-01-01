SELECT
    k.id,
    k.customer_id,
    k.key_hash,
    k.key_type,
    k.scopes,
    k.expires_at,
    k.revoked_at,
    c.suspended_at
FROM api_keys AS k
JOIN customers AS c ON c.id = k.customer_id
WHERE k.key_prefix =
