SELECT id, release_id, object_key, checksum, size, platform, created_at
FROM artifacts
WHERE release_id IN
