# Secure Downloads

Releasy issues short-lived download tokens and resolves them to presigned GET
URLs. Tokens are stored hashed and are tied to a customer, artifact, and TTL.

## Configuration

Set the maximum TTL (seconds) for download tokens:

```
RELEASY_DOWNLOAD_TOKEN_TTL_SECONDS=600
```

Downloads also require artifact storage to be configured (see
`docs/artifacts.md`).

## Issue a Download Token

```
POST /v1/downloads/token
```

Headers:

- `x-releasy-api-key: <api_key>` (must include `downloads:token` scope)

Request body:

```json
{
  "artifact_id": "<artifact-uuid>",
  "purpose": "ci",
  "expires_in_seconds": 300
}
```

Notes:

- `expires_in_seconds` is optional and must be `> 0` and `<= RELEASY_DOWNLOAD_TOKEN_TTL_SECONDS`.
- The release must be `published` and the customer must have an active
  entitlement for the release product.

Response body:

```json
{
  "download_url": "https://example.com/v1/downloads/<token>",
  "expires_at": 1735300000
}
```

Example:

```bash
curl -X POST \
  -H "x-releasy-api-key: $RELEASY_API_KEY" \
  -H "content-type: application/json" \
  -d '{"artifact_id":"...","expires_in_seconds":300}' \
  http://localhost:8080/v1/downloads/token
```

## Resolve a Download Token

```
GET /v1/downloads/{token}
```

Returns a `302 Found` redirect to a presigned GET URL. The redirect response
includes `Cache-Control: no-store`.

Example:

```bash
curl -v http://localhost:8080/v1/downloads/<token>
```

## Entitlements

Download tokens require an active entitlement record for the customer and
release product. Entitlements are stored in the `entitlements` table and are
considered active when `starts_at <= now` and `ends_at` is `NULL` or in the
future.
