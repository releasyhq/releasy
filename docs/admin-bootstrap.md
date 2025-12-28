# Admin Bootstrap

## Purpose

Releasy uses a single admin bootstrap key to perform initial setup tasks.
This key is required for admin endpoints and is not meant for customer use.

## Configure the Admin Key

1) Generate a random key (example):

   ```bash
   openssl rand -hex 32
   ```

2) Export it before starting the server:

   ```bash
   export RELEASY_ADMIN_API_KEY="<your-random-key>"
   ```

## Create the First Customer

`POST /v1/admin/customers`

Requires: `platform_admin` role

Notes:

- Supports `Idempotency-Key` (see `docs/api-conventions.md`).

Request body:

| Field  | Type   | Required | Description                                  |
|--------|--------|----------|----------------------------------------------|
| `name` | string | yes      | Customer name                                |
| `plan` | string | no       | Plan identifier (e.g., `core`, `enterprise`) |

Example:

```bash
curl -X POST "http://localhost:8080/v1/admin/customers" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"name":"Acme","plan":"core"}'
```

Response body:

```json
{
  "id": "<uuid>",
  "name": "Acme",
  "plan": "core",
  "created_at": 1735312000
}
```

## Create a Customer API Key

`POST /v1/admin/keys`

Requires: `platform_admin` role

Notes:

- `Idempotency-Key` is not supported because API keys are only returned once.

Request body:

| Field         | Type    | Required | Description                                                  |
|---------------|---------|----------|--------------------------------------------------------------|
| `customer_id` | string  | yes      | Customer UUID                                                |
| `name`        | string  | no       | Human-readable key name                                      |
| `scopes`      | array   | no       | List of scopes (defaults to all scopes)                      |
| `expires_at`  | integer | no       | Unix timestamp for expiration                                |
| `key_type`    | string  | no       | Key type: `human`, `ci`, or `integration` (default: `human`) |

Available scopes:

- `releases:read` - Read release information
- `downloads:read` - Read download information
- `downloads:token` - Generate download tokens
- `keys:read` - Introspect API keys
- `keys:write` - Manage API keys
- `audit:read` - Read audit logs

Example:

```bash
curl -X POST "http://localhost:8080/v1/admin/keys" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"customer_id":"<customer-id>","name":"CI Key","key_type":"ci","scopes":["releases:read","downloads:read"]}'
```

Response body:

```json
{
  "api_key_id": "<uuid>",
  "api_key": "releasy_abc123...",
  "customer_id": "<customer-id>",
  "key_type": "ci",
  "scopes": [
    "releases:read",
    "downloads:read"
  ],
  "expires_at": null
}
```

The `api_key` field contains the raw API key. Store it securely as it
cannot be retrieved again.

## Revoke an API Key

`POST /v1/admin/keys/revoke`

Requires: `platform_admin` or `platform_support` role

Request body:

| Field        | Type   | Required | Description            |
|--------------|--------|----------|------------------------|
| `api_key_id` | string | yes      | API key UUID to revoke |

Example:

```bash
curl -X POST "http://localhost:8080/v1/admin/keys/revoke" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"api_key_id":"<api-key-id>"}'
```

Response body:

```json
{
  "api_key_id": "<api-key-id>"
}
```

## Using Customer API Keys

Customers authenticate using the `x-releasy-api-key` header:

```bash
curl -X GET "http://localhost:8080/v1/releases?product=myapp" \
  -H "x-releasy-api-key: releasy_abc123..."
```

API keys are validated against their scopes, expiration, and revocation
status on each request.

## API Key Internals

### Usage Tracking

Each successful API key authentication updates the `last_used_at` timestamp
on the key record. This can be used to identify unused keys for cleanup.

### Hash Migration

API keys are hashed with Argon2id for storage. Keys created with older
versions (SHA256 hash) are automatically migrated to Argon2id on first
successful authentication. This migration is transparent and requires no
operator action.

### Token Format

Generated API keys follow the format `releasy_<base64-encoded-random-bytes>`.
The `releasy_` prefix allows for easy identification in logs and configs.
