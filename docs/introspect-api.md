# API Key Introspection

The introspection endpoint allows API key holders to inspect their own
key metadata, including scopes and expiration.

## Authentication

This endpoint requires a customer API key with the `keys:read` scope:

```
x-releasy-api-key: <api-key>
```

## Introspect API Key

`POST /v1/auth/introspect`

Returns information about the authenticated API key.

Response body:

```json
{
  "active": true,
  "api_key_id": "<uuid>",
  "customer_id": "<uuid>",
  "key_type": "human",
  "scopes": [
    "releases:read",
    "downloads:read",
    "keys:read"
  ],
  "expires_at": null
}
```

| Field         | Type            | Description                                            |
|---------------|-----------------|--------------------------------------------------------|
| `active`      | boolean         | Always `true` for valid keys                           |
| `api_key_id`  | string          | UUID of the API key                                    |
| `customer_id` | string          | UUID of the customer                                   |
| `key_type`    | string          | Key type: `human`, `ci`, or `integration`              |
| `scopes`      | array           | List of granted scopes                                 |
| `expires_at`  | integer or null | Unix timestamp of expiration, or null if no expiration |

Example:

```bash
curl -X POST "http://localhost:8080/v1/auth/introspect" \
  -H "x-releasy-api-key: releasy_abc123..."
```

## Error Responses

| Status             | Cause                           |
|--------------------|---------------------------------|
| `401 Unauthorized` | Missing or invalid API key      |
| `403 Forbidden`    | API key lacks `keys:read` scope |
