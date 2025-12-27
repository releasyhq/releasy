# Entitlements

Entitlements control which release products a customer can see and download.
They are required for listing releases with an API key and for issuing download
tokens.

Entitlement timestamps are Unix seconds. An entitlement is active when
`starts_at <= now` and `ends_at` is `NULL` or in the future.

All endpoints require admin authentication (admin key or operator JWT with the
appropriate role).

## List entitlements

`GET /v1/admin/customers/{customer_id}/entitlements`

Response body:

```json
{
  "entitlements": [
    {
      "id": "<uuid>",
      "customer_id": "<uuid>",
      "product": "releasy",
      "starts_at": 1735312000,
      "ends_at": 1737914000,
      "metadata": {
        "tier": "pro"
      }
    }
  ]
}
```

## Create entitlement

`POST /v1/admin/customers/{customer_id}/entitlements`

Request body:

```json
{
  "product": "releasy",
  "starts_at": 1735312000,
  "ends_at": 1737914000,
  "metadata": {
    "tier": "pro"
  }
}
```

Notes:

- `starts_at` must be positive.
- `ends_at`, when provided, must be greater than or equal to `starts_at`.

## Update entitlement

`PATCH /v1/admin/customers/{customer_id}/entitlements/{entitlement_id}`

Request body:

```json
{
  "product": "releasy",
  "starts_at": 1735312000,
  "ends_at": null,
  "metadata": null
}
```

Notes:

- All fields are optional.
- Use `null` for `ends_at` or `metadata` to clear them.

## Delete entitlement

`DELETE /v1/admin/customers/{customer_id}/entitlements/{entitlement_id}`
