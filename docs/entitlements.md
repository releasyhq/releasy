---
title: Entitlements API
description: Manage customer product entitlements in Releasy with time-based validity, custom metadata, and flexible licensing controls.
head:
  - - meta
    - name: keywords
      content: entitlements API, customer licensing, product access control, subscription management, B2B licensing
  - - meta
    - property: og:title
      content: Entitlements API - Releasy
  - - meta
    - property: og:description
      content: Manage customer product entitlements with time-based validity and metadata.
---

# Entitlements

Entitlements control which release products a customer can see and download.
They are required for listing releases with an API key and for issuing download
tokens.

Entitlement timestamps are Unix seconds. An entitlement is active when
`starts_at <= now` and `ends_at` is `NULL` or in the future.

All endpoints require admin authentication (admin key or operator JWT with the
appropriate role).

Role requirements:

- List: `platform_admin` or `platform_support`
- Create/Update/Delete: `platform_admin` only

## List entitlements

`GET /v1/admin/customers/{customer_id}/entitlements`

Query parameters:

- `product`: optional product filter
- `limit`: optional page size (default `50`, max `200`, must be > 0)
- `offset`: optional page offset (default `0`)

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
  ],
  "limit": 50,
  "offset": 0
}
```

## Create entitlement

`POST /v1/admin/customers/{customer_id}/entitlements`

Notes:

- Supports `Idempotency-Key` (see `docs/api-conventions.md`).

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
