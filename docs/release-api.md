---
title: Release API Reference
description: Complete API reference for managing software releases in Releasy, including create, list, publish, unpublish, and delete operations.
head:
  - - meta
    - name: keywords
      content: Release API, software versioning, release management, publish release, draft release, REST API
  - - meta
    - property: og:title
      content: Release API Reference - Releasy
  - - meta
    - property: og:description
      content: API endpoints for creating, publishing, and managing software releases.
---

# Release API

The Release API manages release lifecycle entries (draft -> published) and
supports filtering/pagination for operators.

## Authentication and RBAC

Release endpoints accept either an operator JWT or the admin bootstrap key.

- Operator JWT (preferred):
  - Header: `Authorization: Bearer <jwt>`
  - Roles: `platform_admin`, `platform_support`, `release_publisher`
- Admin key (bootstrap):
  - Header: `x-releasy-admin-key: <admin_key>`
  - Or `Authorization: Bearer <admin_key>` (non-JWT value)

Role requirements:

- Create/publish: `platform_admin` or `release_publisher`
- Unpublish/delete: `platform_admin`
- List: `platform_admin`, `platform_support`, or `release_publisher`

For JWT configuration details, see `operator-auth.md`. For admin bootstrap
setup, see `admin-bootstrap.md`.

## Release model

Fields returned by the API:

- `id`: UUID
- `product`: product identifier (string)
- `version`: version string
- `status`: `draft` or `published`
- `created_at`: unix timestamp (seconds)
- `published_at`: unix timestamp (seconds) or `null`

Lifecycle rules:

- New releases are created in `draft`.
- Publishing sets `status = published` and `published_at = now`.
- Unpublishing sets `status = draft` and clears `published_at`.

## Endpoints

### Create release

`POST /v1/releases`

Request body:

```json
{
  "product": "releasy",
  "version": "1.2.3"
}
```

Response body:

```json
{
  "id": "<uuid>",
  "product": "releasy",
  "version": "1.2.3",
  "status": "draft",
  "created_at": 1735312000,
  "published_at": null
}
```

Example:

```bash
curl -X POST http://localhost:8080/v1/releases \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <jwt>' \
  -d '{"product":"releasy","version":"1.2.3"}'
```

Notes:

- Returns `409 Conflict` with `"release already exists"` if a release with
  the same product and version already exists.
- Supports `Idempotency-Key` (see `docs/api-conventions.md`).

### List releases

`GET /v1/releases`

Authentication:

- Admin operators: `Authorization: Bearer <jwt>` with `platform_admin`,
  `platform_support`, or `release_publisher` roles. Admins can filter by any
  status.
- API keys: `x-releasy-api-key: <api_key>` with `releases:read` scope. API keys
  only see `published` releases for products with an active entitlement.

Query parameters:

- `product`: optional product filter
- `version`: optional version filter
- `status`: optional status filter (`draft` or `published`). For API keys,
  `status` must be `published`.
- `include_artifacts`: optional boolean to include artifact summaries
- `limit`: optional page size (default `50`, max `200`, must be > 0)
- `offset`: optional page offset (default `0`)

Response body:

```json
{
  "releases": [
    {
      "id": "<uuid>",
      "product": "releasy",
      "version": "1.2.3",
      "status": "published",
      "created_at": 1735312000,
      "published_at": 1735312600,
      "artifacts": null
    }
  ],
  "limit": 50,
  "offset": 0
}
```

Example:

```bash
curl -X GET 'http://localhost:8080/v1/releases?product=releasy&status=published' \
  -H 'Authorization: Bearer <jwt>'
```

API key example:

```bash
curl -X GET 'http://localhost:8080/v1/releases?include_artifacts=true' \
  -H 'x-releasy-api-key: <api_key>'
```

### Publish release

`POST /v1/releases/{release_id}/publish`

Example:

```bash
curl -X POST http://localhost:8080/v1/releases/<release_id>/publish \
  -H 'Authorization: Bearer <jwt>'
```

Notes:

- If the release is already published, the API returns `400` with
  `"release already published"`.
- Returns `409 Conflict` with `"release status changed, retry"` if a
  concurrent update occurred. Retry the request in this case.

### Unpublish release

`POST /v1/releases/{release_id}/unpublish`

Example:

```bash
curl -X POST http://localhost:8080/v1/releases/<release_id>/unpublish \
  -H 'Authorization: Bearer <jwt>'
```

Notes:

- Requires `platform_admin`.
- If the release is already draft, the API returns `400` with
  `"release already draft"`.
- Returns `409 Conflict` with `"release status changed, retry"` if a
  concurrent update occurred. Retry the request in this case.

### Delete release

`DELETE /v1/releases/{release_id}`

Example:

```bash
curl -X DELETE http://localhost:8080/v1/releases/<release_id> \
  -H 'Authorization: Bearer <jwt>'
```

Returns `204 No Content` on success.
