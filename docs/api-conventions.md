---
title: API Conventions
description: Understand Releasy API conventions including error responses, idempotency keys, and pagination parameters for consistent API integration.
head:
  - - meta
    - name: keywords
      content: Releasy API, error handling, idempotency, pagination, REST API conventions
  - - meta
    - property: og:title
      content: API Conventions - Releasy
  - - meta
    - property: og:description
      content: Error handling, idempotency, and pagination conventions for the Releasy API.
---

# API Conventions

All endpoints follow these API conventions.

## Error schema

All error responses use a consistent JSON shape:

```json
{
  "error": {
    "code": "bad_request",
    "message": "human-readable error message"
  }
}
```

The `code` field is stable for programmatic handling. Common codes:

- `bad_request` (400)
- `unauthorized` (401)
- `forbidden` (403)
- `not_found` (404)
- `conflict` (409)
- `service_unavailable` (503)
- `internal_error` (500 and other server errors)

Additional conflict codes may be returned for idempotency, such as
`idempotency_conflict` or `idempotency_in_progress`.

## Idempotency

Idempotency is supported for create-style endpoints that return non-sensitive
payloads. Clients may supply an `Idempotency-Key` header (ASCII, max 128
characters). Reusing the same key with the same request body returns the
original response. Reusing the same key with a different request body returns
`409 Conflict` (`idempotency_conflict`).

If a request with the same key is currently in progress, the API returns
`409 Conflict` (`idempotency_in_progress`). Retry with the same key.

Note: `POST /v1/admin/keys` does not accept `Idempotency-Key` because the API
key secret is returned only once.

## Pagination and filtering

List endpoints use consistent pagination parameters:

- `limit`: page size (default `50`, max `200`, must be > 0)
- `offset`: page offset (default `0`)

Filtering parameters, when available, are optional and ignore empty values.
See each endpoint's documentation for supported filters.
