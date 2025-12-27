# Audit Events (Core)

Core stores security-relevant audit data locally in the primary database. The
current implementation focuses on API key authentication events and is intended
for self-hosted operators to inspect when debugging access issues.

## Storage Schema

Audit events are stored in the `audit_events` table:

- `id` (TEXT, PK)
- `customer_id` (TEXT, nullable)
- `actor` (TEXT)
- `event` (TEXT)
- `payload` (TEXT, nullable, JSON string)
- `created_at` (INTEGER, unix timestamp seconds)

## Event Catalog

Core currently emits a single event family for API key authentication.

### api_key.auth

- `actor`: `api_key`
- `event`: `api_key.auth`
- `payload` (JSON):
    - `outcome`: `accept` or `reject`
    - `reason`:
        - `ok`
        - `missing_header`
        - `not_found`
        - `revoked`
        - `expired`
        - `invalid_scopes`
        - `time_unavailable`
    - `api_key_id`: nullable string (when known)

Example payload:

```json
{
  "outcome": "reject",
  "reason": "expired",
  "api_key_id": "key_01h..."
}
```

Notes:

- `customer_id` is populated when the key is resolved; otherwise it is `NULL`.
- Events are best-effort. If system time is unavailable, the event is skipped
  and a warning is logged.
- Payloads must not include secrets. Use IDs and short reason codes only.

## Retention

Core does not enforce retention or automatic cleanup. Operators control data
lifecycle using database tooling (manual SQL, scheduled jobs, or retention
policies). Recommended practice:

- Keep audit events for a minimum operational window (for example 90 days).
- Purge or archive older rows based on your compliance requirements.

See `docs/audit-retention.md` for SQL templates.

## Access Model

## Read API

`GET /v1/admin/audit-events`

Query parameters (optional):

- `customer_id`: filter events for a specific customer
- `actor`: filter by actor (for example `api_key`)
- `event`: filter by event name (for example `api_key.auth`)
- `limit` / `offset`: pagination (see `docs/api-conventions.md`)

Response body:

```json
{
  "events": [
    {
      "id": "evt_...",
      "customer_id": "cust_...",
      "actor": "api_key",
      "event": "api_key.auth",
      "payload": {
        "outcome": "accept",
        "reason": "ok",
        "api_key_id": "key_..."
      },
      "created_at": 1700000000
    }
  ],
  "limit": 50,
  "offset": 0
}
```

## Access Model

Audit events are available only to the admin/operator authorization flow:

- `platform_admin`: read access
- `platform_support`: read access
- `release_publisher`: no access
- customer-level credentials: no access

Customer API keys are not permitted to read audit events. If a customer-facing
read API is introduced later, it will be gated behind a dedicated scope (for
example `audit:read`).
