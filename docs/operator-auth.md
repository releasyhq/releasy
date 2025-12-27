# Operator JWT & RBAC

Releasy supports operator authentication using JWTs verified via JWKS.
When enabled, operator tokens authorize admin endpoints with role-based
access control (RBAC).

## Enable Operator JWT

Set the JWKS URL to enable JWT validation:

```bash
export RELEASY_OPERATOR_JWKS_URL="https://id.example.com/.well-known/jwks.json"
```

Optional validation settings:

```bash
export RELEASY_OPERATOR_ISSUER="https://id.example.com/"
export RELEASY_OPERATOR_AUDIENCE="releasy"
export RELEASY_OPERATOR_RESOURCE="releasy"
export RELEASY_OPERATOR_JWKS_TTL_SECONDS=300
export RELEASY_OPERATOR_JWT_LEEWAY_SECONDS=0
```

If `RELEASY_OPERATOR_JWKS_URL` is not set, operator JWT auth is disabled
and only the admin bootstrap key is accepted for admin endpoints.

## Request Authentication

Send operator JWTs as Bearer tokens:

```
Authorization: Bearer <operator-jwt>
```

Admin bootstrap keys continue to work via:

```
x-releasy-admin-key: <admin-key>
```

## Role Extraction

Roles are collected from these claims (all are merged):

- `roles`
- `realm_access.roles`
- `resource_access.<RELEASY_OPERATOR_RESOURCE>.roles`

## Role Mapping

Releasy maps roles to admin permissions:

- `platform_admin`: full access
- `platform_support`: support-level access (subset of admin endpoints)
- `release_publisher`: release publishing access

Requests without a mapped role are rejected.
