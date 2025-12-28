---
title: Operator Authentication and RBAC
description: Configure JWT/JWKS authentication for operators and understand role-based access control (RBAC) in Releasy.
head:
  - - meta
    - name: keywords
      content: JWT authentication, JWKS, RBAC, role-based access, operator auth, Keycloak integration
  - - meta
    - property: og:title
      content: Operator Authentication and RBAC - Releasy
  - - meta
    - property: og:description
      content: JWT/JWKS authentication and role-based access control for operators.
---

# Operator JWT and RBAC

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

```http
Authorization: Bearer <operator-jwt>
```

Admin bootstrap keys can be sent via header or as non-JWT Bearer token:

```http
x-releasy-admin-key: <admin-key>
```

or:

```http
Authorization: Bearer <admin-key>
```

### Authentication Priority

1. If `x-releasy-admin-key` header is present, Releasy validates the admin
   key first and grants `platform_admin` role on success.
2. If `Authorization: Bearer` contains a JWT (detected by two dots), Releasy
   validates via JWKS and extracts roles from claims.
3. If the Bearer token is not a JWT, Releasy treats it as an admin key.

This means admin keys always take priority when the `x-releasy-admin-key`
header is explicitly set.

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
