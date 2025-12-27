# Configuration

Releasy is configured via environment variables. This document lists all
available settings.

## Server

| Variable            | Required | Default        | Description                                          |
|---------------------|----------|----------------|------------------------------------------------------|
| `RELEASY_BIND_ADDR` | no       | `0.0.0.0:8080` | Address and port to bind the server                  |
| `RELEASY_LOG_LEVEL` | no       | `info`         | Log level: `trace`, `debug`, `info`, `warn`, `error` |

## Database

| Variable                           | Required | Default | Description                       |
|------------------------------------|----------|---------|-----------------------------------|
| `RELEASY_DATABASE_URL`             | yes      | -       | Database connection string        |
| `RELEASY_DATABASE_MAX_CONNECTIONS` | no       | `5`     | Maximum database pool connections |

Supported databases:

- **PostgreSQL**: `postgres://user:pass@host:5432/dbname`
- **SQLite**: `sqlite:path/to/db.sqlite` or `sqlite::memory:`

## Authentication

### Admin Bootstrap Key

| Variable                | Required | Default | Description                           |
|-------------------------|----------|---------|---------------------------------------|
| `RELEASY_ADMIN_API_KEY` | no       | -       | Admin bootstrap key for initial setup |

Generate a secure key:

```bash
openssl rand -hex 32
```

### API Key Security

| Variable                 | Required | Default | Description                           |
|--------------------------|----------|---------|---------------------------------------|
| `RELEASY_API_KEY_PEPPER` | no       | -       | Additional secret for API key hashing |

The pepper adds an extra layer of security to API key hashes. If set,
it should be kept constant; changing it will invalidate all existing keys.
API keys are hashed with Argon2id using a per-key salt.

### Operator JWT (JWKS)

| Variable                              | Required | Default | Description                               |
|---------------------------------------|----------|---------|-------------------------------------------|
| `RELEASY_OPERATOR_JWKS_URL`           | no       | -       | JWKS endpoint URL for JWT validation      |
| `RELEASY_OPERATOR_ISSUER`             | no       | -       | Expected JWT issuer (`iss` claim)         |
| `RELEASY_OPERATOR_AUDIENCE`           | no       | -       | Expected JWT audience (`aud` claim)       |
| `RELEASY_OPERATOR_RESOURCE`           | no       | -       | Resource name for `resource_access` roles |
| `RELEASY_OPERATOR_JWKS_TTL_SECONDS`   | no       | `300`   | JWKS cache TTL in seconds                 |
| `RELEASY_OPERATOR_JWT_LEEWAY_SECONDS` | no       | `0`     | Clock skew tolerance for JWT validation   |

Example for Keycloak:

```bash
export RELEASY_OPERATOR_JWKS_URL="https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
export RELEASY_OPERATOR_ISSUER="https://keycloak.example.com/realms/myrealm"
export RELEASY_OPERATOR_AUDIENCE="releasy"
export RELEASY_OPERATOR_RESOURCE="releasy"
```

## Downloads

| Variable                             | Required | Default | Description                                    |
|--------------------------------------|----------|---------|------------------------------------------------|
| `RELEASY_DOWNLOAD_TOKEN_TTL_SECONDS` | no       | `600`   | Maximum lifetime for download tokens (seconds) |

## Artifact Storage (S3)

All artifact variables must be set together, or none at all.

| Variable                                   | Required | Default | Description                               |
|--------------------------------------------|----------|---------|-------------------------------------------|
| `RELEASY_ARTIFACT_BUCKET`                  | yes*     | -       | S3 bucket name                            |
| `RELEASY_ARTIFACT_REGION`                  | yes*     | -       | S3 region (e.g., `us-east-1`)             |
| `RELEASY_ARTIFACT_ENDPOINT`                | no       | -       | Custom S3 endpoint (for MinIO, etc.)      |
| `RELEASY_ARTIFACT_ACCESS_KEY`              | yes*     | -       | S3 access key                             |
| `RELEASY_ARTIFACT_SECRET_KEY`              | yes*     | -       | S3 secret key                             |
| `RELEASY_ARTIFACT_PATH_STYLE`              | no       | `false` | Use path-style URLs (required for MinIO)  |
| `RELEASY_ARTIFACT_PRESIGN_EXPIRES_SECONDS` | no       | `900`   | Presigned URL expiration (15 min default) |

*Required if artifact storage is enabled.

Example for MinIO:

```bash
export RELEASY_ARTIFACT_BUCKET="releasy-artifacts"
export RELEASY_ARTIFACT_REGION="us-east-1"
export RELEASY_ARTIFACT_ENDPOINT="http://localhost:9000"
export RELEASY_ARTIFACT_ACCESS_KEY="minioadmin"
export RELEASY_ARTIFACT_SECRET_KEY="minioadmin"
export RELEASY_ARTIFACT_PATH_STYLE="true"
```

Example for AWS S3:

```bash
export RELEASY_ARTIFACT_BUCKET="my-releasy-bucket"
export RELEASY_ARTIFACT_REGION="eu-central-1"
export RELEASY_ARTIFACT_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
export RELEASY_ARTIFACT_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

## Complete Example

```bash
# Server
export RELEASY_BIND_ADDR="0.0.0.0:8080"
export RELEASY_LOG_LEVEL="info"

# Database
export RELEASY_DATABASE_URL="postgres://releasy:secret@localhost:5432/releasy"
export RELEASY_DATABASE_MAX_CONNECTIONS="10"

# Auth
export RELEASY_ADMIN_API_KEY="$(openssl rand -hex 32)"
export RELEASY_API_KEY_PEPPER="$(openssl rand -hex 32)"

# Operator JWT (optional)
export RELEASY_OPERATOR_JWKS_URL="https://id.example.com/.well-known/jwks.json"
export RELEASY_OPERATOR_ISSUER="https://id.example.com/"
export RELEASY_OPERATOR_AUDIENCE="releasy"

# Artifact storage (optional)
export RELEASY_ARTIFACT_BUCKET="releasy-artifacts"
export RELEASY_ARTIFACT_REGION="us-east-1"
export RELEASY_ARTIFACT_ACCESS_KEY="access"
export RELEASY_ARTIFACT_SECRET_KEY="secret"
```
