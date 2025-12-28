---
title: Getting Started with Releasy
description: Learn how to set up Releasy, create your first customer, publish a release, and enable secure downloads in this step-by-step tutorial.
head:
  - - meta
    - name: keywords
      content: Releasy tutorial, software release setup, B2B release management, getting started, quick start guide
  - - meta
    - property: og:title
      content: Getting Started with Releasy
  - - meta
    - property: og:description
      content: Step-by-step guide to set up Releasy and publish your first software release.
---

# Getting Started with Releasy

This guide walks you through setting up Releasy and publishing your first
release. By the end, you will have:

- A running Releasy instance
- A customer with an API key
- A published release with an artifact
- A working download flow

## Prerequisites

- Docker (or a Rust toolchain for building from source)
- PostgreSQL 14+ (or SQLite for local testing)
- An S3-compatible storage service (MinIO, AWS S3, etc.) for artifacts
- curl or another HTTP client for API calls

## Step 1: Start Releasy

### Option A: Docker (Recommended)

```bash
# Generate a secure admin key
export RELEASY_ADMIN_API_KEY="$(openssl rand -hex 32)"

# Start PostgreSQL
docker run -d --name releasy-db \
  -e POSTGRES_USER=releasy \
  -e POSTGRES_PASSWORD=releasy \
  -e POSTGRES_DB=releasy \
  -p 5432:5432 \
  postgres:16

# Start Releasy
docker run -d --name releasy \
  -e RELEASY_DATABASE_URL="postgres://releasy:releasy@host.docker.internal:5432/releasy" \
  -e RELEASY_ADMIN_API_KEY \
  -p 8080:8080 \
  ghcr.io/releasyhq/releasy:latest
```

### Option B: SQLite (Quick Local Testing)

```bash
export RELEASY_ADMIN_API_KEY="$(openssl rand -hex 32)"
export RELEASY_DATABASE_URL="sqlite://releasy.db"

docker run -d --name releasy \
  -e RELEASY_DATABASE_URL \
  -e RELEASY_ADMIN_API_KEY \
  -v $(pwd):/data \
  -p 8080:8080 \
  ghcr.io/releasyhq/releasy:latest
```

### Verify the Server

```bash
curl http://localhost:8080/openapi.json | head -c 100
```

You should see the beginning of the OpenAPI specification.

## Step 2: Create a Customer

Customers represent your clients who will access releases. Create one using
the admin API key:

```bash
curl -X POST http://localhost:8080/v1/admin/customers \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "plan": "enterprise"}'
```

Response:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corp",
  "plan": "enterprise",
  "created_at": 1735312000
}
```

Save the customer `id` for the next steps:

```bash
export CUSTOMER_ID="550e8400-e29b-41d4-a716-446655440000"
```

## Step 3: Create a Customer API Key

Generate an API key for the customer to use when accessing releases:

```bash
curl -X POST http://localhost:8080/v1/admin/keys \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "'"$CUSTOMER_ID"'",
    "name": "CI Pipeline Key",
    "key_type": "ci",
    "scopes": ["releases:read", "downloads:read", "downloads:token"]
  }'
```

Response:

```json
{
  "api_key_id": "key-uuid",
  "api_key": "releasy_abc123...",
  "customer_id": "550e8400-e29b-41d4-a716-446655440000",
  "key_type": "ci",
  "scopes": ["releases:read", "downloads:read", "downloads:token"],
  "expires_at": null
}
```

**Important:** Save the `api_key` value securely. It cannot be retrieved again.

```bash
export CUSTOMER_API_KEY="releasy_abc123..."
```

## Step 4: Create an Entitlement

Entitlements control which products a customer can access. Grant access to
your product:

```bash
curl -X POST "http://localhost:8080/v1/admin/customers/$CUSTOMER_ID/entitlements" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "product": "myapp",
    "starts_at": 0,
    "ends_at": null
  }'
```

Optional parameters:

- `metadata`: JSON object for custom entitlement data (e.g., `{"tier": "pro"}`)

This grants permanent access to the product `myapp`. Use `ends_at` with a Unix
timestamp to create time-limited entitlements.

## Step 5: Create a Release

Create a new release in draft status:

```bash
curl -X POST http://localhost:8080/v1/releases \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"product": "myapp", "version": "1.0.0"}'
```

Response:

```json
{
  "id": "release-uuid",
  "product": "myapp",
  "version": "1.0.0",
  "status": "draft",
  "created_at": 1735312000,
  "published_at": null
}
```

```bash
export RELEASE_ID="release-uuid"
```

## Step 6: Upload an Artifact (Optional)

If you have artifact storage configured, upload a file:

### 6a. Get a Presigned Upload URL

```bash
curl -X POST "http://localhost:8080/v1/releases/$RELEASE_ID/artifacts/presign" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"filename": "myapp-linux-amd64.tar.gz", "platform": "linux-amd64"}'
```

Response:

```json
{
  "artifact_id": "artifact-uuid",
  "object_key": "releases/myapp/1.0.0/linux-amd64/artifact-uuid/myapp-linux-amd64.tar.gz",
  "upload_url": "https://s3.example.com/...",
  "expires_at": 1735312900
}
```

### 6b. Upload the File

```bash
curl -X PUT "$UPLOAD_URL" \
  --data-binary @myapp-linux-amd64.tar.gz
```

### 6c. Register the Artifact

```bash
# Calculate checksum
CHECKSUM=$(sha256sum myapp-linux-amd64.tar.gz | cut -d' ' -f1)
SIZE=$(stat -c%s myapp-linux-amd64.tar.gz)

curl -X POST "http://localhost:8080/v1/releases/$RELEASE_ID/artifacts" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "artifact_id": "artifact-uuid",
    "object_key": "releases/myapp/1.0.0/linux-amd64/artifact-uuid/myapp-linux-amd64.tar.gz",
    "checksum": "'"$CHECKSUM"'",
    "size": '"$SIZE"',
    "platform": "linux-amd64"
  }'
```

## Step 7: Publish the Release

Make the release available to customers:

```bash
curl -X POST "http://localhost:8080/v1/releases/$RELEASE_ID/publish" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY"
```

The release status changes to `published` and `published_at` is set.

## Step 8: Access as a Customer

Now test the customer experience using the customer API key:

### List Available Releases

```bash
curl -X GET "http://localhost:8080/v1/releases?product=myapp" \
  -H "x-releasy-api-key: $CUSTOMER_API_KEY"
```

Customers only see `published` releases for products they have entitlements to.

### Get a Download Token

```bash
curl -X POST http://localhost:8080/v1/downloads/token \
  -H "x-releasy-api-key: $CUSTOMER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"artifact_id": "artifact-uuid", "expires_in_seconds": 300}'
```

Optional parameters:

- `purpose`: free-form string to identify the token usage (e.g., `"ci"`)

Response:

```json
{
  "download_url": "http://localhost:8080/v1/downloads/token-string",
  "expires_at": 1735312300
}
```

### Download the Artifact

```bash
curl -L "$DOWNLOAD_URL" -o myapp-linux-amd64.tar.gz
```

The download URL redirects (302) to a presigned S3 URL.

## Next Steps

- [Configuration](configuration.md) – All environment variables
- [Operator Auth](operator-auth.md) – Set up JWT authentication for operators
- [Deployment](deployment.md) – Production deployment patterns
- [API Conventions](api-conventions.md) – Error handling and idempotency

## Troubleshooting

### "unauthorized" Error

- Verify `RELEASY_ADMIN_API_KEY` matches between server and requests
- Check the header name: `x-releasy-admin-key` for admin, `x-releasy-api-key`
  for customers

### "entitlement required" Error

- Ensure the customer has an active entitlement for the product
- Check that `starts_at` is in the past and `ends_at` is null or in the future

### "artifact storage not configured" Error

Set the S3 environment variables. See [Configuration](configuration.md#artifact-storage-s3).

### Database Connection Errors

- Verify `RELEASY_DATABASE_URL` is correct
- Ensure the database is running and accessible
- Check network connectivity between Releasy and the database
