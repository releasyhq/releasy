---
title: Artifacts and Presigned Uploads
description: Learn how to upload and register artifacts in Releasy using presigned S3 URLs for secure, direct-to-storage uploads.
head:
  - - meta
    - name: keywords
      content: artifact upload, presigned URL, S3 upload, file distribution, binary hosting, release artifacts
  - - meta
    - property: og:title
      content: Artifacts and Presigned Uploads - Releasy
  - - meta
    - property: og:description
      content: Upload and register release artifacts using presigned S3 URLs.
---

# Artifacts and Presigned Uploads

Releasy supports presigned uploads to S3-compatible storage and
registering artifacts against a release.

## Authentication and RBAC

Artifact endpoints require operator authentication with either:

- `platform_admin` role, or
- `release_publisher` role

See [operator-auth.md](operator-auth.md) for authentication details.

## Configuration

Set artifact storage settings via environment variables:

```bash
RELEASY_ARTIFACT_BUCKET=releasy-artifacts
RELEASY_ARTIFACT_REGION=us-east-1
RELEASY_ARTIFACT_ENDPOINT=https://s3.example.com
RELEASY_ARTIFACT_ACCESS_KEY=access
RELEASY_ARTIFACT_SECRET_KEY=secret
RELEASY_ARTIFACT_PATH_STYLE=true
RELEASY_ARTIFACT_PRESIGN_EXPIRES_SECONDS=900
```

## Object Key Schema

Object keys are generated as:

```text
releases/{product}/{version}/{platform}/{artifact_id}/{filename}
```

Segments are normalized to lower case and any non-alphanumeric
characters (except `.`, `-`, `_`) are replaced with `_`.

## Presign Upload

Request a presigned PUT URL:

```http
POST /v1/releases/{release_id}/artifacts/presign
```

Notes:

- Supports `Idempotency-Key` (see `docs/api-conventions.md`).

Request body:

```json
{
  "filename": "linux.tar.gz",
  "platform": "linux-x86_64"
}
```

Response body:

```json
{
  "artifact_id": "uuid",
  "object_key": "releases/releasy/1.0.0/linux-x86_64/uuid/linux.tar.gz",
  "upload_url": "https://...",
  "expires_at": 1735300000
}
```

Example:

```bash
curl -X POST \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"filename":"linux.tar.gz","platform":"linux-x86_64"}' \
  http://localhost:8080/v1/releases/$RELEASE_ID/artifacts/presign
```

## Register Artifact

After uploading, register the artifact with its metadata:

```http
POST /v1/releases/{release_id}/artifacts
```

Notes:

- Supports `Idempotency-Key` (see `docs/api-conventions.md`).

Request body:

| Field         | Type    | Required | Description                           |
|---------------|---------|----------|---------------------------------------|
| `artifact_id` | string  | yes      | UUID from presign response            |
| `object_key`  | string  | yes      | Object key from presign response      |
| `checksum`    | string  | yes      | SHA256 checksum (64 hex characters)   |
| `size`        | integer | yes      | File size in bytes (must be positive) |
| `platform`    | string  | yes      | Platform identifier                   |

Example request body:

```json
{
  "artifact_id": "uuid",
  "object_key": "releases/releasy/1.0.0/linux-x86_64/uuid/linux.tar.gz",
  "checksum": "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
  "size": 1024,
  "platform": "linux-x86_64"
}
```

Response body:

```json
{
  "id": "uuid",
  "release_id": "release-id",
  "object_key": "releases/releasy/1.0.0/linux-x86_64/uuid/linux.tar.gz",
  "checksum": "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
  "size": 1024,
  "platform": "linux-x86_64",
  "created_at": 1735300000
}
```

Example:

```bash
curl -X POST \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"artifact_id":"...","object_key":"...","checksum":"...","size":1024,"platform":"linux-x86_64"}' \
  http://localhost:8080/v1/releases/$RELEASE_ID/artifacts
```

## Error Responses

| Status                    | Message                                         | Cause                            |
|---------------------------|-------------------------------------------------|----------------------------------|
| `400 Bad Request`         | `checksum must be a 64 character hex string`    | Invalid checksum format          |
| `400 Bad Request`         | `size must be positive`                         | Size is zero or negative         |
| `400 Bad Request`         | `object_key does not match release or platform` | Object key doesn't match presign |
| `404 Not Found`           | `release not found`                             | Release ID doesn't exist         |
| `409 Conflict`            | `artifact already exists`                       | Duplicate artifact registration  |
| `503 Service Unavailable` | `artifact storage not configured`               | Missing S3 configuration         |
