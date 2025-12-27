# Artifacts & Presigned Uploads

Releasy supports presigned uploads to S3-compatible storage and
registering artifacts against a release.

## Configuration

Set artifact storage settings via environment variables:

```
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

```
releases/{product}/{version}/{platform}/{artifact_id}/{filename}
```

Segments are normalized to lower case and any non-alphanumeric
characters (except `.`, `-`, `_`) are replaced with `_`.

## Presign Upload

Request a presigned PUT URL:

```
POST /v1/releases/{release_id}/artifacts/presign
```

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

```
POST /v1/releases/{release_id}/artifacts
```

Request body:

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
