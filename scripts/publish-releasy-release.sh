#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    die "missing required env var: $name"
  fi
}

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  die "python is required"
fi

require_var RELEASY_BASE_URL
require_var RELEASY_ADMIN_API_KEY
require_var RELEASY_PRODUCT
require_var RELEASY_FILE

RELEASY_BASE_URL="${RELEASY_BASE_URL%/}"
RELEASY_PLATFORM="${RELEASY_PLATFORM:-linux-x86_64}"
RELEASY_TAG="${RELEASY_TAG:-}"
RELEASY_VERSION="${RELEASY_VERSION:-}"

if [ -z "$RELEASY_VERSION" ]; then
  if [ -n "$RELEASY_TAG" ]; then
    RELEASY_VERSION="${RELEASY_TAG#v}"
  else
    die "set RELEASY_VERSION or RELEASY_TAG"
  fi
fi

if [ ! -f "$RELEASY_FILE" ]; then
  die "artifact file not found: $RELEASY_FILE"
fi

if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM="$(sha256sum "$RELEASY_FILE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  CHECKSUM="$(shasum -a 256 "$RELEASY_FILE" | awk '{print $1}')"
else
  die "sha256sum or shasum is required"
fi

if stat --version >/dev/null 2>&1; then
  SIZE="$(stat -c%s "$RELEASY_FILE")"
else
  SIZE="$(stat -f%z "$RELEASY_FILE")"
fi

gen_uuid() {
  "$PYTHON_BIN" - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

RESP_STATUS=""
RESP_BODY=""

request() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local idempotency="${4:-}"
  local url="${RELEASY_BASE_URL}${path}"
  local tmp
  tmp="$(mktemp)"

  local args=(
    -sS
    -o "$tmp"
    -w "%{http_code}"
    -X "$method"
    -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY"
  )

  if [ -n "$idempotency" ]; then
    args+=(-H "Idempotency-Key: $idempotency")
  fi

  if [ -n "$data" ]; then
    args+=(-H "content-type: application/json" -d "$data")
  fi

  RESP_STATUS="$(curl "${args[@]}" "$url")"
  RESP_BODY="$(cat "$tmp")"
  rm -f "$tmp"
}

json_get() {
  local key="$1"
  "$PYTHON_BIN" -c '
import json
import sys

key = sys.argv[1]
raw = sys.stdin.read()
if not raw.strip():
    raise SystemExit("empty response body")
data = json.loads(raw)
if key not in data:
    raise SystemExit(f"missing key: {key}")
value = data[key]
if isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
' "$key"
}

json_get_release_id() {
  "$PYTHON_BIN" -c '
import json
import sys

raw = sys.stdin.read()
if not raw.strip():
    raise SystemExit("empty response body")
data = json.loads(raw)
releases = data.get("releases") or []
if not releases:
    raise SystemExit("no releases found")
release_id = releases[0].get("id")
if not release_id:
    raise SystemExit("release id missing")
print(release_id)
'
}

json_error_message() {
  "$PYTHON_BIN" -c '
import json
import sys

raw = sys.stdin.read()
if not raw.strip():
    sys.exit(0)
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(0)
error = data.get("error") or {}
message = error.get("message")
if message:
    print(message)
'
}

expect_success() {
  local status="$1"
  local context="$2"
  if [[ "$status" =~ ^2 ]]; then
    return 0
  fi
  local msg
  msg="$(printf '%s' "$RESP_BODY" | json_error_message || true)"
  if [ -n "$msg" ]; then
    die "$context failed ($status): $msg"
  fi
  die "$context failed ($status)"
}

log "Creating or resolving release ${RELEASY_PRODUCT} ${RELEASY_VERSION}..."
request POST "/v1/releases" \
  "{\"product\":\"${RELEASY_PRODUCT}\",\"version\":\"${RELEASY_VERSION}\"}" \
  "$(gen_uuid)"

RELEASE_ID=""
if [[ "$RESP_STATUS" =~ ^2 ]]; then
  RELEASE_ID="$(printf '%s' "$RESP_BODY" | json_get id)"
elif [ "$RESP_STATUS" = "409" ]; then
  log "Release already exists, fetching id..."
  request GET "/v1/releases?product=${RELEASY_PRODUCT}&version=${RELEASY_VERSION}&limit=1&offset=0"
  expect_success "$RESP_STATUS" "List releases"
  RELEASE_ID="$(printf '%s' "$RESP_BODY" | json_get_release_id)"
else
  expect_success "$RESP_STATUS" "Create release"
fi

log "Release id: ${RELEASE_ID}"

log "Requesting presigned upload URL..."
filename="$(basename "$RELEASY_FILE")"
request POST "/v1/releases/${RELEASE_ID}/artifacts/presign" \
  "{\"filename\":\"${filename}\",\"platform\":\"${RELEASY_PLATFORM}\"}" \
  "$(gen_uuid)"
expect_success "$RESP_STATUS" "Presign artifact"

ARTIFACT_ID="$(printf '%s' "$RESP_BODY" | json_get artifact_id)"
OBJECT_KEY="$(printf '%s' "$RESP_BODY" | json_get object_key)"
UPLOAD_URL="$(printf '%s' "$RESP_BODY" | json_get upload_url)"

log "Uploading artifact to storage..."
UPLOAD_STATUS="$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$UPLOAD_URL" --data-binary @"$RELEASY_FILE")"
if [[ ! "$UPLOAD_STATUS" =~ ^2 ]]; then
  die "Upload failed ($UPLOAD_STATUS)"
fi

log "Registering artifact..."
request POST "/v1/releases/${RELEASE_ID}/artifacts" \
  "{\"artifact_id\":\"${ARTIFACT_ID}\",\"object_key\":\"${OBJECT_KEY}\",\"checksum\":\"${CHECKSUM}\",\"size\":${SIZE},\"platform\":\"${RELEASY_PLATFORM}\"}" \
  "$(gen_uuid)"
if [[ "$RESP_STATUS" =~ ^2 ]]; then
  : # ok
elif [ "$RESP_STATUS" = "409" ]; then
  msg="$(printf '%s' "$RESP_BODY" | json_error_message || true)"
  if [ -n "$msg" ]; then
    log "Artifact already exists: ${msg}"
  else
    log "Artifact already exists, continuing."
  fi
else
  expect_success "$RESP_STATUS" "Register artifact"
fi

log "Publishing release..."
publish_attempts=0
while :; do
  publish_attempts=$((publish_attempts + 1))
  request POST "/v1/releases/${RELEASE_ID}/publish"
  if [[ "$RESP_STATUS" =~ ^2 ]]; then
    break
  fi
  if [ "$RESP_STATUS" = "400" ]; then
    msg="$(printf '%s' "$RESP_BODY" | json_error_message || true)"
    if [ "$msg" = "release already published" ]; then
      log "Release already published."
      break
    fi
  fi
  if [ "$RESP_STATUS" = "409" ] && [ "$publish_attempts" -lt 2 ]; then
    log "Publish conflict, retrying..."
    sleep 1
    continue
  fi
  expect_success "$RESP_STATUS" "Publish release"
done

log "Done."
log "Release ${RELEASY_PRODUCT} ${RELEASY_VERSION} published with artifact ${ARTIFACT_ID}."
