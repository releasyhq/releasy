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
require_var RELEASY_CUSTOMER_NAME
require_var RELEASY_PRODUCT

RELEASY_BASE_URL="${RELEASY_BASE_URL%/}"
RELEASY_PLAN="${RELEASY_PLAN:-}"
RELEASY_KEY_NAME="${RELEASY_KEY_NAME:-CI Key}"
RELEASY_KEY_TYPE="${RELEASY_KEY_TYPE:-ci}"
RELEASY_SCOPES="${RELEASY_SCOPES:-releases:read,downloads:read,downloads:token}"
RELEASY_KEY_EXPIRES_AT="${RELEASY_KEY_EXPIRES_AT:-}"
RELEASY_ENTITLEMENT_STARTS_AT="${RELEASY_ENTITLEMENT_STARTS_AT:-}"
RELEASY_ENTITLEMENT_ENDS_AT="${RELEASY_ENTITLEMENT_ENDS_AT:-}"
RELEASY_ENTITLEMENT_METADATA="${RELEASY_ENTITLEMENT_METADATA:-}"

if [ -z "$RELEASY_ENTITLEMENT_STARTS_AT" ]; then
  RELEASY_ENTITLEMENT_STARTS_AT="$(date +%s)"
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
  "$PYTHON_BIN" - "$key" <<'PY'
import json
import sys

key = sys.argv[1]
data = json.load(sys.stdin)
if key not in data:
    raise SystemExit(f"missing key: {key}")
value = data[key]
if isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
PY
}

json_error_message() {
  "$PYTHON_BIN" - <<'PY'
import json
import sys

try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(0)
error = data.get("error") or {}
message = error.get("message")
if message:
    print(message)
PY
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

customer_payload="$(
  RELEASY_CUSTOMER_NAME="$RELEASY_CUSTOMER_NAME" \
  RELEASY_PLAN="$RELEASY_PLAN" \
  "$PYTHON_BIN" - <<'PY'
import json
import os

name = os.environ["RELEASY_CUSTOMER_NAME"].strip()
plan = os.environ.get("RELEASY_PLAN", "").strip()
if not name:
    raise SystemExit("customer name is required")
payload = {"name": name}
if plan:
    payload["plan"] = plan
print(json.dumps(payload))
PY
)"

log "Creating customer..."
request POST "/v1/admin/customers" "$customer_payload" "$(gen_uuid)"
expect_success "$RESP_STATUS" "Create customer"
CUSTOMER_ID="$(printf '%s' "$RESP_BODY" | json_get id)"

scopes_json="$(
  RELEASY_SCOPES="$RELEASY_SCOPES" \
  "$PYTHON_BIN" - <<'PY'
import json
import os

raw = os.environ.get("RELEASY_SCOPES", "").strip()
if not raw:
    raise SystemExit("scopes must not be empty")
if raw.startswith("["):
    scopes = json.loads(raw)
    if not isinstance(scopes, list):
        raise SystemExit("scopes JSON must be an array")
else:
    scopes = [item.strip() for item in raw.split(",") if item.strip()]
if not scopes:
    raise SystemExit("scopes must not be empty")
print(json.dumps(scopes))
PY
)"

key_payload="$(
  CUSTOMER_ID="$CUSTOMER_ID" \
  RELEASY_KEY_NAME="$RELEASY_KEY_NAME" \
  RELEASY_KEY_TYPE="$RELEASY_KEY_TYPE" \
  RELEASY_KEY_EXPIRES_AT="$RELEASY_KEY_EXPIRES_AT" \
  SCOPES_JSON="$scopes_json" \
  "$PYTHON_BIN" - <<'PY'
import json
import os

customer_id = os.environ["CUSTOMER_ID"]
name = os.environ.get("RELEASY_KEY_NAME", "").strip()
key_type = os.environ.get("RELEASY_KEY_TYPE", "").strip()
scopes_json = os.environ["SCOPES_JSON"]
expires_at = os.environ.get("RELEASY_KEY_EXPIRES_AT", "").strip()

payload = {"customer_id": customer_id}
if name:
    payload["name"] = name
if key_type:
    payload["key_type"] = key_type
payload["scopes"] = json.loads(scopes_json)
if expires_at:
    payload["expires_at"] = int(expires_at)

print(json.dumps(payload))
PY
)"

log "Creating API key..."
request POST "/v1/admin/keys" "$key_payload"
expect_success "$RESP_STATUS" "Create API key"
API_KEY_ID="$(printf '%s' "$RESP_BODY" | json_get api_key_id)"
API_KEY="$(printf '%s' "$RESP_BODY" | json_get api_key)"

entitlement_payload="$(
  RELEASY_PRODUCT="$RELEASY_PRODUCT" \
  RELEASY_ENTITLEMENT_STARTS_AT="$RELEASY_ENTITLEMENT_STARTS_AT" \
  RELEASY_ENTITLEMENT_ENDS_AT="$RELEASY_ENTITLEMENT_ENDS_AT" \
  RELEASY_ENTITLEMENT_METADATA="$RELEASY_ENTITLEMENT_METADATA" \
  "$PYTHON_BIN" - <<'PY'
import json
import os

product = os.environ["RELEASY_PRODUCT"].strip()
starts_at_raw = os.environ["RELEASY_ENTITLEMENT_STARTS_AT"].strip()
ends_at_raw = os.environ.get("RELEASY_ENTITLEMENT_ENDS_AT", "").strip()
metadata_raw = os.environ.get("RELEASY_ENTITLEMENT_METADATA", "").strip()

if not product:
    raise SystemExit("product is required")

starts_at = int(starts_at_raw)
if starts_at <= 0:
    raise SystemExit("starts_at must be positive")

payload = {"product": product, "starts_at": starts_at, "ends_at": None}

if ends_at_raw:
    if ends_at_raw.lower() == "null":
        payload["ends_at"] = None
    else:
        payload["ends_at"] = int(ends_at_raw)

if payload["ends_at"] is not None and payload["ends_at"] < starts_at:
    raise SystemExit("ends_at must be >= starts_at")

if metadata_raw:
    payload["metadata"] = json.loads(metadata_raw)

print(json.dumps(payload))
PY
)"

log "Creating entitlement..."
request POST "/v1/admin/customers/${CUSTOMER_ID}/entitlements" \
  "$entitlement_payload" \
  "$(gen_uuid)"
expect_success "$RESP_STATUS" "Create entitlement"
ENTITLEMENT_ID="$(printf '%s' "$RESP_BODY" | json_get id)"

log "Done."
log "Customer ID: ${CUSTOMER_ID}"
log "API key ID: ${API_KEY_ID}"
log "API key: ${API_KEY}"
log "Entitlement ID: ${ENTITLEMENT_ID}"
log ""
log "Export:"
log "export RELEASY_CUSTOMER_ID=\"${CUSTOMER_ID}\""
log "export RELEASY_API_KEY=\"${API_KEY}\""
log "export RELEASY_ENTITLEMENT_ID=\"${ENTITLEMENT_ID}\""
