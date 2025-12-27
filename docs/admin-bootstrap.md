# Admin Bootstrap

## Purpose

Releasy uses a single admin bootstrap key to perform initial setup tasks.
This key is required for admin endpoints and is not meant for customer use.

## Configure the Admin Key

1) Generate a random key (example):

   openssl rand -hex 32

2) Export it before starting the server:

   export RELEASY_ADMIN_API_KEY="<your-random-key>"

## Create the First Customer

```bash
curl -X POST "http://localhost:8080/v1/admin/customers" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"name":"Acme","plan":"core"}'
```

The response includes the new customer id.

## Create a Customer API Key

```bash
curl -X POST "http://localhost:8080/v1/admin/keys" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"customer_id":"<customer-id>"}'
```

The response includes the raw API key. Store it securely.

## Revoke an API Key

```bash
curl -X POST "http://localhost:8080/v1/admin/keys/revoke" \
  -H "x-releasy-admin-key: $RELEASY_ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"api_key_id":"<api-key-id>"}'
```
