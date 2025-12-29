# Scripts

Automation scripts live here.

## publish-releasy-release.sh

Publishes a release and artifact to a Releasy instance.

Required environment variables:

- `RELEASY_BASE_URL`
- `RELEASY_ADMIN_API_KEY`
- `RELEASY_PRODUCT`
- `RELEASY_VERSION` (or `RELEASY_TAG`)
- `RELEASY_FILE`

Optional:

- `RELEASY_PLATFORM` (default: `linux-x86_64`)

## create-releasy-customer.sh

Creates a customer, API key, and entitlement.

Required environment variables:

- `RELEASY_BASE_URL`
- `RELEASY_ADMIN_API_KEY`
- `RELEASY_CUSTOMER_NAME`
- `RELEASY_PRODUCT`

Optional:

- `RELEASY_PLAN`
- `RELEASY_KEY_NAME` (default: `CI Key`)
- `RELEASY_KEY_TYPE` (default: `ci`)
- `RELEASY_SCOPES` (default: `releases:read,downloads:read,downloads:token`)
- `RELEASY_KEY_EXPIRES_AT` (unix seconds)
- `RELEASY_ENTITLEMENT_STARTS_AT` (unix seconds, default: now)
- `RELEASY_ENTITLEMENT_ENDS_AT` (unix seconds or `null`)
- `RELEASY_ENTITLEMENT_METADATA` (JSON object)
