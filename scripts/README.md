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
