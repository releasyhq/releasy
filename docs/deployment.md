---
title: Deployment Patterns
description: Self-hosted deployment patterns for Releasy including single-host and split topologies, network requirements, and rollout strategies.
head:
  - - meta
    - name: keywords
      content: self-hosted deployment, Docker deployment, reverse proxy, blue-green deployment, rolling updates
  - - meta
    - property: og:title
      content: Deployment Patterns - Releasy
  - - meta
    - property: og:description
      content: Self-hosted deployment topologies and rollout strategies for Releasy.
---

# Deployment Patterns

Releasy is designed to run behind a reverse proxy with a database. This
guide documents two reference topologies, network/firewall requirements,
and rollout strategies for self-hosted deployments.

## Reference Topologies

### Single-host (dev/test)

All components live on one host. This is suitable for local evaluation
or small single-node installs.

```text
Internet
   |
[Reverse Proxy]
   |
[releasy-server] -- [Postgres]
```

Notes:

- SQLite can replace Postgres for local development.
- The reverse proxy handles TLS termination and routes requests to the
  Releasy server port (see `RELEASY_BIND_ADDR`).

### Split app/db/proxy (prod)

Separate hosts for proxy, app, and database. This supports scaling the
app tier independently and keeps the database isolated.

```text
Internet
   |
[Reverse Proxy]
   |
[releasy-server] --> [Postgres]
```

Optional add-ons can be hosted separately (for example, an IdP).

## Network and Firewall Requirements

Secure defaults:

- Only the reverse proxy should be exposed to the public internet.
- The database must not be reachable from the public internet.
- Restrict admin access (SSH) to trusted CIDRs only.

Recommended flows:

- Ingress (public):
  - 80/443 to reverse proxy
- Ingress (admin):
  - 22 (or your SSH port) from trusted admin networks
- Internal:
  - Reverse proxy -> Releasy server on `RELEASY_BIND_ADDR`
    (default `0.0.0.0:8080`)
  - Releasy server -> Postgres on 5432
- Egress:
  - Releasy server -> object storage endpoints (if configured)
  - Releasy server -> operator JWKS URL (if configured)

If you use SQLite, ensure the database file is on local disk and backed
up like any other persistent data.

## Rollout Strategy

Releasy runs SQL migrations on startup before binding the HTTP listener.
For multi-instance deployments, serialize the first startup so that
migrations run only once.

### Blue/green (single-host)

1. Start a second Releasy instance on a new port.
2. Let it complete migrations and warm up.
3. Switch reverse proxy upstreams to the new instance.
4. Stop the old instance.

### Rolling (multi-host)

1. Remove one app host from the load balancer.
2. Deploy and start the new version.
3. Validate it, then re-add the host.
4. Repeat for the remaining hosts.
