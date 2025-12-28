---
title: Releasy Documentation
titleTemplate: Controlled Software Releases for B2B
description: Releasy is an open-source, API-first platform for managing controlled software releases, customer entitlements, and secure artifact distribution in B2B and SaaS environments.
head:
  - - meta
    - name: keywords
      content: software release management, B2B software distribution, customer entitlements, API-first release platform, secure software downloads, license management, artifact management, SaaS release management
  - - meta
    - property: og:title
      content: Releasy - Controlled Software Releases for B2B
  - - meta
    - property: og:description
      content: Open-source platform for managing software releases, customer entitlements, and secure artifact distribution.
---

# Releasy Documentation

Releasy is an open-source, API-first platform for managing controlled software
releases in B2B and SaaS environments. Distribute software securely, manage
customer entitlements, and control access to your releases.

## Why Releasy?

- **API-First Design** – Built for CI/CD pipelines and automation
- **Customer Entitlements** – Control which customers access which products
- **Secure Distribution** – Presigned URLs and time-limited download tokens
- **Self-Hosted** – Run on your own infrastructure with full control
- **Open Source** – Apache 2.0 licensed with enterprise extensions available

## Quick Start

Get Releasy running in minutes:

```bash
# Set required environment variables
export RELEASY_DATABASE_URL="postgres://user:pass@localhost:5432/releasy"
export RELEASY_ADMIN_API_KEY="$(openssl rand -hex 32)"

# Run with Docker
docker run -d \
  -e RELEASY_DATABASE_URL \
  -e RELEASY_ADMIN_API_KEY \
  -p 8080:8080 \
  ghcr.io/releasyhq/releasy:latest
```

See the [Getting Started Guide](getting-started.md) for a complete walkthrough.

## Core Concepts

### Releases

A release represents a specific version of your software product. Releases
follow a lifecycle from `draft` to `published`, ensuring only approved versions
are available to customers.

### Artifacts

Artifacts are the downloadable files attached to a release (binaries, archives,
installers). Releasy uses presigned URLs for secure uploads to S3-compatible
storage.

### Entitlements

Entitlements define which products a customer can access. They support
time-based validity and custom metadata for flexible licensing models.

### Download Tokens

Short-lived tokens that authorize artifact downloads. Tokens are tied to a
customer and artifact, with configurable expiration.

## Guides

- [Getting Started](getting-started.md) – Set up Releasy and create your first release
- [Configuration](configuration.md) – Environment variables reference
- [Deployment](deployment.md) – Self-hosted topologies and rollout strategies
- [Database](database.md) – PostgreSQL and SQLite support
- [Infrastructure](infra.md) – Ansible deployment layout and runbook
- [Operator Authentication](operator-auth.md) – JWT/JWKS configuration and RBAC

## API Reference

- [API Conventions](api-conventions.md) – Error schema, idempotency, pagination
- [Admin Bootstrap](admin-bootstrap.md) – Initial setup and API key management
- [Release API](release-api.md) – Release lifecycle endpoints
- [Artifacts](artifacts.md) – Presigned uploads and artifact registration
- [Downloads](downloads.md) – Download token issuance and resolution
- [Entitlements](entitlements.md) – Customer entitlement management
- [Introspection](introspect-api.md) – API key introspection
- [Audit Events](audit-events.md) – Security audit logging
- [Audit Retention](audit-retention.md) – Cleanup templates

## Architecture Overview

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   CI/CD     │────▶│   Releasy   │────▶│  S3/MinIO   │
│  Pipeline   │     │   Server    │     │  (Artifacts)│
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │  PostgreSQL │
                    │   / SQLite  │
                    └─────────────┘
```

- **CI/CD Pipeline** – Creates releases, uploads artifacts, publishes versions
- **Releasy Server** – Manages releases, entitlements, and access control
- **Object Storage** – Stores artifacts with presigned URL access
- **Database** – Persists releases, customers, entitlements, and audit logs

## License

Releasy is open source under the [Apache 2.0 License](https://github.com/releasyhq/releasy/blob/main/LICENSE).
