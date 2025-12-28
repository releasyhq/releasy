# Documentation

Releasy is a release distribution service for B2B software teams.
Manage products, entitlements, artifacts, and downloads with a consistent
admin API and customer-facing access controls.

## Guides

- [admin-bootstrap.md](admin-bootstrap.md): Initial admin bootstrap flow and setup steps.
- [api-conventions.md](api-conventions.md): Error schema, idempotency, pagination rules.
- [audit-events.md](audit-events.md): Audit event catalog, retention, and access.
- [audit-retention.md](audit-retention.md): SQL templates for audit retention cleanup.
- [infra.md](infra.md): Ansible deployment layout and runbook.
- [deployment.md](deployment.md): Self-hosted deployment patterns and rollout guidance.
- [operator-auth.md](operator-auth.md): Operator JWT auth, JWKS config, and RBAC roles.

## API Reference

- [release-api.md](release-api.md): Release lifecycle endpoints, RBAC rules, and examples.
- [artifacts.md](artifacts.md): Artifact uploads with presigned URLs.
- [downloads.md](downloads.md): Download token issuance and resolution.
- [entitlements.md](entitlements.md): Admin endpoints for entitlement management.
- [introspect-api.md](introspect-api.md): API key introspection endpoint.

## Configuration

- [configuration.md](configuration.md): Environment variables reference.
