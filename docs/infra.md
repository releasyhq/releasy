---
title: Ansible Infrastructure Deployment
description: Ansible playbook layout, roles, and runbook for deploying Releasy with PostgreSQL, Traefik, and optional Keycloak.
head:
  - - meta
    - name: keywords
      content: Ansible deployment, infrastructure automation, Traefik setup, Keycloak integration, self-hosted infrastructure
  - - meta
    - property: og:title
      content: Ansible Infrastructure Deployment - Releasy
  - - meta
    - property: og:description
      content: Ansible playbooks and roles for deploying Releasy infrastructure.
---

# Ansible Deployment

This section documents the Ansible layout for self-hosted Releasy.

## Layout

Expected structure for the Ansible repo subtree:

```text
infra/
  playbooks/
    site.yml
  roles/
    releasy_postgres/
    releasy_server/
    traefik/
    keycloak/        # optional
    tailscale/       # optional
  inventory/
    hosts.yml
    group_vars/
      all/
        all.yml
        vault.yml
      releasy_app.yml
      releasy_db.yml
      traefik.yml
      keycloak.yml
```

## Playbook Structure

`playbooks/site.yml` should provision components in this order:

1. Database hosts (`releasy_db`) -> `releasy_postgres`.
2. App hosts (`releasy_app`) -> `releasy_server` (run with `serial: 1`).
3. Optional IdP hosts (`keycloak`) -> `keycloak`.
4. Proxy hosts (`traefik`) -> `traefik`.

Use `serial: 1` for app/IdP groups to enable rolling updates. If a
private network is required, include the `tailscale` role per host.

## Roles

- `releasy_postgres`: installs Postgres, creates the app database/user,
  configures listen addresses, and applies DB firewall rules.
- `releasy_server`: installs Docker, renders env files, installs a
  systemd template unit, and performs rolling restarts.
- `traefik`: terminates TLS and routes `/` to the Releasy instances.
- `keycloak` (optional): deploys IdP for operator auth.
- `tailscale` (optional): private networking between hosts.

## Variables and Secrets

Keep non-secret defaults in `group_vars` and keep secrets in Vault.

Recommended files:

- `inventory/group_vars/all/all.yml`: shared defaults (ports, image,
  instance list, registry host).
- `inventory/group_vars/releasy_app.yml`: app settings, ports, firewall
  controls, health endpoint, proxy upstreams.
- `inventory/group_vars/releasy_db.yml`: Postgres settings and allowed
  CIDRs.
- `inventory/group_vars/traefik.yml`: domains, TLS settings, upstreams.
- `inventory/group_vars/keycloak.yml`: optional IdP settings.

When using public container images, set `releasy_registry_login_enabled: false` in
`inventory/group_vars/releasy_app.yml` to skip registry login. In that
case, registry credentials are not required.

Optional artifact bucket provisioning runs on the control node using the
`amazon.aws.s3_bucket` module. Enable it with
`releasy_artifact_bucket_create_enabled: true` and ensure
`releasy_artifact_bucket` + `releasy_artifact_region` are set (use
`releasy_artifact_endpoint` for S3-compatible providers).

If you enable bucket provisioning, install the required Ansible
collection on the control node:

```bash
ansible-galaxy collection install -r infra/requirements.yml
```

The collection requires `boto3` and `botocore` on the control node.

Secrets live in `inventory/group_vars/all/vault.yml` and must be
encrypted with `ansible-vault`. Suggested secret keys:

- `releasy_admin_api_key`
- `releasy_api_key_pepper`
- `releasy_registry_username` (required when registry login is enabled)
- `releasy_registry_password` (required when registry login is enabled)
- `releasy_database_url` (if not derived from Postgres vars)
- `releasy_artifact_access_key` / `releasy_artifact_secret_key`
- `keycloak_admin_user` / `keycloak_admin_password` (if enabled)

## Quickstart

1. Define your inventory in `infra/inventory/hosts.yml`.
2. Fill `group_vars` with non-secret defaults.
3. Create `inventory/group_vars/all/vault.yml` and encrypt it.
4. Run the playbook.

Example inventory (single-host):

```yaml
all:
  vars:
    ansible_user: root
  children:
    releasy_app:
      hosts:
        releasy:
          ansible_host: 10.0.1.10
    releasy_db:
      hosts:
        releasy:
          ansible_host: 10.0.2.10
    traefik:
      hosts:
        releasy:
          ansible_host: 10.0.3.10
```

Run:

```bash
cd infra
ansible-vault encrypt inventory/group_vars/all/vault.yml \
  --vault-password-file ~/.secure/releasy-vault-pass
ansible-playbook playbooks/site.yml \
  --vault-password-file ~/.secure/releasy-vault-pass
```

## Runbook

- Dry run:

  ```bash
  ansible-playbook playbooks/site.yml --check --diff \
    --vault-password-file ~/.secure/releasy-vault-pass
  ```

- Deploy one component:

  ```bash
  ansible-playbook playbooks/site.yml --limit releasy_app \
    --vault-password-file ~/.secure/releasy-vault-pass
  ```

- Rolling update (multi-host): keep `serial: 1` and update hosts one by
  one. For blue/green, update `releasy_server_instances` and adjust the
  proxy upstream list.
- Rollback: pin `releasy_server_image` to the previous tag and rerun the
  playbook.
