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

```text
infra/
  ansible.cfg
  requirements.txt
  requirements.yml
  playbooks/
    site.yml
  roles/
    releasy_artifact_bucket/
      defaults/main.yml
      tasks/main.yml
      molecule/default/
    releasy_postgres/
      tasks/main.yml
      handlers/main.yml
    releasy_server/
      defaults/main.yml
      tasks/main.yml
      tasks/rolling_restart.yml
      handlers/main.yml
      templates/
        releasy.env.j2
        releasy.instance.env.j2
        releasy@.service.j2
        releasy.floating-ip.netplan.yml.j2
    traefik/
      defaults/main.yml
      tasks/main.yml
      handlers/main.yml
      templates/
        traefik.yml.j2
        traefik.service.j2
        dynamic.yml.j2
    keycloak/
      defaults/main.yml
      tasks/main.yml
      tasks/rolling_restart.yml
      handlers/main.yml
      templates/
        keycloak.env.j2
        keycloak.instance.env.j2
        keycloak@.service.j2
        keycloak-run.sh.j2
        realm.json.j2
    tailscale/
      defaults/main.yml
      tasks/main.yml
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

`playbooks/site.yml` provisions components in this order:

1. Database hosts (`releasy_db`) → `tailscale` (optional), `releasy_postgres`
2. App hosts (`releasy_app`) → `tailscale` (optional), `releasy_artifact_bucket` (optional), `releasy_server` (run with
   `serial: 1`)
3. IdP hosts (`keycloak`) → `tailscale` (optional), `keycloak` (run with `serial: 1`)
4. Proxy hosts (`traefik`) → `traefik`

Use `serial: 1` for app/IdP groups to enable rolling updates. If a
private network is required, enable the `tailscale` role per host.

## Roles

### releasy_postgres

Installs PostgreSQL, creates the app database and user (plus optional
Keycloak database), configures listen addresses and `pg_hba.conf`, and
optionally applies UFW firewall rules. Supports automatic CIDR discovery
from inventory or Tailscale.

### releasy_server

Installs Docker, renders environment files, installs a systemd template
unit (`releasy-server@.service`), pulls the container image, and performs
rolling restarts with health checks. Supports blue/green instances,
optional firewall rules, and floating IP assignment.

### releasy_artifact_bucket

Provisions an S3-compatible artifact bucket on the control node using
the `amazon.aws.s3_bucket` module. Supports versioning and object lock
for immutable artifacts.

### traefik

Downloads and installs Traefik as a systemd service, configures TLS via
Let's Encrypt, and routes traffic to Releasy (and optionally Keycloak)
backends with health checks, rate limiting, and sticky sessions.

### keycloak

Deploys Keycloak as a Docker container with systemd template units,
supports HA clustering via JDBC-PING, realm import (template or file),
and rolling restarts with health checks.

### tailscale

Installs Tailscale via the official install script, authenticates with
an auth key, and configures hostname and optional ACL tags.

## Variables Reference

### Shared Variables (`group_vars/all/all.yml`)

| Variable                  | Required | Default                 | Description                              |
|---------------------------|----------|-------------------------|------------------------------------------|
| `releasy_db_primary_host` | no       | first `releasy_db` host | Primary database host for auto-discovery |
| `postgres_host`           | yes      | auto-detected           | Database hostname (Tailscale DNS or IP)  |
| `postgres_port`           | no       | `5432`                  | PostgreSQL port                          |
| `postgres_app_db`         | yes      | `releasy`               | Application database name                |
| `postgres_app_user`       | yes      | `releasy`               | Application database user                |

### Releasy Server Variables (`group_vars/releasy_app.yml`)

#### Service Configuration

| Variable               | Required | Default                    | Description                       |
|------------------------|----------|----------------------------|-----------------------------------|
| `releasy_service_name` | no       | `releasy-server`           | Legacy service name (for cleanup) |
| `releasy_env_dir`      | no       | `/etc/releasy`             | Environment file directory        |
| `releasy_env_file`     | no       | `/etc/releasy/releasy.env` | Main environment file path        |

#### Docker and Instances

| Variable                               | Required | Default                                | Description                           |
|----------------------------------------|----------|----------------------------------------|---------------------------------------|
| `releasy_server_image`                 | yes      | `ghcr.io/releasyhq/releasy:latest`     | Docker image with tag                 |
| `releasy_server_instances`             | yes      | `[blue, green]`                        | List of instance names for blue/green |
| `releasy_server_instance_port_base`    | no       | `8080`                                 | Base port (increments per instance)   |
| `releasy_server_container_name_prefix` | no       | `releasy-server`                       | Container name prefix                 |
| `releasy_port`                         | no       | `8080`                                 | Container port                        |
| `releasy_container_port`               | no       | `{{ releasy_port }}`                   | Internal container port               |
| `releasy_bind_addr`                    | no       | `0.0.0.0:{{ releasy_container_port }}` | Bind address inside container         |
| `releasy_server_docker_extra_args`     | no       | `[]`                                   | Extra Docker run arguments            |
| `releasy_registry`                     | cond.    | `ghcr.io`                              | Container registry host               |
| `releasy_registry_login_enabled`       | no       | `false`                                | Enable registry authentication        |
| `releasy_registry_username`            | cond.    | -                                      | Registry username (if login enabled)  |
| `releasy_registry_password`            | cond.    | -                                      | Registry password (if login enabled)  |

#### Health Checks

| Variable                             | Required | Default  | Description                     |
|--------------------------------------|----------|----------|---------------------------------|
| `releasy_server_healthcheck_path`    | no       | `/ready` | Health check endpoint path      |
| `releasy_server_healthcheck_timeout` | no       | `60`     | Health check timeout (seconds)  |
| `releasy_server_healthcheck_retries` | no       | `10`     | Health check retry count        |
| `releasy_server_healthcheck_delay`   | no       | `2`      | Delay between retries (seconds) |

#### Application Settings

| Variable                             | Required | Default | Description                           |
|--------------------------------------|----------|---------|---------------------------------------|
| `releasy_log_level`                  | no       | `info`  | Log level (debug, info, warn, error)  |
| `releasy_database_url`               | yes      | derived | Full PostgreSQL connection URL        |
| `releasy_database_max_connections`   | no       | `5`     | Database connection pool size         |
| `releasy_admin_api_key`              | yes      | -       | Admin bootstrap API key (vault)       |
| `releasy_api_key_pepper`             | no       | -       | Additional secret for API key hashing |
| `releasy_download_token_ttl_seconds` | no       | `600`   | Download token validity (seconds)     |

#### Operator JWT (OIDC Integration)

| Variable                              | Required | Default | Description                           |
|---------------------------------------|----------|---------|---------------------------------------|
| `releasy_operator_jwks_url`           | no       | -       | JWKS endpoint URL for operator tokens |
| `releasy_operator_issuer`             | no       | -       | Expected JWT issuer                   |
| `releasy_operator_audience`           | no       | -       | Expected JWT audience                 |
| `releasy_operator_resource`           | no       | -       | Expected JWT resource claim           |
| `releasy_operator_jwks_ttl_seconds`   | no       | `300`   | JWKS cache TTL                        |
| `releasy_operator_jwt_leeway_seconds` | no       | `0`     | Clock skew tolerance                  |

#### Artifact Storage (S3-Compatible)

| Variable                                   | Required | Default | Description                               |
|--------------------------------------------|----------|---------|-------------------------------------------|
| `releasy_artifact_endpoint`                | no       | -       | Custom S3 endpoint (MinIO, Hetzner, etc.) |
| `releasy_artifact_region`                  | cond.    | -       | S3 region                                 |
| `releasy_artifact_bucket`                  | cond.    | -       | S3 bucket name                            |
| `releasy_artifact_access_key`              | cond.    | -       | S3 access key (vault)                     |
| `releasy_artifact_secret_key`              | cond.    | -       | S3 secret key (vault)                     |
| `releasy_artifact_path_style`              | no       | `false` | Use path-style S3 URLs                    |
| `releasy_artifact_presign_expires_seconds` | no       | `900`   | Presigned URL expiration                  |

#### Artifact Bucket Provisioning

| Variable                                                | Required | Default | Description                                |
|---------------------------------------------------------|----------|---------|--------------------------------------------|
| `releasy_artifact_bucket_create_enabled`                | no       | `false` | Enable bucket provisioning on control node |
| `releasy_artifact_bucket_versioning_enabled`            | no       | `false` | Enable bucket versioning                   |
| `releasy_artifact_bucket_object_lock_enabled`           | no       | `false` | Enable object lock for immutable artifacts |
| `releasy_artifact_bucket_object_lock_default_retention` | no       | `{}`    | Retention policy (`mode`, `days`/`years`)  |

Example for immutable artifacts:

```yaml
releasy_artifact_bucket_object_lock_enabled: true
releasy_artifact_bucket_object_lock_default_retention:
  mode: compliance
  days: 3650
```

#### Floating IP (Optional)

| Variable                                        | Required | Default | Description                     |
|-------------------------------------------------|----------|---------|---------------------------------|
| `releasy_extra_ip`                              | no       | -       | Additional IP address to assign |
| `releasy_extra_ip_iface`                        | no       | `eth0`  | Network interface for extra IP  |
| `releasy_extra_ip_persistent`                   | no       | `false` | Persist via netplan             |
| `releasy_extra_ip_preserve_ipv6`                | no       | `false` | Keep existing IPv6 in netplan   |
| `releasy_extra_ip_netplan_additional_addresses` | no       | `[]`    | Extra addresses for netplan     |

#### Firewall (UFW)

| Variable                                 | Required | Default         | Description                         |
|------------------------------------------|----------|-----------------|-------------------------------------|
| `releasy_firewall_enabled`               | no       | `false`         | Enable firewall rules               |
| `releasy_firewall_enable_ufw`            | no       | `false`         | Enable UFW service                  |
| `releasy_firewall_default_deny_incoming` | no       | `false`         | Default deny incoming               |
| `releasy_firewall_allow_ssh`             | no       | `true`          | Allow SSH access                    |
| `releasy_firewall_explicit_deny_ssh`     | no       | `true`          | Explicitly deny SSH after allows    |
| `releasy_firewall_ssh_sources`           | no       | Tailscale CIDRs | Allowed SSH source CIDRs            |
| `releasy_firewall_allowed_sources`       | no       | `[]`            | CIDRs allowed to reach server ports |
| `releasy_firewall_show_rules`            | no       | `true`          | Show UFW rules after changes        |
| `releasy_firewall_show_rules_dry_run`    | no       | `true`          | Show UFW status in pre-tasks        |

### PostgreSQL Variables (`group_vars/releasy_db.yml`)

#### Networking

| Variable                              | Required | Default     | Description                                    |
|---------------------------------------|----------|-------------|------------------------------------------------|
| `postgres_listen_addresses`           | yes      | `tailscale` | Listen addresses (`tailscale` for auto-detect) |
| `postgres_allowed_cidrs`              | yes      | -           | CIDRs allowed to connect                       |
| `postgres_allowed_cidrs_auto_enabled` | no       | `true`      | Auto-discover CIDRs from inventory/Tailscale   |

#### Keycloak Database (Optional)

| Variable                    | Required | Default | Description                          |
|-----------------------------|----------|---------|--------------------------------------|
| `keycloak_db_allowed_cidrs` | no       | `[]`    | CIDRs allowed for Keycloak DB access |

#### Firewall (UFW)

| Variable                                  | Required | Default         | Description                      |
|-------------------------------------------|----------|-----------------|----------------------------------|
| `postgres_firewall_enabled`               | no       | `false`         | Enable firewall rules            |
| `postgres_firewall_enable_ufw`            | no       | `false`         | Enable UFW service               |
| `postgres_firewall_default_deny_incoming` | no       | `false`         | Default deny incoming            |
| `postgres_firewall_allow_ssh`             | no       | `true`          | Allow SSH access                 |
| `postgres_firewall_explicit_deny_ssh`     | no       | `true`          | Explicitly deny SSH after allows |
| `postgres_firewall_ssh_sources`           | no       | Tailscale CIDRs | Allowed SSH source CIDRs         |

### Traefik Variables (`group_vars/traefik.yml`)

#### Installation

| Variable            | Required | Default       | Description                        |
|---------------------|----------|---------------|------------------------------------|
| `traefik_version`   | yes      | `3.1.6`       | Traefik version to install         |
| `traefik_arch`      | no       | auto-detected | Binary architecture (amd64, arm64) |
| `traefik_log_level` | no       | `INFO`        | Log level                          |

#### TLS and ACME

| Variable             | Required | Default | Description                 |
|----------------------|----------|---------|-----------------------------|
| `traefik_acme_email` | yes      | -       | Let's Encrypt account email |

#### Rate Limiting

| Variable                     | Required | Default | Description                 |
|------------------------------|----------|---------|-----------------------------|
| `traefik_rate_limit_average` | no       | `1`     | Requests per second average |
| `traefik_rate_limit_burst`   | no       | `30`    | Maximum burst size          |

#### Releasy Backend

| Variable                                      | Required | Default        | Description                        |
|-----------------------------------------------|----------|----------------|------------------------------------|
| `traefik_releasy_enabled`                     | no       | `true`         | Enable Releasy routing             |
| `releasy_public_host`                         | yes      | -              | Public hostname for Releasy        |
| `releasy_server_upstreams`                    | no       | auto-generated | Backend URLs (auto from inventory) |
| `traefik_releasy_server_healthcheck_enabled`  | no       | `true`         | Enable backend health checks       |
| `traefik_releasy_server_healthcheck_path`     | no       | `/ready`       | Health check path                  |
| `traefik_releasy_server_healthcheck_interval` | no       | `10s`          | Health check interval              |
| `traefik_releasy_server_healthcheck_timeout`  | no       | `2s`           | Health check timeout               |

Example for multi-host:

```yaml
releasy_server_upstreams:
  - "http://10.0.1.10:8080"
  - "http://10.0.1.10:8081"
```

#### Keycloak Backend (Optional)

| Variable                              | Required | Default           | Description                        |
|---------------------------------------|----------|-------------------|------------------------------------|
| `keycloak_public_host`                | no       | -                 | Public hostname for Keycloak       |
| `keycloak_upstreams`                  | no       | auto-generated    | Backend URLs (auto from inventory) |
| `keycloak_traefik_sticky`             | no       | `true`            | Enable sticky sessions             |
| `keycloak_traefik_sticky_cookie_name` | no       | `KEYCLOAK_STICKY` | Sticky cookie name                 |

### Keycloak Variables (`group_vars/keycloak.yml`)

#### General

| Variable            | Required | Default                  | Description                   |
|---------------------|----------|--------------------------|-------------------------------|
| `keycloak_enabled`  | no       | `false`                  | Enable Keycloak deployment    |
| `keycloak_image`    | no       | `keycloak/keycloak:26.4` | Keycloak Docker image         |
| `keycloak_hostname` | yes      | -                        | Public hostname for redirects |

#### Instances

| Variable                         | Required | Default    | Description                         |
|----------------------------------|----------|------------|-------------------------------------|
| `keycloak_instances`             | yes      | `[a, b]`   | List of instance names              |
| `keycloak_instance_port_base`    | no       | `8080`     | Base port (increments per instance) |
| `keycloak_http_port`             | no       | `8080`     | HTTP port inside container          |
| `keycloak_container_name_prefix` | no       | `keycloak` | Container name prefix               |
| `keycloak_docker_extra_args`     | no       | `[]`       | Extra Docker run arguments          |

#### Directories

| Variable            | Required | Default                      | Description                |
|---------------------|----------|------------------------------|----------------------------|
| `keycloak_data_dir` | no       | `/var/lib/keycloak`          | Data directory             |
| `keycloak_env_dir`  | no       | `/etc/keycloak`              | Environment file directory |
| `keycloak_env_file` | no       | `/etc/keycloak/keycloak.env` | Main environment file      |

#### Database

| Variable               | Required | Default               | Description               |
|------------------------|----------|-----------------------|---------------------------|
| `keycloak_db_host`     | yes      | `{{ postgres_host }}` | Database hostname         |
| `keycloak_db_port`     | no       | `{{ postgres_port }}` | Database port             |
| `keycloak_db_name`     | yes      | `keycloak`            | Database name             |
| `keycloak_db_user`     | yes      | `keycloak`            | Database user             |
| `keycloak_db_password` | yes      | -                     | Database password (vault) |
| `keycloak_db_ssl_mode` | no       | `disable`             | PostgreSQL SSL mode       |

#### Proxy and Security

| Variable                         | Required | Default      | Description                |
|----------------------------------|----------|--------------|----------------------------|
| `keycloak_proxy_headers`         | no       | `xforwarded` | Proxy header mode          |
| `keycloak_http_enabled`          | no       | `true`       | Enable HTTP listener       |
| `keycloak_hostname_strict`       | no       | `true`       | Strict hostname validation |
| `keycloak_hostname_strict_https` | no       | `true`       | Require HTTPS for hostname |

#### Health and Metrics

| Variable                       | Required | Default         | Description                    |
|--------------------------------|----------|-----------------|--------------------------------|
| `keycloak_health_enabled`      | no       | `true`          | Enable health endpoints        |
| `keycloak_metrics_enabled`     | no       | `false`         | Enable metrics endpoint        |
| `keycloak_healthcheck_path`    | no       | `/health/ready` | Health check endpoint          |
| `keycloak_healthcheck_timeout` | no       | `120`           | Health check timeout (seconds) |

#### Clustering

| Variable                   | Required | Default     | Description            |
|----------------------------|----------|-------------|------------------------|
| `keycloak_cluster_enabled` | no       | `true`      | Enable clustering      |
| `keycloak_cache_stack`     | no       | `jdbc-ping` | Infinispan cache stack |

#### Realm Import

| Variable                        | Required | Default      | Description                          |
|---------------------------------|----------|--------------|--------------------------------------|
| `keycloak_realm_import_enabled` | no       | `false`      | Enable realm import on start         |
| `keycloak_realm_import_source`  | no       | `template`   | Import source (`template` or `file`) |
| `keycloak_realm_import_src`     | cond.    | -            | Path to realm file (if `file`)       |
| `keycloak_realm_import_dest`    | no       | `realm.json` | Destination filename                 |
| `keycloak_start_args`           | no       | `[]`         | Extra start command arguments        |

#### Realm Template Variables

| Variable                        | Required | Default                              | Description                  |
|---------------------------------|----------|--------------------------------------|------------------------------|
| `keycloak_realm_name`           | no       | `releasy`                            | Realm name                   |
| `keycloak_portal_client_id`     | no       | `releasy-portal`                     | Portal client ID             |
| `keycloak_portal_client_secret` | cond.    | -                                    | Portal client secret (vault) |
| `keycloak_portal_root_url`      | no       | -                                    | Portal root URL              |
| `keycloak_portal_redirect_uris` | no       | `[{{ keycloak_portal_root_url }}/*]` | Allowed redirect URIs        |
| `keycloak_portal_web_origins`   | no       | `[{{ keycloak_portal_root_url }}]`   | Allowed web origins          |

#### Admin Credentials

| Variable                  | Required | Default | Description            |
|---------------------------|----------|---------|------------------------|
| `keycloak_admin_user`     | yes      | -       | Admin username (vault) |
| `keycloak_admin_password` | yes      | -       | Admin password (vault) |

### Tailscale Variables

| Variable                   | Required | Default                    | Description                      |
|----------------------------|----------|----------------------------|----------------------------------|
| `tailscale_enabled`        | no       | `false`                    | Enable Tailscale                 |
| `tailscale_hostname`       | no       | `{{ inventory_hostname }}` | Tailscale hostname               |
| `tailscale_auth_key`       | cond.    | -                          | Auth key for first login (vault) |
| `tailscale_advertise_tags` | no       | `[]`                       | ACL tags to advertise            |

## Secrets (Vault)

All secrets belong in `inventory/group_vars/all/vault.yml` and must be
encrypted with `ansible-vault`.

| Variable                        | Required | Description                             |
|---------------------------------|----------|-----------------------------------------|
| `releasy_admin_api_key`         | yes      | Admin bootstrap API key                 |
| `releasy_api_key_pepper`        | no       | Additional secret for API key hashing   |
| `postgres_app_password`         | yes      | Application database password           |
| `releasy_registry_username`     | cond.    | Registry username (if login enabled)    |
| `releasy_registry_password`     | cond.    | Registry password (if login enabled)    |
| `releasy_artifact_access_key`   | cond.    | S3 access key                           |
| `releasy_artifact_secret_key`   | cond.    | S3 secret key                           |
| `keycloak_admin_user`           | cond.    | Keycloak admin username (if enabled)    |
| `keycloak_admin_password`       | cond.    | Keycloak admin password (if enabled)    |
| `keycloak_db_password`          | cond.    | Keycloak database password (if enabled) |
| `keycloak_portal_client_secret` | cond.    | Portal client secret (if realm import)  |
| `tailscale_auth_key`            | cond.    | Tailscale auth key (if enabled)         |

## Quickstart

1. Define your inventory in `infra/inventory/hosts.yml`.
2. Fill `group_vars` with non-secret defaults.
3. Create `inventory/group_vars/all/vault.yml` and encrypt it.
4. Install required collections (if using bucket provisioning).
5. Run the playbook.

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
          ansible_host: 10.0.1.10
    traefik:
      hosts:
        releasy:
          ansible_host: 10.0.1.10
```

Run:

```bash
cd infra
ansible-vault encrypt inventory/group_vars/all/vault.yml \
  --vault-password-file ~/.secure/releasy-vault-pass
ansible-playbook playbooks/site.yml \
  --vault-password-file ~/.secure/releasy-vault-pass
```

## Dependencies

If you enable artifact bucket provisioning, install the required Ansible
collection on the control node:

```bash
ansible-galaxy collection install -r infra/requirements.yml
```

The `amazon.aws` collection requires `boto3` and `botocore` Python
packages on the control node.

## Testing

The Molecule setup targets the artifact bucket role using a local MinIO
container. It requires Docker and free ports `9000`/`9001`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r infra/requirements.txt
ansible-galaxy collection install -r infra/requirements.yml

cd infra/roles/releasy_artifact_bucket
molecule test
```

## Runbook

### Dry Run

```bash
ansible-playbook playbooks/site.yml --check --diff \
  --vault-password-file ~/.secure/releasy-vault-pass
```

### Deploy Single Component

```bash
# Database only
ansible-playbook playbooks/site.yml --limit releasy_db \
  --vault-password-file ~/.secure/releasy-vault-pass

# App servers only
ansible-playbook playbooks/site.yml --limit releasy_app \
  --vault-password-file ~/.secure/releasy-vault-pass

# Traefik only
ansible-playbook playbooks/site.yml --limit traefik \
  --vault-password-file ~/.secure/releasy-vault-pass
```

### Rolling Update

The playbook uses `serial: 1` for app and Keycloak hosts, restarting
instances one at a time with health checks between restarts.

For blue/green deployments, update `releasy_server_image` to the new
tag and rerun the playbook. Traefik health checks will route traffic
only to healthy instances.

### Rollback

Pin `releasy_server_image` to the previous tag and rerun the playbook:

```bash
ansible-playbook playbooks/site.yml --limit releasy_app \
  -e 'releasy_server_image=ghcr.io/releasyhq/releasy:v1.2.3' \
  --vault-password-file ~/.secure/releasy-vault-pass
```

### View Service Logs

```bash
# On app host
journalctl -u releasy-server@blue -f
journalctl -u releasy-server@green -f

# On Keycloak host
journalctl -u keycloak@a -f
journalctl -u keycloak@b -f

# On Traefik host
journalctl -u traefik -f
```

### Restart Services

```bash
# On app host
systemctl restart releasy-server@blue releasy-server@green

# On Keycloak host
systemctl restart keycloak@a keycloak@b

# On Traefik host
systemctl restart traefik
```

### Database Access

```bash
# On DB host
sudo -u postgres psql -d releasy
```

### Tailscale Status

```bash
tailscale status
tailscale ip -4
```
