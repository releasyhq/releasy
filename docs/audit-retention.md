---
title: Audit Retention and Cleanup
description: SQL templates for pruning audit events in Releasy for PostgreSQL and SQLite databases.
head:
  - - meta
    - name: keywords
      content: audit retention, data cleanup, PostgreSQL maintenance, SQLite cleanup, compliance retention
  - - meta
    - property: og:title
      content: Audit Retention and Cleanup - Releasy
  - - meta
    - property: og:description
      content: SQL templates for pruning audit events in PostgreSQL and SQLite.
---

# Audit Retention Helper

This guide provides SQL templates to prune audit events. Adjust the retention
window and schedule according to your compliance requirements.

## PostgreSQL

Delete events older than 90 days:

```sql
DELETE FROM audit_events
WHERE created_at < EXTRACT(EPOCH FROM NOW() - INTERVAL '90 days');
```

## SQLite

Delete events older than 90 days:

```sql
DELETE FROM audit_events
WHERE created_at < CAST(strftime('%s', 'now', '-90 days') AS INTEGER);
```

## Notes

- Run retention tasks off-peak to avoid impacting query latency.
- Consider wrapping the delete in a transaction and limiting batch size for
  very large tables.
