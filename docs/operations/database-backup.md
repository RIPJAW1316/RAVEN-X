# Database backup runbook

Quiesce the control plane before copying SQLite, or use SQLite's online backup
API. Treat backups as sensitive because they contain credentials/verifiers,
sessions, audit history, endpoint data, and compliance evidence. Encrypt and
restrict access. PostgreSQL backups use `pg_dump` only when a PostgreSQL
deployment has been separately validated.
