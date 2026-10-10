# Database support decision

SQLite is the supported database for development and small single-node
production deployments. Backup/restore and additive schema upgrade behavior are
tested. PostgreSQL is not claimed or tested in this release; it requires a
separate validation effort before production support.
