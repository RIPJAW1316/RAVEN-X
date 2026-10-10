# Production deployment

Supported runtime is Python 3.11.x. Recommended topology is HTTPS reverse
proxy → Raven-X API → shared database, with exactly one instance configured
with `RAVENX_ASSESSMENT_SCHEDULER_ENABLED=true`; other API instances disable
the scheduler. Agents make outbound HTTPS requests only and require normal
certificate/hostname validation. Production requires explicit CORS origins,
trusted-proxy configuration, protected environment/secret storage, database
backups, `/health` for liveness, and `/ready` for core database readiness.

SQLite is suitable for development and small single-node deployments; it has
limited write concurrency. PostgreSQL deployment is not validated in this
environment and must be tested separately before being advertised.
