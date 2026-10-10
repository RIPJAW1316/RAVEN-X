# Endpoint registry and durable persistence (Phase 2B)

## Implemented

The endpoint domain now has an explicit persistence boundary:

```text
Endpoint domain
      ↓
EndpointRegistry application service
      ↓
EndpointRepository port
      ↓
SQLAlchemyEndpointRepository
      ↓
endpoints table
```

`EndpointRecord` is an adapter model. `Endpoint` remains the source-of-truth
domain object and never imports SQLAlchemy.

The registry supports explicit registration, retrieval, deterministic listing,
full-domain updates, capability updates, lifecycle updates, revocation, and
resolution to `AssessmentTarget`. Registering an existing `EndpointId` raises a
duplicate error; updates are explicit and never silently performed by
`register()`.

The persisted logical identity is the UUID-encoded `endpoint_id` primary key.
Hostname is not a uniqueness key. Mutable platform, agent, capability, status,
timestamp, and metadata state can change without changing endpoint identity.

Capability snapshots preserve identifiers, availability, provenance, and reason
as JSON. Agent metadata stores only agent version, protocol version, and
installation timestamp. No secrets, credentials, certificates, or trust state
are stored.

Revocation is durable and represented by `status=revoked` plus `revoked_at`.
Revoked records are retained and reload as revoked; they are not physically
deleted.

## Database initialization strategy

Raven-X currently uses `Base.metadata.create_all()` through `DatabaseManager`.
Phase 2B adds only the `endpoints` model, so initialization is additive for new
databases and existing databases. No existing table is renamed, dropped, or
altered, and no Alembic dependency was introduced.

The application’s existing database timestamp convention is naïve UTC. The
mapper converts timezone-aware domain timestamps to naïve UTC for storage and
reattaches UTC on reload. This is isolated to endpoint mapping and does not
change global timestamp behavior.

## Security boundary

Durable identity is not authentication. The existence of an endpoint row does
not prove that a machine owns or controls that identity. Persisted capabilities
are untrusted state until future authenticated agent reporting exists.

Later enrollment/authentication phases must enforce rejected identities and
audit lifecycle changes. Database compromise can alter endpoint records; this
phase does not attempt to solve that threat.

## Deferred

- Endpoint HTTP/API registration
- Enrollment tokens, credentials, certificates, and authentication
- Heartbeats, agent protocol, networking, or remote dispatch
- Organizations, tenants, ownership, RBAC, or groups
- Endpoint-to-scan schema coupling
- Audit-log integration for lifecycle changes
