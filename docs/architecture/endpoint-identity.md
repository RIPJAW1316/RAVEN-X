# Endpoint identity domain (Phase 2A)

## Implemented

Phase 2A introduces a pure `backend/domain/endpoint` package:

```text
Endpoint
   │
   ├── EndpointId
   ├── PlatformInfo
   ├── AgentInfo
   ├── TargetCapabilities
   ├── EndpointStatus
   └── last_seen
         │
         ↓
AssessmentTarget
         ↓
Local / future agent assessment
```

`EndpointId` is an opaque Raven-X UUID value. It is independent of hostname,
IP address, MAC address, user identity, hardware attributes, capabilities, and
agent version. Creating an ID is explicit domain behavior; there is no local
identity storage or automatic endpoint generation in this phase.

Hostname, platform version, architecture, agent metadata, capability snapshots,
status, and `last_seen` are descriptive state that may change without changing
the endpoint ID. `Endpoint.to_assessment_target()` maps the stable ID to the
existing `AssessmentTarget.target_id` while preserving assessable platform and
machine metadata.

The endpoint reuses `TargetCapabilities` and `CapabilityObservation` from the
scanner domain. It does not define a second endpoint capability taxonomy.

Lifecycle states are `NEW`, `ACTIVE`, `DEGRADED`, `OFFLINE`, and `REVOKED`.
`REVOKED` is terminal in the current pure model; it is distinct from temporary
offline status. State transition methods require an explicit timezone-aware
timestamp and create no hidden update side effect.

## Security boundary

An `Endpoint` is a domain identity object, not a trust decision. It does not
mean that a machine has authenticated, enrolled, or been authorized.

Endpoint identity alone does not prevent fake registration, credential theft,
agent impersonation, cloned credentials, replay, or forged capability reports.
Enrollment, authentication, certificates, protocol integrity, and trust
enforcement are deliberately deferred to later phases.

## Deferred

- Additional persistence concerns beyond the Phase 2B endpoint registry
- Endpoint registration or enrollment APIs
- Authentication, certificates, and enrollment tokens
- Organizations, tenants, ownership, and RBAC
- Network heartbeats, agent communication, and remote dispatch
- Machine fingerprinting or automatic local persistent identity storage

The current local assessment runtime remains unchanged. Its local target is an
assessment concern, not automatically a managed endpoint identity.
