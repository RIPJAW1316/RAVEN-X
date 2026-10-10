# Distributed assessment (in-process and HTTP)

The first control-plane workflow is intentionally local and synchronous:

```text
RemoteAssessmentDispatcher
        ↓ dispatch envelope
InProcessDuplexTransport
        ↓
RavenXAgent
        ↓ LocalAssessmentOrchestrator
ScannerExecutionResult[]
        ↓ progress/result envelopes
AgentMessageProcessor (authenticated)
        ↓
RemoteAssessmentRegistry
```

`RemoteAssessment` has its own assessment ID and correlation ID. The dispatcher resolves a durable endpoint, rejects revoked or offline identities, requires a `READY`/`CONNECTED` session, and never runs scanner code itself. The agent is authoritative for actual compatibility and execution. A selected scanner that is unavailable, incompatible, legacy-only, or failed is represented in the agent result; no local fallback is attempted when the endpoint is unavailable.

Progress and result handlers enforce endpoint ownership and correlation ownership. Terminal assessments cannot be completed twice. Session and remote-assessment records are ephemeral and are not added to the SQLAlchemy schema.

Implemented: endpoint-targeted dispatch, in-process duplex delivery, authenticated lifecycle/report handling, result aggregation, offline/revoked checks, and an actual fake-firewall orchestration integration test.

Partial: synchronous in-process delivery stands in for a future transport; timeout handling is a helper/state boundary only.

Deferred from the in-process implementation: physical network delivery, durable queues, retries, scheduling, multi-tenant policy, RBAC, remote remediation, AI, and command execution.

## HTTP transport (Phase 2H)

The same protocol and control-plane handlers can now be used through an outbound-only HTTP adapter:

```text
Agent --POST /api/v1/agent/messages--> Control Plane
Agent --POST /api/v1/agent/work------> Control Plane
Agent <-- assessment.dispatch -------- Control Plane
```

Heartbeat, capability, status, progress, and result submissions carry the existing `AgentMessageEnvelope` and Bearer-present the endpoint credential at the HTTP boundary. The control plane validates the envelope with the existing authenticated processor. Work is held in an endpoint-partitioned in-memory outbox and leased once to a polling agent; this is not durable delivery.

Implemented: HTTP ingress, outbound client, JSON/body-size/content-type checks, safe status mapping, HTTPS-required client configuration, endpoint-isolated work polling, and an end-to-end HTTP distributed-assessment test using an in-process ASGI test adapter.

Partial: the test adapter does not perform a TLS handshake. Production use requires HTTPS with certificate and hostname verification; no inbound agent port exists.

## Durable work delivery (Phase 2I)

When configured, the HTTP work endpoint leases from the additive `agent_work_items`
table instead of the legacy process-memory outbox:

```text
RemoteAssessmentDispatcher
        ↓
AgentWorkRepository (PENDING)
        ↓ POST /api/v1/agent/work
LEASED + lease token
        ↓ assessment.ack / progress / result
ACKNOWLEDGED → COMPLETED / FAILED
```

The durable path is endpoint-scoped and bounded-retry before ACK. It does not claim
exactly-once execution and intentionally keeps acknowledged work from automatic
redelivery after an agent crash. The in-process transport and legacy HTTP outbox
remain available for compatibility tests.

## Durable assessment reconciliation and cancellation (Phase 2J)

`RemoteAssessment` is now persisted separately from `AgentWorkItem`. An explicit
reconciler restores queued, dispatched, running, delivery-failed, and expired state
after control-plane restart. Pre-ACK cancellation prevents future delivery; after
ACK, cancellation becomes an intent record only. No remote cancellation protocol or
process termination is implemented.

## Authorization and audit (Phase 2K)

Authenticated agent messages now map to explicit authorization actions through an
endpoint self-scoped principal. Sensitive lifecycle services can receive the same
replaceable authorizer boundary with an explicit SYSTEM principal for internal work.
Security-relevant authentication, authorization, endpoint, enrollment/credential,
assessment, and cancellation events are written as redacted append-only audit facts.
Human identity and RBAC are intentionally absent.
