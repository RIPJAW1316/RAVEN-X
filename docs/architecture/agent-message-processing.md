# Agent message processing boundary

```text
Future Network Transport
        ↓
AgentMessageReceiver port
        ↓
AgentMessageProcessor
        ↓
Protocol validation + freshness
        ↓
Existing credential authentication
        ↓
Endpoint binding + revocation
        ↓
Direction policy + authorization hook
        ↓
Replay claim
        ↓
Typed message router
        ↓
Application handler
```

## Implemented

- `PresentedCredential` separates credential proof from normal payload data.
- `CredentialEndpointAuthenticator` adapts Phase 2C credential validation.
- `DefaultAgentMessageAuthorizer` permits authenticated agent heartbeat,
  capability, status, progress, and result messages only.
- `TypedMessageRouter` rejects unknown and duplicate handlers and decodes typed
  payloads before invocation.
- In-memory replay claims and additive SQL replay records are available.
- `InMemoryAgentMessageSender` demonstrates the replaceable sender boundary
  without sending data anywhere; direction policy remains a pipeline concern.

## Deferred

No network transport exists yet. Authentication is identity proof, not
authorization. There is no organization policy, RBAC, scheduling, agent
process, remote command, remediation, or fleet behavior.
