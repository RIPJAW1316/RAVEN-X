# Local endpoint-agent runtime (Phase 2F)

```text
RavenXAgent
    │
    ├── Identity Store
    ├── Credential Store
    ├── Capability Provider
    ├── Scanner Registry
    ├── Local Assessment Orchestrator
    ├── Protocol Mapper
    └── AgentMessageSender port
```

Startup loads an enrolled `EndpointId` and machine credential, validates the
configured protocol version, discovers capabilities through the existing
`LocalTargetCapabilityProvider`, and enters `READY`. Missing identity or
credential produces `UNENROLLED`; identity is never derived or regenerated.

The runtime emits typed heartbeat, capability, and status envelopes. A typed
`assessment.dispatch` is accepted only when it targets the local endpoint,
uses the supported protocol, has valid freshness/correlation metadata, and is
control-to-agent traffic. Dispatch scanner IDs flow through the existing
`LocalAssessmentOrchestrator` and scanner registry. Progress and mapped
assessment results are emitted through the sender port.

Only one assessment runs at a time. A failure produces a sanitized failed
assessment result and returns the runtime to `READY`. The agent has no fleet
inventory, organization policy, AI, remediation, arbitrary command handling,
or knowledge of other endpoints.

**No network transport exists.** The sender is an injected port and tests use
an in-memory implementation.
