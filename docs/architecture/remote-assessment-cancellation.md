# Remote assessment cancellation

Cancellation is deliberately conservative because Phase 2J has no remote stop
protocol.

```text
PENDING / LEASED before ACK
        ↓
AgentWorkItem = CANCELLED
RemoteAssessment = CANCELLED

ACKNOWLEDGED / RUNNING
        ↓
RemoteAssessment = CANCEL_REQUESTED
```

Pre-ACK cancellation invalidates the active lease and prevents future polling. A
stale ACK, progress message, or result for cancelled work is rejected. There is a
small unavoidable race if the agent received a leased response immediately before
the control plane cancelled it; Raven-X does not claim absolute cancellation.

After ACK, the service records operator intent only. It does not send an
`assessment.cancel` message, terminate a process, interrupt a scanner, or claim that
endpoint execution stopped. A later authenticated result remains valid and may move
`CANCEL_REQUESTED` to `COMPLETED` or `FAILED`, retaining cancellation metadata.

Terminal assessments are immutable and return an explicit `ALREADY_TERMINAL` outcome.
