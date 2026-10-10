# October 15 prototype implementation

## Acceptance

An operator can bootstrap a new local server, sign in, issue a one-use enrollment token, enroll a Windows agent through verified HTTPS, approve the endpoint, dispatch read-only checks, view returned evidence, request optional local AI interpretation, and export a report that distinguishes scanned and unscanned machines. The Dell Vostro and HP notebook are not currently available; their real connectivity remains unverified until the hardware runbook is executed.

## Boundaries

- Preserve the existing domain/application/adapter architecture and personal scanner.
- Human requests use opaque sessions, verified organization membership, RBAC, and SQL tenant predicates.
- A bootstrap token is single-use, defaults to 60 minutes, and never authenticates operational traffic. `new` means pending approval; only approved endpoints receive work or have assessment messages accepted.
- Credentials last 30 days, remain endpoint-scoped, and are stored on Windows with machine-scope DPAPI and a verified protected ACL. No automatic machine fingerprint rebind or browser credential rotation is exposed.
- Agents make outbound HTTPS calls only. The capability catalog contains read-only checks; it has no command or remediation channel.
- The server binds loopback for local development. The LAN launcher requires a certificate and key, uses one SQLite worker, and serves the built portal on the same HTTPS origin.
- AI is disabled by default, uses an explicitly configured local provider, accepts only tenant-owned stored evidence, and returns advisory text with provenance. Provider failure does not affect scanning.
- Reports use actual endpoint/assessment records and distinguish approval, presence, target selection, success, failure, unavailable, and not scanned.

## Increment ownership

1. P0 agent: configuration/startup, legacy route isolation, unused WebSocket closure, DB logging, ignore rules, baseline gates.
2. Enrollment agent: tenant token administration, atomic redemption, approval/revocation, work/result trust gates, security tests.
3. Windows agent: HTTPS enrollment client, protected stores, executable agent host, read-only capabilities, installer, tests.
4. Root: composition, server bootstrap/TLS/static hosting, portal contracts/enrollment and Obsidian styling, maintenance/presence, local AI, reports, integration verification and documentation.

## Verification

Run focused security tests after each boundary change, then the backend suite, frontend typecheck and build. Exercise a real HTTP/TLS server and outbound agent with an isolated test database; test fixtures are labeled and never presented as real machine results. Validate Windows storage locally when supported. Record physical laptop and LLM GPU/latency validation as unverified until measured.

## Deliberate scope

Single-use enrollment and manual approval are the prototype contract. Multi-use keys, automatic rebind, generic remote execution, destructive remediation, automatic startup scheduling, macOS claims, and an architecture rewrite are excluded from this delivery.
