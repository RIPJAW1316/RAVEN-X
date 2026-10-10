# October 15 implementation acceptance record

Date: 2026-10-10. Base: `ae5948d55019c6edf9354636e7961a071ca75d50` plus current uncommitted mission source. No commit was created because the shared working tree includes unrelated pre-existing changes.

## Verified in this workspace

| Gate | Actual result |
| --- | --- |
| Complete backend | `.venv-ravenx\Scripts\python.exe -m pytest -q`: 536 passed, 1 skipped, 1 warning, 58.01 seconds. |
| Skip/warning | Directory symlink creation unavailable on this Windows host; existing SQLAlchemy `declarative_base` deprecation. The real Windows HTTPS scanner test ran. |
| Portal | `npm run build`: TypeScript and production build passed. `npm run test:e2e`: 3 passed, 9.5 seconds, using the installed local Chromium binary override. |
| Browser coverage | Real isolated API enrollment/approval/replay/revoke, no enrollment secret persisted to browser storage, machine report, unavailable AI; explicitly synthetic failure/lifecycle and finding-to-AI presentation fixtures. Laptop width and printed report labels checked. |
| Real Windows execution | Loopback HTTPS with actual CLI-generated CA/leaf and strict verification, real UAC/BitLocker reads, work/result persistence, partial report and revoked credential denial. Test identities/storage are isolated; this is not a notebook LAN run. |
| Minimal server runtime | Fresh Python 3.11 venv with only server requirements: production startup, health/readiness, legacy remediation 404 and shutdown passed. |
| Minimal agent runtime | Fresh Python 3.11 venv with only agent requirements: CLI and four scanner/runtime registrations constructed without scanning. GUI, personal scanner, server and model packages absent. |
| Static/install checks | Both PowerShell scripts parse; backend compiles; CRLF-aware Git whitespace check passes. |
| Dependencies | `npm audit --audit-level=low`: zero known vulnerabilities; not a complete supply-chain audit. |

Fresh runtime probe environments were retained under Windows Temp: `ravenx-server-runtime-9bb36916d7a94ea2b74b38f53ba0e07f` and `ravenx-agent-smoke-xbjaw7en`. These are verification environments, not installed deployments.

## Available HP Omen hardware

Read-only CIM probe: OMEN Slim Gaming Laptop 16-an0xxx, 31.4 GiB physical RAM, 14.6 GiB free at the probe; Intel Arc 140T and NVIDIA GeForce RTX 5070 Laptop GPU reported. GPU names do not establish usable model VRAM. No LM Studio/Ollama process or listener on ports 1234/11434 was detected. No live model benchmark or successful inference is claimed.

## Physical rehearsal — pending

Use the [setup guide](../deployment/OCTOBER15_SETUP.md) and [demo/recovery runbook](OCTOBER15_DEMO.md). Record actual build, hostname, full endpoint ID, timestamps, CA SHA-256 and assessment ID. Redact passwords, bootstrap tokens and bearer credentials.

| Required proof | HP Omen | Dell Vostro | HP notebook |
| --- | --- | --- | --- |
| Protected Python and elevated fresh installation | Pending | Pending — unavailable | Pending — unavailable |
| SYSTEM/Admin-only private-file ACL; standard account cannot read | Pending | Pending | Pending |
| Verified fingerprint, SAN and HTTPS reachability | Loopback test passed; installed/LAN pending | Pending | Pending |
| Single-use enrollment, NEW work denial and physical approval | Isolated test passed; installed pending | Pending | Pending |
| Heartbeat, online/stale/offline transitions | Automated coverage; installed pending | Pending | Pending |
| Actual scanner coverage and stored evidence | Non-admin local test passed; SYSTEM pending | Pending | Pending |
| Machine/fleet reports and matching audit events | API/browser tests passed; rehearsal pending | Pending | Pending |
| Revoke denies subsequent traffic and retains history | Isolated test passed; installed pending | Pending | Pending |
| Restart, boot task and outage/result recovery | Pending | Pending | Pending |

Inspect protected-object owner, DACL and inheritance with `Get-Acl`/`icacls`. Expect SYSTEM and local Administrators only for private files. Confirm a standard account cannot read `credential.bin`, the result outbox or either server private key; never copy their bytes into the log. Machine DPAPI requires the ACL to protect against other local accounts.

## Optional inference — pending

Enable only an independently verified loopback model. Record model/quantization, usable GPU memory, peak memory, response latency, source assessment IDs, evidence truncation and provider failure behavior. Confirm generated text stays advisory and cannot change findings or dispatch commands. Keep unavailable analysis explicit until this passes.

## Decision and next milestones

The source is a tested controlled prototype candidate. **Final merge approval and installed demonstration readiness remain pending elevated Windows credential-protection and physical rehearsal evidence.** Enrollment's design is safe with the implemented one-use, tenant, approval, expiry, revoke, TLS pinning and OS-storage controls; live storage verification must confirm the assumptions.

Before production: operator-reviewed offline CA-key custody, credential renewal/rotation, backup/update/reprovision procedures, longer outage/reboot trials and PostgreSQL concurrency testing if selected. Later milestones: paginated report history beyond current bounds, additional reviewed read-only checks, validated Linux/macOS execution and the deferred startup scheduler.
