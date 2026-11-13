# RAVEN-X release status

**Snapshot:** 13 November 2026. This public summary describes engineering evidence in the local acceptance records; it does not replace a signed release decision or a fresh test of every byte in the repository.

| Workstream | Recorded evidence | Decision |
| :-- | :-- | :-- |
| WS-01 credential renewal | Preserved source-reviewed baseline; renewal, expiry, replay, revocation and Windows custody source tests | Source-reviewed, non-deployable checkpoint |
| Phase 1A-B collection and reporting | Final recorded Python 3.13 run: 895 passed, 3 skipped. Four fixture browser tests passed. Confirmed findings from failed collection remain visible while coverage stays incomplete. | **Conditional source pass** |
| Windows agent installer candidate | Inno Setup 1.0.0-rc1 EXE built, embedded manifest and offline wheel hashes checked. | **Not signed; physical Dell install not tested** |
| Omen server upgrade | Additive migration and protected backup rehearsed on a copied local state; source and synthetic tests passed in the recorded WS-03 work. | **Live upgrade not accepted** |
| Agent recovery RC6e | Source/package preflight and focused non-elevated tests. Earlier privileged synthetic runs stopped before complete backup/restore/archive acceptance. | **NO-GO for privileged or live acceptance** |
| Dell–Omen pilot | Omen installed version mismatch and absent listener were recorded; Dell installer, enrollment, four-check result and recovery were not observed. | **Blocked before Dell installation** |
| Approximately 70-PC college deployment | Target topology and staged validation plan only. | **Not started / no deployment approval** |

## Open technical and physical gates

1. Qualify the exact current server and agent artifacts together under protected Windows storage, with valid TLS and independent installer/CA authenticity.
2. Complete a privileged **disposable** agent-recovery rehearsal including actual DPAPI, SYSTEM task, backup, restore, ACL, interruption and failure paths.
3. Complete the Omen upgrade and physical Dell pilot with authorized operators, recorded hashes, enrollment approval, assessment evidence, renewal and revocation.
4. Bound subprocess stdout/stderr capture before college scale. The current 15-second timeout does not bound memory consumed before the post-capture length check.
5. Run staged college-lab checks across representative Windows versions, languages, policy settings, power states and network conditions.

The older full backend and browser results belong to the revisions on which they were recorded. They are not RC6e full-suite or physical deployment evidence. The three Phase 1A-B privileged skips remain unverified. Re-run and record fresh gates for an actual release candidate.
