# October 15 demonstration progress

Updated: 2026-10-10. Baseline Git HEAD: `ae5948d55019c6edf9354636e7961a071ca75d50`.

The repository contains pre-existing tracked modifications and untracked enterprise source. No commit or history rewrite has been made for this mission. Existing missing WAL/SHM files and unrelated source changes are preserved. The attached October mission authorizes implementation and supersedes the earlier read-only review request.

## Completed

- Read the required product documents and verified claims against source. Recorded design and ownership in `specs/october15_demo_design.md`.
- Fixed production legacy registration before ASGI lifespan, retired unauthenticated WebSocket, indexed human bearer verification, production CORS/worker defaults, and secret-safe logging. All five legacy router families plus legacy stats reject non-loopback peers in explicit personal mode.
- Implemented tenant-scoped single-use token issuance/list/revoke, NEW enrollment, human approval/revocation, finite credentials, replay/impersonation checks, heartbeat/presence and ACTIVE-only work/result gates.
- Closed concurrent enrollment/identity overwrite, CA transfer-file substitution, forged lease clock and terminal-state races. SQLite mutations are serialized; work/result/assessment completion commits atomically.
- Implemented the outbound Windows agent, machine DPAPI/protected state, durable result retry and four allowlisted read-only checks. Personal scanner source was preserved; reuse/adaptation/deferred/unsafe checks are documented.
- Implemented transactional first-operator bootstrap, strict-verifier-compatible TLS certificates, exclusive key publication, server CLI and fail-closed fresh installers with protected Python discovery and exact CA fingerprint verification.
- Wired the black/amethyst portal to real enrollment, fleet, trust, assessment, evidence, audit, machine/fleet report and local advisory AI APIs. Fixed failed/expired wording, invented lifecycle stages, printed report labels, presence totals and token refresh.
- Added bounded tenant reports with scanned/partial/not-scanned states, JSON/CSV and browser Print/PDF. Optional loopback-only advisory inference is disabled by default; unavailable AI does not interrupt evidence or reports.
- Final backend: **536 passed, 1 skipped, 1 warning in 58.01s**. Skip: one directory-symlink case cannot run on this host. Warning: existing SQLAlchemy declarative-base deprecation. The Windows HTTPS test ran.
- Final portal: production build/typecheck passed; **3 browser tests passed in 9.5s**. Real isolated API workflow covers enrollment/replay/approval/report/unavailable AI/revoke. Presentation fixtures are explicitly synthetic. Laptop width and print labels were checked; screenshots were visually inspected.
- Actual HP Omen loopback HTTPS golden path passed with CLI-generated certificates, strict verification, real UAC/BitLocker execution, persistence/report and revoke. BitLocker returned `READ_FAILED` under the non-admin identity, never a clean result. Earlier local firewall/UAC/SMB probes succeeded.
- Fresh Python 3.11 minimal server and agent runtime smoke checks passed. Agent runtime required no GUI, personal scanner, FastAPI, SQLAlchemy or OpenAI package.
- Both PowerShell installers parse, backend compiles, CRLF-aware Git whitespace check passes and frontend dependency audit reports zero known vulnerabilities. CI now includes backend and portal build/browser gates.
- Prepared setup, live demo/recovery, acceptance and adversarial security verification documents with severity, exact paths, attack cases, fixes and regressions.

## In progress

- No remaining implementation item in the available-machine scope. Physical deployment and rehearsal gates below remain open.

## Blocked

- Elevated installation needs protected system-wide Python 3.11. The current registered interpreter is user-writable and deliberately refused. This session is not elevated.
- Dell Vostro and HP notebook are unavailable, per the user's clarification. Their installers and instructions are prepared.

## Unverified

- Real Program Files/ProgramData installation, final ACLs/DPAPI/NTFS publication, standard-user denial, SYSTEM task execution, restart and long-running outbox recovery.
- Notebook enrollment, Private LAN firewall/TLS connectivity, physical scan execution and reboot persistence.
- Live Llama GPU memory, latency and response quality. No LM Studio/Ollama process or listener at the default ports was detected. AI stays disabled by default.
- Production offline CA-key custody; PostgreSQL concurrency if selected instead of the tested SQLite pilot.

## Next implementation task

After the operator supplies protected Python and elevation, install/rehearse the Omen server and agent using `docs/deployment/OCTOBER15_SETUP.md`. Verify credential protection before merge approval. Then install the two notebooks with independently confirmed CA fingerprints and follow `docs/operations/OCTOBER15_DEMO.md`; record measured outcomes in `docs/operations/OCTOBER15_ACCEPTANCE.md`. Keep unavailable hardware and inference unverified until measured. Scanning 15 minutes after startup remains deferred.

## Independent re-verification — 2026-10-10 21:18 IST

Cursor re-ran the suite on the same dirty tree (`ae5948d5` plus uncommitted enterprise source). No source fix was required.

| Gate | Command | Result |
|---|---|---|
| Backend compile | `.venv-ravenx\Scripts\python.exe -m compileall -q backend` | exit 0. Python 3.11.9 |
| Backend tests | `.venv-ravenx\Scripts\python.exe -m pytest -q --tb=line` | **536 passed, 1 skipped, 1 warning in 67.08s**. Skip: `tests/unit/test_tls_creation_safety.py` directory symlinks unavailable. Warning: SQLAlchemy `declarative_base` deprecation. |
| Portal build | `npm run build` in `frontend/` (Node v22.22.2, npm 12.0.1) | Typecheck and production build passed. JS 461.78 kB / gzip 137.22 kB. |
| Browser | `npm run test:e2e` with `RAVENX_TEST_BROWSER` set to installed Google Chrome | **3 passed in 11.7s**. The default Playwright headless-shell binary is not installed; the first launch failed until system Chrome was supplied. The enrollment test redeemed a token once, rejected replay, refused work before approval (`403`), approved, then revoked and denied the credential (`401`). |

Nothing was committed. Hardware installation, ACL inspection, Dell LAN, and live local AI remain unverified.
