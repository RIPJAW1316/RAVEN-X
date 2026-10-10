# RAVEN-X current-state baseline (Phase 1A)

This document records the implementation state as found during Phase 1A. It is
not a claim that multi-endpoint functionality exists.

## Working

- `scanner.py` remains the personal-mode implementation. It performs local
  Windows checks, produces finding dictionaries, stores local history, renders
  local reports, and can generate remediation scripts.
- The SQLAlchemy models can create and relate `Scan` and `Vulnerability`
  records in SQLite.
- The FastAPI application exposes a lightweight `/health` endpoint after its
  import wiring is corrected.

## Partial

- REST routes exist for scanning, analysis, remediation, reporting, and system
  monitoring, but they still operate on the local machine only.
- AI analysis has a local-LLM boundary and a fallback response path. It is not
  a source of authorization for remediation.
- Compliance and tamper-evident audit utilities exist, but are not yet wired
  into the standard scan lifecycle.
- `EnhancedScanner` now exposes only checks with implementations in that
  module. Its legacy-only and placeholder checks are recorded in
  `MODULE_STATUS`, not advertised as runnable modules.

## Broken or incomplete

- The backend scanner does not yet implement most checks available in
  `scanner.py`; it is not a replacement for personal mode.
- Scan and analysis execution currently have only basic in-process background
  task handling. They do not provide durable progress, cancellation, retry, or
  endpoint dispatch.
- The enhanced GUI remains a partial integration shell and is not the primary
  desktop entry point.
- Docker Compose refers to Docker files that are not present in this checkout.

## Legacy-only behavior

`scanner.py` owns the mature Windows checks and its Tkinter workflow. Phase 1A
does not move, split, or replace that implementation. Its current finding
shape is protected by a representative fixture:

```text
severity, category, title, details, component, remediation, powershell_command
```

Compliance is derived separately from finding category and title; it is not
embedded in the legacy finding dictionary.

## Tests now protecting the baseline

- Imports for API, database, scanner, reporting, remediation, and AI modules.
- FastAPI health availability.
- Isolated SQLite scan/vulnerability lifecycle.
- Enhanced scanner registry consistency and a mocked targeted scan.
- Legacy firewall finding compatibility and compliance inputs.
- Remediation safety routing with mocked subprocess calls and API destructive
  action guard.
- AI analysis with a fake provider.
- Configuration parsing without a live service or credentials.

## Runtime baseline

The checked-in `requirements.txt` contains the core backend test/runtime
packages (`fastapi`, `SQLAlchemy`, `aiosqlite`, `pytest`, `pandas`, `numpy`,
`openai`, `Jinja2`, `PyYAML`, and `uvicorn`). The supplied `venv311` imports
the full tested stack, including the Windows/Tkinter packages. The system
Python used for reconnaissance does not contain `pandas`; use the project
virtual environment for backend execution. `customtkinter` and `pywin32` are
available in that environment but were not found as direct pins in the current
requirements file, so clean-install reproducibility remains a documented
follow-up rather than a Phase 1A dependency rewrite.

## Deliberately deferred

Organizations, endpoint agents, enrollment, RBAC, tenant isolation, distributed
assessment orchestration, centralized findings, scheduling, and policy-driven
enterprise remediation remain out of scope until the local baseline is stable.
