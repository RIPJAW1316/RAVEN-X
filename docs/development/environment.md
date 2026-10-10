# Development environment

The supported Raven-X control-plane development and test interpreter is
**Python 3.11.x**. Python 3.14 is currently unsupported: the active machine
has dependency drift and the legacy optional AI/Windows features have not been
validated against it.

Create a clean environment and install the curated control-plane set:

```powershell
py -3.11 -m venv .venv-ravenx
.\.venv-ravenx\Scripts\python -m pip install --upgrade pip
.\.venv-ravenx\Scripts\python -m pip install -r requirements-dev.txt
.\.venv-ravenx\Scripts\python -m pytest
.\.venv-ravenx\Scripts\python -c "import backend.api.main"
```

`requirements.txt` is a historical broad environment capture and is not a
portable development manifest. `requirements-dev.txt` pins the minimum
control-plane test/runtime dependencies, including the compatible available
`openai==2.11.0` and `httpx==0.28.1` pair and pandas for legacy AI/reporting
imports when those optional routes are enabled.

Start the control plane with:

```powershell
.\.venv-ravenx\Scripts\python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

By default the app attempts to mount the existing legacy routes as well as the
agent and human control-plane routes. If optional legacy dependencies are not
installed, those routers are skipped and the core control-plane still starts.
Set `RAVENX_ENABLE_LEGACY_ROUTES=false` to deliberately compose only the core
control-plane routes. Enabling legacy routes imports scanner, AI, remediation,
reporting, and monitoring modules, which have their own platform dependencies
and may have import-time legacy side effects.
