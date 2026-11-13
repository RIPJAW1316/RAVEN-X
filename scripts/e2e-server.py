"""Loopback-only, isolated fixture server. Contains synthetic test identities."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8849)
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="ravenx-e2e-", dir=os.environ.get("RAVENX_TEST_DATA_ROOT")))
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_directory, assert_ancestry_not_substitutable
        protect_private_directory(directory)
        assert_ancestry_not_substitutable(directory)
    os.environ.update(RAVENX_DATABASE_PATH=str(directory / "test.db"),
                      RAVENX_ENVIRONMENT="production", RAVENX_ENABLE_LEGACY_ROUTES="false",
                      RAVENX_SERVE_FRONTEND="true", RAVENX_PRESENCE_MAINTENANCE_ENABLED="true")
    from backend.core.database.database import db_manager
    from backend.cli import bootstrap
    bootstrap(db_manager, email="browser-test@example.invalid", display_name="Synthetic test operator",
              password="Synthetic-browser-test-only-2026", organization="Synthetic browser test")
    import uvicorn
    uvicorn.run("backend.api.main:app", host="127.0.0.1", port=args.port,
                proxy_headers=False, server_header=False, access_log=False)
