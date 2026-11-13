"""Create an inert, protected pre-WS-01 server fixture for WS-03B rehearsal.

The fixture contains no human or endpoint identities, sessions, or credentials.
It is never a source of production authority.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def create(root: Path, lan_address: str) -> dict:
    if os.name != "nt":
        raise ValueError("disposable fixture requires Windows")
    from backend.application.ops.listeners import validated_hosts
    from backend.cli import prepare_data_dir, generate_local_tls
    from backend.core.database.database import DatabaseManager
    from backend.infrastructure.security.windows_files import (
        atomic_create_protected, protect_directory, verify_directory,
    )

    root = Path(root).absolute()
    expected_parent = Path(os.environ["PROGRAMDATA"]) / "RAVEN-X"
    if root.parent != expected_parent or not re.fullmatch(r"ws03b-disposable-[0-9a-f]{32}", root.name):
        raise ValueError("fixture root is outside the protected disposable parent")
    verify_directory(root)
    validated_hosts(["127.0.0.1", lan_address], None)
    install_parent = protect_directory(root / "RAVEN-X")
    installed = protect_directory(install_parent / "Server")
    atomic_create_protected(installed / "VERSION", b"pre-ws01-synthetic\n")
    config = protect_directory(installed / "config")
    atomic_create_protected(config / "config.yaml", b"server:\n  mode: synthetic\n")
    data = prepare_data_dir(root / "server")
    generate_local_tls(data / "tls", ["127.0.0.1", lan_address])
    database_path = data / "raven_x.db"
    os.environ["RAVENX_DATABASE_PATH"] = str(database_path)
    os.environ["RAVENX_ENABLE_LEGACY_ROUTES"] = "false"
    manager = DatabaseManager()
    try:
        manager.create_tables()
    finally:
        manager.close()
    with sqlite3.connect(database_path) as db:
        db.execute("PRAGMA foreign_keys=OFF")
        for table in ("endpoint_credential_renewals", "ravenx_verifier_keys", "ravenx_schema_versions"):
            db.execute('DROP TABLE "' + table + '"')
        db.commit()
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if len(tables) != 33 or db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("synthetic pre-upgrade database is invalid")
    return {"synthetic": True, "tables": 33, "identities": 0, "credentials": 0}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--lan-address", required=True)
    args = parser.parse_args()
    try:
        result = create(args.root, args.lan_address)
        import json
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        parser.exit(2, "WS-03B fixture refused: " + type(error).__name__ + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
