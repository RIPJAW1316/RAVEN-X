"""Disposable upgrade planner. Inputs arrive as environment variables, never as source text."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys

from backend.application.ops.upgrade import plan_inplace_upgrade


def main() -> int:
    source = Path(os.environ["RAVENX_PLAN_SOURCE"])
    version = source / "VERSION"
    digest = hashlib.sha256(version.read_bytes()).hexdigest() if version.is_file() else None
    expected = os.environ.get("RAVENX_PLAN_SHA256") or None
    plan = plan_inplace_upgrade(
        source_root=source,
        install_root=Path(os.environ["RAVENX_PLAN_INSTALL"]),
        data_root=Path(os.environ["RAVENX_PLAN_DATA"]),
        version_file_sha256=digest,
        expected_version_sha256=expected,
    )
    sys.stdout.write("%s %s %s\n" % (plan.allowed, plan.code, plan.message))
    return 0 if plan.allowed else 3


if __name__ == "__main__":
    raise SystemExit(main())
