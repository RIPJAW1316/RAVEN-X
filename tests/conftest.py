"""Shared test configuration for the RAVEN-X stabilization baseline."""

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# `backend.api.main` reads settings once at import time, and several suites
# exercise the legacy personal-mode routes (/api/v1/scan, /system) against that
# single shared app.  Those routers are off by default in the product, so the
# suite opts in explicitly here to keep that coverage.
#
# This deliberately does NOT weaken the shipped default: the default-closed
# behaviour is asserted in tests/unit/test_unsafe_defaults.py, which starts a
# fresh interpreter with a clean environment rather than relying on this one.
os.environ.setdefault("RAVENX_ENABLE_LEGACY_ROUTES", "true")

# The repository config declares `environment: "production"`.  That value used
# to be unreachable, so the suite silently ran development checks.  Now that it
# is honoured, the suite must state what it actually is: a test run, not a
# production deployment.  Without this the legacy opt-in above would (correctly)
# refuse to start.
os.environ.setdefault("RAVENX_ENVIRONMENT", "test")
