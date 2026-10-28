"""Operator-facing upgrade, migration, and rollback safety checks."""

from .rollback import RollbackDecision, evaluate_database_restore, evaluate_server_rollback
from .schema import CURRENT_SCHEMA_VERSION, PRE_RENEWAL_SCHEMA_VERSION, apply_sqlite_migrations, schema_version
from .upgrade import UpgradePlan, plan_inplace_upgrade

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "PRE_RENEWAL_SCHEMA_VERSION",
    "RollbackDecision",
    "UpgradePlan",
    "apply_sqlite_migrations",
    "evaluate_database_restore",
    "evaluate_server_rollback",
    "plan_inplace_upgrade",
    "schema_version",
]
