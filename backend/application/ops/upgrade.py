"""In-place upgrade planning for disposable installation trees.

This module never touches Program Files or ProgramData unless those paths are
passed in explicitly by the caller. Tests must use temporary directories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple


SUPPORTED_PACKAGE_VERSION = "0.5.0-ws01"
MINIMUM_INSTALL_VERSION = "0.4.0"


@dataclass(frozen=True)
class UpgradePlan:
    allowed: bool
    code: str
    message: str
    source_version: str
    installed_version: str
    steps: Tuple[str, ...] = field(default_factory=tuple)
    backup_paths: Tuple[str, ...] = field(default_factory=tuple)


def _read_version(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def plan_inplace_upgrade(*, source_root: Path, install_root: Path, data_root: Path,
                         package_sha256: str | None = None, expected_sha256: str | None = None,
                         version_file_sha256: str | None = None, expected_version_sha256: str | None = None,
                         source_version: str = SUPPORTED_PACKAGE_VERSION) -> UpgradePlan:
    source_root, install_root, data_root = Path(source_root), Path(install_root), Path(data_root)
    checked = version_file_sha256 if version_file_sha256 is not None else package_sha256
    expected = expected_version_sha256 if expected_version_sha256 is not None else expected_sha256
    if expected and (not checked or checked.lower() != expected.lower()):
        return UpgradePlan(False, "version_file_digest_mismatch",
                           "The VERSION file digest does not match. This check is not a package checksum.",
                           source_version, _read_version(install_root / "VERSION"))
    if not source_root.is_dir():
        return UpgradePlan(False, "missing_source", "Upgrade source tree is missing.",
                           source_version, "")
    if not install_root.is_dir():
        return UpgradePlan(False, "missing_install",
                           "Install root does not exist; use the first-install script.",
                           source_version, "")
    if not data_root.is_dir():
        return UpgradePlan(False, "missing_data",
                           "Data root does not exist; enrollment or TLS state would be lost.",
                           source_version, "")
    installed = _read_version(install_root / "VERSION") or MINIMUM_INSTALL_VERSION
    if installed > source_version:
        return UpgradePlan(False, "installed_newer",
                           "Installed version is newer than the upgrade package.",
                           source_version, installed)
    backups = (
        str(data_root / "upgrade-backup" / "database"),
        str(data_root / "upgrade-backup" / "tls"),
        str(data_root / "upgrade-backup" / "agent-state"),
    )
    steps = (
        "verify_version_file_digest",
        "verify_install_and_data_ownership",
        "quiesce_service_or_task",
        "copy_database_and_tls_to_upgrade_backup",
        "stage_new_code_beside_current_install",
        "apply_sqlite_migrations",
        "evaluate_server_rollback_before_any_downgrade",
        "swap_staged_code",
        "health_check",
        "retain_backup_until_renewal_lineages_are_confirmed",
    )
    return UpgradePlan(True, "upgrade_planned",
                       "Disposable-tree plan only. Checked the VERSION file digest, not a package "
                       "checksum. This is not a production upgrade; WS-03 owns package integrity.",
                       source_version, installed, steps, backups)


def apply_staged_code(*, staged_root: Path, install_root: Path, files) -> None:
    """Replace install code from a staged tree using the injected file helper.

    ``files`` must implement the same atomic create/write verification as the
    Windows helper. This function never copies TLS keys or databases.
    """
    staged_root, install_root = Path(staged_root), Path(install_root)
    if not staged_root.is_dir() or not install_root.is_dir():
        raise ValueError("staged and install roots must exist")
    marker = install_root / "VERSION"
    payload = (staged_root / "VERSION").read_bytes() if (staged_root / "VERSION").is_file() else b"0.5.0-ws01"
    if marker.exists():
        files.atomic_write_protected(marker, payload)
    else:
        files.atomic_create_protected(marker, payload)
