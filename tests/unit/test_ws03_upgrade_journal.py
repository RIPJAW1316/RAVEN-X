import os
from pathlib import Path
import uuid

import pytest

from backend.application.ops.server_upgrade import mark_phase


@pytest.fixture
def data_root(tmp_path):
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_directory
        path = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / ("ws03-journal-" + uuid.uuid4().hex)
        path.mkdir(parents=True)
        protect_private_directory(path)
        return path
    tmp_path.chmod(0o700)
    return tmp_path


def test_journal_requires_order_and_same_release_identity(data_root):
    digest = "a" * 64
    with pytest.raises(ValueError, match="begin"):
        mark_phase(data_root, phase="migrated", package_sha256=digest,
                   backup_path="backup-a", production=False)
    for phase in ("backup_verified", "migrated", "key_bound", "code_switched", "ready"):
        assert mark_phase(data_root, phase=phase, package_sha256=digest,
                          backup_path="backup-a", production=False)["phase"] == phase
    with pytest.raises(ValueError, match="identity"):
        mark_phase(data_root, phase="ready", package_sha256="b" * 64,
                   backup_path="backup-a", production=False)


def test_journal_refuses_skipped_phase(data_root):
    mark_phase(data_root, phase="backup_verified", package_sha256="c" * 64,
               backup_path="backup-b", production=False)
    with pytest.raises(ValueError, match="transition"):
        mark_phase(data_root, phase="key_bound", package_sha256="c" * 64,
                   backup_path="backup-b", production=False)
