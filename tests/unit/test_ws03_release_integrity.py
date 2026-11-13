import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

import pytest


SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "build-server-release.py"
spec = importlib.util.spec_from_file_location("ws03_server_release", SOURCE)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _package(tmp_path, *, member=b"trusted", declared=b"trusted"):
    manifest = {"format": 1, "version": release.VERSION, "source_baseline": release.BASELINE,
                "files": [{"path": "VERSION", "sha256": _sha(declared), "size": len(declared)}]}
    path = tmp_path / "release.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("VERSION", member)
        archive.writestr("release-manifest.json", json.dumps(manifest))
    return path, _sha(path.read_bytes())


def test_independent_package_digest_is_mandatory(tmp_path):
    path, digest = _package(tmp_path)
    assert release.verify(path, expected_sha256=digest)["files"] == 1
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        release.verify(path, expected_sha256="0" * 64)


def test_payload_tamper_fails_even_with_recomputed_zip_digest(tmp_path):
    path, digest = _package(tmp_path, member=b"altered")
    with pytest.raises(ValueError, match="member hash mismatch"):
        release.verify(path, expected_sha256=digest)


def test_extracted_payload_must_match_authenticated_archive(tmp_path):
    path, digest = _package(tmp_path)
    root = tmp_path / "stage"
    root.mkdir()
    with zipfile.ZipFile(path) as archive:
        archive.extractall(root)
    assert release.verify_extracted(root, path, expected_sha256=digest)["files"] == 1
    (root / "VERSION").write_bytes(b"replaced")
    with pytest.raises(ValueError, match="differs"):
        release.verify_extracted(root, path, expected_sha256=digest)
