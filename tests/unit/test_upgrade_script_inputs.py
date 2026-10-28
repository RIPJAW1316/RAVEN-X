"""Upgrade scripts must treat operator input as data and refuse -Execute."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = (ROOT / "scripts" / "upgrade-server.ps1", ROOT / "scripts" / "upgrade-agent.ps1")


def _snapshot(directory: Path):
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob("*") if path.is_file()
    }


def _trees(tmp_path: Path, name="tree"):
    source = tmp_path / name / "source"
    install = tmp_path / name / "install"
    data = tmp_path / name / "data"
    for path in (source, install, data):
        path.mkdir(parents=True)
    version = b"0.5.0-ws01\n"
    (source / "VERSION").write_bytes(version)
    (install / "VERSION").write_text("0.4.0", encoding="utf-8")
    (data / "credential.bin").write_bytes(b"sentinel")
    return source, install, data, hashlib.sha256(version).hexdigest()


def _run(script: Path, *args):
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-File", str(script), *args, "-PythonExe", sys.executable],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return completed


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_valid_sha256_is_planned_as_data(script, tmp_path):
    source, install, data, digest = _trees(tmp_path)
    completed = _run(script, "-SourceRoot", str(source), "-InstallRoot", str(install),
                     "-DataRoot", str(data), "-ExpectedSha256", digest)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "True upgrade_planned" in output
    assert "VERSION file digest" in output
    assert "not a package checksum" in output
    assert "not a production upgrade" in output


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
@pytest.mark.parametrize("digest", ["abcd", "zz" * 32, "é" * 8, "ab" * 31 + "g"])
def test_malformed_digest_stops_without_a_planner(script, tmp_path, digest):
    source, install, data, _digest = _trees(tmp_path, "bad")
    before = _snapshot(tmp_path)
    completed = _run(script, "-SourceRoot", str(source), "-InstallRoot", str(install),
                     "-DataRoot", str(data), "-ExpectedSha256", digest)
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "64 hexadecimal" in output
    assert "upgrade_planned" not in output
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_crafted_executable_payload_does_not_run(script, tmp_path):
    source, install, data, _digest = _trees(tmp_path, "inject")
    marker = tmp_path / "pwned.txt"
    payload = "'); open(r'%s','w').write('executed'); import os; os.system('echo injected') #" % marker.as_posix()
    before = _snapshot(tmp_path)
    completed = _run(script, "-SourceRoot", str(source), "-InstallRoot", str(install),
                     "-DataRoot", str(data), "-ExpectedSha256", payload)
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0, output
    assert not marker.exists()
    assert "executed" not in output
    assert "injected" not in output
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_execute_refuses_without_modifying_files(script, tmp_path):
    source, install, data, digest = _trees(tmp_path, "execute")
    before = _snapshot(tmp_path)
    completed = _run(script, "-SourceRoot", str(source), "-InstallRoot", str(install),
                     "-DataRoot", str(data), "-ExpectedSha256", digest, "-Execute")
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "not a production upgrade" in output
    assert "No files were modified" in output
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
@pytest.mark.parametrize("folder", ["o'brien agents", "path with spaces", "données 代理"])
def test_unusual_paths_are_ordinary_data(script, tmp_path, folder):
    base = tmp_path / folder
    source = base / "source"
    install = base / "install"
    data = base / "data"
    for path in (source, install, data):
        path.mkdir(parents=True)
    version = "0.5.0-ws01\n".encode("utf-8")
    (source / "VERSION").write_bytes(version)
    (install / "VERSION").write_text("0.4.0", encoding="utf-8")
    (data / "credential.bin").write_bytes(b"sentinel")
    digest = hashlib.sha256(version).hexdigest()
    completed = _run(script, "-SourceRoot", str(source), "-InstallRoot", str(install),
                     "-DataRoot", str(data), "-ExpectedSha256", digest)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "True upgrade_planned" in output
    assert folder in output or "upgrade_planned" in output


def test_reparse_install_root_is_refused(tmp_path):
    source, install, data, digest = _trees(tmp_path, "reparse")
    link = tmp_path / "install-link"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(install)],
        capture_output=True, text=True,
    )
    if created.returncode != 0 or not link.exists():
        pytest.skip("this account cannot create a directory junction: %s" % created.stderr.strip())
    before = _snapshot(install)
    completed = _run(SCRIPTS[0], "-SourceRoot", str(source), "-InstallRoot", str(link),
                     "-DataRoot", str(data), "-ExpectedSha256", digest)
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "reparse point" in output
    assert _snapshot(install) == before
