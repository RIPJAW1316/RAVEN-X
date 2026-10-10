"""TLS initialization must never follow a reparse path or replace a key."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from backend import cli
from backend.infrastructure.security import windows_files


def _mkdir(directory):
    directory.mkdir(parents=True, exist_ok=True)


def test_tls_init_refuses_to_replace_existing_material(tmp_path):
    directory = tmp_path / "tls"
    files = cli.generate_local_tls(directory, ["omen.local"], protect=_mkdir)
    before = {name: Path(path).read_bytes() for name, path in files.items()}
    with pytest.raises(ValueError, match="already exists"):
        cli.generate_local_tls(directory, ["other.local"], protect=_mkdir)
    assert {name: Path(path).read_bytes() for name, path in files.items()} == before
    assert not (directory / ".tls-init.lock").exists()


def test_concurrent_tls_init_has_one_owner_before_key_generation(tmp_path, monkeypatch):
    directory = tmp_path / "tls"
    entered, release = Event(), Event()

    def slow_material(_directory, _hosts, _windows):
        entered.set()
        assert release.wait(10)
        return {"owner": "first"}

    monkeypatch.setattr(cli, "_generate_local_tls_material", slow_material)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(cli.generate_local_tls, directory, ["omen.local"], protect=_mkdir)
        assert entered.wait(10)
        with pytest.raises(ValueError, match="already in progress"):
            cli.generate_local_tls(directory, ["omen.local"], protect=_mkdir)
        release.set()
        assert first.result(timeout=10) == {"owner": "first"}
    assert not (directory / ".tls-init.lock").exists()


def test_tls_protection_receives_lexical_path_before_reparse_resolution(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "junction"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks unavailable on this host")

    def reject_reparse(directory):
        assert directory == alias.absolute()
        assert directory.is_symlink()
        raise ValueError("reparse path refused")

    with pytest.raises(ValueError, match="reparse path refused"):
        cli.generate_local_tls(alias, ["omen.local"], protect=reject_reparse)
    assert list(actual.iterdir()) == []


def test_tls_init_never_resolves_before_protection(tmp_path, monkeypatch):
    directory = tmp_path / "tls"
    observed = []
    monkeypatch.setattr(Path, "resolve", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("reparse target followed before protection")))
    monkeypatch.setattr(cli, "_generate_local_tls_material", lambda *_args: {})

    def protect(path):
        observed.append(path)
        path.mkdir()

    assert cli.generate_local_tls(directory, ["omen.local"], protect=protect) == {}
    assert observed == [directory.absolute()]


def test_protected_create_is_atomic_and_exclusive_without_replacing_target(tmp_path, monkeypatch):
    monkeypatch.setattr(windows_files, "verify_directory", lambda path: path)
    monkeypatch.setattr(windows_files, "_assert_no_reparse", lambda path: None)
    monkeypatch.setattr(windows_files, "_set_private_acl", lambda path, *, directory: None)
    monkeypatch.setattr(windows_files, "verify_protected_file", lambda path: path)
    target = tmp_path / "ca-key.pem"
    windows_files.atomic_create_protected(target, b"first private key")
    with pytest.raises(FileExistsError):
        windows_files.atomic_create_protected(target, b"second private key")
    assert target.read_bytes() == b"first private key"
    assert list(tmp_path.glob("*.tmp")) == []
