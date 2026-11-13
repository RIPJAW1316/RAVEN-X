"""Encrypted, same-machine server snapshot and isolated restore rehearsal.

The SQLite online backup API includes committed WAL state. A transient plain
snapshot exists only inside the protected backup directory while encryption
finishes; an interrupted run must be treated as an incomplete backup.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from contextlib import closing
from pathlib import Path
import secrets
import sqlite3
import stat
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class BackupError(RuntimeError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _custody_metadata(path: Path) -> dict:
    if os.name != "nt":
        info = path.stat()
        return {"uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}
    import win32security
    fields = (win32security.OWNER_SECURITY_INFORMATION |
              win32security.GROUP_SECURITY_INFORMATION |
              win32security.DACL_SECURITY_INFORMATION)
    descriptor = win32security.GetFileSecurity(str(path), fields)
    sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        descriptor, win32security.SDDL_REVISION_1, fields)
    return {"sddl": sddl}


def _check_path(path: Path, *, directory: bool, production: bool,
                allow_inherited_file: bool = False) -> None:
    if not path.is_absolute():
        raise BackupError("backup paths must be absolute")
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import (
            assert_ancestry_not_substitutable, verify_directory,
            verify_private_directory, verify_protected_file, verify_protected_child_file,
            verify_verifier_key_custody,
        )
        assert_ancestry_not_substitutable(path)
        if directory:
            (verify_directory if production else verify_private_directory)(path)
        elif production:
            (verify_protected_child_file if allow_inherited_file else verify_protected_file)(path)
        else:
            verify_verifier_key_custody(path, production=False)
    else:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BackupError("backup path custody is unsafe")
        if directory != stat.S_ISDIR(info.st_mode):
            raise BackupError("backup path has unexpected type")


def _create_dir(path: Path, *, production: bool) -> None:
    if path.exists() or path.is_symlink():
        raise BackupError("backup or restore destination already exists")
    _check_path(path.parent, directory=True, production=production)
    path.mkdir(mode=0o700)
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_directory, protect_private_directory
        (protect_directory if production else protect_private_directory)(path)
    _check_path(path, directory=True, production=production)


def _write(path: Path, data: bytes, *, production: bool) -> None:
    if path.exists() or path.is_symlink():
        raise BackupError("backup member already exists")
    if os.name == "nt":
        if production:
            from backend.infrastructure.security.windows_files import atomic_create_protected
            atomic_create_protected(path, data)
        else:
            path.write_bytes(data)
            from backend.infrastructure.security.windows_files import protect_private_secret_file
            protect_private_secret_file(path)
    else:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    _check_path(path, directory=False, production=production)


def _wrap_key(key: bytes) -> bytes:
    if os.name != "nt":
        raise BackupError("production backup encryption requires Windows DPAPI")
    import win32crypt
    import win32cryptcon
    return win32crypt.CryptProtectData(key, "RAVEN-X WS-03 backup", None, None, None,
                                      win32cryptcon.CRYPTPROTECT_LOCAL_MACHINE)


def _unwrap_key(data: bytes) -> bytes:
    if os.name != "nt":
        raise BackupError("production backup decryption requires Windows DPAPI")
    import win32crypt
    return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]


def _database_summary(path: Path) -> dict:
    uri = "file:" + quote(path.as_posix(), safe="/:\\") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise BackupError("database integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise BackupError("database foreign-key check failed")
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        counts = {name: db.execute('SELECT COUNT(*) FROM "' + name.replace('"', '""') + '"').fetchone()[0]
                  for name in tables}
        identity = None
        if "ravenx_verifier_keys" in tables:
            row = db.execute("SELECT key_id FROM ravenx_verifier_keys WHERE id = 1").fetchone()
            identity = row[0] if row else None
        active_hmac = 0
        if "endpoint_credentials" in tables:
            active_hmac = db.execute("SELECT COUNT(*) FROM endpoint_credentials "
                                     "WHERE status='active' AND verifier LIKE 'token-hmac-v2$%'").fetchone()[0]
        return {"tables": tables, "counts": counts,
                "verifier_key_id": identity, "active_hmac_credentials": active_hmac}


def _verify_paired_key(summary: dict, key_path: Path) -> None:
    identity = summary["verifier_key_id"]
    if summary["active_hmac_credentials"] and not identity:
        raise BackupError("active HMAC credentials lack a verifier-key identity")
    if bool(identity) != key_path.is_file():
        raise BackupError("database and verifier-key file are not paired")
    if identity:
        from backend.infrastructure.security.verifier_key import verifier_key_id
        if verifier_key_id(key_path.read_bytes()) != identity:
            raise BackupError("verifier-key file does not match database identity")


def _verify_tls_pair(files: dict[str, Path]) -> None:
    """Refuse a mixed CA/server certificate and private-key set."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    ca = x509.load_pem_x509_certificate(files["tls/ca.pem"].read_bytes())
    server = x509.load_pem_x509_certificate(files["tls/server.pem"].read_bytes())
    ca_key = serialization.load_pem_private_key(files["tls/ca-key.pem"].read_bytes(), password=None)
    server_key = serialization.load_pem_private_key(files["tls/server-key.pem"].read_bytes(), password=None)
    encoding, format = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if (ca.public_key().public_bytes(encoding, format) != ca_key.public_key().public_bytes(encoding, format)
            or server.public_key().public_bytes(encoding, format) != server_key.public_key().public_bytes(encoding, format)
            or server.issuer != ca.subject):
        raise BackupError("TLS certificate and key identities do not match")
    try:
        ca.public_key().verify(server.signature, server.tbs_certificate_bytes,
                               padding.PKCS1v15(), server.signature_hash_algorithm)
    except Exception as error:
        raise BackupError("server certificate is not signed by the preserved CA") from error


def _row_fingerprints(path: Path) -> dict[str, str]:
    """Private comparison material; never return row digests in a CLI response."""
    uri = "file:" + quote(path.as_posix(), safe="/:\\") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        result = {}
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            row_hashes = []
            for row in db.execute("SELECT * FROM " + quoted):
                typed = []
                for value in row:
                    if isinstance(value, bytes):
                        typed.append(["bytes", base64.b64encode(value).decode("ascii")])
                    elif value is None:
                        typed.append(["null", None])
                    elif isinstance(value, int):
                        typed.append(["integer", value])
                    elif isinstance(value, float):
                        typed.append(["real", repr(value)])
                    else:
                        typed.append(["text", value])
                row_hashes.append(_sha(json.dumps(typed, ensure_ascii=True,
                                                 separators=(",", ":")).encode("ascii")))
            columns = [(item[1], item[2], item[3], item[4], item[5])
                       for item in db.execute("PRAGMA table_info(" + quoted + ")")]
            schema = json.dumps(columns, ensure_ascii=True, separators=(",", ":"))
            result[name] = _sha((schema + "\n" + "\n".join(sorted(row_hashes))).encode("ascii"))
        return result


def compare_existing_records(before: Path, after: Path, *, production: bool = True) -> dict:
    """Ensure migration preserved every preexisting row, including authority state."""
    for path in (before, after):
        _check_path(path.absolute(), directory=False, production=production, allow_inherited_file=True)
        _database_summary(path)
    original, migrated = _row_fingerprints(before), _row_fingerprints(after)
    changed = sorted(name for name, digest in original.items() if migrated.get(name) != digest)
    return {"preserved": not changed, "checked_tables": len(original), "changed_tables": changed}


def create_backup(*, data_root: Path, install_root: Path, destination: Path,
                  production: bool = True) -> dict:
    """Create an encrypted snapshot. Never create or modify verifier authority."""
    data_root, install_root, destination = map(lambda p: Path(p).absolute(),
                                                (data_root, install_root, destination))
    if destination.is_relative_to(data_root) or destination.is_relative_to(install_root):
        raise BackupError("backup must be outside installed code and data")
    for directory in (data_root, install_root):
        _check_path(directory, directory=True, production=production)
    database = data_root / "raven_x.db"
    _check_path(database, directory=False, production=production, allow_inherited_file=True)
    source_files: dict[str, Path] = {}
    for name in ("ca.pem", "ca-key.pem", "server.pem", "server-key.pem"):
        path = data_root / "tls" / name
        _check_path(path.parent, directory=True, production=production)
        _check_path(path, directory=False, production=production)
        source_files["tls/" + name] = path
    key_path = data_root / "credential-hmac.key"
    if key_path.exists() or key_path.is_symlink():
        _check_path(key_path, directory=False, production=production)
        source_files["credential-hmac.key"] = key_path
    for name in ("server-address.json", "VERSION", "config/config.yaml"):
        path = install_root / name
        if path.exists() or path.is_symlink():
            _check_path(path, directory=False, production=production, allow_inherited_file=True)
            source_files["install/" + name] = path
    _verify_tls_pair(source_files)
    _create_dir(destination, production=production)
    key = secrets.token_bytes(32)
    if production:
        _write(destination / "dpapi-key.bin", _wrap_key(key), production=True)
    else:
        # Synthetic tests use an explicit key supplied to restore. This mode
        # is never accepted as a production backup.
        _write(destination / "test-key.bin", key, production=False)
    temporary = destination / "sqlite-online-snapshot.db"
    _write(temporary, b"", production=production)
    try:
        uri = "file:" + quote(database.as_posix(), safe="/:\\") + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as source:
            with closing(sqlite3.connect(temporary)) as target:
                source.backup(target)
        summary = _database_summary(temporary)
        _verify_paired_key(summary, key_path)
        source_files["raven_x.db"] = temporary
        entries = []
        cipher = AESGCM(key)
        for index, (name, source) in enumerate(sorted(source_files.items())):
            plain = source.read_bytes()
            custody_source = database if name == "raven_x.db" else source
            nonce = secrets.token_bytes(12)
            member = f"member-{index:03d}.enc"
            encrypted = nonce + cipher.encrypt(nonce, plain, name.encode("utf-8"))
            _write(destination / member, encrypted, production=production)
            if name != "raven_x.db" and source.read_bytes() != plain:
                raise BackupError("source material changed during backup")
            entries.append({"name": name, "member": member, "sha256": _sha(plain),
                            "source_custody": _custody_metadata(custody_source),
                            "encrypted_sha256": _sha(encrypted), "size": len(plain)})
        manifest = {"format": 1, "kind": "ravenx-server-backup", "encrypted": True,
                    "machine_bound": production, "database": summary,
                    "directory_custody": {"data": _custody_metadata(data_root),
                                          "install": _custody_metadata(install_root),
                                          "tls": _custody_metadata(data_root / "tls")},
                    "files": entries}
        payload = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        _write(destination / "manifest.json", payload, production=production)
        verified = verify_backup(destination, production=production)
        return {"manifest_sha256": _sha(payload), "tables": len(summary["tables"]),
                "files": len(entries), "verified": verified}
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_backup(root: Path, *, production: bool = True) -> bool:
    root = Path(root).absolute()
    _check_path(root, directory=True, production=production)
    manifest_file = root / "manifest.json"
    _check_path(manifest_file, directory=False, production=production)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest.get("format") != 1 or manifest.get("kind") != "ravenx-server-backup":
        raise BackupError("backup manifest is invalid")
    key_file = root / ("dpapi-key.bin" if production else "test-key.bin")
    _check_path(key_file, directory=False, production=production)
    key = _unwrap_key(key_file.read_bytes()) if production else key_file.read_bytes()
    names = set()
    for item in manifest["files"]:
        name, member = item["name"], item["member"]
        if name in names or not re.fullmatch(r"member-[0-9]{3}\.enc", member):
            raise BackupError("backup manifest contains an unsafe member")
        names.add(name)
        file = root / member
        _check_path(file, directory=False, production=production)
        encrypted = file.read_bytes()
        if _sha(encrypted) != item["encrypted_sha256"]:
            raise BackupError("encrypted backup member hash mismatch")
        plain = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], name.encode("utf-8"))
        if _sha(plain) != item["sha256"] or len(plain) != item["size"]:
            raise BackupError("backup member hash mismatch")
    if "raven_x.db" not in names or not {"tls/ca.pem", "tls/server.pem", "tls/server-key.pem", "tls/ca-key.pem"} <= names:
        raise BackupError("backup is incomplete")
    return True


def restore_isolated(*, backup_root: Path, destination: Path, production: bool = True,
                     network_isolated: bool = False) -> dict:
    """Restore to a NEW protected directory only; never overwrite live state."""
    if not network_isolated:
        raise BackupError("restore rehearsal requires explicit network isolation")
    verify_backup(backup_root, production=production)
    root = Path(backup_root).absolute()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    key_file = root / ("dpapi-key.bin" if production else "test-key.bin")
    key = _unwrap_key(key_file.read_bytes()) if production else key_file.read_bytes()
    destination = Path(destination).absolute()
    if destination.is_relative_to(root):
        raise BackupError("restore destination must be separate from backup")
    _create_dir(destination, production=production)
    for item in manifest["files"]:
        name = item["name"]
        if name not in {"raven_x.db", "credential-hmac.key", "tls/ca.pem", "tls/ca-key.pem",
                        "tls/server.pem", "tls/server-key.pem", "install/server-address.json",
                        "install/VERSION", "install/config/config.yaml"}:
            raise BackupError("restore manifest contains an unexpected path")
        target = destination / name
        parent = destination
        for component in Path(name).parts[:-1]:
            parent = parent / component
            if not parent.exists():
                _create_dir(parent, production=production)
        encrypted = (root / item["member"]).read_bytes()
        plain = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], name.encode("utf-8"))
        _write(target, plain, production=production)
    summary = _database_summary(destination / "raven_x.db")
    if summary != manifest["database"]:
        raise BackupError("restored database records differ from the backup manifest")
    _verify_paired_key(summary, destination / "credential-hmac.key")
    return {"tables": len(summary["tables"]), "counts": summary["counts"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="RAVEN-X WS-03 protected backup")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--data-root", type=Path, required=True)
    create.add_argument("--install-root", type=Path, required=True)
    create.add_argument("--destination", type=Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--backup-root", type=Path, required=True)
    restore = sub.add_parser("restore-isolated")
    restore.add_argument("--backup-root", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    summary = sub.add_parser("summarize")
    summary.add_argument("--database", type=Path, required=True)
    compare = sub.add_parser("compare-records")
    compare.add_argument("--before", type=Path, required=True)
    compare.add_argument("--after", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_backup(data_root=args.data_root, install_root=args.install_root,
                                   destination=args.destination)
        elif args.command == "verify":
            result = {"verified": verify_backup(args.backup_root)}
        elif args.command == "summarize":
            _check_path(args.database.absolute(), directory=False, production=True,
                        allow_inherited_file=True)
            result = _database_summary(args.database.absolute())
        elif args.command == "compare-records":
            result = compare_existing_records(args.before, args.after)
            if not result["preserved"]:
                print(json.dumps(result, sort_keys=True))
                return 3
        else:
            result = restore_isolated(backup_root=args.backup_root, destination=args.destination,
                                      network_isolated=True)
        # Only aggregate counts and hashes are printed. No raw records or keys.
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        parser.exit(2, f"RAVEN-X backup refused: {type(error).__name__}\n")


if __name__ == "__main__":
    raise SystemExit(main())
