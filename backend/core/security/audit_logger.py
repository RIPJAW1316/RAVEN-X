"""
RAVEN-X Enterprise — Tamper-Proof Audit Logger
Hash-chained, append-only event log for defense compliance.
Every entry is cryptographically linked to the previous one —
tampering with any entry breaks the chain and is immediately detectable.
"""

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

_LOG_DIR = Path("data/audit")
_LOG_FILE = _LOG_DIR / "audit_chain.jsonl"
_LOCK = threading.Lock()

EVENTS = {
    "SYSTEM_START":      "System started",
    "SYSTEM_STOP":       "System stopped",
    "SCAN_STARTED":      "Scan initiated",
    "SCAN_COMPLETED":    "Scan completed",
    "SCAN_FAILED":       "Scan failed",
    "VULN_DETECTED":     "Vulnerability detected",
    "FIX_REQUESTED":     "Remediation requested",
    "FIX_APPLIED":       "Fix applied",
    "FIX_ROLLED_BACK":   "Fix rolled back",
    "FIX_FAILED":        "Fix failed",
    "ANALYSIS_STARTED":  "AI analysis started",
    "ANALYSIS_DONE":     "AI analysis completed",
    "REPORT_GENERATED":  "Report generated",
    "CONFIG_CHANGED":    "Configuration changed",
    "AUDIT_VERIFIED":    "Audit chain verified",
    "AUDIT_TAMPERED":    "AUDIT CHAIN INTEGRITY FAILURE",
    "INCIDENT_REPORTED": "CERT-In incident report generated",
}


def _ensure_log_dir() -> None:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)


def _prev_hash() -> str:
    """Return the SHA-256 hash of the last log entry (or genesis hash)."""
    if not _LOG_FILE.exists() or _LOG_FILE.stat().st_size == 0:
        return hashlib.sha256(b"RAVEN-X-GENESIS").hexdigest()
    with open(_LOG_FILE, "rb") as f:
        # Seek to last newline-terminated line efficiently
        f.seek(0, 2)
        size = f.tell()
        if size == 0:
            return hashlib.sha256(b"RAVEN-X-GENESIS").hexdigest()
        # Walk backwards to find last complete line
        pos = size - 1
        while pos > 0:
            f.seek(pos)
            ch = f.read(1)
            if ch == b"\n" and pos < size - 1:
                break
            pos -= 1
        line = f.read().strip()
    if not line:
        return hashlib.sha256(b"RAVEN-X-GENESIS").hexdigest()
    try:
        entry = json.loads(line)
        return entry.get("entry_hash", hashlib.sha256(b"RAVEN-X-GENESIS").hexdigest())
    except Exception:
        return hashlib.sha256(b"RAVEN-X-GENESIS").hexdigest()


def _compute_entry_hash(entry_without_hash: dict) -> str:
    canonical = json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def log_event(
    event_type: str,
    actor: str = "system",
    details: Optional[Dict] = None,
    severity: str = "info",
) -> dict:
    """
    Append a tamper-proof entry to the audit chain.

    Returns the written entry dict.
    """
    _ensure_log_dir()
    with _LOCK:
        prev = _prev_hash()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "description": EVENTS.get(event_type, event_type),
            "actor": actor,
            "severity": severity,
            "details": details or {},
            "prev_hash": prev,
        }
        entry["entry_hash"] = _compute_entry_hash(entry)

        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    logger.debug(f"[AUDIT] {event_type} — {entry['entry_hash'][:12]}…")
    return entry


def verify_chain() -> Dict:
    """
    Walk every entry and verify the hash chain.
    Returns {"intact": bool, "entries": int, "broken_at": Optional[int]}
    """
    _ensure_log_dir()
    if not _LOG_FILE.exists():
        return {"intact": True, "entries": 0, "broken_at": None}

    entries = 0
    prev_hash = hashlib.sha256(b"RAVEN-X-GENESIS").hexdigest()
    broken_at = None

    with open(_LOG_FILE, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                broken_at = lineno
                break

            # Verify prev_hash linkage
            if entry.get("prev_hash") != prev_hash:
                broken_at = lineno
                break

            # Re-compute hash (strip entry_hash from payload)
            stored_hash = entry.pop("entry_hash", None)
            computed = _compute_entry_hash(entry)
            entry["entry_hash"] = stored_hash  # restore

            if computed != stored_hash:
                broken_at = lineno
                break

            prev_hash = stored_hash
            entries += 1

    intact = broken_at is None
    if not intact:
        log_event("AUDIT_TAMPERED", severity="critical",
                  details={"broken_at_line": broken_at})
        logger.critical(f"[AUDIT] ⚠️  Chain integrity FAILED at line {broken_at}!")
    else:
        logger.info(f"[AUDIT] ✅ Chain intact — {entries} entries verified.")

    return {"intact": intact, "entries": entries, "broken_at": broken_at}


def get_recent_entries(n: int = 100) -> List[dict]:
    """Return the last n audit entries (newest first)."""
    _ensure_log_dir()
    if not _LOG_FILE.exists():
        return []
    entries = []
    with open(_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return list(reversed(entries[-n:]))


def get_all_entries() -> List[dict]:
    """Return every audit entry."""
    return get_recent_entries(n=10_000_000)


# Log system start on module import
log_event("SYSTEM_START", details={"module": "audit_logger"})
