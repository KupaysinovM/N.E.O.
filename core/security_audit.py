"""Local, append-only, tamper-evident security audit journal."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class AuditIntegrityError(RuntimeError):
    pass


def _secure_directory_permissions(path: Path) -> None:
    if os.name == "nt":
        windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
        whoami = windows / "System32" / "whoami.exe"
        icacls = windows / "System32" / "icacls.exe"
        if not whoami.is_file() or not icacls.is_file():
            raise AuditIntegrityError("Windows ACL tools are unavailable")
        identity = subprocess.run(
            [str(whoami), "/user", "/fo", "csv", "/nh"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout
        match = re.search(r'"(S-1-(?:\d+-)+\d+)"\s*$', identity.strip())
        if match is None:
            raise AuditIntegrityError("current Windows user SID is unavailable")
        result = subprocess.run(
            [str(icacls), str(path), "/inheritance:r", "/grant:r",
             f"*{match.group(1)}:(OI)(CI)(F)",
             "*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if result.returncode:
            raise AuditIntegrityError("could not restrict Windows audit-directory ACL")
        return
    try:
        path.chmod(0o700)
        if path.stat().st_mode & 0o077:
            raise AuditIntegrityError("audit-directory permissions are not private")
    except OSError as exc:
        raise AuditIntegrityError("could not restrict audit-directory permissions") from exc


def _secure_file_permissions(path: Path) -> None:
    """Restrict audit artifacts to the current user and Windows administrators."""
    if os.name == "nt":
        windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
        whoami = windows / "System32" / "whoami.exe"
        icacls = windows / "System32" / "icacls.exe"
        if not whoami.is_file() or not icacls.is_file():
            raise AuditIntegrityError("Windows ACL tools are unavailable")

        identity = subprocess.run(
            [str(whoami), "/user", "/fo", "csv", "/nh"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout
        match = re.search(r'"(S-1-(?:\d+-)+\d+)"\s*$', identity.strip())
        if match is None:
            raise AuditIntegrityError("current Windows user SID is unavailable")

        user_sid = match.group(1)
        result = subprocess.run(
            [str(icacls), str(path), "/inheritance:r", "/grant:r",
             f"*{user_sid}:(F)", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if result.returncode:
            raise AuditIntegrityError("could not restrict Windows audit-file ACL")
        return

    try:
        path.chmod(0o600)
        if path.stat().st_mode & 0o077:
            raise AuditIntegrityError("audit-file permissions are not private")
    except OSError as exc:
        raise AuditIntegrityError("could not restrict audit-file permissions") from exc


def default_audit_path() -> Path:
    return (Path(__file__).resolve().parent.parent / "state" / "security-audit"
            / "security-audit.sqlite3")


class SecurityAuditStore:
    """Persist privacy-minimized audit facts with a keyed integrity chain.

    The key is kept separately from the journal. Files are restricted to the
    current user (plus SYSTEM/Administrators on Windows). This detects
    modification, reordering, and truncation; it cannot protect against an
    attacker who controls the current user account and both files.
    """

    def __init__(self, path: Path | str | None = None,
                 key_path: Path | str | None = None,
                 legacy_path: Path | str | None = None):
        default_store = path is None
        self.path = Path(path) if path is not None else default_audit_path()
        self.key_path = (Path(key_path) if key_path is not None
                         else self.path.with_suffix(".key"))
        if legacy_path is not None:
            self.legacy_path = Path(legacy_path)
        elif default_store:
            self.legacy_path = self.path.parent.parent / "security-audit.sqlite3"
        else:
            self.legacy_path = None
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _secure_directory_permissions(self.path.parent)
        self._migrate_legacy_files()
        self._key = self._load_or_create_key()
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        _secure_file_permissions(self.path)
        self._initialize()
        self.verify()

    def _migrate_legacy_files(self) -> None:
        if (self.legacy_path is None or self.path.exists()
                or not self.legacy_path.exists()):
            return
        legacy_key = self.legacy_path.with_suffix(".key")
        if not legacy_key.is_file():
            raise AuditIntegrityError("legacy audit key is missing")
        _secure_file_permissions(self.legacy_path)
        _secure_file_permissions(legacy_key)
        target_key = self.key_path
        temp_db = self.path.with_suffix(self.path.suffix + ".migrating")
        temp_key = target_key.with_suffix(target_key.suffix + ".migrating")
        try:
            shutil.copy2(self.legacy_path, temp_db)
            shutil.copy2(legacy_key, temp_key)
            _secure_file_permissions(temp_db)
            _secure_file_permissions(temp_key)
            temp_key.replace(target_key)
            temp_db.replace(self.path)
        except OSError as exc:
            for temporary in (temp_db, temp_key):
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            raise AuditIntegrityError("could not migrate the existing audit journal") from exc

    def _load_or_create_key(self) -> bytes:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
        except FileExistsError:
            _secure_file_permissions(self.key_path)
            key = self.key_path.read_bytes()
            if len(key) != 32:
                raise AuditIntegrityError("audit key has an invalid length")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
        _secure_file_permissions(self.key_path)
        return key

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _database(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._database() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS security_audit ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "created_at REAL NOT NULL,"
                "event_json TEXT NOT NULL,"
                "previous_mac TEXT NOT NULL,"
                "mac TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS security_audit_meta ("
                "id INTEGER PRIMARY KEY CHECK (id = 1),"
                "seq INTEGER NOT NULL,"
                "last_mac TEXT NOT NULL,"
                "checkpoint_mac TEXT NOT NULL)"
            )
            checkpoint = db.execute(
                "SELECT seq FROM security_audit_meta WHERE id = 1").fetchone()
            if checkpoint is None:
                has_records = db.execute(
                    "SELECT 1 FROM security_audit LIMIT 1").fetchone()
                if has_records:
                    raise AuditIntegrityError(
                        "audit journal has records but no trusted checkpoint")
                db.execute(
                    "INSERT INTO security_audit_meta "
                    "(id, seq, last_mac, checkpoint_mac) VALUES (1, 0, ?, ?)",
                    ("GENESIS", self._checkpoint_mac(0, "GENESIS")))

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)

    def _checkpoint_mac(self, seq: int, last_mac: str) -> str:
        material = self._canonical(
            {"seq": seq, "last_mac": last_mac}).encode("ascii")
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def _verify_connection(self, db: sqlite3.Connection) -> tuple[int, str]:
        rows = db.execute(
            "SELECT seq, created_at, event_json, previous_mac, mac "
            "FROM security_audit ORDER BY seq").fetchall()
        previous = "GENESIS"
        expected_seq = 1
        for seq, created_at, event_json, previous_mac, mac in rows:
            if seq != expected_seq or previous_mac != previous:
                raise AuditIntegrityError(
                    f"audit chain is broken at record {expected_seq}")
            material = self._canonical({
                "seq": seq, "created_at": created_at,
                "event_json": event_json, "previous_mac": previous,
            }).encode("ascii")
            expected = hmac.new(self._key, material, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, mac):
                raise AuditIntegrityError(
                    f"audit integrity check failed at record {seq}")
            previous = mac
            expected_seq += 1

        checkpoint = db.execute(
            "SELECT seq, last_mac, checkpoint_mac "
            "FROM security_audit_meta WHERE id = 1").fetchone()
        if checkpoint is None:
            raise AuditIntegrityError("audit checkpoint is missing")
        checkpoint_seq, checkpoint_mac, signature = checkpoint
        if (checkpoint_seq != len(rows) or checkpoint_mac != previous
                or not hmac.compare_digest(
                    self._checkpoint_mac(checkpoint_seq, checkpoint_mac), signature)):
            raise AuditIntegrityError("audit checkpoint does not match the journal")
        return checkpoint_seq, checkpoint_mac

    def verify(self) -> int:
        with self._lock, self._database() as db:
            seq, _last_mac = self._verify_connection(db)
            return seq

    def append(self, event: dict[str, Any]) -> int:
        """Append a JSON-safe fact; raw arguments must never be passed here."""
        encoded = self._canonical(event)
        with self._lock, self._database() as db:
            previous_seq, previous = self._verify_connection(db)
            created_at = time.time()
            seq = previous_seq + 1
            material = self._canonical({
                "seq": seq, "created_at": created_at,
                "event_json": encoded, "previous_mac": previous,
            }).encode("ascii")
            mac = hmac.new(self._key, material, hashlib.sha256).hexdigest()
            db.execute(
                "INSERT INTO security_audit "
                "(seq, created_at, event_json, previous_mac, mac) "
                "VALUES (?, ?, ?, ?, ?)",
                (seq, created_at, encoded, previous, mac))
            db.execute(
                "UPDATE security_audit_meta SET seq = ?, last_mac = ?, "
                "checkpoint_mac = ? WHERE id = 1",
                (seq, mac, self._checkpoint_mac(seq, mac)))
            return seq

    def read(self, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        self.verify()
        with self._database() as db:
            rows = db.execute(
                "SELECT seq, created_at, event_json, mac FROM security_audit "
                "WHERE seq > ? ORDER BY seq LIMIT ?",
                (max(0, int(after)), max(1, min(int(limit), 1000)))).fetchall()
        return [{"sequence": seq, "created_at": created_at,
                 "event": json.loads(payload), "integrity": mac}
                for seq, created_at, payload, mac in rows]
