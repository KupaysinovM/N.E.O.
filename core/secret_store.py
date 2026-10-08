"""
core/secret_store.py — where NEO's API credential actually lives.

WHY THIS EXISTS
    The previous build kept the Gemini API key in plaintext inside
    config/api_keys.json: a file that lives in the project tree, gets copied
    into bug reports, and ends up in whatever backup someone runs. A key stored
    that way is compromised the moment the folder leaves the machine it was
    typed on. Nothing in NEO may read credentials from a plaintext settings
    file again.

WHERE THE KEY LIVES NOW
    1. Windows DPAPI — an encrypted blob at config/secure/gemini.dat, readable
       only by this Windows user on this machine (CryptProtectData with
       user-scoped protection). No new dependency: it is a Win32 call through
       ctypes, the same way the rest of this codebase talks to NVML.
    2. Environment variable — NEO_GEMINI_API_KEY, or GEMINI_API_KEY as the
       conventional fallback. This is the path for macOS/Linux, where no
       built-in per-user secret store is reachable without a new package.
    3. Legacy plaintext — read once, only so an existing install keeps working;
       migrate_legacy_settings() then moves the value into (1) and deletes the
       file. This path disappears with the file it reads.

WHAT THIS MODULE WILL NEVER DO
    * log or print a key, not even truncated — every message here names the
      location, never the value;
    * write a key to a plaintext file;
    * invent a placeholder key to make a feature look configured.

A key that cannot be stored safely is not stored at all: the caller is told to
set the environment variable instead, and NEO keeps running unconfigured.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import threading
from pathlib import Path

_IS_WINDOWS = platform.system() == "Windows"

# Environment variables checked, in order. The NEO_ name is the documented one;
# GEMINI_API_KEY is accepted because it is the convention every Gemini tool
# already uses.
ENV_KEYS = ("NEO_GEMINI_API_KEY", "GEMINI_API_KEY")


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


BASE_DIR = _base_dir()
CONFIG_DIR = BASE_DIR / "config"
SECRET_DIR = CONFIG_DIR / "secure"
CREDENTIAL_FILE = SECRET_DIR / "gemini.dat"

# The settings file NEO owns, and the legacy file it migrates away from.
SETTINGS_FILE = CONFIG_DIR / "neo_settings.json"
LEGACY_SETTINGS_FILE = CONFIG_DIR / "api_keys.json"

_lock = threading.Lock()
_cached_key: str | None = None


# ── Windows DPAPI (no dependency; ctypes like the NVML probes) ────────────────

class _DataBlob:
    """Lazily-defined DATA_BLOB so this module imports fine on non-Windows."""


def _dpapi_available() -> bool:
    if not _IS_WINDOWS:
        return False
    try:
        import ctypes  # noqa: F401
        import ctypes.wintypes  # noqa: F401
        ctypes.windll.crypt32.CryptProtectData  # noqa: B018 — presence check
        return True
    except Exception:
        return False


def _blob_structs():
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    return ctypes, DATA_BLOB


def _protect(data: bytes) -> bytes | None:
    """Encrypt for the current Windows user. None when unavailable."""
    if not _dpapi_available():
        return None
    try:
        ctypes, DATA_BLOB = _blob_structs()
        blob_in = DATA_BLOB(len(data),
                            ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                        ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        # CRYPTPROTECT_UI_FORBIDDEN: never show a Windows prompt from a
        # background thread. User scope (no LOCAL_MACHINE): only this account
        # can decrypt it.
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0x1,
            ctypes.byref(blob_out),
        )
        if not ok:
            return None
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    except Exception:
        return None


def _unprotect(blob: bytes) -> str | None:
    if not _dpapi_available():
        return None
    try:
        ctypes, DATA_BLOB = _blob_structs()
        blob_in = DATA_BLOB(len(blob),
                            ctypes.cast(ctypes.create_string_buffer(blob, len(blob)),
                                        ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0x1,
            ctypes.byref(blob_out),
        )
        if not ok:
            return None
        try:
            raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return raw.decode("utf-8")
    except Exception:
        return None


# ── Read ──────────────────────────────────────────────────────────────────────

def _from_env() -> str:
    for name in ENV_KEYS:
        val = (os.environ.get(name) or "").strip()
        if val:
            return val
    return ""


def _from_store() -> str:
    try:
        if not CREDENTIAL_FILE.exists():
            return ""
        return _unprotect(CREDENTIAL_FILE.read_bytes()) or ""
    except Exception:
        return ""


def _legacy_plaintext_key() -> str:
    """The key the old build left in the settings file. Last resort, read-only."""
    try:
        data = json.loads(LEGACY_SETTINGS_FILE.read_text(encoding="utf-8"))
        return str(data.get("gemini_api_key") or "").strip()
    except Exception:
        return ""


def credential_source() -> str:
    """'store' | 'environment' | 'legacy-plaintext' | '' — for status lines.

    Reports where a credential came from without ever reporting what it is, so
    the UI can warn that a plaintext key still needs migrating."""
    if _from_store():
        return "store"
    if _from_env():
        return "environment"
    if _legacy_plaintext_key():
        return "legacy-plaintext"
    return ""


def get_api_key() -> str:
    """The Gemini key, or '' when none is configured. Cached; never raises."""
    global _cached_key
    with _lock:
        if _cached_key:
            return _cached_key
        for source in (_from_store, _from_env, _legacy_plaintext_key):
            val = source()
            if val:
                _cached_key = val
                return val
        return ""


def refresh() -> str:
    """Drop the cache and re-resolve (used after the setup screen saves a key)."""
    global _cached_key
    with _lock:
        _cached_key = None
    return get_api_key()


def has_api_key() -> bool:
    return bool(get_api_key())


def looks_configured() -> bool:
    """Same bar the previous build used: a real key, not an empty string."""
    return len(get_api_key()) > 15


# ── Write ─────────────────────────────────────────────────────────────────────

def store_api_key(key: str) -> tuple[bool, str]:
    """Persist a key. Returns (ok, message); the message never contains the key.

    Never falls back to writing plaintext: if the platform has no safe store,
    the caller is told to use the environment variable instead."""
    global _cached_key

    key = (key or "").strip()
    if not key:
        return False, "No key was provided, so nothing was stored."

    if not _dpapi_available():
        return (False,
                "This platform has no built-in per-user secret store, so the "
                f"key was NOT saved to disk. Set {ENV_KEYS[0]} in your "
                "environment and restart NEO.")

    blob = _protect(key.encode("utf-8"))
    if blob is None:
        return (False,
                "Windows could not encrypt the key for this user account, so "
                f"it was NOT saved. Set {ENV_KEYS[0]} in your environment "
                "instead.")

    try:
        SECRET_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CREDENTIAL_FILE.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(CREDENTIAL_FILE)
    except Exception as e:
        return False, f"The encrypted key file could not be written ({e})."

    # Best effort: restrict to the current user, matching what DPAPI implies.
    try:
        os.chmod(CREDENTIAL_FILE, 0o600)
    except Exception:
        pass

    with _lock:
        _cached_key = key
    return True, "Key stored encrypted for this Windows account."


def clear_api_key() -> str:
    """Remove the stored key. Returns a status line, never the value."""
    global _cached_key
    removed = False
    try:
        if CREDENTIAL_FILE.exists():
            CREDENTIAL_FILE.unlink()
            removed = True
    except Exception as e:
        return f"Could not remove the stored key: {e}"
    with _lock:
        _cached_key = None
    return "Stored key removed." if removed else "No stored key to remove."


# ── Migration off the legacy plaintext file ───────────────────────────────────

def migrate_legacy_settings() -> str:
    """One-time move from config/api_keys.json to NEO's settings + secret store.

    Returns a status line for the console (never a value). Idempotent: once the
    legacy file is gone this is a no-op, so it is safe to call on every startup.

    The order matters. The credential is stored FIRST; the plaintext file is
    only deleted once the key is safely encrypted, or when there was no key in
    it to lose. A migration that cannot store the key leaves the file alone and
    says so, rather than destroying the only copy of someone's credential.
    """
    if not LEGACY_SETTINGS_FILE.exists():
        return ""

    try:
        legacy = json.loads(LEGACY_SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        return f"Legacy settings file could not be read ({e}); it was left in place."
    if not isinstance(legacy, dict):
        return "Legacy settings file was not a JSON object; it was left in place."

    raw_key = str(legacy.pop("gemini_api_key", "") or "").strip()
    stored_key = ""
    store_note = ""
    if raw_key:
        if _from_store():
            stored_key = "already-stored"
        else:
            ok, msg = store_api_key(raw_key)
            if ok:
                stored_key = "stored"
            else:
                store_note = msg

    # Settings (everything except the credential) move to NEO's own file.
    write_failed = False
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        existing: dict = {}
        if SETTINGS_FILE.exists():
            try:
                loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except Exception:
                existing = {}
        merged = {**legacy, **existing}      # NEO's own file wins on conflicts
        SETTINGS_FILE.write_text(json.dumps(merged, indent=4), encoding="utf-8")
    except Exception as e:
        write_failed = True
        store_note = store_note or f"settings could not be written ({e})"

    if raw_key and not stored_key:
        return ("Legacy plaintext key could NOT be stored: "
                f"{store_note} The old file was kept so nothing is lost — "
                "revoke that key and enter a new one in settings.")

    if write_failed:
        return f"Legacy settings could not be migrated: {store_note}"

    try:
        LEGACY_SETTINGS_FILE.unlink()
    except Exception as e:
        return (f"Settings migrated, but the old plaintext file could not be "
                f"removed ({e}). Delete it by hand and revoke the old key.")

    if raw_key:
        return ("Migrated settings to config/neo_settings.json and moved the API "
                "key into encrypted per-user storage. The key that was stored in "
                "plaintext must be revoked and replaced.")
    return "Migrated settings to config/neo_settings.json."
