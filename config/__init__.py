# config/__init__.py
"""Read NEO's settings file, and remember which OS this install targets.

Settings live in config/neo_settings.json. A credential never appears here: the
Gemini key lives in core/secret_store.py (Windows DPAPI, or an environment
variable). An install coming from the previous build is migrated by that same
module the first time memory.config_manager reads its settings.
"""
import json, os, platform
from pathlib import Path

_CONFIG_PATH = Path(__file__).parent / "neo_settings.json"
_LEGACY_PATH = Path(__file__).parent / "api_keys.json"


def _platform_os() -> str:
    """Auto-detect OS when config file is absent."""
    return {"Windows": "windows", "Darwin": "mac", "Linux": "linux"}.get(
        platform.system(), "linux"
    )


def get_config() -> dict:
    for path in (_CONFIG_PATH, _LEGACY_PATH):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return {}


def update_config(values: dict) -> None:
    """Persist settings to config/neo_settings.json.

    Reads merge the legacy file when it is still present; writes never go there,
    and a credential is stripped rather than written — the Gemini key belongs to
    core/secret_store.py.
    """
    data = get_config()
    data.update(values or {})
    data.pop("gemini_api_key", None)
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(data, indent=4), encoding="utf-8")


def get_os() -> str:
    """Returns: 'windows' | 'mac' | 'linux'"""
    return get_config().get("os_system", _platform_os()).lower()


def is_windows() -> bool: return get_os() == "windows"
def is_mac()     -> bool: return get_os() == "mac"
def is_linux()   -> bool: return get_os() == "linux"
