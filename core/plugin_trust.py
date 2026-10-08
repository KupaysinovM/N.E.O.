"""Classify and validate plugin files without importing or executing them.

Phase 7 requires plugin classification, capability validation, and a rule that
installation alone never grants security authority. Python plugins still cannot
run in NEO's process: there is no isolated host, so even a hash-reviewed file
is recorded as trusted-without-runtime and is not loaded.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
_SECURITY_AUTHORITY_NAMES = frozenset({
    "authorization_policy", "authorize", "security", "security_audit",
    "confirm", "confirmation", "policy", "execute_python", "run_shell",
    "eval", "exec", "os_command", "arbitrary_code",
})
_SECURITY_AUTHORITY_KEYS = frozenset({
    "authority", "security_authority", "security_policy", "bypass_confirmation",
    "confirmed", "grant_authorization", "policy_override",
})


class PluginClassification(str, Enum):
    INVALID_METADATA = "INVALID_METADATA"
    REVIEW_MISMATCH = "REVIEW_MISMATCH"
    FORBIDDEN_CAPABILITY = "FORBIDDEN_CAPABILITY"
    CORE_NAME_COLLISION = "CORE_NAME_COLLISION"
    DISCOVERED_UNTRUSTED = "DISCOVERED_UNTRUSTED"
    REVIEWED_WITHOUT_ISOLATED_HOST = "REVIEWED_WITHOUT_ISOLATED_HOST"


@dataclass(frozen=True)
class PluginTrustRecord:
    path_name: str
    sha256: str
    classification: PluginClassification
    reason: str
    declared_name: str = ""
    declared_capabilities: tuple[str, ...] = ()
    reviewed: bool = False
    executable: bool = False


@dataclass
class PluginTrustManifest:
    """Explicit human review records keyed by plugin file sha256."""
    by_hash: dict[str, dict[str, Any]] = field(default_factory=dict)

    def review_for(self, digest: str) -> Optional[dict[str, Any]]:
        return self.by_hash.get(digest)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_trust_manifest(path: Path) -> PluginTrustManifest:
    if not path.is_file():
        return PluginTrustManifest()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return PluginTrustManifest()
    reviewed = payload.get("reviewed") if isinstance(payload, dict) else None
    by_hash: dict[str, dict[str, Any]] = {}
    if isinstance(reviewed, list):
        for entry in reviewed:
            if not isinstance(entry, dict):
                continue
            digest = str(entry.get("sha256") or "").strip().lower()
            if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                by_hash[digest] = entry
    return PluginTrustManifest(by_hash)


def extract_plugin_metadata(source: str) -> dict[str, Any]:
    """Return the module-level PLUGIN dict using AST only. Never executes code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"plugin source is not valid Python ({type(exc).__name__})") from None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "PLUGIN"
                   for target in node.targets):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            raise ValueError("PLUGIN is not a literal dictionary") from None
        if not isinstance(value, dict):
            raise ValueError("PLUGIN is not a dictionary")
        return value
    raise ValueError("missing PLUGIN dict constant")


def classify_plugin_file(
    path: Path,
    *,
    core_tool_names: set[str],
    manifest: Optional[PluginTrustManifest] = None,
) -> PluginTrustRecord:
    digest = file_sha256(path)
    try:
        metadata = extract_plugin_metadata(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.INVALID_METADATA,
            reason=str(exc) if isinstance(exc, ValueError)
            else f"plugin file could not be read ({type(exc).__name__})",
        )

    name = metadata.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.INVALID_METADATA,
            reason="PLUGIN['name'] missing or not a valid identifier",
        )
    description = metadata.get("description")
    if not isinstance(description, str) or not description.strip():
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.INVALID_METADATA,
            reason="PLUGIN['description'] missing or empty",
            declared_name=name,
        )

    # The plugin name is its primary capability.  A plugin can additionally
    # declare aliases/capabilities, but they must be plain identifiers so a
    # trust record is not built around ambiguous or executable metadata.
    declared = [name]
    extra = metadata.get("capabilities")
    if extra is None:
        extra = metadata.get("capability")
    if isinstance(extra, str):
        declared.append(extra)
    elif isinstance(extra, (list, tuple)):
        if not all(isinstance(item, str) for item in extra):
            return PluginTrustRecord(
                path_name=path.name, sha256=digest,
                classification=PluginClassification.INVALID_METADATA,
                reason="plugin capabilities must be strings",
                declared_name=name,
            )
        declared.extend(extra)
    elif extra is not None:
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.INVALID_METADATA,
            reason="plugin capability declaration must be a string or list of strings",
            declared_name=name,
        )

    if (any(not _NAME_RE.match(item) for item in declared)
            or len(set(declared)) != len(declared)):
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.INVALID_METADATA,
            reason="plugin capabilities must be unique valid identifiers",
            declared_name=name,
            declared_capabilities=tuple(declared),
        )

    if any(key in metadata for key in _SECURITY_AUTHORITY_KEYS):
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.FORBIDDEN_CAPABILITY,
            reason="plugin metadata claims security authority",
            declared_name=name,
            declared_capabilities=tuple(declared),
        )
    lowered = {item.strip().lower() for item in declared}
    if lowered & _SECURITY_AUTHORITY_NAMES or name.lower() in _SECURITY_AUTHORITY_NAMES:
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.FORBIDDEN_CAPABILITY,
            reason="plugin declares a reserved security capability",
            declared_name=name,
            declared_capabilities=tuple(declared),
        )
    if set(declared) & core_tool_names:
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.CORE_NAME_COLLISION,
            reason="plugin capability collides with a core NEO capability",
            declared_name=name,
            declared_capabilities=tuple(declared),
        )

    review = (manifest or PluginTrustManifest()).review_for(digest)
    if review is not None:
        allowed = review.get("capabilities")
        # A review is valid only when it explicitly pins this exact capability
        # set.  A missing, broader, or malformed allowlist must not become an
        # implicit approval merely because the file hash happens to match.
        if (not isinstance(allowed, list)
                or not all(isinstance(item, str) and _NAME_RE.match(item)
                           for item in allowed)
                or len(set(allowed)) != len(allowed)
                or set(allowed) != set(declared)):
            return PluginTrustRecord(
                path_name=path.name, sha256=digest,
                classification=PluginClassification.REVIEW_MISMATCH,
                reason=("review record must exactly list the plugin's declared "
                        "capabilities"),
                declared_name=name,
                declared_capabilities=tuple(declared),
            )
        return PluginTrustRecord(
            path_name=path.name, sha256=digest,
            classification=PluginClassification.REVIEWED_WITHOUT_ISOLATED_HOST,
            reason=("file hash was explicitly reviewed, but NEO has no isolated "
                    "plugin host so the code is not loaded"),
            declared_name=name,
            declared_capabilities=tuple(declared),
            reviewed=True,
            executable=False,
        )

    return PluginTrustRecord(
        path_name=path.name, sha256=digest,
        classification=PluginClassification.DISCOVERED_UNTRUSTED,
        reason="installed plugin files are untrusted until reviewed; code is not loaded",
        declared_name=name,
        declared_capabilities=tuple(declared),
    )
