"""Risk classification for the NEO execution boundary — facts, not the decision.

WHAT THIS MODULE IS
    The classifier. `AuthorizationPolicy.authorize()` answers questions about
    a request: what risk class it carries, whether the capability is
    registered and audited, whether the operation is supported, whether the
    arguments can be fingerprinted. Its `AuthorizationDecision` is therefore
    a *provisional* verdict — `ALLOW` means "nothing here needs attention",
    `REQUIRE_CONFIRMATION` means "under prompt-based security a human would
    have been asked", and `DENY` means "refuse".

WHAT THIS MODULE IS NOT
    It is not an authorization authority. The one effective ALLOW-or-DENY
    decision for normal NEO execution is produced by `config/policy.resolve()`
    and applied once, in `core/execution.py`. A `REQUIRE_CONFIRMATION` from
    here never reaches a user as a prompt during normal execution: the policy
    converts it explicitly and deterministically (in policy → execute,
    otherwise → deny and report). A `DENY` from here always survives — the
    policy never converts a denial into an allowance.

    Neither the model nor an agent nor external content appears anywhere in
    this module's inputs beyond `arguments`, and a field such as `confirmed`
    is never read: nothing here can be talked into a more permissive answer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator, Optional

from core import capabilities


class RiskClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    LOW_RISK_REVERSIBLE = "LOW_RISK_REVERSIBLE"
    EXTERNAL_COMMUNICATION = "EXTERNAL_COMMUNICATION"
    SENSITIVE_DATA_ACCESS = "SENSITIVE_DATA_ACCESS"
    DESTRUCTIVE = "DESTRUCTIVE"
    IRREVERSIBLE = "IRREVERSIBLE"
    SYSTEM_LEVEL = "SYSTEM_LEVEL"
    UNKNOWN = "UNKNOWN"


class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    DENY = "DENY"


_SENSITIVE_KEY = re.compile(
    r"(?:pass(?:word|phrase)?|secret|token|api[_-]?key|authorization|cookie|"
    r"credential|private[_-]?key|access[_-]?key|message|body|document|text|query|"
    r"value|path|url|title|recipient|topic|field|app[_-]?name|memory[_-]?key|"
    r"ssn|social[_-]?security|account[_-]?(?:number|id)|credit[_-]?card|"
    r"email|e[_-]?mail|phone|telephone|mobile|iban|bank[_-]?(?:account|number)|"
    r"card[_-]?(?:number|cvv|cvc)|routing[_-]?(?:number|id)|financial)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:AIza[0-9A-Za-z_-]{20,}|"
    r"(?i:bearer)\s+[A-Za-z0-9._~+/=-]{12,}|"
    r"(?i:\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b)|"
    r"(?s:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)|"
    r"""(?i:["']?(?:password|passphrase|secret|token|api[_-]?key|access[_-]?token|authorization|cookie|credential)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^,\s}\]]+))|"""
    r"(?i:[?&](?:api[_-]?key|access[_-]?token|token|password|secret|session|auth|key)=[^&#\s]+)|"
    r"(?i:\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)|"
    r"(?<!\w)(?:\+?1[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\w)|"
    r"(?i:\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b)|"
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)|"
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d))"
)
_DESTRUCTIVE_OPERATIONS = frozenset({
    "delete",
})
_READ_OPERATIONS = frozenset({
    "list", "read", "info", "find", "disk_usage", "largest",
})
_FILE_MUTATIONS = frozenset({
    "create_file", "create_folder", "move", "copy", "rename", "write",
    "organize_desktop",
})
_COMPUTER_CONTROL_OPERATIONS = frozenset({
    "type", "smart_type", "click", "left_click", "double_click", "right_click",
    "move", "drag", "hotkey", "press", "scroll", "copy", "paste", "screenshot",
    "screen_find", "screen_click", "wait", "clear_field", "focus_window",
    "user_data",
})
_COMPUTER_SETTINGS_OPERATIONS = frozenset({
    "volume_up", "volume_down", "volume_set", "mute", "unmute", "toggle_mute",
    "brightness_up", "brightness_down", "sleep_display", "screen_off",
    "pause_video", "play_pause", "close_app", "close_window", "full_screen",
    "fullscreen", "minimize", "maximize", "snap_left", "snap_right",
    "switch_window", "show_desktop", "task_manager", "focus_search",
    "refresh_page", "reload", "close_tab", "new_tab", "next_tab", "prev_tab",
    "go_back", "go_forward", "zoom_in", "zoom_out", "zoom_reset", "find_on_page",
    "scroll_up", "scroll_down", "scroll_top", "scroll_bottom", "page_up",
    "page_down", "copy", "paste", "cut", "undo", "redo", "select_all", "save",
    "enter", "escape", "screenshot", "lock_screen", "open_settings",
    "file_explorer", "open_run", "dark_mode", "toggle_wifi", "restart",
    "shutdown", "type_text", "write_on_screen", "type", "write", "press_key",
    "reload_n", "refresh_n", "reload_page_n",
})
_POWER_OPERATIONS = frozenset({"shutdown", "restart", "reboot", "power_off"})
_execution_receipt = threading.local()
_FINGERPRINT_KEY = secrets.token_bytes(32)
_LIVE_TOOL_NAMES = frozenset({
    "system_status", "screen_process", "close_camera", "manage_monitor",
    "shutdown_neo", "save_memory", "recall_memory", "undo",
    "manage_capability_grants",
})


@dataclass(frozen=True)
class Authorization:
    action: str
    operation: str
    risk: RiskClass
    decision: AuthorizationDecision
    reason: str
    target_digest: str
    confirmation_delegated: bool = False

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "operation": self.operation,
            "risk": self.risk.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "target_digest": self.target_digest,
            "confirmation_delegated": self.confirmation_delegated,
        }


@dataclass(frozen=True)
class CapabilityGrantSpec:
    """A policy-owned reusable permission shape."""

    capability: str
    action: str
    scope: str
    operation_class: str
    risk: RiskClass
    description: str


@dataclass
class CapabilityGrant:
    """An in-memory grant issued only after a HUD confirmation."""

    grant_id: str
    capability: str
    action: str
    scope: str
    operation_class: str
    risk: RiskClass
    granted_by: str
    granted_at: float
    expires_at: float
    revoked_at: float = 0.0
    revocation_reason: str = ""

    @property
    def active(self) -> bool:
        return not self.revoked_at


@dataclass(frozen=True)
class GrantResolution:
    grant: Optional[CapabilityGrant] = None
    expired: tuple[CapabilityGrant, ...] = ()
    escalation: bool = False


class CapabilityGrantStore:
    """Central, non-persistent grants for one NEO process.

    A matching grant only comes from a static policy-generated spec. It cannot
    be assembled from model input and never confers another capability.
    """

    DEFAULT_TTL_SECONDS = 15 * 60.0

    def __init__(self, *, now: Callable[[], float] = time.time,
                 ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self._now = now
        self._ttl_seconds = max(1.0, float(ttl_seconds))
        self._grants: dict[str, CapabilityGrant] = {}
        self._lock = threading.RLock()

    def prepare(self, spec: CapabilityGrantSpec) -> CapabilityGrant:
        issued = float(self._now())
        return CapabilityGrant(
            grant_id=secrets.token_urlsafe(18), capability=spec.capability,
            action=spec.action, scope=spec.scope,
            operation_class=spec.operation_class, risk=spec.risk,
            granted_by="ui_confirmation", granted_at=issued,
            expires_at=issued + self._ttl_seconds,
        )

    def activate(self, grant: CapabilityGrant) -> None:
        """Make a previously audited grant available in this process only."""
        with self._lock:
            self._grants[grant.grant_id] = grant

    def resolve(self, spec: Optional[CapabilityGrantSpec]) -> GrantResolution:
        if spec is None:
            return GrantResolution()
        now = float(self._now())
        expired: list[CapabilityGrant] = []
        escalation = False
        with self._lock:
            for grant in self._grants.values():
                if not grant.active:
                    continue
                if now >= grant.expires_at:
                    grant.revoked_at = now
                    grant.revocation_reason = "EXPIRED"
                    expired.append(grant)
                    continue
                if grant.capability != spec.capability:
                    # The same underlying action can expose another physical
                    # source (screen vs. webcam). That is an escalation, not a
                    # reusable grant, even though both use screen_process.
                    escalation = escalation or grant.action == spec.action
                    continue
                if (grant.action == spec.action and grant.scope == spec.scope
                        and grant.operation_class == spec.operation_class
                        and grant.risk == spec.risk):
                    return GrantResolution(grant=grant, expired=tuple(expired))
                escalation = True
        return GrantResolution(expired=tuple(expired), escalation=escalation)

    def revoke(self, capability: str, scope: str = "") -> list[CapabilityGrant]:
        """Immediately revoke matching active grants; this never grants access."""
        revoked: list[CapabilityGrant] = []
        now = float(self._now())
        with self._lock:
            for grant in self._grants.values():
                if (grant.active and grant.capability == capability
                        and (not scope or grant.scope == scope)):
                    grant.revoked_at = now
                    grant.revocation_reason = "REVOKED"
                    revoked.append(grant)
        return revoked

    def active(self) -> list[CapabilityGrant]:
        now = float(self._now())
        with self._lock:
            return [grant for grant in self._grants.values()
                    if grant.active and now < grant.expires_at]


def capability_grant_spec(auth: Authorization,
                          arguments: dict) -> Optional[CapabilityGrantSpec]:
    """Return the only reusable grant shape the static policy permits today.

    Screen/webcam observation is repeatedly invoked while NEO answers a
    request. Other sensitive capabilities intentionally have no reusable rule:
    their operation-level scope is not classified enough to safely make a
    confirmation enduring.
    """
    if (auth.decision is not AuthorizationDecision.REQUIRE_CONFIRMATION
            or auth.action != "screen_process"
            or auth.risk is not RiskClass.SENSITIVE_DATA_ACCESS):
        return None
    angle = str(arguments.get("angle", "screen")).lower().strip()
    if angle == "screen":
        return CapabilityGrantSpec(
            capability="SCREEN_VISION", action="screen_process",
            scope="CURRENT_DESKTOP", operation_class="OBSERVE_ANALYZE",
            risk=RiskClass.SENSITIVE_DATA_ACCESS,
            description="screen observation and visual analysis of the current desktop",
        )
    if angle == "camera":
        return CapabilityGrantSpec(
            capability="WEBCAM_VISION", action="screen_process",
            scope="CONFIGURED_WEBCAM", operation_class="OBSERVE_ANALYZE",
            risk=RiskClass.SENSITIVE_DATA_ACCESS,
            description="webcam observation and visual analysis from the configured camera",
        )
    return None


def _normalised_operation(arguments: dict) -> str:
    value = arguments.get("operation", arguments.get("action", ""))
    return str(value or "").strip().lower().replace(" ", "_")


def _target_digest(arguments: dict) -> str:
    try:
        encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        return ""
    return hmac.new(_FINGERPRINT_KEY, encoded, hashlib.sha256).hexdigest()


def request_fingerprint(value: dict) -> str:
    """Return a process-keyed digest for private audit correlation."""
    return _target_digest(value)


def redact(value: Any, key: str = "", *, max_string_length: int = 500) -> Any:
    """Return bounded, log-safe data without changing the value used to execute."""
    if _SENSITIVE_KEY.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k), max_string_length=max_string_length)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, max_string_length=max_string_length) for item in value]
    if isinstance(value, str):
        return _SENSITIVE_VALUE.sub("[REDACTED]", value[:max_string_length])
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return f"[{type(value).__name__}]"


def untrusted_data(value: Any, source: str = "external content") -> str:
    """Encode externally sourced text as data, not model-facing instructions."""
    label = re.sub(r"[^a-zA-Z0-9 _.-]", "", str(source))[:48] or "external content"
    text = str(value)
    if len(text) > 20_000:
        text = text[:20_000] + f" [TRUNCATED; original length {len(text)}]"
    try:
        encoded = json.dumps(text, ensure_ascii=True)
    except (TypeError, ValueError):
        encoded = json.dumps(f"[{type(value).__name__}]", ensure_ascii=True)
    return f"[UNTRUSTED DATA: {label}]\n{encoded}"


def tool_result_payload(result: Any, *, source: str = "tool output",
                        **metadata) -> dict:
    """Sanitize and provenance-wrap tool output before it re-enters model context."""
    safe_result = redact(result, max_string_length=20_000)
    if not isinstance(safe_result, str):
        safe_result = json.dumps(safe_result, ensure_ascii=True, separators=(",", ":"))
    return {
        **metadata,
        "result": untrusted_data(safe_result, source),
        "data_origin": "untrusted_data",
    }


def dashboard_transcript_payload(speaker: str, text: str, timestamp: str) -> dict:
    """Send transcript metadata to the optional dashboard, never its contents."""
    return {
        "type": "log",
        "speaker": str(speaker)[:24],
        "text": "[private transcript withheld]",
        "characters": len(str(text)),
        "ts": str(timestamp)[:40],
    }


def confirmation_detail(auth: Authorization, arguments: dict) -> str:
    """Describe the requested target without exposing arbitrary argument values."""
    fields = []
    for key in ("target", "path", "file_path", "app_name", "recipient", "topic"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            safe = _SENSITIVE_VALUE.sub("[REDACTED]", value.strip())
            fields.append(f"{key}={safe[:100]}")
    target = ", ".join(fields) if fields else "target details withheld"
    digest = auth.target_digest[:16] if auth.target_digest else "unavailable"
    disclosure = ""
    if auth.risk is RiskClass.SENSITIVE_DATA_ACCESS:
        disclosure = (
            " Sensitive data may be read; returned content can enter the "
            "configured model's conversation context."
        )
    if auth.action == "screen_process":
        source = ("webcam" if str(arguments.get("angle", "screen")).lower()
                  == "camera" else "screen")
        disclosure = (
            f" The {source} image will be sent to the configured Gemini model "
            "for analysis."
        )
    elif auth.action == "computer_control" and auth.operation in {
            "screen_find", "screen_click"}:
        disclosure = (
            " A screen image will be sent to the configured Gemini model "
            "to locate the requested control."
        )
    elif auth.action == "computer_control" and auth.operation == "copy":
        disclosure = (
            " Clipboard contents will be read and returned to the model "
            "conversation."
        )
    elif auth.action == "file_processor":
        suffix = str(arguments.get("file_path", "")).rsplit(".", 1)[-1].lower()
        if suffix in {"jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff"}:
            disclosure = (
                " The selected image will be sent to the configured Gemini "
                "model for analysis."
            )
        elif suffix in {"mp3", "wav", "ogg", "m4a", "aac", "flac", "wma", "opus"}:
            disclosure = (
                " Raw audio from the selected file will be sent to the "
                "configured Gemini model for transcription."
            )
    grant = capability_grant_spec(auth, arguments)
    if grant is not None:
        disclosure += (
            f" Confirming also grants {grant.capability} for {grant.description} "
            "for up to 15 minutes in this NEO session. This does not authorize "
            "messages, file changes, account changes, purchases, deletions, "
            "or any other capability."
        )
    return (f"Capability: {auth.action}; operation: {auth.operation or 'default'}; "
            f"risk: {auth.risk.value}. {target}. Request fingerprint: {digest}."
            f"{disclosure}")


class AuthorizationPolicy:
    """Static, deny-by-default classifier; model input never changes it.

    The `Authorization` it returns carries risk facts plus a provisional
    verdict. `config/policy.resolve()` combines that verdict with the
    configured permission policy to produce the single effective decision;
    this class never decides alone during normal execution.
    """

    def __init__(self, overrides: Optional[dict[str, RiskClass]] = None):
        # Overrides are intended for explicitly constructed test fixtures only.
        # Production startup uses the fixed audited capability table.
        self._overrides = dict(overrides or {})

    def authorize(self, action: str, arguments: dict, registry_kind: str) -> Authorization:
        name = str(action or "")
        operation = _normalised_operation(arguments)
        digest = _target_digest(arguments)

        override = self._overrides.get(name)
        if override is not None:
            return Authorization(name, operation, override, AuthorizationDecision.ALLOW,
                                 "explicit policy entry", digest)

        if not digest:
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "arguments cannot be safely fingerprinted", "")
        if registry_kind == "plugins":
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "plugin has no trusted NEO security classification",
                                 digest)

        if name in _LIVE_TOOL_NAMES:
            if name == "system_status":
                return Authorization(name, operation, RiskClass.READ_ONLY,
                                     AuthorizationDecision.ALLOW,
                                     "audited local status operation", digest)
            if name == "close_camera":
                return Authorization(name, operation, RiskClass.LOW_RISK_REVERSIBLE,
                                     AuthorizationDecision.ALLOW,
                                     "audited camera-stop operation", digest)
            if name == "manage_capability_grants":
                if operation == "list":
                    return Authorization(name, operation, RiskClass.READ_ONLY,
                                         AuthorizationDecision.ALLOW,
                                         "read-only capability grant status", digest)
                if (operation == "revoke"
                        and str(arguments.get("capability", ""))
                        in {"SCREEN_VISION", "WEBCAM_VISION"}):
                    return Authorization(name, operation,
                                         RiskClass.LOW_RISK_REVERSIBLE,
                                         AuthorizationDecision.ALLOW,
                                         "capability grant revocation reduces access", digest)
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "unsupported capability grant operation", digest)
            if name == "manage_monitor" and operation == "list":
                return Authorization(name, operation, RiskClass.READ_ONLY,
                                     AuthorizationDecision.ALLOW,
                                     "read-only monitoring status", digest)
            if name == "undo" and operation == "list":
                return Authorization(name, operation, RiskClass.READ_ONLY,
                                     AuthorizationDecision.ALLOW,
                                     "read-only undo history", digest)
            if name == "manage_monitor" and operation not in {"add", "remove"}:
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "unsupported monitoring operation", digest)
            if name == "manage_monitor" and not (
                    isinstance(arguments.get("topic"), str)
                    and arguments["topic"].strip()):
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "monitoring topic is required", digest)
            if name == "undo" and operation not in {"", "undo"}:
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "unsupported undo operation", digest)
            if name == "save_memory" and not all(
                    isinstance(arguments.get(key), str)
                    and arguments[key].strip() for key in ("key", "value")):
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "memory key and value are required", digest)
            if name == "screen_process" and str(
                    arguments.get("angle", "screen")).lower() not in {"screen", "camera"}:
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "unsupported capture source", digest)
            risk = (RiskClass.SYSTEM_LEVEL if name == "shutdown_neo"
                    else RiskClass.DESTRUCTIVE if name == "undo"
                    else RiskClass.SENSITIVE_DATA_ACCESS)
            return Authorization(name, operation, risk,
                                 AuthorizationDecision.REQUIRE_CONFIRMATION,
                                 "live-session action requires explicit user approval",
                                 digest)

        capability = capabilities.get(name)
        if capability is None:
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "capability is not present in the security audit",
                                 digest)

        # These capabilities can execute model-provided code or perform
        # development writes. A confirmation banner is not a safe substitute
        # for removing arbitrary execution from the assistant boundary.
        if name in {"code_helper", "dev_agent", "desktop_control"}:
            return Authorization(name, operation, RiskClass.SYSTEM_LEVEL,
                                 AuthorizationDecision.DENY,
                                 "capability is prohibited by NEO's execution policy",
                                 digest)
        if name == "file_processor" and operation == "run":
            return Authorization(name, operation, RiskClass.SYSTEM_LEVEL,
                                 AuthorizationDecision.DENY,
                                 "arbitrary source-code execution is prohibited",
                                 digest)

        # A message can be sent only after the user confirms this exact request.
        if name == "send_message":
            return Authorization(name, operation, RiskClass.EXTERNAL_COMMUNICATION,
                                 AuthorizationDecision.REQUIRE_CONFIRMATION,
                                 "external communication requires explicit user approval",
                                 digest)

        if name == "file_controller":
            if operation in _DESTRUCTIVE_OPERATIONS:
                return Authorization(name, operation, RiskClass.DESTRUCTIVE,
                                     AuthorizationDecision.REQUIRE_CONFIRMATION,
                                     "destructive file operation requires explicit approval",
                                     digest)
            if operation in _READ_OPERATIONS:
                if operation in {"read", "find"}:
                    return Authorization(
                        name, operation, RiskClass.SENSITIVE_DATA_ACCESS,
                        AuthorizationDecision.REQUIRE_CONFIRMATION,
                        "reading file contents requires explicit user approval",
                        digest)
                return Authorization(name, operation, RiskClass.READ_ONLY,
                                     AuthorizationDecision.ALLOW,
                                     "audited read-only file operation", digest)
            if operation in _FILE_MUTATIONS:
                return Authorization(name, operation, RiskClass.LOW_RISK_REVERSIBLE,
                                     AuthorizationDecision.REQUIRE_CONFIRMATION,
                                     "file mutation requires explicit approval", digest)
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "unsupported file operation", digest)

        if name == "windows_control":
            from core.windows.control import OPERATIONS
            if operation not in OPERATIONS:
                return Authorization(name, operation, RiskClass.UNKNOWN,
                                     AuthorizationDecision.DENY,
                                     "unsupported Windows control operation", digest)

        if name == "computer_settings" and operation in _POWER_OPERATIONS:
            return Authorization(name, operation, RiskClass.SYSTEM_LEVEL,
                                 AuthorizationDecision.REQUIRE_CONFIRMATION,
                                 "system power operation requires explicit approval",
                                 digest)
        if name == "computer_settings" and operation and (
                operation not in _COMPUTER_SETTINGS_OPERATIONS):
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "unsupported computer settings operation", digest)
        if name == "computer_settings" and not operation and not str(
                arguments.get("description", "")).strip():
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "computer settings action or description is required",
                                 digest)

        if name == "windows_control" and operation in {
                "close_window", "close", "dismiss_dialog"}:
            return Authorization(name, operation, RiskClass.DESTRUCTIVE,
                                 AuthorizationDecision.REQUIRE_CONFIRMATION,
                                 "closing a window requires explicit approval",
                                 digest)
        if name == "computer_control" and operation not in _COMPUTER_CONTROL_OPERATIONS:
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "unsupported computer control operation", digest)

        if capability.verdict in (capabilities.UNSAFE, capabilities.UNSUPPORTED,
                                  capabilities.DEAD):
            return Authorization(name, operation, RiskClass.UNKNOWN,
                                 AuthorizationDecision.DENY,
                                 "capability is not approved for execution",
                                 digest)

        if capability.risk == capabilities.HIGH:
            return Authorization(name, operation, RiskClass.IRREVERSIBLE,
                                 AuthorizationDecision.REQUIRE_CONFIRMATION,
                                 "high-risk capability requires explicit approval",
                                 digest)
        if capability.risk == capabilities.MEDIUM:
            return Authorization(name, operation, RiskClass.SENSITIVE_DATA_ACCESS,
                                 AuthorizationDecision.REQUIRE_CONFIRMATION,
                                 "capability may access sensitive state or external content",
                                 digest)

        return Authorization(name, operation, RiskClass.LOW_RISK_REVERSIBLE,
                             AuthorizationDecision.ALLOW,
                             "audited low-risk capability", digest)

    @staticmethod
    def capability_grant_spec(auth: Authorization,
                              arguments: dict) -> Optional[CapabilityGrantSpec]:
        """Expose only the static policy's reusable-grant decisions."""
        return capability_grant_spec(auth, arguments)


@contextmanager
def authorized_execution(action: str, arguments: dict) -> Iterator[None]:
    """Mark one exact request as already approved while its handler runs."""
    previous = getattr(_execution_receipt, "value", None)
    _execution_receipt.value = (str(action), _target_digest(arguments))
    try:
        yield
    finally:
        _execution_receipt.value = previous


def is_authorized_execution(action: str, arguments: dict) -> bool:
    """Check the unforgeable-in-model, thread-local receipt used by gated actions."""
    return getattr(_execution_receipt, "value", None) == (
        str(action), _target_digest(arguments))
