"""
NEO's authorization policy — the single effective decision.

    MODEL → PLAN → POLICY → ALLOW / DENY → EXECUTE → VERIFY

There is exactly one place where a request becomes ALLOW or DENY for normal
NEO execution: `resolve()` in this module. It is the *policy* layer; it reads
two inputs and combines them with one rule:

    1. the risk classification from `core/security.py` (facts: what kind of
       operation is this, is it registered, is it prohibited), and
    2. these documents — which categories the user has enabled, what is
       marked out of policy, and how each scope resolves.

THE COMBINATION RULE IS A CONJUNCTION — denial in either input wins:

    classification DENY                      → DENY  (deny by default stays)
    untrusted-labelled content in arguments  → DENY  (content cannot grant)
    scope not `in_policy`                    → DENY  (least privilege)
    otherwise                                → ALLOW (execute silently)

A classification of `REQUIRE_CONFIRMATION` is *not* a second opinion. It is
the classifier saying "under prompt-based security this would have asked a
human". Under the configured `authorizationMode: silent_policy` this module
converts it — explicitly and deterministically — exactly like an `ALLOW`:
scope `in_policy` + behavior `execute` → ALLOW. There is no other conversion
and no other authority. `core/confirm.py` still exists for the legacy gate
(`autonomy.permissionPrompts`), but during normal execution it never decides
anything: the branch that could reach it is taken only when the configuration
itself turns prompts back on.

THE FOUR STATES A CAPABILITY CAN BE IN
    exists        — the registry holds the name (execution resolves it first)
    in policy     — mapped category, enabled, not out of policy, operation not
                    on the category's deny list, no untrusted content, and
                    the classification did not deny → execute silently
    out of policy — category disabled or `outOfPolicy: deny`, or the operation
                    is on the category's `deniedOperations` → deny + report
    unknown       — nothing in the configuration covers the name (or the
                    classification says it is unregistered) → deny + report

`category.enabled == true` is deliberately NOT the whole answer: the
classification still refuses prohibited capabilities (`code_helper`,
`dev_agent`, arbitrary code execution) and unsupported operations inside an
enabled category, and `deniedOperations` lets the configuration refuse a
specific operation without disabling the category.

THE DIRECTION OF THE FAIL-SAFE — CLOSED, NOT OPEN
    A missing, unreadable, malformed, schema-invalid, partially valid, or
    contradictory document does **not** authorize anything and does **not**
    resurrect the human check. `config_failure()` names the problem and the
    execution layer blocks the request outright:

        INVALID / MISSING CONFIG → SAFE_BLOCKED → NO EXECUTION
                                  → NO PROMPT → REPORT CONFIGURATION FAILURE

    Fail closed means *deny the action*, never "ask the user". Every prompt
    switch in the three schemas is `const: false`, so a schema-valid
    configuration cannot request prompts either — the only way the legacy
    gate is ever reached is an explicit override of `prompts_enabled()`,
    which is how its own tests keep it honest. Granting anything still
    requires an explicit, well-formed configuration that says so.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

CONFIG_DIR = Path(__file__).parent
SCHEMA_DIR = CONFIG_DIR / "schema"

#: document name → (data file, schema file)
DOCUMENTS = {
    "profile":     ("profile.json", "profile.schema.json"),
    "permissions": ("permissions.json", "permissions.schema.json"),
    "security":    ("security.json", "security.schema.json"),
}

#: A request with no category has no policy covering it. `unknownPolicy:
#: deny_and_report` — never "ask instead".
CATEGORY_BY_ACTION: dict = {
    # filesystem
    "file_controller": "filesystem",
    "file_processor": "filesystem",
    "save_memory": "filesystem",
    "recall_memory": "filesystem",
    # process
    "open_app": "process",
    "background_monitor": "process",
    "code_helper": "process",
    "dev_agent": "process",
    "proactive": "process",
    "undo": "process",
    "demo_singleton": "process",
    # browser
    "browser_control": "browser",
    "web_search": "browser",
    "flight_finder": "browser",
    "youtube_video": "browser",
    "video_player": "browser",
    "game_updater": "browser",
    "weather_report": "browser",
    # communication
    "send_message": "communication",
    "reminder": "communication",
    # device
    "windows_control": "device",
    "computer_control": "device",
    "desktop": "device",
    "screen_processor": "device",
    "screen_process": "device",
    "close_camera": "device",
    "manage_capability_grants": "device",
    "demo_control": "device",
    # system
    "computer_settings": "system",
    "system_monitor": "system",
    "system_status": "system",
    "manage_monitor": "system",
    "shutdown_neo": "system",
}

# ── loading ─────────────────────────────────────────────────────────────────

_cache: dict = {}


def reset() -> None:
    """Forget every cached document. Tests use this; production loads once."""
    _cache.clear()


def _read(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load(document: str) -> Optional[dict]:
    """One policy document, or None when it is missing, unreadable, or invalid.

    `None` means "there is no usable policy here", which callers must treat as
    the safe answer rather than as permission.
    """
    if document in _cache:
        return _cache[document]
    data_name, schema_name = DOCUMENTS[document]
    try:
        data = _read(CONFIG_DIR / data_name)
        schema = _read(SCHEMA_DIR / schema_name)
    except Exception:
        return None
    errors = validate(data, schema)
    if errors:
        return None
    _cache[document] = data
    return data


def load_all() -> dict:
    return {name: load(name) for name in DOCUMENTS}


# ── schema validation ───────────────────────────────────────────────────────

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
}


def _matches_type(value: Any, expected: str) -> bool:
    python_type = _TYPES.get(expected)
    if python_type is None:
        return True                      # unknown keyword type → do not block
    if expected in ("integer", "number") and isinstance(value, bool):
        return False                     # bool is not a number here
    return isinstance(value, python_type)


def validate(value: Any, schema: dict, path: str = "$") -> list:
    """Validate against the draft-2020-12 subset these schemas actually use.

    Supported: `type`, `const`, `required`, `properties`, `additionalProperties`
    and `items`. That is exactly what the three shipped schemas are written in,
    so anything a schema author reaches for beyond it fails loudly in a test
    rather than being silently ignored here.
    """
    errors: list = []
    if not isinstance(schema, dict):
        return errors

    expected = schema.get("type")
    if expected is not None and not _matches_type(value, expected):
        errors.append(f"{path}: expected {expected}, got {type(value).__name__}")
        return errors                     # no point inspecting children

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")

    if isinstance(value, dict):
        for key in schema.get("required", ()):
            if key not in value:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties") or {}
        for key, child in properties.items():
            if key in value:
                errors.extend(validate(value[key], child, f"{path}.{key}"))
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key!r}")

    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            errors.extend(validate(item, schema["items"], f"{path}[{index}]"))

    return errors


def validate_all() -> dict:
    """`{document: [error, ...]}` for the three shipped documents."""
    report = {}
    for name, (data_name, schema_name) in DOCUMENTS.items():
        try:
            data = _read(CONFIG_DIR / data_name)
            schema = _read(SCHEMA_DIR / schema_name)
        except Exception as exc:
            report[name] = [f"{type(exc).__name__}: {exc}"]
            continue
        report[name] = validate(data, schema)
    return report


def is_valid() -> bool:
    return all(not errors for errors in validate_all().values())


# ── configuration health: fail closed, never fail open ────────────────────

#: The switches that would ask for an interactive permission prompt. In a
#: valid document each is `const: false` (profile.autonomy, permissions.policy,
#: security.authorization — see the schemas), so a configuration that requests
#: prompts is not a valid configuration; it is a configuration *failure*, and
#: a failure blocks instead of resurrecting the banner.
_PROMPT_SWITCHES = (
    ("profile", "autonomy", "permissionPrompts"),
    ("profile", "autonomy", "firstUsePrompts"),
    ("profile", "autonomy", "repeatedPrompts"),
    ("permissions", "policy", "userApprovalPrompts"),
    ("permissions", "policy", "firstUseApproval"),
    ("permissions", "policy", "repeatedApproval"),
    ("security", "authorization", "interactivePrompts"),
    ("security", "authorization", "firstUsePrompts"),
    ("security", "authorization", "repeatedPrompts"),
)


def _nested(document: Optional[dict], *path: str) -> Any:
    node: Any = document
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _posture_contradictions() -> list:
    """Contradictions the schemas cannot see — cross-document and loose.

    The schemas pin the prompt switches and the headline constants, but the
    `credentials`, `plugins`, `browser` and `execution` objects are deliberately
    open (`"type": "object"`). A document can therefore be schema-valid while
    contradicting the autonomous posture the other two documents declare —
    "silent policy" plus "allow security bypass" is not a configuration NEO
    can honestly act on. Ambiguity resolves to blocked, never to a prompt.
    """
    profile = load("profile")
    permissions = load("permissions")
    security = load("security")
    problems: list = []

    for document, section, key in _PROMPT_SWITCHES:
        if _nested(load(document), section, key) is not False:
            problems.append(f"{document}.{section}.{key} is not false, which "
                            "contradicts authorizationMode: silent_policy")

    if _nested(permissions, "policy", "modelMayGrant") is not False:
        problems.append("permissions.policy.modelMayGrant must be false")
    if _nested(permissions, "policy", "agentMayGrant") is not False:
        problems.append("permissions.policy.agentMayGrant must be false")
    if _nested(permissions, "behavior", "doNotPromptUser") is not True:
        problems.append("permissions.behavior.doNotPromptUser must be true")

    if _nested(security, "execution", "allowSecurityBypass") is True:
        problems.append("security.execution.allowSecurityBypass is true, which "
                        "contradicts mode: strict_autonomous")
    if _nested(security, "execution", "requireVerification") is False:
        problems.append("security.execution.requireVerification is false, which "
                        "contradicts the verification mandate")
    if _nested(security, "credentials", "allowSecretsInConfig") is True:
        problems.append("security.credentials.allowSecretsInConfig is true, "
                        "which contradicts environment/secure-store credentials")
    if _nested(security, "plugins", "allowSelfAuthorization") is True:
        problems.append("security.plugins.allowSelfAuthorization is true, which "
                        "contradicts modelMayGrant/agentMayGrant: false")
    if _nested(security, "promptInjection",
               "treatExternalContentAsUntrusted") is False:
        problems.append("security.promptInjection."
                        "treatExternalContentAsUntrusted is false, which "
                        "contradicts modelMayGrant: false")
    return problems


def config_failure() -> str:
    """Non-empty when the configuration cannot authorize anything.

    Checked before every request in `core/execution.py`. Any missing,
    unreadable, schema-invalid, partial, or contradictory document lands here,
    and a non-empty answer is SAFE_BLOCKED: deny the action, execute nothing,
    prompt nobody, and report this string. This is the fail-closed direction —
    "fail closed" means deny, never "ask the user".
    """
    problems = []
    for name in DOCUMENTS:
        if load(name) is None:
            problems.append(f"the {name} document is missing, unreadable, or invalid")
    if not problems:
        problems.extend(_posture_contradictions())
    return "; ".join(problems)


# ── the question execution actually asks ────────────────────────────────────

#: `core.security.untrusted_data()` labels every external payload it wraps.
#: `config/security.json` sets `promptInjection.treatExternalContentAsUntrusted`
#: to true, and this is what makes that mean something once nobody is watching
#: the banner: content that carries this label is never executed silently on the
#: model's say-so.
UNTRUSTED_MARKER = "[UNTRUSTED DATA:"


def carries_untrusted_content(value: Any) -> bool:
    """True when a request's arguments embed content labelled as untrusted.

    The model may *ask* (`modelMayRequest: true`); it may not *grant*
    (`modelMayGrant: false`). Under a silent policy the only grant is the user's
    own configuration, which authorises what the *user* asks for — not whatever a
    webpage, document, or tool result persuaded the model to ask for. A value
    that still bears the provenance label has crossed that line, so it is refused
    rather than asked about.
    """
    if isinstance(value, str):
        return UNTRUSTED_MARKER in value
    if isinstance(value, dict):
        return any(carries_untrusted_content(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(carries_untrusted_content(item) for item in value)
    return False


def prompts_enabled() -> bool:
    """Whether the legacy prompt gate is switched on — never by a broken config.

    A configuration failure answers **False** first: invalid, missing,
    partial, or contradictory documents block execution through
    `config_failure()` and can never resurrect the interactive prompt.
    Because every prompt switch is `const: false` in the schemas, a valid
    configuration answers False as well; the posture check below is kept as
    the explicit assertion of that fact, and the only way True is returned in
    practice is an explicit override — the legacy test seam in
    `tests/support.py`.
    """
    if config_failure():
        return False

    profile = load("profile")
    permissions = load("permissions")
    security = load("security")
    if profile is None or permissions is None or security is None:
        return False

    autonomy = profile.get("autonomy") or {}
    policy = permissions.get("policy") or {}
    behavior = permissions.get("behavior") or {}
    authorization = security.get("authorization") or {}

    asks = [
        autonomy.get("permissionPrompts"),
        autonomy.get("firstUsePrompts"),
        autonomy.get("repeatedPrompts"),
        policy.get("userApprovalPrompts"),
        policy.get("firstUseApproval"),
        policy.get("repeatedApproval"),
        authorization.get("interactivePrompts"),
        authorization.get("firstUsePrompts"),
        authorization.get("repeatedPrompts"),
        behavior.get("doNotPromptUser") is False,   # asking must be *forbidden*
    ]
    # Every knob has to say "no prompts". One that asks for prompts keeps them.
    return not all(flag is False for flag in asks)


def category_for(action: str) -> Optional[str]:
    """The permission category covering this action, or None if none does."""
    return CATEGORY_BY_ACTION.get(str(action))


def _normalised_operation(arguments: Any) -> str:
    """The same operation spelling `core.security` classifies."""
    if not isinstance(arguments, dict):
        return ""
    value = arguments.get("operation", arguments.get("action", ""))
    return str(value or "").strip().lower().replace(" ", "_")


def authorization_scope(action: str, arguments: Optional[dict] = None) -> str:
    """`in_policy`, `out_of_policy`, or `unknown` — for one request.

    Scope is decided from the configuration only, and it is deliberately
    narrower than "the category exists":

    * unknown  — nothing in the configuration covers this name (no category
      mapping, or the mapped category is absent from `permissions.json`).
      `unknownPolicy` is `deny_and_report`, so an unrecognized capability is
      refused, never prompted for.
    * out_of_policy — the category exists but is marked `outOfPolicy: deny`
      (financial and credentials are configured that way), or it is not
      enabled, or the requested *operation* is listed in the category's
      `deniedOperations`. A category-level grant is not an operation-level
      grant when the configuration says otherwise.
    * in_policy — the category is enabled, not marked out of policy, and the
      operation is not on the category's deny list. Whether the request may
      still execute is decided by `resolve()`, which also weighs the risk
      classification — `in_policy` alone never executes anything.
    """
    permissions = load("permissions")
    if permissions is None:
        return "unknown"
    name = category_for(action)
    if name is None:
        return "unknown"
    category = (permissions.get("categories") or {}).get(name)
    if not isinstance(category, dict):
        return "unknown"
    if str(category.get("outOfPolicy", "")) == "deny":
        return "out_of_policy"
    if category.get("enabled") is not True:
        return "out_of_policy"
    if arguments is not None:
        denied = {str(op) for op in (category.get("deniedOperations") or [])}
        if _normalised_operation(arguments) in denied:
            return "out_of_policy"
    return "in_policy"


def behavior_for(scope: str) -> str:
    """The configured behavior for a scope: `execute` or `deny_and_report`."""
    permissions = load("permissions")
    if permissions is None:
        return "deny_and_report"
    behavior = permissions.get("behavior") or {}
    key = {"in_policy": "inPolicy",
           "out_of_policy": "outOfPolicy"}.get(scope, "unknownPolicy")
    return str(behavior.get(key, "deny_and_report"))


def silent_resolution(action: str) -> tuple:
    """(scope, behavior) where behavior is `execute` or `deny_and_report`.

    Kept as the scope-only view for callers and tests; `resolve()` is the
    authority that combines this with the risk classification.
    """
    scope = authorization_scope(action)
    return scope, behavior_for(scope)


@dataclass(frozen=True)
class Resolution:
    """The one effective authorization decision for a request."""

    allowed: bool
    #: where the answer came from: `classification`, `untrusted_content`,
    #: or `policy` — "who said no" for the report and the audit trail.
    source: str
    scope: str          # in_policy | out_of_policy | unknown | security_classification |
    behavior: str       # execute | deny_and_report
    reason: str

    @property
    def decision(self) -> str:
        return "ALLOW" if self.allowed else "DENY"


def resolve(action: str, arguments: Any, classification: str,
            classification_reason: str = "") -> Resolution:
    """Decide ALLOW or DENY for one request. This is the single authority.

    `classification` is the value `core.security.AuthorizationPolicy.authorize`
    produced (`ALLOW`, `REQUIRE_CONFIRMATION`, `DENY`). That function
    *classifies*; it does not decide. The rules, in order:

      1. A `DENY` classification denies. The classifier withholds; this
         function never converts a denial into an allowance.
      2. Content still carrying the untrusted-data label denies. The model may
         ask (`modelMayRequest`); neither model nor content may grant.
      3. Anything whose scope is not `in_policy` denies — out of policy and
         unknown both resolve to `deny_and_report`. Never "ask instead".
      4. `in_policy` + configured behavior `execute` allows. THIS is where a
         classification of `REQUIRE_CONFIRMATION` becomes an allowance: the
         user's standing configuration answers the question the prompt would
         have asked, identically on the first use and every later use. The
         conversion is explicit (documented above), deterministic (same inputs,
         same result), and the only path from `REQUIRE_CONFIRMATION` to `ALLOW`.
    """
    if str(classification) == "DENY":
        return Resolution(allowed=False, source="classification",
                          scope="security_classification",
                          behavior="deny_and_report",
                          reason=str(classification_reason)
                          or "denied by the security classification")
    if carries_untrusted_content(arguments):
        return Resolution(allowed=False, source="untrusted_content",
                          scope="untrusted_content", behavior="deny_and_report",
                          reason="request embeds content labelled as untrusted")
    scope = authorization_scope(action, arguments)
    behavior = behavior_for(scope)
    if scope != "in_policy":
        return Resolution(allowed=False, source="policy", scope=scope,
                          behavior=behavior,
                          reason=f"'{action}' is {scope.replace('_', ' ')} under "
                                 "the configured permission policy")
    if behavior != "execute":
        return Resolution(allowed=False, source="policy", scope=scope,
                          behavior=behavior,
                          reason=f"configured behavior for in-policy requests is "
                                 f"'{behavior}', not 'execute'")
    return Resolution(allowed=True, source="policy", scope=scope,
                      behavior=behavior,
                      reason="category enabled, operation not denied, no "
                             "untrusted content")
