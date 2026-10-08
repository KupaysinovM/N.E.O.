"""
The execution boundary — the only way a task reaches a real capability.

    Task
      ↓
    ExecutionRequest            (structured: task id, action, arguments, who asked)
      ↓
    Risk classification         (core/security.py — facts + a provisional verdict)
      ↓
    Authorization policy        (config/policy.py resolve() — THE one ALLOW/DENY)
      ↓                          legacy core/confirm.py gate only when the
      ↓                          configuration itself re-enables prompts
    Registered action           (core/action_loader.py / core/plugin_loader.py)
      ↓
    Real execution on this PC
      ↓
    ExecutionResult             (SUCCESS / FAILED / NOT_SUPPORTED / NOT_AVAILABLE /
      ↓                          REQUIRES_CONFIRMATION / CANCELLED)
    Task state update

WHY THIS FILE EXISTS
    Phase 1 removed the one path where a model could get Python written and run
    for it. What remained was still informal: a tool name and a dict went
    straight from a Gemini function call into a registry, and the only result
    was whatever string the handler returned. Nothing could say whether the OS
    had done anything, nothing could be cancelled, and nothing recorded what
    happened in a shape another component could read.

    This module is that boundary. It does not replace the registries and does
    not re-implement authorization: classification lives in `core/security.py`,
    and the single effective ALLOW-or-DENY decision lives in
    `config/policy.resolve()`, called exactly once below. What this module
    does own is the *application* of that decision — one decision, one audit
    record before anything runs, deny + report without asking when it is DENY,
    and execution with verification when it is ALLOW. The legacy
    `core/confirm.py` gate is reachable only when the configuration explicitly
    turns permission prompts back on; it never decides during normal
    execution.

THE TRUTHFUL SUCCESS RULE
    An action returns a sentence. Some sentences are explicit refusals — the
    gates in actions/desktop.py and actions/computer_control.py return
    `NOT_SUPPORTED:` / `NOT_AVAILABLE:` — and those are mapped exactly. The
    rest carry no machine-readable outcome at all, and this layer will not
    invent one beyond what the existing path can honestly claim: the action ran
    through its own real code path and reported completion without raising.
    Every result therefore carries `verified = False` and, for that case,
    `data["legacy_message"] = True`, so neither NEO nor a later phase mistakes
    "the handler said so" for "the PC was checked". Phase 4 adds the checking;
    Phase 2 only stops pretending it is already there.

WHAT THE MODEL CANNOT DO
    Arguments stay structured data. They are never rendered into Python source,
    never handed to the interpreter, and never used to build a command line
    here (see the scan in tests/test_regression.py). An unknown name is a
    NOT_AVAILABLE result, not a lookup into anything
    else, and a malformed request is rejected before any registry is touched.
"""
from __future__ import annotations

import inspect
import copy
import re
import sys
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from core import confirm
from config import policy
from core.security import (
    Authorization,
    AuthorizationDecision,
    AuthorizationPolicy,
    CapabilityGrant,
    CapabilityGrantStore,
    RiskClass,
    authorized_execution,
    capability_grant_spec,
    confirmation_detail,
    request_fingerprint,
)
from core.events import Event, EventBus, EventType
from core.task_models import ErrorKind, Task, TaskContext, TaskError, TaskStateError, TaskStatus
from core.security_audit import SecurityAuditStore

# ── canonical result statuses ────────────────────────────────────────────────

class ExecStatus(str, Enum):
    SUCCESS                = "SUCCESS"
    FAILED                 = "FAILED"
    NOT_SUPPORTED          = "NOT_SUPPORTED"
    NOT_AVAILABLE          = "NOT_AVAILABLE"
    REQUIRES_CONFIRMATION  = "REQUIRES_CONFIRMATION"
    CANCELLED              = "CANCELLED"
    #: Phase 4. The action ran and reported success, but the state it was
    #: supposed to produce could not be observed. This is deliberately not the
    #: same value as FAILED: nothing broke, and nothing was confirmed either.
    NOT_VERIFIED           = "NOT_VERIFIED"


@dataclass
class ExecutionRequest:
    """One capability invocation, fully described before anything runs."""

    action: str
    arguments: dict = field(default_factory=dict)
    task_id: str = ""
    step: str = ""                       # human-readable step (never executed)
    requested_by: str = "model"          # model | user | system | plugin
    tool_call_id: str = ""               # provider-side id, for tracing only

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "arguments": dict(self.arguments),
            "task_id": self.task_id,
            "step": self.step,
            "requested_by": self.requested_by,
            "tool_call_id": self.tool_call_id,
        }


@dataclass
class ExecutionResult:
    """What actually happened, in a shape the task layer can consume.

    `status` is what the *execution* reported. `verification_status` is what an
    independent look at the machine found afterwards, and `final_status` is the
    one a caller should branch on — it is `status` unless verification had
    something to say, in which case a successful call whose effect could not be
    observed becomes NOT_VERIFIED rather than SUCCESS.

    `verified` is True only when something was checked and found to be true.
    """

    status: ExecStatus
    action: str
    task_id: str = ""
    message: str = ""                    # the sentence the model may be given
    data: dict = field(default_factory=dict)
    error: Optional[TaskError] = None
    verified: bool = False
    verification_status: str = "NOT_AVAILABLE"
    verification: Optional[dict] = None
    final_status: Optional[ExecStatus] = None

    @property
    def ok(self) -> bool:
        return self.status is ExecStatus.SUCCESS

    @property
    def outcome(self) -> ExecStatus:
        """The status a caller should act on."""
        return self.final_status or self.status

    @property
    def invoked(self) -> bool:
        return bool(self.data.get("invoked", False))

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "action": self.action,
            "task_id": self.task_id,
            "message": self.message,
            "data": dict(self.data),
            "error": self.error.to_dict() if self.error else None,
            "verified": self.verified,
            "verification_status": self.verification_status,
            "verification": self.verification,
            "final_status": (self.final_status or self.status).value,
        }


# ── adapter for the strings existing tools already return ────────────────────
# Only markers that are already machine-shaped are trusted. Prose is never
# pattern-matched: an action that says "could not find that file" is reporting
# a result, not declaring a failure taxonomy, and guessing from wording is how
# a truthful layer starts inventing outcomes.

_RE_CONFIRM_PENDING      = re.compile(r"^\[CONFIRMATION_PENDING\]")
_RE_CONFIRM_UNAVAILABLE  = re.compile(r"^\[CONFIRMATION_UNAVAILABLE\]")
_RE_CONFIRM_FAILED       = re.compile(r"^\[CONFIRMATION_FAILED\]")
_RE_NOT_SUPPORTED        = re.compile(r"^NOT_SUPPORTED:\s*")
_RE_NOT_AVAILABLE        = re.compile(r"^NOT_AVAILABLE:\s*")
_RE_ACTION_UNKNOWN       = re.compile(r"^Action '[^']*' is not available\.\s*$")
_RE_ACTION_FAILED        = re.compile(r"^Tool '[^']*' failed: ")
_RE_PLUGIN_UNKNOWN       = re.compile(r"^Plugin '[^']*' is not available\.\s*$")
_RE_PLUGIN_DISABLED      = re.compile(r"^The '[^']*' plugin is currently disabled\.\s*$")
_RE_PLUGIN_FAILED        = re.compile(r"^The '[^']*' plugin failed: ")
_RE_UNKNOWN_TOOL         = re.compile(r"^Unknown (?:tool|action): ")
# The gate's own refusal, in the wording older builds returned before the
# [CONFIRMATION_UNAVAILABLE] marker existed. Recognised so that "I did not do
# it" can never be read as success if a string like this is ever seen again.
_RE_GATE_NO_INTERFACE    = re.compile(
    r"^I cannot confirm '.*' right now because the interface is not available, "
    r"so I have not done it\.\s*$")


def classify_legacy_message(text: Any) -> tuple[ExecStatus, Optional[TaskError], bool]:
    """Map a handler's return value onto the canonical result contract.

    Returns (status, error, legacy_message). `legacy_message` is True when the
    string carried no explicit outcome marker, meaning the only thing that can
    honestly be claimed is that the action's own code path reported completion.
    """
    message = "" if text is None else (text if isinstance(text, str) else str(text))
    if not message.strip():
        # The registries substitute "Done." for an empty return before we see
        # it; an empty value here still means "the handler finished", no more.
        return ExecStatus.SUCCESS, None, True

    if _RE_CONFIRM_PENDING.match(message):
        return (ExecStatus.REQUIRES_CONFIRMATION,
                TaskError(message="Waiting for the user to authorize this action.",
                          kind=ErrorKind.AUTHORIZATION_REQUIRED), False)
    if _RE_CONFIRM_UNAVAILABLE.match(message) or _RE_GATE_NO_INTERFACE.match(message):
        return (ExecStatus.FAILED,
                TaskError(message=message, kind=ErrorKind.AUTHORIZATION_UNAVAILABLE), False)
    if _RE_CONFIRM_FAILED.match(message):
        return (ExecStatus.FAILED,
                TaskError(message=message, kind=ErrorKind.INTERNAL_ERROR), False)
    if _RE_NOT_SUPPORTED.match(message):
        return (ExecStatus.NOT_SUPPORTED,
                TaskError(message=message, kind=ErrorKind.ACTION_NOT_SUPPORTED), False)
    if _RE_NOT_AVAILABLE.match(message):
        return (ExecStatus.NOT_AVAILABLE,
                TaskError(message=message, kind=ErrorKind.ACTION_UNAVAILABLE), False)
    if _RE_ACTION_FAILED.match(message) or _RE_PLUGIN_FAILED.match(message):
        return (ExecStatus.FAILED,
                TaskError(message=message, kind=ErrorKind.ACTION_FAILED), False)
    if _RE_ACTION_UNKNOWN.match(message) or _RE_PLUGIN_UNKNOWN.match(message):
        return (ExecStatus.NOT_AVAILABLE,
                TaskError(message=message, kind=ErrorKind.UNKNOWN_ACTION), False)
    if _RE_PLUGIN_DISABLED.match(message):
        return (ExecStatus.NOT_AVAILABLE,
                TaskError(message=message, kind=ErrorKind.ACTION_UNAVAILABLE), False)
    if _RE_UNKNOWN_TOOL.match(message):
        return (ExecStatus.NOT_AVAILABLE,
                TaskError(message=message, kind=ErrorKind.UNKNOWN_ACTION), False)

    return ExecStatus.SUCCESS, None, True


def _expectation_provider(handler: Any):
    """An action's verification contract, if it declares one.

    An action opts in simply by exposing `expectation_for(params, data)` at its
    module level. Nothing here knows what any action does: the execution layer
    asks, gets a structured expectation or `None`, and checks it. Actions that
    declare nothing are never verified, which is the safe default.
    """
    if handler is None:
        return None
    module_name = getattr(handler, "__module__", None)
    module = sys.modules.get(module_name) if module_name else None
    provider = getattr(module, "expectation_for", None)
    return provider if callable(provider) else None


def _capture_expectation(expectation, context: Optional[TaskContext]):
    """Read the state an expectation will later be compared against."""
    if expectation is None:
        return None
    try:
        from core.verification import verifier as _verifier
        return _verifier.capture(
            expectation, cancel_event=context.cancel_event if context else None)
    except Exception:
        return None


def resolve_capability(name: str, actions: Any = None,
                       plugins: Any = None) -> tuple[Optional[Any], str, Optional[Any]]:
    """Find a capability by name in the real registries, actions first.

    Returns `(registry, kind, handler)`, or `(None, "", None)` when nothing is
    registered under that name. This is the one place that knows where handlers
    live; the execution layer uses it to dispatch, and Phase 5's planner uses it
    to ask an action what it verifies *before* planning anything. Sharing it is
    what keeps "the planner checked the registry" and "the executor will run it"
    referring to the same lookup rather than two that can drift apart.
    """
    for registry, kind in ((actions, "actions"), (plugins, "plugins")):
        if registry is None or not registry.has(name):
            continue
        attribute = "_actions" if kind == "actions" else "_plugins"
        records = getattr(registry, attribute, None)
        record = records.get(name) if isinstance(records, dict) else None
        handler = (getattr(record, "handler", None) if kind == "actions"
                   else getattr(record, "run", None))
        return registry, kind, handler
    return None, "", None


def _declares_cancel_param(handler: Any) -> bool:
    """Does this handler accept the optional cooperative cancel flag?

    Used only to describe cancellation honestly: a handler that declares
    `cancel_event` can be asked to stop, one that does not cannot, and the
    result says which of the two happened instead of claiming an interrupt.
    """
    try:
        params = inspect.signature(handler).parameters
    except (TypeError, ValueError):
        return False
    if "cancel_event" in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


# ── the layer ────────────────────────────────────────────────────────────────

class ExecutionLayer:
    """Invoke registered capabilities for tasks. Never raises to its caller."""

    def __init__(self, actions: Any, plugins: Any = None, manager: Any = None,
                 bus: Optional[EventBus] = None,
                 logger: Optional[Callable[[str], None]] = None,
                 notify: Optional[Callable[[str], None]] = None,
                 security_policy: Optional[AuthorizationPolicy] = None,
                 security_audit: Optional[SecurityAuditStore] = None,
                 capability_grants: Optional[CapabilityGrantStore] = None):
        # Registries are used through their public contract (has/run) rather
        # than their classes, so the existing registries stay authoritative and
        # a test can supply a fixture without touching production code.
        self._actions = actions
        self._plugins = plugins
        self._manager = manager
        self._bus = bus if bus is not None else (getattr(manager, "bus", None) or EventBus())
        self._logger = logger or (lambda _msg: None)
        self._notify = notify or (lambda _msg: None)
        self._security_policy = security_policy or AuthorizationPolicy()
        self._capability_grants = capability_grants or CapabilityGrantStore()
        audit_path = getattr(getattr(manager, "store", None), "path", None)
        if security_audit is not None:
            self._security_audit_store = security_audit
        elif audit_path is not None:
            self._security_audit_store = SecurityAuditStore(
                audit_path.parent / "security-audit" / "security-audit.sqlite3",
                legacy_path=audit_path.with_name("security-audit.sqlite3"))
        else:
            self._security_audit_store = SecurityAuditStore()
        self._unsubscribe_audit_events = self._bus.subscribe(
            self._record_recovery_event)
        # Only one confirmation can be pending at a time — that is the existing
        # gate's own design — so this maps the pending key to the task that is
        # waiting on it.
        self._awaiting: dict[str, tuple[str, str, Optional[Authorization]]] = {}
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    def bind_confirmation_gate(self) -> None:
        """Ask core/confirm.py to report how a parked action was resolved.

        Additive: the gate keeps its own behaviour (token issued by the
        interface, one-shot, expires) and simply tells us afterwards whether it
        ran, was declined, expired or raised. Without this the task behind a
        parked action could never learn the outcome.
        """
        confirm.bind_resolution(self._on_confirmation_resolved)

    def pending_authorizations(self) -> dict:
        with self._lock:
            return {key: {"task_id": entry[0], "action": entry[1]}
                    for key, entry in self._awaiting.items()}

    def _record_recovery_event(self, event: Event) -> None:
        recovery_events = {
            EventType.STEP_RECOVERY_STARTED,
            EventType.STEP_RECOVERY_COMPLETED,
            EventType.GOAL_REPLANNING,
            EventType.GOAL_REPLANNED,
            EventType.GOAL_REPLAN_REFUSED,
        }
        if event.type not in recovery_events:
            return
        record = {
            "event": event.type.value,
            "task_id": event.task_id,
            "goal_id": event.goal_id,
            "step_digest": (request_fingerprint({"step_id": event.step_id})
                            if event.step_id else ""),
            "action": event.action,
            "status": event.status,
        }
        try:
            self._security_audit_store.append(record)
        except Exception as exc:
            self._logger(
                f"[Security] recovery audit persistence failed ({type(exc).__name__}).")
            self._notify("Security audit storage is unavailable for recovery events.")

    def execute(self, request: ExecutionRequest,
                context: Optional[TaskContext] = None,
                handler_ctx: Optional[dict] = None) -> ExecutionResult:
        """Run one request through the real registry, recording what happened."""
        try:
            return self._execute(request, context, handler_ctx or {})
        except Exception as e:
            # Nothing above this may see an exception: the caller is a
            # conversation loop, and a crash here would take the session down.
            error_type = type(e).__name__
            self._logger(
                f"[Exec] internal error for '{getattr(request, 'action', '?')}' "
                f"({error_type}).")
            result = ExecutionResult(
                status=ExecStatus.FAILED, action=str(getattr(request, "action", "")),
                task_id=str(getattr(request, "task_id", "")),
                message=f"Execution failed inside NEO ({error_type}).",
                error=TaskError(message=f"Internal execution error ({error_type}).",
                                kind=ErrorKind.INTERNAL_ERROR),
                data={"invoked": False, "internal_error": True},
            )
            self._record(request, result)
            self._apply_to_task(request, result)
            return result

    # -- internals ----------------------------------------------------------

    def _execute(self, request: ExecutionRequest, context: Optional[TaskContext],
                 handler_ctx: dict) -> ExecutionResult:
        bad = self._validate_request(request)
        if bad is not None:
            self._record(request, bad)
            self._apply_to_task(request, bad)
            return bad

        # ── fail closed on configuration, never fail open to a prompt ──────
        # A missing, unreadable, malformed, schema-invalid, partially valid,
        # or contradictory security configuration does NOT fall back to the
        # confirmation gate. It blocks: no execution, no prompt, and the
        # configuration failure itself is the report. "Fail closed" means
        # deny the action — never "ask the user".
        config_problem = policy.config_failure()
        if config_problem:
            return self._block_configuration_failure(request, config_problem)

        manager = self._manager
        task: Optional[Task] = None
        if request.task_id and manager is not None:
            task = manager.get_task(request.task_id)
            if task is None:
                return self._finish(request, ExecutionResult(
                    status=ExecStatus.FAILED, action=request.action,
                    task_id=request.task_id,
                    message=f"Execution refused: task '{request.task_id}' is not known to NEO.",
                    error=TaskError(message="Unknown task id.",
                                    kind=ErrorKind.INVALID_REQUEST),
                    data={"invoked": False}))
            if task.status is TaskStatus.CANCELLED:
                return self._finish(request, ExecutionResult(
                    status=ExecStatus.CANCELLED, action=request.action,
                    task_id=request.task_id,
                    message=f"Task {task.short_id()} was cancelled — nothing was executed.",
                    error=TaskError(message="Task was already cancelled.",
                                    kind=ErrorKind.TASK_CANCELLED),
                    data={"invoked": False, "cancelled_before_execution": True}))
            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                return self._finish(request, ExecutionResult(
                    status=ExecStatus.FAILED, action=request.action,
                    task_id=request.task_id,
                    message=(f"Execution refused: task {task.short_id()} is already "
                             f"{task.status.value}."),
                    error=TaskError(message="Task is no longer open.",
                                    kind=ErrorKind.INVALID_REQUEST),
                    data={"invoked": False}))
            if task.status is TaskStatus.PENDING:
                manager.start_task(task.task_id)
            if context is None:
                context = manager.context_for(task.task_id, {"requested_by": request.requested_by})

        if context is not None and context.is_cancelled():
            # Cancelled between task creation and dispatch: stop here, before
            # anything on the machine is touched.
            outcome = (manager.cancel_task(task.task_id)
                       if manager is not None and task is not None
                       and task.status is not TaskStatus.CANCELLED else None)
            return self._finish(request, ExecutionResult(
                status=ExecStatus.CANCELLED, action=request.action,
                task_id=context.task_id,
                message=(outcome.message if outcome else
                         f"Cancelled before it started — nothing was executed."),
                error=TaskError(message="Cancellation was requested before dispatch.",
                                kind=ErrorKind.TASK_CANCELLED),
                data={"invoked": False, "cancelled_before_execution": True}))

        registry, kind = self._resolve(request.action)
        if registry is None:
            # No action started, so this is the only way a name that ran nothing
            # still shows up in the lifecycle as a failure.
            self._emit(EventType.ACTION_FAILED, task, request.action,
                       status=ExecStatus.NOT_AVAILABLE.value,
                       data={"invoked": False, "reason": "unknown_action"})
            return self._finish(request, ExecutionResult(
                status=ExecStatus.NOT_AVAILABLE, action=request.action,
                task_id=request.task_id,
                message=f"Unknown action: '{request.action}'.",
                error=TaskError(message=f"No registered action or plugin named "
                                        f"'{request.action}'.",
                                kind=ErrorKind.UNKNOWN_ACTION),
                data={"invoked": False}))

        authorization = self._security_policy.authorize(
            request.action, request.arguments, kind)

        # ── vision grants belong to the legacy HUD subsystem only ───────────
        # The 15-minute SCREEN_VISION/WEBCAM_VISION grant exists to spare a
        # user repeated *prompts*. Normal execution never prompts, so it never
        # creates, resolves, or requires a grant: vision is decided like every
        # other capability — CLASSIFICATION → POLICY → ALLOW/DENY → EXECUTE —
        # and runs without any human grant having ever existed. The grant
        # machinery below runs only when the configuration (or a test seam)
        # explicitly puts the legacy prompt gate back on.
        silent = not policy.prompts_enabled()
        grant_details = {}
        if not silent:
            grant_spec = capability_grant_spec(authorization, request.arguments)
            grant_resolution = self._capability_grants.resolve(grant_spec)
            for expired_grant in grant_resolution.expired:
                if not self._audit_security(
                        request, task, authorization,
                        **self._grant_audit_details("EXPIRED", expired_grant)):
                    message = ("Execution refused: the security audit journal "
                               "is unavailable.")
                    return self._finish(request, ExecutionResult(
                        status=ExecStatus.FAILED, action=request.action,
                        task_id=request.task_id, message=message,
                        error=TaskError(message=message,
                                        kind=ErrorKind.AUTHORIZATION_UNAVAILABLE),
                        data={"invoked": False, "security": authorization.to_dict(),
                              "audit_status": "UNAVAILABLE"}))
            if grant_resolution.grant is not None:
                grant = grant_resolution.grant
                authorization = Authorization(
                    authorization.action, authorization.operation,
                    authorization.risk,
                    AuthorizationDecision.ALLOW,
                    "active scoped capability grant",
                    authorization.target_digest,
                )
                grant_details = self._grant_audit_details("USED", grant)
            elif grant_resolution.escalation:
                # A grant for the same capability cannot be widened to another
                # scope/operation class. The static policy still requires
                # approval.
                grant_details = {"grant_event": "ESCALATION"}

        # ── the single authorization decision ────────────────────────────────
        # `core.security.authorize` only *classified* this request (facts plus
        # a provisional verdict). `config.policy.resolve` is the one and only
        # place ALLOW or DENY is decided: a DENY classification, untrusted-
        # labelled content, and any scope other than `in_policy` all deny; a
        # scope of `in_policy` with behavior `execute` allows — including when
        # the classification said REQUIRE_CONFIRMATION, which the standing
        # configuration answers silently and identically on every use. The
        # full contract, including why the combination is a conjunction, is
        # documented in `config/policy.py`.
        resolution = policy.resolve(
            request.action, request.arguments,
            classification=authorization.decision.value,
            classification_reason=authorization.reason)
        if not resolution.allowed:
            authorization = Authorization(
                authorization.action, authorization.operation, authorization.risk,
                AuthorizationDecision.DENY, resolution.reason,
                authorization.target_digest)
        elif (silent
              and authorization.decision is AuthorizationDecision.REQUIRE_CONFIRMATION):
            # The one explicit, deterministic conversion: the classifier's
            # "a human would have been asked" becomes ALLOW because the
            # configured policy says execute for this scope. It happens here,
            # only here, and only after the policy allowed the request.
            authorization = Authorization(
                authorization.action, authorization.operation, authorization.risk,
                AuthorizationDecision.ALLOW,
                f"{authorization.reason}; allowed silently by the configured "
                f"policy ({resolution.scope})",
                authorization.target_digest)
        security_data = authorization.to_dict()

        if resolution.allowed:
            audit_confirmation = "GRANTED" if silent else ""
        else:
            audit_confirmation = ("" if resolution.source == "classification"
                                  else "POLICY")
        if not self._audit_security(
                request, task, authorization, confirmation=audit_confirmation,
                policy_scope=resolution.scope,
                policy_behavior=resolution.behavior, **grant_details):
            message = "Execution refused: the security audit journal is unavailable."
            return self._finish(request, ExecutionResult(
                status=ExecStatus.FAILED, action=request.action,
                task_id=request.task_id, message=message,
                error=TaskError(message=message,
                                kind=ErrorKind.AUTHORIZATION_UNAVAILABLE),
                data={"invoked": False, "security": security_data,
                      "audit_status": "UNAVAILABLE"}))

        if not resolution.allowed:
            if resolution.source == "classification":
                # Denied by the classification (unsupported operation,
                # prohibited capability, untrusted registry). The classifier's
                # reason is the report. Deny + report, never deny + ask.
                message = (f"Authorization denied for '{request.action}': "
                           f"{resolution.reason}.")
                denied = ExecutionResult(
                    status=ExecStatus.FAILED, action=request.action,
                    task_id=request.task_id, message=message,
                    error=TaskError(message=message,
                                    kind=ErrorKind.AUTHORIZATION_DENIED),
                    data={"invoked": False, "security": security_data})
                self._emit(EventType.ACTION_FAILED, task, request.action,
                           status=ExecStatus.FAILED.value,
                           data={"invoked": False, "authorization": "denied"})
                return self._finish(request, denied)
            return self._deny_unprompted(request, task, authorization, resolution)

        if (not silent
                and authorization.decision is AuthorizationDecision.REQUIRE_CONFIRMATION):
            # Legacy subsystem — reachable only when the configuration itself
            # turns permission prompts back on. During normal execution the
            # policy has already decided ALLOW and this branch is never taken,
            # so `core/confirm.py` cannot compete with the autonomous policy.
            return self._request_authorization(
                request, task, registry, kind, context, handler_ctx, authorization)

        if manager is not None and task is not None:
            manager.set_action(
                task.task_id, request.action,
                "" if request.requested_by == "model" else request.step)

        handler = self._handler_of(registry, kind, request.action)
        interruptible = _declares_cancel_param(handler) if handler is not None else False
        self._emit(EventType.ACTION_STARTED, task, request.action,
                   data={"registry": kind, "requested_by": request.requested_by})

        # Phase 4, before: anything whose "did it change?" check needs the prior
        # state has to read it *now*. Captured before the action, and treated as a
        # reading rather than as current truth.
        precondition = None
        provider = _expectation_provider(handler)
        if provider is not None and not (context is not None and context.is_cancelled()):
            try:
                precondition, _post = provider(request.arguments, {})
            except Exception:
                precondition = None
        before_observation = _capture_expectation(precondition, context)

        # Every invocation this layer performs carries the unforgeable receipt,
        # so a handler's own legacy gate (windows_control close, irreversible
        # computer_settings) sees that the boundary authorized this exact
        # request instead of putting a second prompt in front of the user.
        # The receipt is set only here, after the policy decision, and only for
        # the exact (action, arguments) pair being invoked.
        with authorized_execution(request.action, request.arguments):
            legacy_text = self._invoke(registry, kind, request, context, handler_ctx)

        # Two shapes of return are accepted, and they mean different things:
        #   a plain string  → the original contract; classified by the adapter
        #   ExecutionResult → the structured contract, for handlers that have
        #                      real outcomes to report (Phase 3's Windows control
        #                      is the first). Nothing is parsed out of a string
        #                      it produced itself.
        if isinstance(legacy_text, ExecutionResult):
            structured = legacy_text
            if not structured.action:
                structured.action = request.action
            if not structured.task_id:
                structured.task_id = request.task_id
            status = structured.status
            message = structured.message or "Done."
            error = structured.error
            data = dict(structured.data)
            data.update({"invoked": True, "registry": kind, "legacy_message": False,
                         "interruptible": interruptible})
        else:
            status, error, legacy_only = classify_legacy_message(legacy_text)
            message = (legacy_text if isinstance(legacy_text, str) and legacy_text.strip()
                       else "Done.")
            data = {"invoked": True, "registry": kind, "legacy_message": legacy_only,
                    "interruptible": interruptible}
        data["security"] = security_data

        # A cancel that arrived while the action was running. The action cannot
        # be interrupted in Phase 2, so the result says exactly that instead of
        # reporting an instant stop that did not happen.
        cancelled_now = ((context is not None and context.is_cancelled())
                         or (task is not None and task.status is TaskStatus.CANCELLED))
        if cancelled_now and status is not ExecStatus.REQUIRES_CONFIRMATION:
            data["completed_after_cancellation"] = True
            message_note = (f"Cancellation was requested while '{request.action}' was "
                            f"already running; NEO cannot interrupt a running action, "
                            f"so it finished and reported: {message}")
            result = ExecutionResult(
                status=ExecStatus.CANCELLED, action=request.action,
                task_id=request.task_id, message=message_note,
                error=TaskError(message="Cancelled during execution.",
                                kind=ErrorKind.TASK_CANCELLED),
                data=data)
            self._emit(EventType.ACTION_COMPLETED, task, request.action,
                       status=ExecStatus.CANCELLED.value, data=data)
            return self._finish(request, result)

        if status is ExecStatus.REQUIRES_CONFIRMATION:
            data["security"] = security_data
            data["confirmation_key"] = self._register_pending(
                request, task, authorization)
            self._audit_security(request, task, authorization,
                                 confirmation="PENDING")
            self._emit(EventType.ACTION_COMPLETED, task, request.action,
                       status=status.value, data=data)
            # The task stays RUNNING: nothing is authorized yet.
            return self._finish(request, ExecutionResult(
                status=status, action=request.action, task_id=request.task_id,
                message=message, error=error, data=data))

        # Phase 4. An action that returned successfully has still produced
        # nothing. Only now is the machine looked at — and only when there is
        # something observable to look for.
        execution_status = status
        (status, message, error, verified, verification_status,
         verification_payload) = self._verify(
            request, task, status, message, error, data, provider,
            before_observation, context,
            sensitive=authorization.risk.value in {
                "SENSITIVE_DATA_ACCESS", "EXTERNAL_COMMUNICATION"})
        if verification_payload is not None:
            data["verification"] = verification_payload
            data["verification_status"] = verification_status

        self._audit_security(
            request, task, authorization, confirmation=audit_confirmation,
            policy_scope=resolution.scope, policy_behavior=resolution.behavior,
            execution=status.value,
            verified=verified, verification_status=verification_status,
            failure_kind=error.kind.value if error else "")
        failed_like = status in (ExecStatus.FAILED, ExecStatus.NOT_SUPPORTED,
                                 ExecStatus.NOT_AVAILABLE, ExecStatus.NOT_VERIFIED)
        if failed_like:
            self._emit(EventType.ACTION_FAILED, task, request.action,
                       status=status.value, data=data)
        else:
            self._emit(EventType.ACTION_COMPLETED, task, request.action,
                       status=status.value, data=data)

        result = ExecutionResult(status=execution_status,
                                 action=request.action, task_id=request.task_id,
                                 message=message, error=error, data=data,
                                 verified=verified,
                                 verification_status=verification_status,
                                 verification=verification_payload,
                                 final_status=status)
        return self._finish(request, result)

    # -- verification (Phase 4) --------------------------------------------

    def _verify(self, request: ExecutionRequest, task: Optional[Task], status: ExecStatus,
                message: str, error: Optional[TaskError], data: dict, provider,
                before_observation, context: Optional[TaskContext],
                sensitive: bool = False):
        """Look at the machine after the action, and report what is really there.

        Returns the (possibly downgraded) status, message, error and the
        verification facts. Nothing here can turn a failure into a success: the
        only thing verification is allowed to change is `SUCCESS` into
        `NOT_VERIFIED`.
        """
        no_check = (status, message, error, False, "NOT_AVAILABLE", None)

        if status is not ExecStatus.SUCCESS:
            return no_check                       # nothing ran, nothing to check
        if provider is None:
            return no_check                       # this action declares no expectation

        try:
            _pre, expectation = provider(request.arguments, dict(data))
        except Exception as e:
            self._logger(
                f"[Exec] could not build an expectation ({type(e).__name__}).")
            return no_check

        from core.verification import verifier as _verifier

        cancel_event = context.cancel_event if context is not None else None
        self._emit(EventType.VERIFICATION_STARTED, task, request.action,
                   data={"expectation": (
                       {"kind": expectation.kind}
                       if sensitive and expectation is not None
                       else expectation.to_dict() if expectation is not None else None),
                         "sensitive_details_redacted": sensitive})
        try:
            outcome = _verifier.verify(expectation, before=before_observation,
                                       cancel_event=cancel_event)
        except Exception as e:                    # verification must not kill the task
            self._logger(
                f"[Exec] verification failed for '{request.action}' "
                f"({type(e).__name__}).")
            return (status, message, error, False, "VERIFICATION_FAILED", None)

        payload = ({"status": outcome.status.value,
                    "sensitive_details_redacted": True}
                   if sensitive else outcome.to_dict())
        verified = outcome.status is _verifier.Status.VERIFIED

        if verified:
            self._emit(EventType.VERIFICATION_COMPLETED, task, request.action,
                       status=outcome.status.value, data=payload)
            return status, message, error, True, outcome.status.value, payload

        if outcome.status in (_verifier.Status.NOT_AVAILABLE,
                              _verifier.Status.FAILED):
            # The check ran and its answer was "there is nothing here to
            # check". That is a completed verification, not a failed one.
            self._emit(EventType.VERIFICATION_COMPLETED, task, request.action,
                       status=outcome.status.value, data=payload)
            return status, message, error, False, outcome.status.value, payload

        self._emit(EventType.VERIFICATION_FAILED, task, request.action,
                   status=outcome.status.value, data=payload)

        if outcome.status is _verifier.Status.CANCELLED:
            return (ExecStatus.CANCELLED,
                    f"'{request.action}' ran, but the result was never confirmed "
                    f"because the wait was cancelled.",
                    TaskError(message="Cancelled while verifying the result.",
                              kind=ErrorKind.TASK_CANCELLED),
                    False, outcome.status.value, payload)

        if outcome.status is _verifier.Status.NOT_AVAILABLE:
            # Nothing was wrong and nothing was proven. The execution status
            # stands on its own; verification simply had nothing to add.
            return status, message, error, False, outcome.status.value, payload

        # VERIFIED is false and something concrete was observed instead. This is
        # the case Phase 4 exists for: the call worked, the effect did not
        # appear. It must not be reported as success.
        detail = ("Sensitive verification details were withheld."
                  if sensitive else outcome.describe())
        return (ExecStatus.NOT_VERIFIED,
                f"{message}\nNot verified: {detail}",
                TaskError(message=detail, kind=ErrorKind.NOT_VERIFIED),
                False, outcome.status.value, payload)

    def _validate_request(self, request: ExecutionRequest) -> Optional[ExecutionResult]:
        if not isinstance(request, ExecutionRequest):
            return ExecutionResult(
                status=ExecStatus.FAILED, action="",
                message="Execution request was not understood.",
                error=TaskError(message="Request must be an ExecutionRequest.",
                                kind=ErrorKind.INVALID_REQUEST),
                data={"invoked": False})
        if not isinstance(request.action, str) or not request.action.strip():
            return ExecutionResult(
                status=ExecStatus.FAILED, action=str(request.action),
                task_id=request.task_id,
                message="Execution refused: no action was named.",
                error=TaskError(message="Empty action name.",
                                kind=ErrorKind.INVALID_REQUEST),
                data={"invoked": False})
        if not isinstance(request.arguments, dict):
            return ExecutionResult(
                status=ExecStatus.FAILED, action=request.action,
                task_id=request.task_id,
                message=(f"Execution refused: '{request.action}' received arguments "
                         f"that are not a structured object."),
                error=TaskError(message=f"Arguments must be a dict, got "
                                        f"{type(request.arguments).__name__}.",
                                kind=ErrorKind.INVALID_ARGUMENTS),
                data={"invoked": False})
        return None

    def _resolve(self, name: str) -> tuple[Optional[Any], str]:
        """Actions first, then plugins — the precedence the app already had."""
        registry, kind, _handler = resolve_capability(name, self._actions, self._plugins)
        return registry, kind

    @staticmethod
    def _handler_of(registry: Any, kind: str, name: str) -> Any:
        records = (getattr(registry, "_actions", None) if kind == "actions"
                   else getattr(registry, "_plugins", None))
        record = records.get(name) if isinstance(records, dict) else None
        return getattr(record, "handler", None) if kind == "actions" else getattr(record, "run", None)

    def _invoke(self, registry: Any, kind: str, request: ExecutionRequest,
                context: Optional[TaskContext], handler_ctx: dict) -> Any:
        """Call the existing registry exactly the way main.py always has."""
        if kind == "actions":
            ctx = dict(handler_ctx)
            if context is not None:
                ctx["cancel_event"] = context.cancel_event
            return registry.run(request.action, dict(request.arguments), ctx)
        return registry.run(request.action, dict(request.arguments),
                            player=handler_ctx.get("player"),
                            session_memory=handler_ctx.get("session_memory"))

    def _block_configuration_failure(self, request: ExecutionRequest,
                                     problem: str) -> ExecutionResult:
        """SAFE_BLOCKED: no execution, no prompt, the failure is the report.

        Reached before anything else in `_execute` when `config_failure()` is
        non-empty — missing, unreadable, malformed, schema-invalid, partial,
        or contradictory documents. This is fail *closed*: the action is
        denied outright and the configuration failure is reported to the
        caller, the task, and the audit journal. There is deliberately no
        branch here that could end in the confirmation gate.
        """
        message = ("NEO blocked this request: security configuration failure — "
                   f"{problem}. Nothing was executed, and NEO does not prompt "
                   "for approval.")
        arguments = request.arguments if isinstance(request.arguments, dict) else {}
        authorization = Authorization(
            action=str(request.action or ""), operation="",
            risk=RiskClass.UNKNOWN, decision=AuthorizationDecision.DENY,
            reason=f"configuration failure: {problem}",
            target_digest=request_fingerprint(arguments))
        # The audit journal is independent of the policy documents, so record
        # the block when it is available — and block either way.
        self._audit_security(request, None, authorization,
                             confirmation="CONFIGURATION",
                             policy_scope="configuration_failure",
                             policy_behavior="deny_and_report")
        result = ExecutionResult(
            status=ExecStatus.FAILED, action=request.action,
            task_id=request.task_id, message=message,
            error=TaskError(message=message,
                            kind=ErrorKind.AUTHORIZATION_UNAVAILABLE),
            data={"invoked": False, "security": authorization.to_dict(),
                  "configuration": {"failure": problem}})
        self._emit(EventType.ACTION_FAILED, None, request.action,
                   status=ExecStatus.FAILED.value,
                   data={"invoked": False,
                         "authorization": "configuration_blocked",
                         "configuration_failure": problem})
        return self._finish(request, result)

    def _request_authorization(self, request: ExecutionRequest, task: Optional[Task],
                               registry: Any, kind: str,
                               context: Optional[TaskContext], handler_ctx: dict,
                               authorization: Authorization) -> ExecutionResult:
        """Park the exact request in the legacy UI confirmation service.

        LEGACY SUBSYSTEM. `core/execution._execute` only calls this when the
        policy has already decided ALLOW *and* the configuration has turned
        permission prompts back on (`policy.prompts_enabled()`), with a
        classification of REQUIRE_CONFIRMATION to put in front of the user.
        During normal NEO execution — `authorizationMode: silent_policy` — the
        policy decides first and this function is never reached, so the banner
        cannot compete with the autonomous authorization policy.
        """
        try:
            arguments = copy.deepcopy(request.arguments)
        except Exception:
            authorization = Authorization(
                authorization.action, authorization.operation, authorization.risk,
                AuthorizationDecision.DENY,
                "request arguments cannot be safely isolated for confirmation",
                authorization.target_digest)
            self._audit_security(request, task, authorization)
            message = f"Authorization denied for '{request.action}': {authorization.reason}."
            return self._finish(request, ExecutionResult(
                status=ExecStatus.FAILED, action=request.action,
                task_id=request.task_id, message=message,
                error=TaskError(message=message, kind=ErrorKind.AUTHORIZATION_DENIED),
                data={"invoked": False, "security": authorization.to_dict()}))

        def run_authorized():
            if context is not None and context.is_cancelled():
                return "NOT_AVAILABLE: task was cancelled before authorization."
            grant = None
            spec = capability_grant_spec(authorization, arguments)
            if spec is not None:
                grant = self._capability_grants.prepare(spec)
                audit_details = self._grant_audit_details("GRANTED", grant)
            else:
                audit_details = {}
            if not self._audit_security(
                    request, task, authorization, confirmation="GRANTED",
                    **audit_details):
                return ("NOT_AVAILABLE: security audit storage is unavailable; "
                        "the action was not run.")
            if grant is not None:
                self._capability_grants.activate(grant)
            authorized_request = ExecutionRequest(
                action=request.action, arguments=arguments,
                task_id=request.task_id, step=request.step,
                requested_by=request.requested_by, tool_call_id=request.tool_call_id)
            # Confirmation authorizes the attempt, never the outcome. The
            # same Phase 4 reading the direct path takes runs here too, or a
            # confirmed action whose effect was never observed would be
            # recorded as a plain success.
            authorized_handler = self._handler_of(registry, kind, request.action)
            provider = _expectation_provider(authorized_handler)
            precondition = None
            if provider is not None and not (
                    context is not None and context.is_cancelled()):
                try:
                    precondition, _post = provider(arguments, {})
                except Exception:
                    precondition = None
            before_observation = _capture_expectation(precondition, context)
            with authorized_execution(request.action, arguments):
                legacy_text = self._invoke(registry, kind, authorized_request,
                                           context, handler_ctx)
            if isinstance(legacy_text, ExecutionResult):
                status = legacy_text.status
                text = legacy_text.message or "Done."
                error = legacy_text.error
                data = dict(legacy_text.data)
            else:
                status, error, _legacy = classify_legacy_message(legacy_text)
                text = (legacy_text if isinstance(legacy_text, str)
                        and legacy_text.strip() else "Done.")
                data = {}
            if status is ExecStatus.SUCCESS:
                (final, text, error, verified, verification_status,
                 verification_payload) = self._verify(
                    request, task, status, text, error, data, provider,
                    before_observation, context,
                    sensitive=authorization.risk.value in {
                        "SENSITIVE_DATA_ACCESS", "EXTERNAL_COMMUNICATION"})
                if verification_payload is not None:
                    data["verification"] = verification_payload
                    data["verification_status"] = verification_status
                return ExecutionResult(
                    status=status, action=request.action, task_id=request.task_id,
                    message=text, error=error, data=data, verified=verified,
                    verification_status=verification_status,
                    verification=verification_payload, final_status=final)
            return ExecutionResult(status=status, action=request.action,
                                   task_id=request.task_id, message=text,
                                   error=error, data=data)

        # ── permission checking stays, permission asking goes ────────────
        # The decision itself was made before this function was called (see
        # the single-decision block in `_execute`). What remains here is the
        # legacy prompt path, guarded by `prompts_enabled()` at the call site:
        # a banner on the HUD and a wait for a human. It is reachable only
        # when the configuration explicitly turns prompts back on.
        key = f"neo-auth:{request.task_id or uuid.uuid4().hex}:{request.action}"
        message = confirm.request(
            key=key, title=f"Authorize {request.action}",
            detail=confirmation_detail(authorization, arguments),
            run=run_authorized)
        status, error, _legacy = classify_legacy_message(message)
        data = {"invoked": False, "security": authorization.to_dict()}
        if status is ExecStatus.REQUIRES_CONFIRMATION:
            data["confirmation_key"] = self._register_pending(
                request, task, authorization)
            self._audit_security(request, task, authorization,
                                 confirmation="PENDING")
            self._emit(EventType.ACTION_COMPLETED, task, request.action,
                       status=status.value,
                       data={"invoked": False, "authorization": "pending"})
            return self._finish(request, ExecutionResult(
                status=status, action=request.action, task_id=request.task_id,
                message=message, error=error, data=data))

        data["security"]["confirmation"] = "UNAVAILABLE"
        self._audit_security(request, task, authorization,
                             confirmation="UNAVAILABLE")
        self._emit(EventType.ACTION_FAILED, task, request.action,
                   status=ExecStatus.FAILED.value,
                   data={"invoked": False, "authorization": "unavailable"})
        return self._finish(request, ExecutionResult(
            status=ExecStatus.FAILED, action=request.action,
            task_id=request.task_id, message=message, error=error, data=data))

    def _deny_unprompted(self, request: ExecutionRequest, task: Optional[Task],
                         authorization: Authorization,
                         resolution) -> ExecutionResult:
        """Refuse a request the policy does not cover — without asking.

        This is `outOfPolicy` / `unknownPolicy` / untrusted content in the
        configured documents: deny and report. The alternative used to be
        "ask the user", and that option is exactly what has been removed, so
        refusing is the only safe answer left. `resolution` carries the scope
        and behavior from the single decision; `authorization` already carries
        DENY.
        """
        scope = resolution.scope
        behavior = resolution.behavior
        message = (f"Authorization denied for '{request.action}': {scope} under "
                   f"silent policy ({behavior}). NEO does not prompt for approval.")
        denied = ExecutionResult(
            status=ExecStatus.FAILED, action=request.action,
            task_id=request.task_id, message=message,
            error=TaskError(message=message, kind=ErrorKind.AUTHORIZATION_DENIED),
            data={"invoked": False, "security": authorization.to_dict(),
                  "policy": {"scope": scope, "behavior": behavior}})
        # The authorization audit record was already written — once — by the
        # single-decision block in `_execute` before anything else happened.
        # Nothing is re-audited here, so one request is one decision.
        self._emit(EventType.ACTION_FAILED, task, request.action,
                   status=ExecStatus.FAILED.value,
                   data={"invoked": False, "authorization": "denied",
                         "policy_scope": scope})
        return self._finish(request, denied)

    @staticmethod
    def _grant_audit_details(event: str, grant: CapabilityGrant) -> dict:
        """Return privacy-safe grant facts for the durable audit journal."""
        return {
            "grant_event": event,
            "grant_id": grant.grant_id,
            "grant_capability": grant.capability,
            "grant_scope": grant.scope,
            "grant_operation_class": grant.operation_class,
            "grant_expires_at": grant.expires_at,
        }

    def revoke_capability_grants(self, capability: str, scope: str = "") -> int:
        """Immediately remove matching session grants and audit their removal.

        Revocation always removes access, even if the durable journal is
        unavailable. An audit failure can therefore never turn into continued
        capability access.
        """
        revoked = self._capability_grants.revoke(str(capability), str(scope))
        for grant in revoked:
            authorization = Authorization(
                action=grant.action, operation="", risk=grant.risk,
                decision=AuthorizationDecision.ALLOW,
                reason="session capability grant revoked", target_digest="",
            )
            self._audit_security(
                ExecutionRequest(action=grant.action, requested_by="user"), None,
                authorization, **self._grant_audit_details("REVOKED", grant))
        return len(revoked)

    def active_capability_grants(self) -> list[dict]:
        """Return non-sensitive status for the session permission UI/tool."""
        return [{
            "capability": grant.capability,
            "scope": grant.scope,
            "operation_class": grant.operation_class,
            "expires_at": grant.expires_at,
        } for grant in self._capability_grants.active()]

    def _audit_security(self, request: ExecutionRequest, task: Optional[Task],
                        authorization: Authorization,
                        confirmation: str = "", **details) -> bool:
        data = authorization.to_dict()
        data["requested_by"] = request.requested_by
        data["confirmation"] = confirmation
        data.update(details)
        goal_id = str((task.metadata if task else {}).get("goal_id", ""))
        audit_record = {
            "task_id": request.task_id,
            "goal_id": goal_id,
            "step_digest": (request_fingerprint({"step": request.step})
                            if request.step else ""),
            "action": authorization.action,
            "operation": authorization.operation,
            "risk": authorization.risk.value,
            "decision": authorization.decision.value,
            "reason": authorization.reason,
            "target_digest": authorization.target_digest,
            "requested_by": request.requested_by,
            "confirmation": confirmation,
            "execution": details.get("execution", ""),
            "verified": bool(details.get("verified", False)),
            "verification_status": details.get("verification_status", ""),
            "failure_kind": str(details.get("failure_kind", "")),
            "grant_event": str(details.get("grant_event", "")),
            "grant_id": str(details.get("grant_id", "")),
            "grant_capability": str(details.get("grant_capability", "")),
            "grant_scope": str(details.get("grant_scope", "")),
            "grant_operation_class": str(details.get("grant_operation_class", "")),
            "grant_expires_at": float(details.get("grant_expires_at", 0.0) or 0.0),
            "policy_scope": str(details.get("policy_scope", "")),
            "policy_behavior": str(details.get("policy_behavior", "")),
        }
        try:
            self._security_audit_store.append(audit_record)
        except Exception as exc:
            self._logger(f"[Security] audit persistence failed ({type(exc).__name__}).")
            self._notify("Security audit storage is unavailable.")
            return False
        self._bus.emit(Event(
            type=EventType.SECURITY_AUDIT,
            task_id=request.task_id,
            goal_id=goal_id,
            step_id="",
            action=request.action,
            status=authorization.decision.value,
            data=data,
        ))
        return True

    def _register_pending(self, request: ExecutionRequest, task: Optional[Task],
                          authorization: Optional[Authorization] = None) -> str:
        key = confirm.pending_key()
        if not key:
            # Already resolved before we could see it (a sub-second window), or
            # no value was stored. Reported as such rather than assumed.
            self._logger("[Exec] confirmation resolved before it could be tracked")
            return ""
        superseded = None
        if task is not None:
            self._manager.mark_awaiting_confirmation(task.task_id, key, confirm.pending_title())
            with self._lock:
                superseded = self._awaiting.get(key)
                self._awaiting[key] = (task.task_id, request.action, authorization)
        if superseded and superseded[0] != task.task_id:
            # The gate holds exactly one token, so a newer request has already
            # thrown the older one away: that action can never be authorized
            # now. Saying so is the only truthful option — leaving its task
            # RUNNING forever would look like it was still waiting.
            self._logger(f"[Exec] pending authorization for task {superseded[0][:8]} was "
                         f"superseded — closing it")
            self._manager.cancel_task(superseded[0], error=TaskError(
                message=(f"Authorization for '{superseded[1]}' was replaced by a newer "
                         f"confirmation request and can no longer be granted."),
                kind=ErrorKind.AUTHORIZATION_UNAVAILABLE))
        return key

    # -- confirmation outcome -------------------------------------------------

    def _on_confirmation_resolved(self, key: str, accepted: bool, result: str,
                                  error: str) -> None:
        """Called by core/confirm.py after the gate has finished with a token."""
        with self._lock:
            entry = self._awaiting.pop(key, None)
        if entry is None:
            return
        task_id, action, authorization = entry
        manager = self._manager
        if manager is None:
            return
        try:
            task = manager.get_task(task_id)
            if task is None or task.is_terminal:
                self._logger(f"[Exec] confirmation for task {task_id[:8]} arrived after "
                             f"the task had already finished — recording only")
                return
            if not accepted:
                detail = error or "the user did not approve it"
                error_kind = (ErrorKind.AUTHORIZATION_UNAVAILABLE
                              if error and any(word in error.lower()
                                               for word in ("replaced", "expired"))
                              else ErrorKind.AUTHORIZATION_DENIED)
                if authorization is not None:
                    self._audit_security(
                        ExecutionRequest(action=action, task_id=task_id),
                        task, authorization, confirmation="DENIED")
                manager.cancel_task(task_id, error=TaskError(
                    message=f"Authorization for '{action}' was not given ({detail}).",
                    kind=error_kind, detail=error))
                self._emit(EventType.ACTION_COMPLETED, task, action,
                           status=ExecStatus.CANCELLED.value,
                           data={"authorization": "not_granted", "invoked": False})
                return
            if error:
                private = authorization is not None and authorization.risk.value in {
                    "SENSITIVE_DATA_ACCESS", "EXTERNAL_COMMUNICATION"}
                safe_error = ("Sensitive action failure details were withheld from task history."
                              if private else error)
                if authorization is not None:
                    self._audit_security(
                        ExecutionRequest(action=action, task_id=task_id),
                        task, authorization, confirmation="GRANTED",
                        execution=ExecStatus.FAILED.value, verified=False,
                        verification_status="NOT_AVAILABLE",
                        failure_kind="ACTION_FAILED")
                manager.fail_task(
                    task_id,
                    error=f"'{action}' failed after confirmation: {safe_error}",
                    kind=ErrorKind.ACTION_FAILED,
                    detail="" if private else safe_error)
                self._emit(EventType.ACTION_FAILED, task, action,
                           status=ExecStatus.FAILED.value,
                           data={"authorization": "granted", "invoked": True})
                return
            if isinstance(result, ExecutionResult):
                raw_status = result.status
                outcome = result.outcome
                result_error = result.error
                text = result.message or "Done."
                verified = bool(result.verified)
                verification_status = result.verification_status or "NOT_AVAILABLE"
                verification_payload = result.verification
                legacy = False
            else:
                raw_status, result_error, legacy = classify_legacy_message(result)
                outcome = raw_status
                text = result if isinstance(result, str) and result else "Done."
                verified = False
                verification_status = "NOT_AVAILABLE"
                verification_payload = None
            if raw_status is not ExecStatus.SUCCESS:
                if authorization is not None:
                    self._audit_security(
                        ExecutionRequest(action=action, task_id=task_id),
                        task, authorization, confirmation="GRANTED",
                        execution=outcome.value, verified=False,
                        verification_status="NOT_AVAILABLE",
                        failure_kind="ACTION_FAILED")
                task_error = result_error or TaskError(
                    message=f"'{action}' did not complete after authorization: {text}",
                    kind=ErrorKind.ACTION_FAILED)
                if authorization is not None and authorization.risk.value in {
                        "SENSITIVE_DATA_ACCESS", "EXTERNAL_COMMUNICATION"}:
                    task_error = TaskError(
                        message="Sensitive action failure details were withheld from task history.",
                        kind=task_error.kind)
                manager.fail_task(task_id, error=task_error.message,
                                  kind=task_error.kind, detail=task_error.detail)
                self._emit(EventType.ACTION_FAILED, task, action,
                           status=outcome.value,
                           data={"authorization": "granted", "invoked": True})
                return
            if authorization is not None:
                self._audit_security(
                    ExecutionRequest(action=action, task_id=task_id),
                    task, authorization, confirmation="GRANTED",
                    execution=outcome.value, verified=verified,
                    verification_status=verification_status, failure_kind="")
            if task.status is TaskStatus.PAUSED:      # never fabricate a stopped action
                manager.resume_task(task_id)
            # A handler that answers through the gate may return the structured
            # contract rather than a sentence (Phase 3's Windows control does).
            # What belongs in a task record is the sentence, not a repr.
            sensitive_risk = (authorization is not None
                              and authorization.risk.value in {
                                  "SENSITIVE_DATA_ACCESS", "EXTERNAL_COMMUNICATION"})
            history_text = (text if not sensitive_risk
                            else "Sensitive action result withheld from task history.")
            manager.record_result(task_id, {
                "status": raw_status.value, "action": action,
                "task_id": task_id, "message": history_text,
                "error": None, "verified": verified,
                "verification_status": verification_status,
                "verification": None if sensitive_risk else verification_payload,
                "final_status": outcome.value,
                "data": {"invoked": True, "authorization": "granted",
                         "legacy_message": legacy,
                         "security": authorization.to_dict()
                         if authorization is not None else None},
            })
            manager.complete_task(task_id, result=history_text)
            self._emit(EventType.ACTION_COMPLETED, task, action,
                       status=outcome.value,
                       data={"authorization": "granted", "invoked": True})

        except TaskStateError as e:
            self._logger(f"[Exec] confirmation could not update task {task_id[:8]} "
                         f"({type(e).__name__}).")
        except Exception as e:
            self._logger(
                f"[Exec] confirmation handling failed for {action} "
                f"({type(e).__name__}).")

    # -- task bookkeeping -----------------------------------------------------

    def _finish(self, request: ExecutionRequest, result: ExecutionResult) -> ExecutionResult:
        history_result = self._history_safe_result(result)
        self._record(request, history_result)
        self._apply_to_task(request, history_result)
        return result

    @staticmethod
    def _history_safe_result(result: ExecutionResult) -> ExecutionResult:
        security = result.data.get("security", {})
        if security.get("risk") not in {
                "SENSITIVE_DATA_ACCESS", "EXTERNAL_COMMUNICATION"}:
            return result
        safe_data = {
            key: result.data[key]
            for key in ("invoked", "registry", "legacy_message", "interruptible",
                        "security", "confirmation_key", "completed_after_cancellation")
            if key in result.data
        }
        safe_data["sensitive_result_redacted"] = True
        safe_data.pop("verification", None)
        if "verification_status" in safe_data:
            safe_data["verification_status"] = "REDACTED"
        safe_error = (TaskError(
            message="Sensitive action details were withheld from task history.",
            kind=result.error.kind)
            if result.error else None)
        return ExecutionResult(
            status=result.status, action=result.action, task_id=result.task_id,
            message="Sensitive action result withheld from task history.",
            data=safe_data, error=safe_error, verified=result.verified,
            verification_status="REDACTED" if result.verification else result.verification_status,
            verification=None, final_status=result.final_status)

    def _record(self, request: ExecutionRequest, result: ExecutionResult) -> None:
        manager = self._manager
        task_id = result.task_id or (request.task_id if isinstance(request, ExecutionRequest) else "")
        if manager is None or not task_id:
            return
        try:
            manager.record_result(task_id, result.to_dict())
        except Exception as e:
            self._logger(f"[Exec] could not record result for {task_id[:8]} "
                         f"({type(e).__name__}).")

    def _apply_to_task(self, request: ExecutionRequest, result: ExecutionResult) -> None:
        """Move the task to the state its real result implies."""
        manager = self._manager
        if manager is None or not result.task_id:
            return
        try:
            task = manager.get_task(result.task_id)
            if task is None or task.is_terminal:
                return
            if result.status is ExecStatus.SUCCESS:
                if task.status is TaskStatus.PAUSED:
                    manager.resume_task(task.task_id)
                manager.complete_task(task.task_id, result=result.message)
            elif result.status is ExecStatus.CANCELLED:
                manager.cancel_task(task.task_id, error=result.error)
            elif result.status is ExecStatus.REQUIRES_CONFIRMATION:
                pass                    # stays RUNNING; the gate will close it
            else:
                if task.status is TaskStatus.PAUSED:
                    manager.resume_task(task.task_id)
                manager.fail_task(task.task_id,
                                  error=result.error or TaskError(
                                      message=result.message,
                                      kind=ErrorKind.ACTION_FAILED))
        except TaskStateError as e:
            # The task moved underneath us (a cancel or a manual finish). The
            # execution result is still returned and recorded; the state change
            # is refused rather than forced.
            self._logger(f"[Exec] task state refused the result "
                         f"({type(e).__name__}).")
        except Exception as e:
            self._logger(f"[Exec] could not update task state "
                         f"({type(e).__name__}).")

    def _emit(self, kind: EventType, task: Optional[Task], action: str,
              status: str = "", data: Optional[dict] = None) -> None:
        self._bus.emit(Event(type=kind, task_id=task.task_id if task else "",
                             action=action, status=status, data=dict(data or {})))
