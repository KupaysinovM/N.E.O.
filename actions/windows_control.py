"""
Windows desktop control, routed through NEO's Phase 2 task/execution core.

This action owns no Windows knowledge. It maps a model request onto one call of
the façade in core/windows/control.py, converts the result into a structured
`ExecutionResult`, and lets the execution layer write that result onto the task
and emit the lifecycle events. Every operation therefore appears in task history
with a status that reflects what Windows actually reported.

    Task → ExecutionRequest → ExecutionLayer → windows_control → Windows façade
         → real Windows call → ExecutionResult → task state + events

WHY IT IS NOT A SHELL
    There is no `run_command`, no shell string, and no path from a model's text
    to a command line. Applications are resolved through an allowlist and
    started as an executable with no interpretation step; key presses come from
    a fixed vocabulary; coordinates are bounds-checked.

WHAT THE RESULT MAY SAY
    "Invoke() returned on button X" — never "the button was pressed and the
    application responded". The execution layer applies this action's fixed
    verification expectations where available; unsupported observations stay
    unverified.

CONFIRMATION
    Closing an application is the one operation here that can destroy unsaved
    work, so the central execution policy requires UI confirmation before
    dispatch. The action also checks the exact-request execution receipt as
    defense in depth.
"""
from __future__ import annotations

from core import confirm
from core.security import authorized_execution, is_authorized_execution
from core.execution import ExecStatus, ExecutionResult
from core.task_models import ErrorKind, TaskError
from core.verification import expectations as _expectations
from core.windows import control
from core.windows.errors import WindowsError, to_error_kind

# The action name is a prefix so a model asking for desktop control does not
# have to choose between twenty similarly-named tools; `operation` picks what
# actually happens.
OPERATIONS = control.OPERATIONS


def expectation_for(params: dict, result_data: dict):
    """This action's verification contract (Phase 4).

    The execution layer looks for this function and, when it is here, checks
    the machine afterwards. It is code, not a model instruction: a caller
    chooses `focus_window`, and which fact has to be true afterwards is decided
    here, in Python, from a fixed vocabulary. An operation with no observable
    consequence returns `None`, which the layer reports as NOT_AVAILABLE rather
    than treating as a pass.

    Returns `(precondition, expectation)`. The precondition is captured before
    the action runs, which is what makes "this toggle actually changed" a
    question with an answer.
    """
    operation = str((params or {}).get("operation", "")).strip().lower()

    class _Result:                      # the façade result's shape, read-only
        data = result_data or {}

    return (_expectations.preconditions(operation, params or {}),
            _expectations.expected_after(operation, params or {}, _Result()))


def _result_from(result: control.WindowsResult) -> ExecutionResult:
    """A façade result → the Phase 2 execution contract.

    The Windows error kind rides along in `data["windows_error_kind"]` while the
    shared `ErrorKind` taxonomy carries the meaning for everything upstream.
    """
    status_map = {
        "SUCCESS": ExecStatus.SUCCESS,
        "FAILED": ExecStatus.FAILED,
        "NOT_AVAILABLE": ExecStatus.NOT_AVAILABLE,
        "NOT_SUPPORTED": ExecStatus.NOT_SUPPORTED,
        "CANCELLED": ExecStatus.CANCELLED,
        "REQUIRES_CONFIRMATION": ExecStatus.REQUIRES_CONFIRMATION,
    }
    data = dict(result.data)
    data["windows_operation"] = result.operation
    data["target"] = result.target
    data["duration_seconds"] = result.duration
    data["windows_status"] = result.status
    if result.error is not None:
        data["windows_error_kind"] = result.error.kind
    return ExecutionResult(
        status=status_map.get(result.status, ExecStatus.FAILED),
        action="windows_control",
        task_id="",
        message=result.message or result.status,
        data=data,
        error=(TaskError(message=result.message, kind=to_error_kind(result.error.kind),
                         detail=result.error.detail)
               if result.error is not None else None),
    )


def _summarize_for_model(result: control.WindowsResult, limit: int = 12) -> str:
    """A bounded, honest text answer for the model.

    Control and window lists are summarised rather than pasted in full: the
    structured copy is already on the task, and a 300-element dump here would
    crowd out the conversation it is supposed to serve.
    """
    if result.status != "SUCCESS":
        return result.message

    data = result.data
    if "windows" in data:
        lines = [f"{len(data.get('windows', []))} window(s)"]
        for window in data.get("windows", [])[:limit]:
            lines.append(f"  - '{window.get('title', '')}' "
                         f"(pid {window.get('process_id')}, "
                         f"{window.get('process_name') or 'unknown process'})")
        if data.get("truncated"):
            lines.append(f"  … and {data.get('total_found', 0) - limit} more")
        return "\n".join(lines)

    if "controls" in data:
        lines = [data.get("summary") or data.get("message", "")]
        for control_item in data.get("controls", [])[:limit]:
            flags = []
            if control_item.get("enabled") is False:
                flags.append("disabled")
            if control_item.get("offscreen"):
                flags.append("offscreen")
            if control_item.get("sensitive"):
                flags.append("credential field — value withheld")
            suffix = f" [{', '.join(flags)}]" if flags else ""
            capabilities = ",".join(control_item.get("capabilities", [])[:5])
            lines.append(f"  - {control_item.get('control_type')} "
                         f"'{control_item.get('name') or control_item.get('automation_id') or ''}'"
                         f"{suffix}" + (f" patterns: {capabilities}"
                                        if capabilities else ""))
        if data.get("ambiguous"):
            lines.append(f"  ({data.get('total_found', 0)} control(s) match; more "
                         f"than one matches equally well, so an index is needed)")
        return "\n".join(lines)

    if "grouped" in data:
        # Phase 6: the structured summary is the whole point of describe_controls.
        return str(data.get("summary") or data.get("message", ""))

    if "written" in data:
        if not data.get("written"):
            return str(data.get("message") or data.get("refused")
                       or "Nothing was typed.")
        state = {True: "the text was read back and matches",
                 False: "the text was NOT read back matching — treat this as unverified",
                 None: "the value could not be read back"}[data.get("read_back_matches")]
        return (f"{data.get('message', '')} — {state}.")

    if "detection" in data:
        caveats = data.get("caveats") or []
        lines = [str(data.get("message", ""))]
        lines += [f"  note: {c}" for c in caveats[:3]]
        return "\n".join(lines)

    if "kind" in data and "may_act" in data:
        lines = [str(data.get("message", ""))]
        if data.get("buttons"):
            lines.append("  buttons: " + ", ".join(data["buttons"][:6]))
        return "\n".join(lines)

    if "candidates" in data and "resolved" in data:
        lines = [str(data.get("message", ""))]
        for candidate in data.get("candidates", [])[:5]:
            window = candidate.get("window", {})
            lines.append(f"  candidate (score {candidate.get('score')}): "
                         f"'{window.get('title')}' pid {window.get('process_id')}")
        return "\n".join(lines)

    if "processes" in data:
        lines = [data.get("message", "")]
        for process in data.get("processes", [])[:limit]:
            lines.append(f"  - {process.get('name')} (pid {process.get('pid')})")
        return "\n".join(lines)

    return result.message


def windows_control(
    parameters: dict = None,
    response=None,
    player=None,
    session_memory=None,
    cancel_event=None,
) -> ExecutionResult:
    """Act on the real Windows desktop through structured UI Automation.

    parameters:
      operation        : what to do (see TOOL['parameters'])
      title            : window title substring (defaults to the active window)
      process_id       : window/process to target
      window_handle    : exact window handle, when the caller has one
      element_name     : visible name of a control
      automation_id    : stable id of a control (preferred over name)
      control_type     : Button | Edit | MenuItem | TabItem | …
      index            : which candidate, when a query matches several
      text             : text for set_value / type_text
      keys             : key or combination, e.g. 'ctrl+a'
      x, y             : screen coordinates
      amount, direction: scroll amount and direction
      state            : minimize | maximize | restore | normal
      app_name         : application to launch or check
      name             : process name filter
      limit, max_depth : discovery bounds
    """
    params = dict(parameters or {})
    operation = str(params.get("operation", "")).strip().lower()
    action_fn = OPERATIONS.get(operation)

    if not operation:
        return ExecutionResult(
            status=ExecStatus.FAILED, action="windows_control",
            message="No Windows operation was named.",
            error=TaskError(message="operation is required.",
                            kind=ErrorKind.INVALID_REQUEST),
            data={"invoked": False})

    if action_fn is None:
        return ExecutionResult(
            status=ExecStatus.NOT_SUPPORTED, action="windows_control",
            message=(f"'{operation}' is not a Windows control operation. "
                     f"Supported: {', '.join(sorted(OPERATIONS))}."),
            error=TaskError(message=f"Unknown Windows operation '{operation}'.",
                            kind=ErrorKind.ACTION_NOT_SUPPORTED),
            data={"invoked": False, "available_operations": sorted(OPERATIONS)})

    if player:
        try:
            player.write_log(f"[Windows] {operation}")
        except Exception:
            pass

    # Closing an application is the one operation here that can lose unsaved
    # work. The gate is Phase 2's, unchanged; NEO asks the user out loud rather
    # than deciding for them.
    if operation in control.CONFIRMATION_REQUIRED:
        target = params.get("title") or params.get("app_name") or "this window"
        if not is_authorized_execution("windows_control", params):
            def _run_after_confirmation():
                with authorized_execution("windows_control", params):
                    return windows_control(params, player=player,
                                          cancel_event=cancel_event)

            parked = confirm.request(
                key=f"windows:{operation}", title=f"Close '{target}'?",
                detail=(f"NEO wants to close '{target}'. If it has unsaved work, "
                        f"Windows will ask it what to do."),
                run=_run_after_confirmation)
            if parked.startswith("[CONFIRMATION_PENDING]"):
                return _result_from(control.WindowsResult(
                    operation=operation, status="REQUIRES_CONFIRMATION", target=str(target),
                    message=parked,
                    data={"invoked": False, "awaiting_confirmation": True}))

            # The gate could not ask — no interface is bound, or showing the
            # banner failed. Nothing is waiting on the user, so this has to end
            # here: a task parked for a confirmation that can never arrive would
            # stay RUNNING for the rest of the session. The action was refused,
            # and saying so is the honest result.
            return ExecutionResult(
                status=ExecStatus.FAILED, action="windows_control",
                message=parked,
                error=TaskError(message="Confirmation was required but unavailable.",
                                kind=ErrorKind.AUTHORIZATION_UNAVAILABLE),
                data={"invoked": False, "awaiting_confirmation": False,
                      "windows_operation": operation, "target": str(target)})

    try:
        result = _invoke(operation, action_fn, params, cancel_event)
    except WindowsError as e:
        return _result_from(control.WindowsResult(
            operation=operation, status="FAILED", target="", message=e.message,
            error=e, data={"invoked": False}))
    except Exception as e:                       # a façade bug must not end the session
        from core.windows.errors import os_error
        return _result_from(control.WindowsResult(
            operation=operation, status="FAILED", target="",
            message=f"The Windows operation failed: {e}",
            error=os_error("Unexpected failure in the Windows control façade.", str(e)),
            data={"invoked": False}))

    if result.status == "SUCCESS" and player:
        try:
            player.write_log(f"[Windows] {result.message}")
        except Exception:
            pass

    structured = _result_from(result)
    structured.message = _summarize_for_model(result)
    structured.data["reported_message"] = result.message
    return structured


def _invoke(operation: str, action_fn, params: dict, cancel_event):
    """Call the façade with only the arguments that operation takes.

    Every operation is wrapped in control._run, which records timings and maps
    failures onto the shared taxonomy — so the action does not repeat that.
    """
    if operation in ("list_windows",):
        return action_fn(title=params.get("title", ""),
                         include_untitled=bool(params.get("include_untitled")),
                         limit=params.get("limit", control.DEFAULT_WINDOW_LIMIT),
                         cancel_event=cancel_event)
    if operation == "active_window":
        return action_fn(cancel_event=cancel_event)
    if operation in ("locate_window", "focus_window", "window_state", "close_window"):
        if operation == "window_state":
            return action_fn(state=params.get("state", "restore"), **_window_args(params),
                             cancel_event=cancel_event)
        return action_fn(**_window_args(params), cancel_event=cancel_event)
    if operation == "resolve_window":
        # Phase 6. The parameters dict is passed whole because targeting reads
        # app_name/class_name/index as well as the window selectors.
        return action_fn(params, cancel_event=cancel_event)
    if operation in ("list_controls", "find_control", "find_controls",
                     "describe_controls"):
        if operation in ("find_control", "find_controls"):
            return action_fn(_control_args(params), **_window_args(params),
                             limit=params.get("limit", control.DEFAULT_CONTROL_LIMIT),
                             max_depth=params.get("max_depth", control.MAX_DEPTH),
                             visible_only=bool(params.get("visible_only")),
                             cancel_event=cancel_event)
        if operation == "describe_controls":
            return action_fn(limit=params.get("limit", 120),
                             max_depth=params.get("max_depth", control.MAX_DEPTH),
                             interactive_only=params.get("interactive_only", True),
                             visible_only=bool(params.get("visible_only")),
                             **_window_args(params), cancel_event=cancel_event)
        return action_fn(control_type=params.get("control_type", ""),
                         limit=params.get("limit", control.DEFAULT_CONTROL_LIMIT),
                         max_depth=params.get("max_depth", control.MAX_DEPTH),visible_only=bool(params.get("visible_only")),
                          named_only=bool(params.get("named_only")),
                          **_window_args(params), cancel_event=cancel_event)
    if operation in ("invoke", "toggle", "select", "expand", "collapse",
                     "focus_control", "set_value", "get_value", "type_into"):
        return action_fn(_control_args(params), cancel_event=cancel_event)
    if operation in ("list_controls", "find_control"):
        if operation == "find_control":
            return action_fn(_control_args(params), **_window_args(params),
                             cancel_event=cancel_event)
        return action_fn(control_type=params.get("control_type", ""),
                         limit=params.get("limit", control.DEFAULT_CONTROL_LIMIT),
                         max_depth=params.get("max_depth", control.MAX_DEPTH),visible_only=bool(params.get("visible_only")),
                          named_only=bool(params.get("named_only")),
                          **_window_args(params), cancel_event=cancel_event)
    if operation in ("invoke", "toggle", "select", "expand", "collapse",
                     "focus_control", "set_value", "get_value"):
        return action_fn(_control_args(params), cancel_event=cancel_event)
    if operation == "press_keys":
        return action_fn(params.get("keys", ""), cancel_event=cancel_event,
                         sensitive_target=bool(params.get("sensitive_target")),
                         target=params.get("element_name") or "the focused control")
    if operation == "type_text":
        return action_fn(params.get("text", ""), cancel_event=cancel_event,
                         sensitive_target=bool(params.get("sensitive_target")),
                         target=params.get("element_name") or "the focused control",
                         via_clipboard=bool(params.get("via_clipboard")))
    if operation == "click":
        return action_fn(params.get("x", 0), params.get("y", 0),
                         button=params.get("button", "left"),
                         clicks=params.get("clicks", 1), cancel_event=cancel_event)
    if operation == "move_mouse":
        return action_fn(params.get("x", 0), params.get("y", 0), cancel_event=cancel_event)
    if operation == "scroll":
        return action_fn(amount=params.get("amount", 3),
                         direction=params.get("direction", "down"), cancel_event=cancel_event)
    if operation == "drag":
        return action_fn(params.get("x1", 0), params.get("y1", 0),
                         params.get("x2", 0), params.get("y2", 0), cancel_event=cancel_event)
    if operation == "cursor_position":
        return action_fn(cancel_event=cancel_event)
    if operation == "launch_app":
        return action_fn(params.get("app_name", ""), cancel_event=cancel_event,
                         wait_for_window=params.get("wait_for_window", True))
    if operation == "app_running":
        return action_fn(params.get("app_name", ""), cancel_event=cancel_event)
    if operation == "list_processes":
        return action_fn(name_contains=params.get("name", ""),
                         limit=params.get("limit", 40), cancel_event=cancel_event)
    if operation == "process_info":
        return action_fn(params.get("pid", 0), cancel_event=cancel_event)
    if operation in ("classify_dialog", "dismiss_dialog"):
        return action_fn(params, cancel_event=cancel_event)
    if operation == "desktop_snapshot":
        return action_fn(max_windows=params.get("limit", 8),
                         max_controls=params.get("limit", 40),
                         include_controls=not params.get("skip_controls"),
                         cancel_event=cancel_event)
    raise ValueError(f"No façade call is defined for '{operation}'.")


def _window_args(params: dict) -> dict:
    args = {"title": params.get("title", "")}
    if params.get("process_id"):
        args["process_id"] = params["process_id"]
    if params.get("window_handle"):
        args["window_handle"] = params["window_handle"]
    return args


def _control_args(params: dict) -> dict:
    args = dict(params)
    if params.get("element_name"):
        args["element_name"] = params["element_name"]
    args["max_depth"] = params.get("max_depth", control.MAX_DEPTH)
    return args


# ── Tool declaration (auto-discovered by core/action_loader.py) ──────────────
TOOL = {
    "name": "windows_control",
    "description": (
        "Control the real Windows desktop through structured UI Automation: "
        "list and inspect windows, read a window's controls with their names, "
        "types and capabilities, and act on them through real automation "
        "patterns (invoke a button, toggle a checkbox, select a tab, set a "
        "field's text, open a menu). Prefer this over clicking coordinates: it "
        "finds controls by name, reports exactly which control it acted on, and "
        "says so when a target is missing, ambiguous or unsupported. "
        "Coordinates and key presses are available as fallbacks for applications "
        "that expose no accessibility information."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "operation": {
                "type": "STRING",
                "description": (
                    "list_windows | active_window | locate_window | resolve_window | "
                    "focus_window | window_state | close_window | list_controls | "
                    "find_control | find_controls | describe_controls | "
                    "invoke | toggle | select | expand | collapse | focus_control | "
                    "set_value | get_value | type_into | press_keys | type_text | "
                    "click | move_mouse | scroll | drag | cursor_position | "
                    "launch_app | app_running | list_processes | process_info | "
                    "classify_dialog | dismiss_dialog | desktop_snapshot"
                ),
            },
            "title": {
                "type": "STRING",
                "description": "Substring of the window title. Defaults to the active window.",
            },
            "process_id": {
                "type": "INTEGER",
                "description": "Target a window owned by this process id.",
            },
            "window_handle": {
                "type": "INTEGER",
                "description": "Target an exact window handle when one is known.",
            },
            "element_name": {
                "type": "STRING",
                "description": "Visible name of the control, e.g. 'Save' or 'File'.",
            },
            "automation_id": {
                "type": "STRING",
                "description": "Stable control id. Preferred: unlike a name it is not duplicated.",
            },
            "control_type": {
                "type": "STRING",
                "description": (
                    "Restrict the search to one control type: Button | CheckBox | "
                    "Edit | MenuItem | TabItem | ComboBox | ListItem | Text | TreeItem"
                ),
            },
            "index": {
                "type": "INTEGER",
                "description": (
                    "Which candidate to use when several match. Without it NEO "
                    "refuses to guess between them."
                ),
            },
            "text": {"type": "STRING", "description": "Text for set_value or type_text."},
            "replace": {
                "type": "BOOLEAN",
                "description": "For type_into: clear the field before writing.",
            },
            "method": {
                "type": "STRING",
                "description": ("For type_into: value_pattern | keyboard | "
                                "clipboard. Left out, the control's own "
                                "capability decides."),
            },
            "class_name": {
                "type": "STRING",
                "description": "Window class to match, e.g. 'Notepad'.",
            },
            "wait_for_window": {
                "type": "BOOLEAN",
                "description": ("For launch_app: briefly follow a Windows app "
                                "hand-off to find the window that really opened."),
            },
            "keys": {
                "type": "STRING",
                "description": "Key or combination, e.g. 'ctrl+a', 'enter', 'f5'.",
            },
            "x": {"type": "INTEGER", "description": "Screen X coordinate."},
            "y": {"type": "INTEGER", "description": "Screen Y coordinate."},
            "x1": {"type": "INTEGER", "description": "Drag start X."},
            "y1": {"type": "INTEGER", "description": "Drag start Y."},
            "x2": {"type": "INTEGER", "description": "Drag end X."},
            "y2": {"type": "INTEGER", "description": "Drag end Y."},
            "button": {"type": "STRING", "description": "left | right | middle."},
            "clicks": {"type": "INTEGER", "description": "1–3."},
            "amount": {"type": "INTEGER", "description": "Scroll amount."},
            "direction": {"type": "STRING", "description": "up | down | left | right."},
            "state": {
                "type": "STRING",
                "description": "Window state for window_state: minimize | maximize | restore | normal.",
            },
            "app_name": {"type": "STRING", "description": "Application to launch or check."},
            "name": {"type": "STRING", "description": "Process-name filter."},
            "pid": {"type": "INTEGER", "description": "Process id for process_info."},
            "limit": {"type": "INTEGER", "description": "Maximum results (bounded)."},
            "max_depth": {"type": "INTEGER", "description": "How deep to walk the control tree."},
            "visible_only": {"type": "BOOLEAN", "description": "Only visible controls."},
            "named_only": {"type": "BOOLEAN",
                           "description": ("Skip unnamed layout/decoration controls.")},
            "include_untitled": {"type": "BOOLEAN", "description": "Include windows with no title."},
            "via_clipboard": {"type": "BOOLEAN", "description": "Type through the clipboard."},
        },
        "required": ["operation"],
    },
    "behavior": "NON_BLOCKING",
    "scheduling": "WHEN_IDLE",
    "handler": windows_control,
}