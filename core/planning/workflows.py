"""
Multi-capability workflows — the recipes that make NEO useful rather than correct.

WHY RECIPES AND NOT A PLANNER
    Four things come up every day: open something and type into it, open a
    browser and search, find a file and open it, open a calculator and work
    something out. A general planner can usually derive them, but "usually" is
    not what an assistant needs for the requests it hears most often — and
    every one of them needs a detail a general planner would have to *know*
    rather than infer: which window handle to carry forward, which control type
    an editor publishes, when a handle may have moved under it.

    So these are recipes. They return raw step dicts, which go through
    `Planner.build()` exactly like any other plan. They get no privilege, they
    cannot name an unregistered capability, and a recipe that references a
    capability this machine does not have is refused like any other plan.

WHAT IS HERE AND WHAT IS NOT
    Workflow A (open and type), B (open a browser and search), C (find a file
    and open it) and D (calculate) are implemented, because every step in them
    is a capability that exists and can be verified.

    Nothing else is. A recipe that needed a capability NEO does not have would
    be a promise the executor could not keep, and the honest response to a
    request like that is the refusal path in `ModelPlanner`, not a workflow that
    half-works.

THE ONE INTERESTING RECIPE
    Calculator is Workflow D, and it is the honest example of what Phase 4 is
    for. The visible digits are a `Text` control whose value is the whole
    expression, so "123 × 456" is entered and then *read back* — the result is
    observed, not assumed, and a Calculator build that lays out its display
    differently fails as NOT_VERIFIED rather than as a wrong answer.
"""
from __future__ import annotations

from typing import Callable, Optional

from core.goals.planner import PlanRejected
from core.planning import intent as _intent

#: A recipe turns its parameters into raw step dicts.
Builder = Callable[[dict], list]


# ── Workflow A: open an app and put text in it ─────────────────────────────

def open_and_type(params: dict) -> list:
    app = str(params.get("app_name", "")).strip()
    text = str(params.get("text", ""))
    if not app:
        raise PlanRejected("which application should NEO open?")
    steps = [{"id": "open", "description": f"Open {app}",
              "action": "windows_control",
              "arguments": {"operation": "launch_app", "app_name": app}}]
    if not text:
        # "Open Notepad" is one step. Planning a text entry for a request that
        # carried no text would run an operation guaranteed to do nothing, and
        # then report the failure as if the user's request had failed.
        return steps
    steps.append(
        {"id": "type", "description": f"Enter {len(text)} characters into {app}",
         "action": "windows_control", "depends_on": ["open"],
         "arguments": {"operation": "type_into",
                       "window_handle": {"$from": "step:open.handle"},
                       "control_type": str(params.get("control_type", "Document")),
                       "text": text,
                       "replace": bool(params.get("replace", True))},
         # A single-instance Windows app (Notepad) replaces its own window
         # mid-session, so the handle the launch reported can already be stale
         # when this step runs. One bounded re-location is the supported
         # recovery — the same window, found again, never a different one.
         "re_resolve": True,
         "retry": {"attempts": 2, "delay": 0.25, "on": "transient",
                   "reason": "the editor may not publish its text area the "
                             "instant the window appears"}})
    return steps


# ── Workflow B: open a browser and search ──────────────────────────────────

def browser_search(params: dict) -> list:
    browser = str(params.get("app_name", "") or "firefox").strip()
    query = str(params.get("query", "")).strip()
    if not query:
        raise PlanRejected("what should NEO search for?")
    return [
        {"id": "open", "description": f"Open {browser}",
         "action": "windows_control",
         "arguments": {"operation": "launch_app", "app_name": browser}},
        {"id": "search", "description": f"Search for '{query}'",
         "action": "web_search", "depends_on": ["open"],
         "arguments": {"query": query}},
    ]


# ── Workflow C: find a file and open it ────────────────────────────────────

def open_recent_file(params: dict) -> list:
    """Find a file by name, then hand it to the OS default handler.

    The selection step is where this workflow can honestly go wrong, and it is
    written so that it goes wrong visibly: `file_controller`'s search returns
    prose, so this recipe only runs when the caller already knows the path. A
    request phrased as "the file I worked on today" needs observation and a
    disambiguation step that Phase 6 does not have a capability for, and the
    planner refuses it rather than opening the wrong one.
    """
    path = str(params.get("path", "")).strip()
    if not path:
        raise PlanRejected("which file should NEO open? NEO needs the file's path "
                           "rather than a description of it.")
    return [
        {"id": "open", "description": f"Open {path}",
         "action": "open_app",
         "arguments": {"app_name": path}},
    ]


# ── Workflow D: calculate ───────────────────────────────────────────────────

def calculate(params: dict) -> list:
    expression = str(params.get("expression", "")).strip()
    if not expression:
        raise PlanRejected("what should NEO calculate?")
    return [
        {"id": "open", "description": "Open Calculator",
         "action": "windows_control",
         "arguments": {"operation": "launch_app", "app_name": "calculator"}},
        {"id": "calc", "description": f"Calculate {expression}",
         "action": "windows_control", "depends_on": ["open"],
         "arguments": {"operation": "type_into",
                       "window_handle": {"$from": "step:open.handle"},
                       "control_type": "Text",
                       "text": expression},
         "re_resolve": True,
         # Two attempts, not three: a calculator that did not take the text the
         # first time will not take it the third, and a bounded failure with a
         # reason beats a longer one without.
         "retry": {"attempts": 2, "delay": 0.5, "on": "transient",
                   "reason": "Calculator's display publishes a moment after the "
                             "window opens"}},
    ]


# ── the recipe table ────────────────────────────────────────────────────────

WORKFLOWS: dict = {
    "open_and_type": open_and_type,
    "browser_search": browser_search,
    "open_recent_file": open_recent_file,
    "calculate": calculate,
}


def names() -> list:
    return sorted(WORKFLOWS)


def steps_for_intent(parsed: _intent.Intent) -> Optional[list]:
    """The steps for an intent, or `None` when no recipe covers it.

    `None` is the important return value: it is what tells `ModelPlanner` that
    the deterministic route has nothing to offer and that the bounded proposer
    is warranted. It is never an empty list, which would read as "here is a
    plan with no steps" — a different and much less honest thing.

    Order matters here and is by *specificity*, not by cue position: an
    arithmetic expression is a stronger signal than "open", and a quoted string
    is a stronger signal than a bare application name.
    """
    slots = parsed.slots
    if parsed.kind in (_intent.CALCULATE, _intent.OPEN_APP, _intent.WRITE_TEXT) \
            and slots.get("expression"):
        return calculate({"expression": slots["expression"]})
    if "app_name" in slots and (parsed.kind in (_intent.OPEN_APP,
                                                _intent.WRITE_TEXT)):
        return open_and_type({"app_name": slots["app_name"],
                              "text": slots.get("text", "")})
    if parsed.kind == _intent.SEARCH_WEB and slots.get("query"):
        return browser_search({"query": slots["query"],
                               "app_name": slots.get("browser", "firefox")})
    if parsed.kind == _intent.FOCUS_WINDOW and "app_name" in slots:
        return [{"id": "focus", "description":
                 f"Bring {parsed.slots['app_name']} to the front",
                 "action": "windows_control",
                 "arguments": {"operation": "focus_window",
                               "title": parsed.slots["app_name"]},
                 "re_resolve": True,
                 "retry": {"attempts": 2, "delay": 0.25, "on": "transient",
                           "reason": "Windows refuses activation while the user "
                                     "is working elsewhere"}}]
    if parsed.kind == _intent.CLOSE_WINDOW and "app_name" in parsed.slots:
        return [{"id": "close", "description":
                 f"Close {parsed.slots['app_name']}",
                 "action": "windows_control",
                 "arguments": {"operation": "close_window",
                               "title": parsed.slots["app_name"]}}]
    return None


def describe() -> dict:
    """What this module can do, for documentation and for a planner prompt."""
    return {"workflows": names(),
            "uses_only_registered_capabilities": True,
            "notes": {
                "open_and_type": "launch_app then type_into, with the window "
                                 "handle carried forward and one bounded "
                                 "re-location for single-instance apps",
                "browser_search": "launch_app then web_search",
                "open_recent_file": "open_app on a path the caller already knows; "
                                    "NEO does not guess which file 'the one I "
                                    "worked on today' refers to",
                "calculate": "launch_app then type_into, with the display read "
                             "back by Phase 4 verification",
            }}