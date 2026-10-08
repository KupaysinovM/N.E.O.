"""
The inherited Mark-LV capabilities, audited — and the one way to reach them.

WHAT THIS FILE IS
    Phase 6 inherited roughly ten thousand lines of working capability code in
    `actions/` and `plugins/`. Most of it is good. Some of it is dangerous. A
    little of it is dead. The first job here is to say which is which, honestly
    and in a file rather than in a conversation; the second is to give the goal
    layer a bounded, structured way to *know what exists* without reaching into
    the registries' internals.

    It is emphatically NOT a second action registry. There is one registry —
    `ActionRegistry` in core/action_loader.py, `PluginRegistry` in
    core/plugin_loader.py — and `ExecutionLayer` is the only thing that
    dispatches through it. Everything here is read-only metadata plus a
    catalogue function; nothing here can run a handler.

THE SIX VERDICTS
    `EXISTING_WORKING`
        Registered, no confirmation gate needed, and either declares a
        verification contract or has no observable consequence to verify.
    `EXISTING_NEEDS_REPAIR`
        Registered and callable, but with a defect that makes its result
        untrustworthy — a subprocess path, an unbounded loop, a prompt for
        text where a structured call belongs.
    `EXISTING_NEEDS_INTEGRATION`
        Real and safe, but not yet reachable as a *plan step*: it is not in the
        goal vocabulary, or its result is a sentence where the goal layer needs
        structured data.
    `UNSAFE`
        Must not be reachable from a model-derived plan at all. This is not a
        judgement about the code being bad — it is about what the model should
        be able to reach without a human in the loop.
    `UNSUPPORTED`
        Declared by the project but not implemented on this machine (a
        dependency is absent, or the platform does not support it).
    `DEAD`
        Present in the tree, unreachable, or superseded. Documented so it is
        not rediscovered as if it were new.

WHY UNSAFE IS A VERDICT ABOUT *REACHABILITY*
    `desktop_control` still contains the shell of a feature that once asked a
    model to write Python and ran it. That code is gone — Phase 1 removed it
    and the removal is not optional to undo — but the module still refuses the
    request explicitly, which is the right behaviour and worth keeping. It is
    marked UNSAFE because a planner must never route to it for a *new*
    capability, and because a reader of this file should know the hazard exists
    in this area of the tree.

THE ONE RULE THIS ENFORCES
    A model-derived plan may name anything registered, except anything marked
    UNSAFE. That is enforced in `core/planning/`, and it is enforced against
    this table rather than against the model's opinion.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

#: The six verdicts, as plain strings so they survive JSON without an enum.
EXISTING_WORKING = "EXISTING + WORKING"
EXISTING_NEEDS_REPAIR = "EXISTING + NEEDS REPAIR"
EXISTING_NEEDS_INTEGRATION = "EXISTING + NEEDS NEO INTEGRATION"
UNSAFE = "UNSAFE"
UNSUPPORTED = "UNSUPPORTED"
DEAD = "DEAD/ORPHANED"

VERDICTS = (EXISTING_WORKING, EXISTING_NEEDS_REPAIR, EXISTING_NEEDS_INTEGRATION,
            UNSAFE, UNSUPPORTED, DEAD)

#: Risk, which is a different axis from the verdict. A capability can be real,
#: safe and still irreversible; those are two separate questions and Phase 12 is
#: about this one.
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"


@dataclass(frozen=True)
class Capability:
    """One audited capability. `action` is its registry name."""

    action: str
    module: str
    verdict: str
    risk: str = LOW
    summary: str = ""
    #: Does the module expose `expectation_for`, i.e. does Phase 4 have a
    #: contract for it? Absent means "no observable consequence", which the
    #: executor reports as NOT_AVAILABLE rather than as a pass.
    verifiable: bool = False
    #: Does it park behind core/confirm.py?
    gated: bool = False
    #: Why this verdict. Written down, because a verdict nobody can check is an
    #: opinion.
    note: str = ""
    #: The action names or operations a planner should prefer instead.
    prefer_over: tuple = ()

    def to_dict(self) -> dict:
        return {"action": self.action, "module": self.module,
                "verdict": self.verdict, "risk": self.risk,
                "summary": self.summary, "verifiable": self.verifiable,
                "gated": self.gated, "note": self.note,
                "prefer_over": list(self.prefer_over)}


#: The audit. Every module in actions/ appears exactly once, so a new action
#: cannot be added without being classified — and `catalogue()` reports any
#: registered action missing from this table as UNSAFE, which is the right
#: default: an unaudited capability is not automatically a permitted one.
AUDIT: tuple = (
    Capability("windows_control", "actions/windows_control.py", EXISTING_WORKING,
               LOW, "Real UI Automation control of windows and controls, with a "
               "declared verification contract for every operation that has an "
               "observable consequence.", verifiable=True, gated=True,
               note="Phase 3's façade plus Phase 6 targeting, discovery, typing, "
                    "dialog and launch detection. The reference implementation "
                    "for how a capability should be shaped."),
    Capability("open_app", "actions/open_app.py", EXISTING_NEEDS_INTEGRATION,
               LOW, "Opens an application by name, resolved through "
               "core/windows/apps.py rather than a shell.",
               verifiable=True,
               note="Phase 3 already replaced its shell=True launch with "
                    "apps.resolve(). Kept because it works, but windows_control's "
                    "launch_app reports *which window opened*, which this one "
                    "does not, so a planner should prefer that."),
    Capability("browser_control", "actions/browser_control.py",
               EXISTING_NEEDS_INTEGRATION, MEDIUM,
               "Browser automation: navigate, click, type, read a page.",
               verifiable=True,
               note="Subprocess-driven and string-typed. Real capability, not yet "
                    "expressible as a plan step because its results are prose. "
                    "Phase 8's browser workflow uses the action directly, not "
                    "through the goal layer, until it returns structured data."),
    Capability("web_search", "actions/web_search.py", EXISTING_WORKING, LOW,
               "Web search returning a summarised, bounded answer.",
               verifiable=True,
               note="Read-only and bounded. Safe to expose to a planner."),
    Capability("file_processor", "actions/file_processor.py",
               EXISTING_NEEDS_REPAIR, MEDIUM,
               "Reads and summarises a user-supplied file.",
               note="Uses subprocess to convert documents. Works for the formats "
                    "it supports; the conversion step is outside NEO's "
                    "authority to verify, so its results should be reported as "
                    "'the converter said', not as fact."),
    Capability("file_controller", "actions/file_controller.py",
               EXISTING_NEEDS_REPAIR, HIGH,
               "Lists, creates, copies, moves, renames and deletes files.",
               note="Contains irreversible deletion. Phase 1 added a "
                    "confirmation gate to the destructive operations; a planner "
                    "must still treat it as HIGH risk and require the user to "
                    "ask for the deletion explicitly."),
    Capability("reminder", "actions/reminder.py", EXISTING_WORKING, LOW,
               "Schedules a reminder through Task Scheduler.",
               verifiable=True,
               note="Creates a real scheduled task. Bounded and reversible "
                    "(delete the task)."),
    Capability("send_message", "actions/send_message.py", UNSAFE, HIGH,
               "Sends a message through a messaging integration.",
               note="Sends to another person on the user's behalf. Unreversible "
                    "once delivered, and not something a model-derived plan "
                    "should reach on its own — the user asks for it, in those "
                    "words, every time."),
    Capability("computer_settings", "actions/computer_settings.py",
               EXISTING_NEEDS_REPAIR, HIGH,
               "Volume, brightness, power and window management.",
               gated=True,
               note="Phase 1's gate covers shutdown/restart. Brightness on "
                    "Linux falls back to a shell=True command with interpolated "
                    "output — unreachable on Windows, and the reason this is "
                    "marked NEEDS REPAIR rather than WORKING."),
    Capability("computer_control", "actions/computer_control.py",
               EXISTING_NEEDS_INTEGRATION, MEDIUM,
               "Direct mouse and keyboard control plus screen capture.",
               note="The real implementation behind windows_control's coordinate "
                    "fallbacks. Prefers raw input over UIA; keep it as the "
                    "fallback tier and do not let a planner reach for it first."),
    Capability("desktop_control", "actions/desktop.py", UNSAFE, MEDIUM,
               "Wallpaper, desktop organisation and statistics.",
               note="Contains the explicit refusal left behind by Phase 1, "
                    "which asked a model to write Python and ran it with exec(). "
                    "That code is removed and stays removed. The module is kept "
                    "because the refusal is the honest answer to that request."),
    Capability("code_helper", "actions/code_helper.py", UNSAFE, HIGH,
               "Writes, edits and runs code files.",
               note="Writes files and runs them through a subprocess. That is "
                    "arbitrary code execution with a model's name on it, which "
                    "Phase 6 explicitly does not add. Never planner-reachable."),
    Capability("dev_agent", "actions/dev_agent.py", UNSAFE, HIGH,
               "Opens projects in an editor and automates development work.",
               note="Spawns an editor with a model-chosen path, and can write "
                    "files. Not planner-reachable."),
    Capability("game_updater", "actions/game_updater.py", EXISTING_NEEDS_REPAIR,
               MEDIUM, "Installs and updates Steam/Epic games.",
               note="Drives external launchers and downloads large payloads. "
                    "Real, but its outcome is not observable by NEO afterwards."),
    Capability("flight_finder", "actions/flight_finder.py",
               EXISTING_NEEDS_INTEGRATION, LOW,
               "Searches Google Flights and summarises options.",
               verifiable=True,
               note="Browser-driven and read-only. The result is prose, so it "
                    "is not yet a plan step."),
    Capability("weather_report", "actions/weather_report.py", EXISTING_WORKING,
               LOW, "A weather report for a place.", verifiable=True,
               note="Read-only and bounded."),
    Capability("youtube_video", "actions/youtube_video.py",
               EXISTING_NEEDS_INTEGRATION, LOW,
               "Plays, summarises and searches YouTube.",
               note="Drives a browser and a media player. Read-mostly, but it "
                    "starts playback on the user's machine."),
    Capability("video_player", "actions/video_player.py",
               EXISTING_NEEDS_INTEGRATION, LOW,
               "Local media playback.",
               note="Needs the `player` context object main.py supplies, so it "
                    "cannot run in a goal step that has no player attached."),
    Capability("system_monitor", "actions/system_monitor.py", DEAD, LOW,
               "Reads CPU and memory usage.",
               note="No TOOL dict, so it is never discovered. It is also the "
                    "data source behind the HUD's system panel, which is why it "
                    "is DEAD as an action and not dead as code."),
    Capability("background_monitor", "actions/background_monitor.py", DEAD, LOW,
               "Watches the desktop on a timer.",
               note="No TOOL dict. Used by the HUD's proactive features."),
    Capability("proactive", "actions/proactive.py", DEAD, LOW,
               "Formats persistent memory into the system prompt.",
               note="No TOOL dict; imported by main.py."),
    Capability("screen_processor", "actions/screen_processor.py", DEAD, LOW,
               "Screenshot capture helper.",
               note="No TOOL dict; a capture-only module."),
)

_BY_ACTION = {c.action: c for c in AUDIT}

#: Phase 6's own assistant pipeline. Not a capability in the audit above — it
#: is the thing that *uses* capabilities — but it belongs in the catalogue so a
#: planner can see it exists.
PIPELINE_ACTION = "run_goal"

PIPELINE = Capability(
    PIPELINE_ACTION, "core/planning/assistant.py", EXISTING_WORKING, MEDIUM,
    "Turns a sentence into a bounded goal, plans it and runs it.",
    note="Phase 6. Callable from any assistant pipeline; the voice pipeline is "
         "documented as NOT VERIFIED end-to-end, so it is not offered as a "
         "capability until that is repaired.")

ALL_CAPABILITIES = dict(_BY_ACTION)
ALL_CAPABILITIES[PIPELINE_ACTION] = PIPELINE


# ── lookups ─────────────────────────────────────────────────────────────────

def get(action: str) -> Optional[Capability]:
    return ALL_CAPABILITIES.get(str(action or ""))


def verdict_of(action: str) -> str:
    """The verdict for one capability. Unknown names are UNSAFE, not assumed fine.

    The asymmetry is the point: adding an action to `actions/` without adding
    it to this table locks it out of model-derived plans, which is the correct
    failure direction. A capability becomes planner-reachable by being audited,
    not by being registered.
    """
    capability = ALL_CAPABILITIES.get(str(action or ""))
    return capability.verdict if capability else UNSAFE


def risk_of(action: str) -> str:
    capability = ALL_CAPABILITIES.get(str(action or ""))
    return capability.risk if capability else HIGH


def is_unsafe(action: str) -> bool:
    return verdict_of(action) == UNSAFE


def is_plannable(action: str) -> bool:
    """May a model-derived plan name this capability?

    No, when it is UNSAFE, UNSUPPORTED or DEAD — and, equally, when it is not
    registered at all, which `Planner.build()` rejects on its own. This function
    exists so the refusal happens *before* a model is asked, rather than after.
    """
    return verdict_of(action) not in (UNSAFE, UNSUPPORTED, DEAD)


def is_high_risk(action: str) -> bool:
    return risk_of(action) == HIGH


def is_gated(action: str) -> bool:
    """Does this capability ask the user before doing the irreversible part?"""
    capability = ALL_CAPABILITIES.get(str(action or ""))
    return bool(capability and capability.gated)


def audit_report() -> dict:
    """The whole audit, grouped by verdict. What docs/phase6.md cites."""
    grouped: dict = {verdict: [] for verdict in VERDICTS}
    for capability in ALL_CAPABILITIES.values():
        grouped.setdefault(capability.verdict, []).append(capability.action)
    return {"verdicts": VERDICTS,
            "counts": {verdict: len(items) for verdict, items in grouped.items()},
            "by_verdict": grouped,
            "high_risk": sorted(a for a, c in ALL_CAPABILITIES.items()
                                if c.risk == HIGH),
            "plannable": sorted(a for a in ALL_CAPABILITIES if is_plannable(a)),
            "unplannable": sorted(a for a in ALL_CAPABILITIES if not is_plannable(a))}


# ── the catalogue the planner actually reads ────────────────────────────────

@dataclass
class Catalogue:
    """A bounded, structured view of what a planner may use.

    Built from the *live registries*, not from the audit table alone: the
    registries decide what exists, and the audit decides what a model may
    reach. A capability that is registered but unaudited appears here as
    UNSAFE, which is the honest and safe direction.
    """

    entries: list = field(default_factory=list)
    missing_from_audit: list = field(default_factory=list)

    def names(self) -> set:
        return {entry["name"] for entry in self.entries}

    def allowed(self) -> set:
        return {entry["name"] for entry in self.entries if entry["plannable"]}

    def entry(self, name: str) -> Optional[dict]:
        for item in self.entries:
            if item["name"] == str(name):
                return item
        return None

    def to_dict(self) -> dict:
        return {"entries": list(self.entries),
                "missing_from_audit": list(self.missing_from_audit)}


def _description_of(actions: Any, name: str) -> str:
    """The registry's own one-line description, if it exposes one."""
    records = getattr(actions, "_actions", None)
    record = records.get(name) if isinstance(records, dict) else None
    description = getattr(record, "description", "") if record else ""
    return str(description or "")


def _parameters_of(actions: Any, name: str) -> dict:
    records = getattr(actions, "_actions", None)
    record = records.get(name) if isinstance(records, dict) else None
    schema = getattr(record, "parameters", None) if record else None
    return schema if isinstance(schema, dict) else {}


def _declares_expectation(handler: Any) -> bool:
    import sys

    module_name = getattr(handler, "__module__", None)
    module = sys.modules.get(module_name) if module_name else None
    return callable(getattr(module, "expectation_for", None)) if module else False


def build_catalogue(actions: Any = None, plugins: Any = None,
                    limit: int = 40) -> Catalogue:
    """Everything a planner is allowed to know about, bounded on purpose.

    Only the fields a planner can act on: the name, a short description, the
    verdict, the risk, whether the user must approve it, and whether Phase 4 can
    check it. No schemas, no handler objects, no source.
    """
    from core.execution import resolve_capability

    names: list = []
    for registry in (actions, plugins):
        if registry is None:
            continue
        lister = getattr(registry, "names", None)
        if callable(lister):
            try:
                names.extend(sorted(str(n) for n in lister()))
                continue
            except Exception:
                pass
        declarations = getattr(registry, "get_tool_declarations", None)
        if callable(declarations):
            try:
                names.extend(sorted(str(d.get("name")) for d in declarations()
                                    if isinstance(d, dict) and d.get("name")))
            except Exception:
                continue

    catalogue = Catalogue()
    for name in sorted(set(names))[: max(1, min(int(limit), 120))]:
        _registry, kind, handler = resolve_capability(name, actions, plugins)
        if kind == "":
            continue                              # vanished between listing and use
        capability = get(name)
        if capability is None:
            catalogue.missing_from_audit.append(name)
        entry = {
            "name": name,
            "description": _description_of(actions, name)[:240],
            "verdict": verdict_of(name),
            "risk": risk_of(name),
            "gated": is_gated(name),
            "verifiable": bool(capability and capability.verifiable)
                          or (kind == "actions" and _declares_expectation(handler)),
            "plannable": is_plannable(name),
            "summary": capability.summary if capability else "not audited",
            "note": (capability.note if capability else
                     "registered but absent from the Phase 6 audit, so a planner "
                     "may not reach it until it has been reviewed")[:300],
        }
        if kind == "actions":
            entry["operations"] = _operations_of(name)
        catalogue.entries.append(entry)
    return catalogue


def _operations_of(name: str) -> list:
    """Operation names for a capability that dispatches on one.

    `windows_control` is the important case: a planner that knows the action
    name but not the operation vocabulary cannot produce a valid step, so the
    operation list travels with it.
    """
    import actions.windows_control as _windows

    if name == "windows_control":
        return sorted(_windows.OPERATIONS)
    return []


def prompt_block(catalogue: Catalogue, limit: int = 24) -> str:
    """The bounded text a planner prompt carries.

    Deliberately terse: a model given a 4,000-line tool catalogue plans worse
    and costs more than one given twenty honest lines. Anything not here is
    still reachable by name if the model asks, and still validated.
    """
    lines = ["Capabilities this planner may use (name | risk | approval | "
             "verifiable):"]
    rows = [e for e in catalogue.entries if e["plannable"]][: max(1, int(limit))]
    for entry in rows:
        lines.append(f"- {entry['name']} | {entry['risk'].lower()} risk | "
                     f"{'needs approval' if entry['gated'] else 'no approval needed'}"
                     f" | {'verifiable' if entry['verifiable'] else 'not verifiable'}"
                     f" — {entry['summary']}")
    blocked = [e["name"] for e in catalogue.entries if not e["plannable"]][:12]
    if blocked:
        lines.append("Not available to a plan: " + ", ".join(blocked))
    return "\n".join(lines)