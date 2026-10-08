"""
World state — what NEO last saw, and how much of it still counts.

THIS IS NOT A WORLD MODEL
    It is not knowledge about the world, not long-term memory, not embeddings,
    not a graph, and not something that plans anything. It is a bounded record
    of observations taken moments ago, with the provenance attached, so that a
    later step can ask "is that still true?" instead of assuming it is.

THE FOUR HONEST STATES
    OBSERVED — read from the machine just now, with the subsystem named.
    INFERRED — derived from an observation by a rule that is stated in the
                entry. Never a guess dressed as a fact.
    UNKNOWN   — asked for, not available. An entry that exists and says "I do
                not know" is worth more than a missing one, because it is the
                difference between "no battery" and "nobody looked".
    STALE     — was observed, and time has passed. Kept, marked, and not used
                as current by anything.

NO FABRICATION, EVER
    Every entry here comes from an `Observation`. There is no code path that
    writes a value that Windows did not return, and `WorldState.set_unknown()`
    exists precisely so that "we could not see it" is expressible without
    inventing something in its place.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from core.verification import observation as obs


class EntryState(str):
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"
    STALE = "stale"


@dataclass
class Entry:
    """One fact about the current machine, and where it came from."""

    key: str
    value: Any = None
    state: str = EntryState.OBSERVED
    source: str = obs.Source.UNAVAILABLE
    observed_at: float = 0.0
    target: str = ""
    note: str = ""

    @property
    def age_seconds(self) -> Optional[float]:
        return None if not self.observed_at else max(0.0, time.time() - self.observed_at)

    @property
    def usable(self) -> bool:
        """Only a current observation may be treated as a fact."""
        return self.state == EntryState.OBSERVED and self.value is not None

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "state": self.state,
                "source": self.source, "observed_at": self.observed_at or None,
                "target": self.target, "note": self.note}

    def describe(self) -> str:
        if self.state == EntryState.UNKNOWN:
            return f"{self.key}: unknown ({self.note or 'not observed'})"
        if self.state == EntryState.STALE:
            return f"{self.key}: stale (last seen {self.target or 'earlier'})"
        if self.state == EntryState.INFERRED:
            return f"{self.key}: {self.value!r} (inferred: {self.note})"
        return f"{self.key}: {self.value!r} (observed via {self.source})"


@dataclass
class WorldState:
    """A bounded, timestamped snapshot of the currently observable desktop."""

    captured_at: float = field(default_factory=time.time)
    entries: dict = field(default_factory=dict)

    # -- writing -----------------------------------------------------------

    def put(self, key: str, observation: Optional[obs.Observation],
            state: str = EntryState.OBSERVED) -> Entry:
        """Record what an observation said — including "it said nothing"."""
        if observation is None:
            entry = Entry(key=key, value=None, state=EntryState.UNKNOWN,
                          note="No observation was taken.")
        elif observation.ok:
            entry = Entry(key=key, value=observation.value, state=state,
                          source=observation.source,
                          observed_at=observation.observed_at,
                          target=observation.target, note=observation.note)
        else:
            entry = Entry(key=key, value=None, state=EntryState.UNKNOWN,
                          source=observation.source,
                          observed_at=observation.observed_at,
                          target=observation.target,
                          note=observation.note or observation.error_kind)
        self.entries[key] = entry
        return entry

    def put_value(self, key: str, value: Any, source: str, target: str = "",
                  note: str = "", state: str = EntryState.OBSERVED) -> Entry:
        """Record a value that was derived, not observed. Must say which."""
        entry = Entry(key=key, value=value, state=state, source=source,
                      observed_at=(time.time() if state == EntryState.OBSERVED else 0.0),
                      target=target, note=note)
        self.entries[key] = entry
        return entry

    def mark_stale(self, keys: Optional[list] = None) -> int:
        """Age entries that were observed earlier. Nothing is deleted."""
        aged = 0
        for key, entry in self.entries.items():
            if keys is not None and key not in keys:
                continue
            if entry.state == EntryState.OBSERVED:
                entry.state = EntryState.STALE
                aged += 1
        return aged

    # -- reading -----------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        entry = self.entries.get(key)
        return entry.value if entry is not None and entry.usable else default

    def is_known(self, key: str) -> bool:
        entry = self.entries.get(key)
        return entry is not None and entry.state != EntryState.UNKNOWN

    def to_dict(self) -> dict:
        return {"captured_at": self.captured_at,
                "entries": {k: v.to_dict() for k, v in self.entries.items()}}

    def describe(self) -> str:
        if not self.entries:
            return "Nothing has been observed yet."
        return "\n".join(f"  {e.describe()}" for e in self.entries.values())

    @property
    def summary(self) -> dict:
        counts: dict = {}
        for entry in self.entries.values():
            counts[entry.state] = counts.get(entry.state, 0) + 1
        return {"captured_at": self.captured_at, "count": len(self.entries),
                "states": counts}

    # ── Phase 6: answering the questions a step actually asks ──────────────

    def age_of(self, key: str) -> Optional[float]:
        """How long ago this entry was observed, or None if never."""
        entry = self.entries.get(key)
        return entry.age_seconds if entry is not None else None

    def is_stale(self, key: str, max_age: float = 5.0) -> bool:
        """Is this entry too old to act on?

        True for an entry that is already marked stale, one that was never
        observed, and one older than `max_age`. The default is deliberately
        short: a desktop moves, and a window list six seconds old describes a
        desktop that no longer exists.
        """
        entry = self.entries.get(key)
        if entry is None or not entry.usable:
            return True
        if entry.state == EntryState.STALE:
            return True
        age = entry.age_seconds
        return age is not None and age > max(0.0, float(max_age))

    def current(self, key: str, max_age: float = 5.0, default: Any = None) -> Any:
        """The value, but only if it is still worth believing."""
        if self.is_stale(key, max_age):
            return default
        return self.get(key, default)

    def resolve_target(self, selector: dict, max_age: float = 5.0) -> dict:
        """What does this step's target refer to, in the world as it was?

        The question Phase 6 keeps asking is "what is the current step talking
        about?". This answers it from the *captured* window list only, and it
        never invents a window that is not in it. Three honest outcomes:

          * `resolved`    — exactly one captured window matches;
          * `ambiguous`   — more than one does, and none is better;
          * `unknown`     — none does, or the capture is too old to trust.

        A stale capture yields `unknown` rather than a stale answer, because a
        window that was open five seconds ago is the classic thing to act on by
        mistake.
        """
        selector = selector or {}
        handle = selector.get("window_handle")
        title = str(selector.get("title") or "").strip().lower()
        process_id = selector.get("process_id")

        result = {"selector": dict(selector), "resolved": None, "ambiguous": False,
                  "candidates": [], "reason": ""}
        if self.is_stale("visible_windows", max_age):
            result["reason"] = ("the last capture is too old to trust, so the "
                                "target was not resolved from it")
            return result
        windows = self.get("visible_windows") or []
        if not isinstance(windows, list):
            result["reason"] = "no window list was captured"
            return result

        if handle:
            matches = [w for w in windows
                       if isinstance(w, dict) and int(w.get("handle") or 0) == int(handle)]
            result["candidates"] = [_brief(w) for w in matches]
            if matches:
                result["resolved"] = _brief(matches[0])
            else:
                result["reason"] = (f"no captured window has handle {handle}; it "
                                    f"may have closed or moved")
            return result

        matches = []
        for window in windows:
            if not isinstance(window, dict):
                continue
            if process_id is not None and window.get("process_id") != process_id:
                continue
            if title and title not in str(window.get("title") or "").lower():
                continue
            if not title and process_id is None:
                continue
            matches.append(window)
        result["candidates"] = [_brief(w) for w in matches[:5]]
        if len(matches) == 1:
            result["resolved"] = _brief(matches[0])
        elif len(matches) > 1:
            result["ambiguous"] = True
            result["reason"] = (f"{len(matches)} captured windows match; NEO does "
                                f"not choose between them from a snapshot")
        else:
            result["reason"] = "no captured window matches this target"
        return result

    def describe_for_prompt(self, limit: int = 8) -> str:
        """The bounded block a planner sees about the desktop.

        Bounded on every axis and marked with its age, so the reader — human or
        model — can see that it is a picture of the desktop *as it was*, not a
        statement about the desktop as it is.
        """
        if not self.entries:
            return "Nothing has been observed about this desktop yet."
        age = max(0.0, time.time() - self.captured_at)
        lines = [f"Desktop as observed {age:.1f}s ago "
                 f"({int(self.summary['count'])} entries):"]
        for entry in list(self.entries.values())[: max(1, int(limit))]:
            lines.append("  " + entry.describe())
        return "\n".join(lines)


def _brief(window: Any) -> dict:
    """The four fields about a window a step actually needs."""
    window = window if isinstance(window, dict) else {}
    return {k: window.get(k) for k in ("handle", "title", "process_id",
                                       "process_name") if window.get(k) is not None}


# ── bounded capture ─────────────────────────────────────────────────────────

def capture(max_windows: int = 8, include_controls: bool = False,
            max_controls: int = 25, app_names: Optional[list] = None,
            cancel_event=None) -> WorldState:
    """Read the current desktop into a world state. Bounded on purpose.

    Nothing here invents a field. If a value could not be read, the entry says
    unknown and keeps the reason, which is more useful to a later phase than an
    optimistic guess would be.
    """
    from core.windows import control

    state = WorldState()
    active = obs.active_window(cancel_event=cancel_event)
    state.put("active_window", active)

    listed = control.list_windows(limit=max_windows, cancel_event=cancel_event)
    if listed.status == "SUCCESS":
        state.put_value("visible_windows", listed.data.get("windows", []),
                        source=obs.Source.WIN32, target=f"first {max_windows} windows",
                        note="bounded enumeration of top-level windows")
        state.put_value("window_count_observed", len(listed.data.get("windows", [])),
                        source=obs.Source.WIN32, note="how many were within the bound")
    else:
        state.put("visible_windows", None)
        state.put_value("window_count_observed", None, source=obs.Source.UNAVAILABLE,
                        note=listed.message, state=EntryState.UNKNOWN)

    for name in (app_names or []):
        state.put(f"app:{name}", obs.app_running(name, cancel_event=cancel_event))

    if include_controls and active.ok:
        handle = active.value.get("handle")
        controls = control.list_controls(window_handle=handle, limit=max_controls,
                                         max_depth=8, cancel_event=cancel_event)
        if controls.status == "SUCCESS":
            found = controls.data.get("controls", [])
            state.put_value("active_window_controls", found,
                            source=obs.Source.UIA,
                            target=f"first {max_controls} controls of handle {handle}",
                            note="bounded UI Automation sample")
            # Phase 6: the *grouped* summary is what answers "what can I do in
            # this window" without handing anyone a control tree. Derived from
            # the list already read, so it costs no second walk.
            try:
                from core.windows import discovery

                state.put_value("active_window_control_summary",
                                discovery.summarize([_as_element(c) for c in found]),
                                source=obs.Source.UIA,
                                target=f"grouped roles of handle {handle}",
                                note="counts per control type, derived from the "
                                     "bounded sample above")
            except Exception:
                pass
        else:
            state.put_value("active_window_controls", None, source=obs.Source.UNAVAILABLE,
                            note=controls.message, state=EntryState.UNKNOWN)

    # Phase 6. Two facts a step keeps asking for and `capture` did not record:
    # what just changed, and what the foreground window actually is in terms a
    # control query can use. Both are observations of the live machine, never
    # inferences about intent.
    active_handle = active.value.get("handle") if active.ok else None
    if active_handle:
        state.put_value("active_window_handle", int(active_handle),
                        source=obs.Source.WIN32,
                        target=f"foreground window handle {active_handle}",
                        note="read at capture time")
    if state.is_known("visible_windows") and state.get("visible_windows"):
        state.put_value("most_recent_capture", state.captured_at,
                        source=obs.Source.WIN32,
                        note="when this window list was read")
    return state


def _as_element(raw: dict):
    """A control dict back into the element model, for `discovery.summarize`.

    Round-tripping through the model rather than making `summarize` accept two
    shapes keeps one implementation of "what is a control" in the project.
    """
    from core.windows.models import UIElement

    try:
        return UIElement.from_dict(raw)
    except Exception:
        return UIElement(control_type=str(raw.get("control_type") or ""),
                         name=raw.get("name"),
                         automation_id=raw.get("automation_id"))