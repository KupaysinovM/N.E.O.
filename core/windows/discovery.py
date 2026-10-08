"""
Structured UI Automation discovery — answers "what can I press in Telegram?".

WHY THIS FILE EXISTS
    Phase 3 could `list_controls`, which walks a tree and returns a bounded list
    of element dicts. That is honest, but it is the wrong shape for the
    question an assistant actually asks: not "dump every element", but "find
    the Send button in this window", "which checkboxes are ticked", "what tabs
    does this app have". A raw tree dump costs the reader thousands of tokens
    of layout furniture and answers none of those.

    So discovery here is *structured*: a bounded query returns a bounded answer.

      * `find_all` returns every candidate that matched, scored, with an
        explicit `ambiguous` flag — so "two Send buttons" is a fact the caller
        can act on instead of a first-match guess.
      * `summarize` groups a window's controls by role, so "this app has four
        buttons, one edit field, and a menu" is one line instead of two hundred.
      * Everything stays bounded: `MAX_RESULTS`, `MAX_DEPTH`, and a hard refusal
        to return more than the caller asked for.

WHAT IT DOES NOT DO
    It never acts. Discovery reads; `UiaSession.perform` and `set_value_text`
    change things, and they are reached through the façade like every other
    mutation. Keeping the two apart is what makes "look at this checkbox"
    safe to ask for.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.windows.identifiers import ElementQuery, matches
from core.windows.models import UIElement

#: Hard ceiling on how many controls any one discovery call returns. A caller
#: asking for more than this is asking for a screen dump, which is the thing
#: this module exists to avoid.
MAX_RESULTS = 60

#: Ceiling on grouped output. Long enough for a real application dialog, short
#: enough that a summary stays a summary.
MAX_GROUPS = 40

#: Roles that matter more than the rest when a window is summarised. A window
#: full of separators and panes is uninteresting; a window with buttons and
#: text fields is not.
INTERACTIVE_TYPES = ("button", "edit", "checkbox", "combobox", "listitem",
                     "menuitem", "tabitem", "treeitem", "radiobutton",
                     "hyperlink", "slider", "spinbutton")

#: The control types a caller may name in a structured query. It is a real
#: vocabulary rather than "any string", so a typo is an error instead of a
#: silently empty result.
KNOWN_ROLES = ("window", "button", "edit", "checkbox", "combobox", "list",
               "listitem", "menu", "menuitem", "tab", "tabitem", "tree",
               "treeitem", "radiobutton", "hyperlink", "slider", "spinbutton",
               "text", "document", "dialog", "pane", "group", "image",
               "progressbar", "statusbar", "toolbar")


@dataclass
class Hit:
    """One discovered control, with why it matched and what it can be asked to do."""

    element: UIElement
    score: int = 0
    reasons: list = field(default_factory=list)

    def to_dict(self) -> dict:
        data = self.element.to_dict()
        data["match"] = {"score": self.score, "reasons": list(self.reasons)}
        return data


@dataclass
class Findings:
    """A bounded, structured answer. Never a tree dump."""

    window: Optional[dict] = None
    hits: list = field(default_factory=list)
    ambiguous: bool = False
    truncated: bool = False
    total_found: int = 0
    query: str = ""

    @property
    def count(self) -> int:
        return len(self.hits)

    def best(self) -> Optional[Hit]:
        return self.hits[0] if self.hits else None

    def to_dict(self) -> dict:
        return {"window": self.window, "query": self.query,
                "count": self.count, "ambiguous": self.ambiguous,
                "truncated": self.truncated, "total_found": self.total_found,
                "controls": [h.to_dict() for h in self.hits]}


def _score(element: UIElement, query: ElementQuery) -> tuple:
    """How well this element answers this query, and why. Deterministic."""
    score = 0
    reasons: list = []
    wanted_name = (query.name or "").strip().lower()
    have_name = (element.name or "").strip().lower()
    if wanted_name:
        if have_name == wanted_name:
            score += 100
            reasons.append("its visible name matches exactly")
        elif have_name.startswith(wanted_name):
            score += 70
            reasons.append("its visible name starts with the requested text")
        elif wanted_name in have_name:
            score += 50
            reasons.append("its visible name contains the requested text")
    if query.automation_id:
        if (element.automation_id or "") == query.automation_id:
            score += 100
            reasons.append("its automation id matches exactly")
        else:
            return 0, []
    if query.class_name and (element.class_name or "") == query.class_name:
        score += 25
        reasons.append(f"its class is {query.class_name}")
    if element.control_type:
        score += 10
    if element.automation_id:
        # A stable id is worth more than a name: it survives a redraw.
        score += 5
        reasons.append("it has a stable automation id")
    if element.enabled:
        score += 3
    if element.offscreen:
        score -= 15
        reasons.append("it is scrolled off screen")
    if element.sensitive:
        score -= 50
        reasons.append(f"it holds a credential ({element.sensitive_reason}) "
                       f"and its value is withheld")
    return score, reasons


def find_all(elements: list, query: ElementQuery, limit: int = MAX_RESULTS) -> Findings:
    """Every control that answers this query, best first, bounded.

    Unlike `resolve_one`, this never raises for ambiguity: "there are two Send
    buttons" is the answer, and the caller decides whether to narrow the query
    or to stop. It raises for nothing at all.
    """
    limit = max(1, min(int(limit), MAX_RESULTS))
    hits: list = []
    for element in elements:
        if not matches(element, query):
            continue
        score, reasons = _score(element, query)
        if score <= 0:
            continue
        hits.append(Hit(element=element, score=score, reasons=reasons))
    hits.sort(key=lambda h: (-h.score, h.element.control_type,
                             str(h.element.name or "")))
    total = len(hits)
    truncated = total > limit
    top = hits[0].score if hits else 0
    ambiguous = sum(1 for h in hits if h.score == top) > 1
    return Findings(hits=hits[:limit], ambiguous=ambiguous, truncated=truncated,
                    total_found=total, query=query.describe())


def describe(hit: Hit) -> str:
    """One line a model can act on."""
    element = hit.element
    flags = []
    if element.enabled is False:
        flags.append("disabled")
    if element.offscreen:
        flags.append("off screen")
    if element.focused:
        flags.append("focused")
    if element.sensitive:
        flags.append("credential field — value withheld")
    capabilities = ", ".join(element.capabilities[:6])
    return (f"{element.control_type} '{element.name or element.automation_id or ''}'"
            f"{(' [' + ', '.join(flags) + ']') if flags else ''}"
            f"{('; can: ' + capabilities) if capabilities else ''}")


def summarize(elements: list, limit: int = MAX_GROUPS,
              interactive_only: bool = False) -> dict:
    """One window's controls, grouped by role. A map, not a dump.

    `interactive_only` drops the layout furniture — panels, separators, empty
    groups — which is what makes the difference between a summary a person can
    read and a list a machine can only page through.
    """
    groups: dict = {}
    sensitive = 0
    disabled = 0
    for element in elements:
        if element.sensitive:
            sensitive += 1
        if element.enabled is False:
            disabled += 1
        ctype = (element.control_type or "Control")
        if interactive_only and ctype.lower() not in INTERACTIVE_TYPES:
            continue
        bucket = groups.setdefault(ctype, {"count": 0, "named": [], "ids": []})
        bucket["count"] += 1
        if element.name and len(bucket["named"]) < 6:
            bucket["named"].append(str(element.name)[:40])
        elif element.automation_id and len(bucket["ids"]) < 6:
            bucket["ids"].append(str(element.automation_id)[:40])

    ordered = sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
    return {
        "control_types": len(groups),
        "total_controls": len(elements),
        "interactive_controls": sum(1 for e in elements
                                    if (e.control_type or "").lower() in INTERACTIVE_TYPES),
        "sensitive_controls": sensitive,
        "disabled_controls": disabled,
        "groups": [{"control_type": name, "count": bucket["count"],
                    "named": bucket["named"], "automation_ids": bucket["ids"]}
                   for name, bucket in ordered[:max(1, min(int(limit), MAX_GROUPS))]],
    }


def summarize_text(summary: dict) -> str:
    """The grouped answer as one bounded paragraph."""
    parts = [f"{summary['total_controls']} control(s) in "
             f"{summary['control_types']} role(s)"]
    if summary["sensitive_controls"]:
        parts.append(f"{summary['sensitive_controls']} credential field(s) "
                     f"withheld")
    if summary["disabled_controls"]:
        parts.append(f"{summary['disabled_controls']} disabled")
    lines = ["; ".join(parts)]
    for group in summary["groups"][:12]:
        named = ", ".join(group["named"][:4])
        lines.append(f"  {group['control_type']} ×{group['count']}"
                     + (f" — {named}" if named else ""))
    return "\n".join(lines)