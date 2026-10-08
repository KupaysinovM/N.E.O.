"""
Element identification: how a caller names a control, and how it is resolved.

THE PROBLEM
    Windows does not give one universally unique name for a control. An
    automation id is usually stable but not guaranteed unique and not always
    present. A name is visible to the user but duplicates constantly ("OK" in a
    dialog with three panes). Matching on either alone means clicking the wrong
    button in the wrong window.

THE RULE HERE
    Resolution returns exactly one element or an error. Never "the first match",
    never "the best guess". When more than one candidate survives the filters,
    the caller gets ELEMENT_AMBIGUOUS together with the candidates it had to
    choose between, so the decision goes back to whoever asked — in Phase 5
    that will be a planner; today it is the user, through the model.

    Narrowing is always possible: filter by control_type, restrict to one
    window, or ask for a control type that is rare in the tree. That is the
    supported way to resolve a collision, not picking whichever came first.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from core.windows.errors import element_ambiguous, element_not_found, invalid_argument
from core.windows.models import UIElement

# Operations NEO asks of an element. Kept short on purpose: each one needs a
# defined meaning, a failure mode, and a test.
SUPPORTED_OPERATIONS = ("invoke", "toggle", "set_value", "get_value", "select",
                        "expand", "collapse", "set_focus", "select_item")


@dataclass
class ElementQuery:
    """What the caller asked for. Every field narrows; none of them guesses."""

    name: Optional[str] = None
    automation_id: Optional[str] = None
    control_type: Optional[str] = None
    class_name: Optional[str] = None
    index: Optional[int] = None

    def describe(self) -> str:
        bits = []
        if self.automation_id:
            bits.append(f"automation_id={self.automation_id!r}")
        if self.name:
            bits.append(f"name={self.name!r}")
        if self.control_type:
            bits.append(f"type={self.control_type}")
        if self.class_name:
            bits.append(f"class={self.class_name!r}")
        return ", ".join(bits) or "any control"

    def to_dict(self) -> dict:
        return {"name": self.name, "automation_id": self.automation_id,
                "control_type": self.control_type, "class_name": self.class_name,
                "index": self.index}


def _norm(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def matches(element: UIElement, query: ElementQuery) -> bool:
    """Every supplied field must match. A missing field never excludes."""
    if query.automation_id:
        if _norm(element.automation_id) != _norm(query.automation_id):
            return False
    if query.name:
        if _norm(element.name) != _norm(query.name):
            return False
    if query.control_type:
        if _norm(element.control_type) != _norm(query.control_type):
            return False
    if query.class_name:
        if _norm(element.class_name) != _norm(query.class_name):
            return False
    return True


def filter_elements(elements: Sequence[UIElement], query: ElementQuery) -> list[UIElement]:
    """All candidates for a query. Empty means not found; more than one is a
    decision the caller has to make, not a detail to be smoothed over."""
    return [e for e in elements if matches(e, query)]


def _candidate_summary(elements: Sequence[UIElement], limit: int = 5) -> str:
    shown = [e.describe() for e in elements[:limit]]
    extra = len(elements) - len(shown)
    return "; ".join(shown) + (f"; +{extra} more" if extra > 0 else "")


def resolve_one(elements: Sequence[UIElement], query: ElementQuery) -> UIElement:
    """The single element matching `query`, or a specific error.

    Raises WindowsError with ELEMENT_NOT_FOUND when nothing matches and
    ELEMENT_AMBIGUOUS when more than one does. `query.index` is the deliberate
    way to say which one, and it must be in range or it raises too — it is
    never clamped, because silently picking the last element of a list is how
    the wrong button gets clicked.
    """
    candidates = filter_elements(elements, query)
    if not candidates:
        raise element_not_found(query.describe())
    # The index is validated whether or not it was needed: an out-of-range index
    # means the caller's model of the window is wrong, and silently ignoring
    # that is how the wrong control gets used.
    index = None
    if query.index is not None:
        try:
            index = int(query.index)
        except (TypeError, ValueError):
            raise invalid_argument(f"index must be a whole number, got {query.index!r}")
        if index < 0 or index >= len(candidates):
            raise invalid_argument(
                f"index {index} is out of range: {len(candidates)} control(s) match "
                f"{query.describe()}")
    if len(candidates) == 1:
        return candidates[0]
    if index is not None:
        return candidates[index]
    raise element_ambiguous(query.describe(), len(candidates),
                            _candidate_summary(candidates))


def build_runtime_id(runtime_id: Sequence[int]) -> tuple:
    """Normalise a UIA runtime id into a plain tuple of ints."""
    try:
        return tuple(int(part) for part in (runtime_id or ()))
    except (TypeError, ValueError):
        return ()


def describe_identity(element: UIElement) -> dict:
    """The identity facts a caller can reuse, and the honest caveat with them."""
    return {
        "runtime_id": list(element.runtime_id),
        "automation_id": element.automation_id,
        "name": element.name,
        "control_type": element.control_type,
        "note": element.identity_note,
    }