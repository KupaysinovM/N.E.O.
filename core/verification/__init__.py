"""
Verification — the part of NEO that checks its own work.

    Phase 3: "I called Invoke() on a button."
    Phase 4: "The window I asked for exists, and it is the one Windows says is
              in front."  — or an honest "I could not tell".

LAYOUT
    observation.py  reading real state through the Phase 3 Windows adapter,
                    with provenance, freshness and sensitivity on every value
    world.py        a minimal, bounded snapshot of what was just observed
    expectations.py structured expectations, chosen by code — never by the model
    verifier.py     bounded polling, comparison, and the honest outcomes

THE SEAM
    This package is platform-aware but not platform-bound: it asks questions of
    the machine rather than driving it. Today the machine is Windows, read
    through `core.windows.control`. A macOS adapter would answer the same
    questions from another subsystem, and nothing above this package would
    change — which is exactly why observation lives here instead of inside the
    Windows boundary.

WHAT IT WILL NOT DO
    It does not plan, retry on its own, or pursue a goal. It answers one
    question about one action, in bounded time, and then stops.
"""
from __future__ import annotations

from core.verification.expectations import (
    Expectation,
    ExpectationKind,
    app_running,
    control_exists,
    control_state,
    control_value,
    expected_after,
    preconditions,
    window_active,
    window_closed,
    window_exists,
)
from core.verification.observation import (
    Freshness,
    Kind,
    Observation,
    Sensitivity,
    Source,
)
from core.verification.verifier import Outcome, Status, capture, verify
from core.verification.world import Entry, EntryState, WorldState

__all__ = [
    "Expectation", "ExpectationKind", "expected_after", "preconditions",
    "window_exists", "window_closed", "window_active", "control_exists",
    "control_value", "control_state", "app_running",
    "Observation", "Source", "Kind", "Freshness", "Sensitivity",
    "verify", "capture", "Outcome", "Status",
    "WorldState", "Entry", "EntryState",
]