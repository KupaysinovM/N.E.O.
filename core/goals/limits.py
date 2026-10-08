"""
Every bound in Phases 5 and 6, in one file, with the reason each number exists.

WHY THESE ARE HERE AND NOT SCATTERED
    "Bounded" is only a real property if the bounds are written down and can be
    asserted. If each loop picks its own limit, then "bounded" means "someone
    remembered to stop", and the only way to find out is to hang. Every loop in
    core/goals/ takes its ceiling from a `Limits` instance, and the defaults
    below are the values the shipped executor uses.

THE LOOP THAT MUST NOT EXIST
    There is no code path shaped like

        while goal_not_complete:
            ask_model()
            try_again()

    Planning is attempted at most `max_planning_attempts` times, each step is
    attempted at most `retry.attempts` times (and at most `max_step_attempts`
    even if a plan asks for more), a step takes part in at most
    `max_recovery_attempts` recoveries, a goal takes part in at most
    `max_recovery_total` recoveries in total, a plan holds at most
    `max_steps` steps, and the whole run is cut off at
    `max_goal_seconds` regardless of what the individual steps believe.

WHAT THE NUMBERS ARE SIZED AGAINST
    A desktop goal in this phase is a handful of Windows operations on one or
    two applications. Phase 4 verification already waits up to 6s per
    expectation, so a four-step goal with retries is tens of seconds.
    `max_goal_seconds` is generous enough for that and small enough that a
    stuck goal is reported as stuck rather than sitting in the background
    forever.

WHAT PHASE 6 ADDED HERE
    A goal may now be given a *new* plan after execution starts, which is the
    whole point of adaptive replanning and also the easiest way to build an
    assistant that loops forever. So the new numbers are not decoration:
    `max_replans` bounds how many times one goal may be re-planned,
    `max_replans_per_step` bounds how many of those may be spent on a single
    step, `max_total_steps` bounds the plan length *across* all replans, and
    `replanner_seconds` bounds one call. A `Limits` that arrives from a
    model-backed planner is passed through `clamped()` first, so a planner
    cannot raise its own ceiling by asking.
"""
from __future__ import annotations

from dataclasses import dataclass

#: A plan longer than this is rejected outright rather than truncated. A plan
#: that needs fifteen steps to open a window is a plan that has gone wrong.
DEFAULT_MAX_STEPS = 12

#: How many times planning may be attempted. One is enough for a correct
#: planner; the extra attempts exist for a *bounded* proposer seam, not for a
#: model being asked to try again until something sticks.
DEFAULT_MAX_PLANNING_ATTEMPTS = 3

#: Hard ceiling on attempts for one step, whatever a plan's retry policy says.
#: A plan may lower this; it may not raise it.
DEFAULT_MAX_STEP_ATTEMPTS = 2

#: Recoveries (re-observe and try once more) a single step may take.
DEFAULT_MAX_RECOVERY_ATTEMPTS = 1

#: Recoveries across the whole goal. Bounded globally so a plan where every
#: step fails transiently cannot multiply into a long silent retry storm.
DEFAULT_MAX_RECOVERY_TOTAL = 3

#: Wall-clock ceiling for one step attempt, and for a whole goal. These are
#: checked between attempts and between steps; they do not and cannot interrupt
#: a Windows call that is already inside the OS, which is Phase 2's honest
#: boundary and is not weakened here.
DEFAULT_MAX_STEP_SECONDS = 45.0
DEFAULT_MAX_GOAL_SECONDS = 300.0

#: Ceiling on a plan-supplied verification timeout. A plan may ask for a
#: shorter wait than Phase 4's 6s default; it may not ask for an unbounded one.
DEFAULT_MAX_EXPECTATION_TIMEOUT = 20.0

#: Bounds on the bounded execution context carried through a goal. The item
#: count is sized against the executor's own bookkeeping rather than the plan
#: alone: one launch records its handle, the window's identity, and the
#: verification observation, and a single recovery re-observes the desktop on
#: top of that. A bound below that footprint makes a completed goal forget the
#: handle it had just published. Anything a not-yet-run step still names by
#: hand is kept regardless (see `GoalContext.pinned`), so this is the ceiling on
#: the *incidental* context, not on the goal's dependencies.
DEFAULT_MAX_CONTEXT_ITEMS = 32
DEFAULT_MAX_STEP_NOTES = 6
DEFAULT_MAX_RESULT_CHARS = 600

#: How many `{"$from": key}` references one step may contain, and how deep an
#: argument tree may be. Both exist so a plan cannot make argument resolution
#: into an unbounded walk.
DEFAULT_MAX_REFERENCES = 12
DEFAULT_MAX_ARGUMENT_DEPTH = 6

#: How many candidate plans `Planner.propose` will consider, and how long a
#: single proposer call may take. A proposer that hangs is abandoned, not
#: waited on.
DEFAULT_MAX_PROPOSALS = 3
DEFAULT_PROPOSER_SECONDS = 20.0

# ── Phase 6: bounded adaptive replanning ────────────────────────────────────
# Phase 5 deliberately could not change a plan after it started. Phase 6 can,
# but only inside numbers written down here. The loop this forbids is still
# the same one:
#
#     while step_not_done:
#         ask_model_for_a_new_plan()
#         run_it()
#
# There is no such loop here. `max_replans` is the hard count of plans a goal
# may be given *after* execution began; `max_replan_seconds` is the wall clock
# one replan may consume; `max_replans_per_step` stops a single bad step from
# consuming the whole goal's budget; and `max_total_steps` caps the plan length
# across every replan, so ten small replans cannot quietly build a
# hundred-step goal out of a twelve-step budget.
DEFAULT_MAX_REPLANS = 2
DEFAULT_MAX_REPLANS_PER_STEP = 1
DEFAULT_REPLANNER_SECONDS = 20.0
DEFAULT_MAX_TOTAL_STEPS = 24

#: Ceiling on the bounded state a replanner is shown. The replanner is a model
#: like any other, so the window it can see is a limit rather than a courtesy.
DEFAULT_MAX_REPLAN_CONTEXT_CHARS = 1200


@dataclass(frozen=True)
class Limits:
    """The complete set of ceilings one goal run operates under."""

    max_steps: int = DEFAULT_MAX_STEPS
    max_planning_attempts: int = DEFAULT_MAX_PLANNING_ATTEMPTS
    max_step_attempts: int = DEFAULT_MAX_STEP_ATTEMPTS
    max_recovery_attempts: int = DEFAULT_MAX_RECOVERY_ATTEMPTS
    max_recovery_total: int = DEFAULT_MAX_RECOVERY_TOTAL
    max_step_seconds: float = DEFAULT_MAX_STEP_SECONDS
    max_goal_seconds: float = DEFAULT_MAX_GOAL_SECONDS
    max_expectation_timeout: float = DEFAULT_MAX_EXPECTATION_TIMEOUT
    max_context_items: int = DEFAULT_MAX_CONTEXT_ITEMS
    max_step_notes: int = DEFAULT_MAX_STEP_NOTES
    max_result_chars: int = DEFAULT_MAX_RESULT_CHARS
    max_references: int = DEFAULT_MAX_REFERENCES
    max_argument_depth: int = DEFAULT_MAX_ARGUMENT_DEPTH
    max_proposals: int = DEFAULT_MAX_PROPOSALS
    proposer_seconds: float = DEFAULT_PROPOSER_SECONDS
    #: Phase 6. `max_replans` is 0 in a default Phase 5 caller only if it is set
    #: to 0; the shipped default allows a bounded replan, because an assistant
    #: that can never reconsider is not one that recovers.
    max_replans: int = DEFAULT_MAX_REPLANS
    max_replans_per_step: int = DEFAULT_MAX_REPLANS_PER_STEP
    replanner_seconds: float = DEFAULT_REPLANNER_SECONDS
    max_total_steps: int = DEFAULT_MAX_TOTAL_STEPS
    max_replan_context_chars: int = DEFAULT_MAX_REPLAN_CONTEXT_CHARS

    def clamped(self) -> "Limits":
        """A copy with every value forced into a sane range.

        Limits arrive from a caller and, for a model-backed planner in a later
        phase, from something that should not be trusted to be sensible. A
        negative step limit must not become "run forever", and a zero must not
        become "never run anything", so each field is clamped to a positive
        minimum and the seconds to a hard ceiling.
        """
        return Limits(
            max_steps=max(1, min(int(self.max_steps), 100)),
            max_planning_attempts=max(1, min(int(self.max_planning_attempts), 10)),
            max_step_attempts=max(1, min(int(self.max_step_attempts),
                                         DEFAULT_MAX_STEP_ATTEMPTS)),
            max_recovery_attempts=max(0, min(int(self.max_recovery_attempts), 5)),
            max_recovery_total=max(0, min(int(self.max_recovery_total), 20)),
            max_step_seconds=max(1.0, min(float(self.max_step_seconds), 600.0)),
            max_goal_seconds=max(1.0, min(float(self.max_goal_seconds), 3600.0)),
            max_expectation_timeout=max(0.2, min(float(self.max_expectation_timeout), 60.0)),
            max_context_items=max(1, min(int(self.max_context_items), 100)),
            max_step_notes=max(1, min(int(self.max_step_notes), 50)),
            max_result_chars=max(80, min(int(self.max_result_chars), 8000)),
            max_references=max(0, min(int(self.max_references), 100)),
            max_argument_depth=max(1, min(int(self.max_argument_depth), 20)),
            max_proposals=max(1, min(int(self.max_proposals), 10)),
            proposer_seconds=max(0.1, min(float(self.proposer_seconds), 120.0)),
            max_replans=max(0, min(int(self.max_replans), 6)),
            max_replans_per_step=max(0, min(int(self.max_replans_per_step), 3)),
            replanner_seconds=max(0.1, min(float(self.replanner_seconds), 120.0)),
            max_total_steps=max(1, min(int(self.max_total_steps), 200)),
            max_replan_context_chars=max(100, min(int(self.max_replan_context_chars),
                                                  8000)),
        )

    def to_dict(self) -> dict:
        return {
            "max_steps": self.max_steps,
            "max_planning_attempts": self.max_planning_attempts,
            "max_step_attempts": self.max_step_attempts,
            "max_recovery_attempts": self.max_recovery_attempts,
            "max_recovery_total": self.max_recovery_total,
            "max_step_seconds": self.max_step_seconds,
            "max_goal_seconds": self.max_goal_seconds,
            "max_expectation_timeout": self.max_expectation_timeout,
            "max_proposals": self.max_proposals,
            "max_replans": self.max_replans,
            "max_replans_per_step": self.max_replans_per_step,
            "max_total_steps": self.max_total_steps,
        }
