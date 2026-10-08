"""
Phase 6 — natural-language orchestration.

THE CHAIN, IN ONE PLACE
    sentence
      ↓  intent.extract        what it plainly says, no model
      ↓  model_planner         (only if that was not enough) one bounded call
      ↓  schema.enforce        shape: keys, types, depth, inert values
      ↓  core.capabilities     reachability: what a plan may name at all
      ↓  Planner.build         Phase 5's gate: the live registries, ordering,
      ↓                       cycles, limits, expectations
      ↓  GoalExecutor.run      Phase 2 task → execution → Phase 4 verification
      ↓                       → bounded recovery → bounded replan
      ↓  truthful result

WHAT EACH PIECE OWNS
    `intent`      reads a sentence into slots and says how much it could not
                  explain. Never calls a model.
    `schema`      the strict shape a model-proposed plan must fit. Refuses
                  unknown keys, non-data values and over-long payloads.
    `model_planner` the bounded planning layer: one off-thread proposer call
                  with a timeout, every gate applied in order, and an exact
                  refusal when nothing safe can be built.
    `workflows`   the four multi-capability recipes Phase 6 guarantees. They
                  are recipes, not a second planner, and get no privilege.
    `memory_context` a read-only, bounded, redacted view of what the user
                  stored. It reaches prompts and nothing else.
    `assistant`   one call from a sentence to an honest answer. Callable from
                  any pipeline; it knows nothing about Qt or audio.

WHAT THIS PACKAGE DELIBERATELY DOES NOT HAVE
    A way to run an action. Every step goes through `core/goals/executor.py`
    and therefore through the Phase 2 task manager, the confirmation gate and
    Phase 4 verification. A planner that could execute would be a second
    execution architecture, and Phase 6 is not that.
"""
from core.planning import assistant, intent, memory_context, model_planner
from core.planning import schema, workflows

__all__ = [
    "AssistantGoals",
    "ModelPlanner",
    "MemoryContext",
    "PlanningOutcome",
    "PlanningRefused",
    "WorkflowsAreNotAPlanner",
    "extract",
    "steps_for_intent",
]


def __getattr__(name):          # lazy re-exports, so importing one piece is cheap
    if name == "AssistantGoals":
        return assistant.AssistantGoals
    if name in ("ModelPlanner", "PlanningOutcome", "PlanningRefused"):
        return getattr(model_planner, name)
    if name == "MemoryContext":
        return memory_context.MemoryContext
    if name == "extract":
        return intent.extract
    if name == "steps_for_intent":
        return workflows.steps_for_intent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


#: A name for the thing this package is *not*, so a reader does not have to
#: infer it. See the module docstring.
WorkflowsAreNotAPlanner = None