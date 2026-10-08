"""
The strict schema a model-proposed plan has to satisfy.

WHY A SCHEMA AND NOT A PROMPT
    "Return JSON in this format" is a suggestion. A schema is a gate: the
    planner's output is checked against this structure *before* `Planner.build()`
    ever sees it, and anything that does not fit is refused with a reason. The
    model therefore cannot smuggle a code string, an unknown operation, a shell
    command, or an eleventh verification verb past a prompt that told it not to.

WHAT THE SCHEMA IS
    A small declarative vocabulary — the exact keys a step may have, the types
    each takes, and how deep a value tree may be — expressed as data so it can
    be asserted against in tests and quoted in documentation. It is deliberately
    smaller than JSON Schema: there is no `$ref`, no `anyOf`, and no way to
    describe a shape nobody has needed yet.

WHAT IT DOES NOT CHECK
    Whether an action is *registered* — that is `Planner.build()`'s job, against
    the live registry — and whether a capability is *safe for a plan* — that is
    `core/capabilities.py`'s. This file checks shape; the other two check
    substance. Keeping them apart means each can fail with its own message and
    neither has to pretend to be the other.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from core.goals.models import scrub_sensitive

#: Hard ceilings on the raw text a model may send back. A plan is a few
#: hundred characters; anything approaching this is a model having a bad time,
#: and parsing it costs more than rejecting it.
MAX_MODEL_CHARS = 24000
MAX_STEPS_IN_PAYLOAD = 40
MAX_KEYS_PER_STEP = 12
MAX_KEY_CHARS = 120
MAX_VALUE_CHARS = 4000
MAX_VALUE_DEPTH = 6

#: Exactly these keys may appear on a step. A step carrying anything else is
#: refused rather than cleaned, because "ignore the extra key" is how a field
#: like `run` or `command` eventually gets implemented by accident.
STEP_KEYS = frozenset({
    "id", "description", "action", "arguments", "depends_on",
    "expected", "retry", "re_resolve", "required",
})

#: Argument keys a plan may use. `$from` is Phase 5's reference to an observed
#: value; everything else is data the capability itself defines.
REFERENCE_KEY = "$from"

EXPECTATION_KEYS = frozenset({
    "kind", "target", "expected", "property", "compare", "timeout",
    "interval", "note",
})

RETRY_KEYS = frozenset({"attempts", "delay", "reason", "on"})

#: Ways a step may say what failure it tolerates. A closed set, because
#: "retry until it works" is the one phrase that must never be expressible.
RETRY_MODES = ("never", "transient", "always")


@dataclass(frozen=True)
class SchemaProblem:
    """One thing wrong with a model's output, in a sentence a model can fix."""

    where: str
    message: str

    def describe(self) -> str:
        return f"{self.where}: {self.message}"


class SchemaRejected(Exception):
    """The payload did not fit the schema. Never reaches `Planner.build()`."""

    def __init__(self, problems: list):
        self.problems = list(problems)
        detail = " | ".join(p.describe() for p in self.problems[:4])
        super().__init__(f"the proposed plan does not match NEO's schema: {detail}")


def _typed(value: Any) -> str:
    return type(value).__name__


def _check_value(value: Any, where: str, depth: int = 0,
                 problems: Optional[list] = None) -> list:
    """Reject anything in an argument tree that is not inert data.

    The same rule `Planner._check_value` applies, applied one layer earlier so
    the model gets told about it before it is described as a plan failure. Both
    exist on purpose: the planner is the security boundary, and the schema is
    the interface boundary.
    """
    problems = problems if problems is not None else []
    if depth > MAX_VALUE_DEPTH:
        problems.append(SchemaProblem(where, f"nests deeper than {MAX_VALUE_DEPTH}"))
        return problems
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            problems.append(SchemaProblem(where, f"is longer than {MAX_VALUE_CHARS} characters"))
        return problems
    if isinstance(value, dict):
        if REFERENCE_KEY in value:
            if not isinstance(value[REFERENCE_KEY], str) or not value[REFERENCE_KEY].strip():
                problems.append(SchemaProblem(f"{where}.{REFERENCE_KEY}",
                                              "must name an observed value"))
            return problems
        if len(value) > MAX_KEYS_PER_STEP:
            problems.append(SchemaProblem(where, f"has {len(value)} keys, more than "
                                                   f"{MAX_KEYS_PER_STEP}"))
        for key, item in value.items():
            if not isinstance(key, str):
                problems.append(SchemaProblem(where, f"has a {_typed(key)} key"))
                continue
            if len(key) > MAX_KEY_CHARS:
                problems.append(SchemaProblem(where, f"has a key longer than "
                                                       f"{MAX_KEY_CHARS} characters"))
            _check_value(item, f"{where}.{key}", depth + 1, problems)
        return problems
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_value(item, f"{where}[{index}]", depth + 1, problems)
        return problems
    problems.append(SchemaProblem(where, f"contains a {_typed(value)}, which is not "
                                         f"plain data"))
    return problems


def validate(payload: Any, max_steps: int = 12) -> list:
    """Every structural problem with `payload`, as a list. Empty means it fits.

    Returns problems rather than raising, so a caller can log all of them at
    once — a model that got five things wrong should be told five things.
    """
    problems: list = []

    if isinstance(payload, str):
        if len(payload) > MAX_MODEL_CHARS:
            problems.append(SchemaProblem("payload", f"is {len(payload)} characters, "
                                                      f"more than {MAX_MODEL_CHARS}"))
        return problems

    if not isinstance(payload, (list, dict)):
        problems.append(SchemaProblem("payload", f"is a {_typed(payload)}; a list of "
                                                 f"steps or an object was expected"))
        return problems

    steps = payload
    if isinstance(payload, dict):
        unknown = set(payload) - {"steps", "objective", "note"}
        for key in sorted(unknown):
            problems.append(SchemaProblem("payload", f"has an unknown key '{key}'"))
        steps = payload.get("steps")
        if steps is None:
            problems.append(SchemaProblem("payload", "has no 'steps' list"))
            return problems
        if not isinstance(payload.get("objective", ""), str):
            problems.append(SchemaProblem("payload.objective", "must be text"))

    if not isinstance(steps, list):
        problems.append(SchemaProblem("payload.steps", f"is a {_typed(steps)}, not a list"))
        return problems
    if not steps:
        problems.append(SchemaProblem("payload.steps", "is empty"))
        return problems
    if len(steps) > min(max_steps, MAX_STEPS_IN_PAYLOAD):
        problems.append(SchemaProblem("payload.steps",
                                      f"has {len(steps)} steps; the limit is {max_steps}"))
        return problems

    for index, step in enumerate(steps):
        problems.extend(_check_step(step, f"steps[{index}]"))
    return problems


def _check_step(step: Any, where: str) -> list:
    problems: list = []
    if not isinstance(step, dict):
        return [SchemaProblem(where, f"is a {_typed(step)}, not an object")]

    for key in sorted(set(step) - STEP_KEYS):
        problems.append(SchemaProblem(where, f"has an unknown key '{key}'"))

    action = step.get("action")
    if not isinstance(action, str) or not action.strip():
        problems.append(SchemaProblem(f"{where}.action", "must name a registered action"))
    elif len(action) > 64:
        problems.append(SchemaProblem(f"{where}.action", "is too long to be an action name"))

    if "arguments" in step and step["arguments"] is not None:
        if not isinstance(step["arguments"], dict):
            problems.append(SchemaProblem(f"{where}.arguments", "must be an object"))
        else:
            _check_value(step["arguments"], f"{where}.arguments", 1, problems)

    if "depends_on" in step:
        depends = step["depends_on"]
        if isinstance(depends, str):
            depends = [depends]
        if not isinstance(depends, list) or any(not isinstance(d, str) for d in depends):
            problems.append(SchemaProblem(f"{where}.depends_on",
                                          "must be a list of step ids"))

    if "expected" in step and step["expected"] is not None:
        expected = step["expected"]
        if not isinstance(expected, dict):
            problems.append(SchemaProblem(f"{where}.expected", "must be an object"))
        else:
            for key in sorted(set(expected) - EXPECTATION_KEYS):
                problems.append(SchemaProblem(f"{where}.expected",
                                              f"has an unknown key '{key}'"))
            _check_value(expected, f"{where}.expected", 1, problems)

    if "retry" in step and step["retry"] is not None:
        retry = step["retry"]
        if not isinstance(retry, dict):
            problems.append(SchemaProblem(f"{where}.retry", "must be an object"))
        else:
            for key in sorted(set(retry) - RETRY_KEYS):
                problems.append(SchemaProblem(f"{where}.retry",
                                              f"has an unknown key '{key}'"))
            mode = retry.get("on")
            if mode is not None and str(mode).lower() not in RETRY_MODES:
                problems.append(SchemaProblem(f"{where}.retry.on",
                                              f"'{mode}' is not one of "
                                              f"{', '.join(RETRY_MODES)}"))
            attempts = retry.get("attempts")
            if attempts is not None and (not isinstance(attempts, int)
                                         or isinstance(attempts, bool) or attempts < 1):
                problems.append(SchemaProblem(f"{where}.retry.attempts",
                                              "must be a positive whole number"))

    for flag in ("re_resolve", "required"):
        if flag in step and not isinstance(step[flag], bool):
            problems.append(SchemaProblem(f"{where}.{flag}", "must be true or false"))

    if "description" in step and not isinstance(step["description"], str):
        problems.append(SchemaProblem(f"{where}.description", "must be text"))

    return problems


def enforce(payload: Any, max_steps: int = 12) -> list:
    """Validate and raise if anything is wrong."""
    problems = validate(payload, max_steps=max_steps)
    if problems:
        raise SchemaRejected(problems)
    return payload if isinstance(payload, list) else payload.get("steps")


def describe_schema() -> str:
    """The schema, as the bounded text a planner prompt carries.

    Small on purpose. A model given four hundred lines of specification plans
    worse than one given this, because what it needs to know is the *shape*,
    and the registry has already told it the vocabulary.
    """
    return (
        "Return a JSON object with \"steps\": a list of at most "
        f"{min(12, MAX_STEPS_IN_PAYLOAD)} steps. Each step may use only these keys:\n"
        f"  {', '.join(sorted(STEP_KEYS))}\n"
        "  action      — the exact name of a registered capability\n"
        "  arguments   — an object of plain data (text, numbers, booleans, lists)\n"
        "  id          — a short unique id for this step, e.g. \"open\"\n"
        "  depends_on  — ids of earlier steps this one needs\n"
        "  description — what this step is for, in plain words\n"
        "  required    — false only when the goal is still meaningful without it\n"
        "  re_resolve  — true when the target window may move (single-instance apps)\n"
        "  retry       — {\"attempts\": 2, \"delay\": 0.25, \"on\": \"transient\"}\n"
        "  expected    — only for actions that declare no verification of their own\n"
        "\n"
        "Rules: name only capabilities from the catalogue. Arguments are values, "
        "never code, commands or file paths to execute. Use "
        f"{{\"{REFERENCE_KEY}\": \"step:open.handle\"}} to pass an observed value "
        "forward. If no supported plan achieves the objective, return an empty "
        "steps list rather than inventing one."
    )


def safe_preview(payload: Any, limit: int = 400) -> str:
    """A loggable, scrubbed preview of what a model sent back.

    Never logged raw: a model can echo the user's text back, and the user's text
    is exactly what should not end up in a log file.
    """
    try:
        text = repr(scrub_sensitive(payload))
    except Exception:
        text = "<unprintable payload>"
    return text[:limit]