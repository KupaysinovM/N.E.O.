"""
When is a second attempt allowed, and when is it a lie?

THE PROBLEM
    "Retry on failure" is the single easiest way to turn a truthful system into
    a dishonest one. Retrying a permission refusal forty times produces forty
    refusals and one eventual success that the user was never asked about.
    Retrying an unsupported operation is worse: it is the shape of a loop that
    invents a different operation each time and never stops.

THE RULE HERE
    A retry is allowed only when the *actual* failure kind says the failure was
    transient, the step's policy asked for it, the goal's global ceilings have
    room, and re-observing first might change the answer. Everything else is
    permanent: it is reported, and the goal stops.

    Permanent is the default. Adding a kind to TRANSIENT is a deliberate act
    with a reason attached, not a matter of taste.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from core.task_models import ErrorKind

#: Failures that mean "the machine was busy", not "this is not going to work".
#:
#: ACCESS_DENIED is here because Windows' foreground lock refuses activation
#: while the user is working, and a short wait genuinely changes that answer.
#: It is *not* here for permission errors on files, which are ACCESS_DENIED too
#: and are not worth repeating: the cap of one retry is what keeps that safe.
TRANSIENT_ERROR_KINDS = frozenset({
    ErrorKind.TIMEOUT,
    ErrorKind.ACCESS_DENIED,
    ErrorKind.ELEMENT_STALE,
    #: "The call worked and the effect could not be seen" is not always a
    #: permanent truth: a control that was mid-repaint, or a foreground request
    #: Windows refused a moment ago, genuinely can become observable. So this is
    #: retryable — but only after the executor has re-observed, and only for the
    #: single extra attempt the ceilings allow. It is never a licence to repeat.
    ErrorKind.NOT_VERIFIED,
})

#: Kinds that must never be retried, listed explicitly so that "the default is
#: permanent" is visible in the code rather than merely implied by an absence.
PERMANENT_ERROR_KINDS = frozenset({
    ErrorKind.ACTION_NOT_SUPPORTED,
    ErrorKind.UNKNOWN_ACTION,
    ErrorKind.ACTION_UNAVAILABLE,
    ErrorKind.AUTHORIZATION_REQUIRED,
    ErrorKind.AUTHORIZATION_DENIED,
    ErrorKind.AUTHORIZATION_UNAVAILABLE,
    ErrorKind.INVALID_REQUEST,
    ErrorKind.INVALID_ARGUMENTS,
    ErrorKind.TASK_CANCELLED,
    ErrorKind.INTERRUPTED,
    ErrorKind.ELEMENT_DISABLED,
    ErrorKind.ELEMENT_AMBIGUOUS,
    ErrorKind.ELEMENT_NOT_FOUND,
    ErrorKind.UNSUPPORTED_CONTROL,
    ErrorKind.APPLICATION_NOT_FOUND,
    ErrorKind.PROCESS_NOT_FOUND,
    ErrorKind.WINDOW_NOT_FOUND,
    ErrorKind.INTERNAL_ERROR,
})


@dataclass(frozen=True)
class RetryPolicy:
    """How many times one step may be attempted, and for what.

    `attempts` counts the *first* try, so the default of 1 means "try once and
    report". `kinds` is the set of failure kinds this policy will act on; a
    failure outside it is permanent regardless of `attempts`.
    """

    attempts: int = 1
    delay: float = 0.0
    kinds: frozenset = field(default_factory=lambda: TRANSIENT_ERROR_KINDS)
    reason: str = ""

    def with_attempts(self, attempts: int) -> "RetryPolicy":
        return RetryPolicy(attempts=max(1, int(attempts)), delay=self.delay,
                           kinds=self.kinds, reason=self.reason)

    def allows(self, kind: Optional[ErrorKind], attempt: int) -> tuple[bool, str]:
        """May attempt number `attempt + 1` follow a failure of `kind`?"""
        if kind is None:
            return False, "there is no error kind to judge the failure by"
        if kind in PERMANENT_ERROR_KINDS:
            return False, f"{kind.value} is a permanent failure"
        if kind not in self.kinds:
            return False, f"{kind.value} is not a transient failure"
        if attempt + 1 > self.attempts:
            return False, (f"the retry policy allows {self.attempts} attempt(s) "
                           f"and {attempt} already ran")
        return True, "transient failure inside the step's retry policy"

    def to_dict(self) -> dict:
        return {"attempts": self.attempts, "delay": self.delay,
                "kinds": sorted(k.value for k in self.kinds), "reason": self.reason}

    @classmethod
    def from_dict(cls, raw: Optional[dict]) -> "RetryPolicy":
        if not isinstance(raw, dict):
            return NO_RETRIES
        kinds: Iterable[ErrorKind] = TRANSIENT_ERROR_KINDS
        if isinstance(raw.get("kinds"), list):
            parsed = []
            for item in raw["kinds"]:
                try:
                    parsed.append(ErrorKind(str(item).upper()))
                except ValueError:
                    continue          # an unknown kind simply is not retryable
            kinds = frozenset(parsed)
        return cls(attempts=max(1, int(raw.get("attempts", 1))),
                   delay=max(0.0, float(raw.get("delay", 0.0))),
                   kinds=frozenset(kinds), reason=str(raw.get("reason", ""))[:200])


#: The default: one attempt, no repetition. A step is not retried unless
#: something deliberately said it may be.
NO_RETRIES = RetryPolicy(attempts=1, delay=0.0,
                         reason="no retry was requested for this step")

#: What a step gets when its failure is transient and re-observing first is
#: worth doing: one extra attempt, after a short pause.
TRANSIENT_RETRY = RetryPolicy(attempts=2, delay=0.25,
                              reason="transient failure; re-observe and try once more")


def is_transient(kind: Optional[ErrorKind]) -> bool:
    """Pure classification, with no attempt counting."""
    return kind is not None and kind in TRANSIENT_ERROR_KINDS


def classify(kind: Optional[ErrorKind]) -> str:
    """'transient' | 'permanent' | 'unknown' — for logs and for the goal report."""
    if kind is None:
        return "unknown"
    return "transient" if kind in TRANSIENT_ERROR_KINDS else "permanent"


def is_recoverable(kind: Optional[ErrorKind]) -> bool:
    """Whether a bounded re-observe-then-retry is offered for this failure.

    This is the question the prompt's Calculator example asks: "the focus was
    not verified — should NEO look again and try once?" The answer is yes for a
    short, fixed list, and no for everything else. It never asks the model.
    """
    return is_transient(kind)
