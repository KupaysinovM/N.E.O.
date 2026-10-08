# Goals (Phase 5)

Phase 5 is NEO's first bounded, multi-step pursuit of an outcome. It takes a
goal, turns it into a validated list of registered steps, runs them through the
Phase 2 execution boundary, verifies each one with Phase 4, and stops and
reports honestly.

> **Phase 5 provides bounded goal-oriented multi-step execution.**
> NEO is not autonomous. There is no loop here that runs until the goal is done,
> no strategy invention, no code generation, and no way to execute an operation
> that is not already in the action registry.

---

## 1. The relationship, stated once

```text
Goal                 core/goals/models.py
 └── Plan            an ordered, bounded, validated list
      └── Step       one operation + what has to be true afterwards
           └── Task  a REAL Phase 2 task, one per attempt
                └── ExecutionRequest → ExecutionLayer → registry → real capability
                     └── Phase 4 observation → Phase 4 verification
                          └── Step result → next step / stop / bounded recovery
                               └── GoalResult
```

**A Step is not a Task.** Every attempt at a step creates a genuine task through
the existing `TaskManager`, so Phase 2's persistence, lifecycle events,
cancellation, confirmation and result taxonomy apply to goal work with no second
implementation of any of them. The goal layer adds ordering, dependency and
verification requirements; it owns no capability and does not replace anything.

**The goal layer never calls an action.** It builds an `ExecutionRequest` and
hands it to the existing `ExecutionLayer`. That is the only path from a plan to
a real capability, and it is the same path a single model tool call takes.

---

## 2. Modules

| File | Responsibility |
|---|---|
| [core/goals/models.py](../core/goals/models.py) | `Goal`, `Plan`, `Step`, `Attempt`, `GoalContext`, `GoalResult`, the two status vocabularies, record (de)serialisation |
| [core/goals/limits.py](../core/goals/limits.py) | Every bound in the phase, in one file, with the reason each number exists |
| [core/goals/planner.py](../core/goals/planner.py) | Validation against the registries, dependency ordering, whitelisted recipes, bounded proposing |
| [core/goals/recovery.py](../core/goals/recovery.py) | `RetryPolicy`, the transient/permanent split, `PERMANENT_ERROR_KINDS` |
| [core/goals/executor.py](../core/goals/executor.py) | The run loop: dependencies, confirmation, execution, verification, recovery, stop, pause, cancel |
| [core/goals/store.py](../core/goals/store.py) | `GoalStore` / `GoalHistory` — `state/goals.json`, atomic write, suspicious loader |

---

## 3. The goal model

```text
Goal
- goal_id, description, status, created_at, started_at, completed_at
- plan          (or None — an unplanned goal can execute nothing)
- current_step
- context       bounded: observed values, step summaries, task ids, recovery count
- result        the final GoalResult, or None
- error         the TaskError that ended it, if one did
- limits        the bounds this goal runs under
- cancel_event  set once, never replaced
- pause_requested
```

### Step status

`PENDING · READY · RUNNING · VERIFIED · COMPLETED · NOT_VERIFIED · FAILED ·
BLOCKED · AWAITING_CONFIRMATION · CANCELLED · SKIPPED`

### Goal status

`PENDING · PLANNING · READY · RUNNING · PAUSED · AWAITING_CONFIRMATION ·
COMPLETED · FAILED · NOT_VERIFIED · BLOCKED · CANCELLED · NOT_SUPPORTED ·
PLANNING_FAILED`

### These are not new words

The status *values* are the vocabulary the earlier phases already used, so a
step status of `NOT_VERIFIED` **is** an `ExecStatus.NOT_VERIFIED`, `VERIFIED`
**is** a `verifier.Status.VERIFIED`, and `PENDING / RUNNING / FAILED /
CANCELLED` are `TaskStatus` values. One enum to reason about, not five.

---

## 4. The plan model

```text
Plan
- goal_id, steps[], created_at, source (explicit | template:<name> | proposal), version

Step
- step_id, description, action, arguments
- expected          an Expectation, or None
- expected_by       none | plan | action
- depends_on[]
- retry             RetryPolicy (attempts, delay, kinds, reason)
- required          True unless the plan says otherwise
- status, attempts, recovery_attempts, task_id, result, history[], notes[]
```

A plan is **data**. It is not a script, not a command line, and not Python
source. Arguments must be inert values (`str`, `int`, `float`, `bool`, `None`,
`list`, `dict`) or a bounded `{"$from": "key"}` reference; a callable, a module,
a lock or any live object is rejected with `never code`.

### Verification contracts

An expectation is chosen by **code**, never by the model — Phase 4's rule, kept.

* If the **action declares** a contract (`expectation_for` at module level), the
  action's contract is used and a plan cannot weaken it. A plan that asks for
  `window_exists` after a `close_window` still gets `window_closed`.
* If the action declares **none**, a plan may add one — but only from the fixed
  `ExpectationKind` vocabulary. That can add rigour, never remove it.
* If neither, the step has nothing to verify and says so (`expected_by: none`).
  It may end `COMPLETED`, and it is never counted as `VERIFIED`.

---

## 5. Planning is bounded, and validated against the real registry

```python
planner.build(goal_id, raw_steps)        # validate + topologically order
planner.template("open_and_type", goal_id, params)
planner.propose(goal_id, proposer, attempts=3)
```

Validation, all of it fatal to the plan:

| Refused | Kind |
|---|---|
| an action that is not in the action or plugin registry | `ACTION_NOT_SUPPORTED` |
| more steps than `limits.max_steps` | `INVALID_REQUEST` |
| no steps at all | `INVALID_REQUEST` |
| duplicate step ids | `INVALID_REQUEST` |
| a dependency on a step that is not in the plan, or on itself | `INVALID_REQUEST` |
| a dependency loop | `INVALID_REQUEST` |
| an argument that is not inert data | `INVALID_REQUEST` |
| an expectation kind the verifier does not know | `INVALID_REQUEST` |
| an expectation timeout above the ceiling | `INVALID_REQUEST` |

A refused plan never executes anything, and the goal ends as `NOT_SUPPORTED` or
`PLANNING_FAILED` with the reason kept in the taxonomy.

### There is no free-form natural-language planner

Phase 5 ships **whitelisted, deterministic recipes** — `open_app`,
`open_and_type`, `open_and_focus`, `close_window` — that a caller selects by
name, and a `propose()` seam where a future model-backed planner plugs in. Free
text is not parsed into a plan here; that is a Phase 6+ capability. Every route
goes through the same `build()` validation, so even a model-backed planner
cannot produce a plan the registry does not recognise.

The proposer seam is bounded twice over: `max_proposals` attempts, and the
proposer itself runs off-thread and is **abandoned** if it overruns
`proposer_seconds`. A planner that hangs is a logged failure, not a frozen
process.

---

## 6. Running a step

```text
resolve arguments  →  check dependencies  →  confirm if asked
     →  execute through the Phase 2 layer  →  observe  →  verify
     →  record  →  continue / recover / stop
```

No step of that chain is optional. In particular, a successful execution is
never taken as completion: verification runs after every applicable step.

### What a step ends as

| Execution | Verification | Step status |
|---|---|---|
| SUCCESS | VERIFIED | `VERIFIED` |
| SUCCESS | NOT_AVAILABLE (nothing observable) | `COMPLETED` |
| SUCCESS | anything else | `NOT_VERIFIED` |
| FAILED / NOT_SUPPORTED / NOT_AVAILABLE | — | `FAILED` |
| CANCELLED | — | `CANCELLED` |
| REQUIRES_CONFIRMATION | — | `AWAITING_CONFIRMATION` |

### Using newly observed state

A later step can name a value an earlier one actually reported:

```json
{"operation": "focus_window", "window_handle": {"$from": "step:open.handle"}}
```

The executor substitutes from the goal's own bounded context. A reference to
something never observed — or one observed as *not there* — **fails the step**
with `INVALID_ARGUMENTS` and executes nothing. An unfilled argument is how a
step ends up doing nothing while looking like it did something.

That context is bounded and drops its oldest entry when it fills, but a key a
step that has not finished still names is *pinned* and never dropped: a
reference is a dependency, not an observation, and evicting one would fail a
step whose earlier work had already succeeded. Only the incidental context —
observations nothing has asked for by name — is subject to the bound.

---

## 7. Goal completion

```text
A goal is COMPLETED only when every required step reached its required outcome:
    VERIFIED  (its effect was observed)
or  COMPLETED (it ran and there was nothing observable to check)

and no required step is NOT_VERIFIED, FAILED, BLOCKED or CANCELLED.
```

`"all the calls came back without raising"` is **not** the definition, and there
is no path through `_overall_status()` that returns `COMPLETED` while a required
step is `NOT_VERIFIED`.

The result carries honest counts — `verified`, `completed`, `not_verified`,
`failed`, `blocked`, `cancelled`, `skipped`, `awaiting_confirmation` — and
`GoalResult.ok` is True only for `COMPLETED`.

`required: false` is an explicit opt-out ("this step is nice to have"), and it is
the only thing that lets a failing step not fail the goal. A `NOT_VERIFIED`
*required* step always stops the goal.

---

## 8. Partial completion

```text
Step 1  VERIFIED
Step 2  NOT_VERIFIED      ← stopped here
Step 3  BLOCKED           ← never ran; the goal stopped
Step 4  BLOCKED
```

Steps that never ran are marked `BLOCKED` with the reason, not silently left
`PENDING`, and a `STEP_BLOCKED` event is emitted for each. Nothing downstream of
an unverified step runs.

---

## 9. Recovery is bounded, explicit and based on the real failure

```text
NOT_VERIFIED / TIMEOUT / ACCESS_DENIED / ELEMENT_STALE
    → is it transient?          (the existing ErrorKind taxonomy)
    → did the step ask to retry? (RetryPolicy, attempts ≤ max_step_attempts)
    → is there recovery room?    (per step and per goal)
    → re-observe once            (one bounded world capture)
    → repeat the SAME step once
    → announce STEP_RECOVERY_STARTED / _COMPLETED
```

Anything else is permanent and stops the goal:

```text
ACTION_NOT_SUPPORTED · UNKNOWN_ACTION · ACTION_UNAVAILABLE
AUTHORIZATION_REQUIRED / _DENIED / _UNAVAILABLE
INVALID_REQUEST · INVALID_ARGUMENTS · TASK_CANCELLED · INTERRUPTED
ELEMENT_DISABLED / _AMBIGUOUS / _NOT_FOUND · UNSUPPORTED_CONTROL
APPLICATION_NOT_FOUND · PROCESS_NOT_FOUND · WINDOW_NOT_FOUND · INTERNAL_ERROR
```

Permanent is the **default**; adding a kind to `TRANSIENT_ERROR_KINDS` is a
deliberate act with a reason attached. `PERMANENT_ERROR_KINDS` is listed
explicitly in the code so "the default is permanent" is visible rather than
implied by an absence.

Recovery **never** changes the plan and never invents an operation. It re-observes
and repeats the same step. That is the whole of Phase 5's recovery; adaptive
replanning is Phase 6+.

---

## 10. The bounds

Every number is in [core/goals/limits.py](../core/goals/limits.py), with a
clamped constructor so a caller cannot raise a ceiling by asking.

| Bound | Default |
|---|---|
| `max_steps` | 12 |
| `max_planning_attempts` / `max_proposals` | 3 |
| `max_step_attempts` | 2 |
| `max_recovery_attempts` (per step) / `max_recovery_total` (per goal) | 1 / 3 |
| `max_step_seconds` / `max_goal_seconds` | 45 / 300 |
| `max_expectation_timeout` | 20 |
| `max_references` / `max_argument_depth` | 12 / 6 |
| `proposer_seconds` | 20 |

There is no

```python
while not goal.is_complete:
    ask_model()
    try_again()
```

anywhere in this package, and no unbounded poll.

---

## 11. Cancellation and pause — both cooperative, both honest

**Cancel** sets the goal's cancel event (once, never replaced), cancels the task
in flight through the Phase 2 boundary, refuses to start anything new, marks the
remaining steps `CANCELLED`, and ends the goal as `CANCELLED`. A step already
inside Windows is **not** killed: nothing here can interrupt it safely, and the
`GOAL_CANCELLED` event says `execution_in_flight` rather than claiming a kill.
The cancel event is also handed to Phase 4, so a verification in progress returns
`CANCELLED` instead of quietly passing.

**Pause** refuses to start a new step and leaves the goal in `PAUSED`. A step
already running finishes first. `GOAL_PAUSED` carries a note saying exactly
that. **Resume** clears the flag and continues.

`run()` may be called again on a paused or waiting goal and continues from where
it stopped. That is *not* crash-resume — see below.

---

## 12. Confirmation stays authoritative

The planner cannot override the gate and the executor does not bypass it. The
action parks behind `core/confirm.py` and returns `REQUIRES_CONFIRMATION`; the
step becomes `AWAITING_CONFIRMATION` and the goal reports
`AWAITING_CONFIRMATION` — a state that says "waiting for the user" rather than
one that looks finished.

Three endings, and no fourth:

| What happened | Step | Goal |
|---|---|---|
| the user approved and Windows ran it | `COMPLETED` (with a note that the confirmed path does not run independent verification) | continues |
| the user **refused** | `BLOCKED` | `BLOCKED` |
| the gate could not ask (no interface, banner failed) | `FAILED` / `AUTHORIZATION_UNAVAILABLE` | `FAILED` |

Nothing sits in "awaiting confirmation" after an explicit refusal, and a goal
that is waiting is visibly waiting rather than parked invisibly.

---

## 13. Events

Goal and step events go on the existing Phase 2 `EventBus`. `Event` gained
additive `goal_id` and `step_id` fields with defaults, so existing emitters and
subscribers are unaffected. Phase 2 events (`TASK_*`, `ACTION_*`,
`VERIFICATION_*`) are still emitted for every step.

```text
GOAL_CREATED  GOAL_PLANNING  GOAL_PLANNED  GOAL_STARTED
GOAL_PAUSED   GOAL_RESUMED   GOAL_CANCELLED
GOAL_COMPLETED  GOAL_FAILED  GOAL_NOT_VERIFIED

STEP_STARTED  STEP_FINISHED  STEP_VERIFIED  STEP_NOT_VERIFIED
STEP_FAILED   STEP_BLOCKED   STEP_CANCELLED
STEP_AWAITING_CONFIRMATION
STEP_RECOVERY_STARTED  STEP_RECOVERY_COMPLETED
```

---

## 14. Persistence — history, not resume

`state/goals.json`, beside `state/tasks.json`. Atomic (`tmp` + `os.replace`),
bounded (100 goals, newest kept, deterministic order), suspicious on load: a
malformed record is skipped and reported, an unreadable file is moved aside
rather than overwritten, an unknown schema version is reported and not
interpreted.

Nothing secret is written: `metadata` and `context` are scrubbed of
credential-shaped keys and key-shaped strings on the way to disk, while the
running goal keeps them.

**Crash-resume is not implemented and is not claimed.** A goal left
`PLANNING`/`READY`/`RUNNING`/`PAUSED`/`AWAITING_CONFIRMATION` when NEO stopped is
marked `FAILED`/`INTERRUPTED` on the next load — the same rule Phase 2 applies to
tasks. State after process termination is *interrupted*, not resumable.

---

## 15. Security

Every Phase 1–4 guarantee is preserved. The goal layer adds none of its own
escapes:

* no `exec`, `eval`, `compile`, `__import__`
* no `subprocess`, no shell, no PowerShell, no `ctypes`
* no model-generated code, and no code-shaped value anywhere in a plan
* every operation checked against the real registry before execution
* confirmation unchanged and un-bypassable
* no fabricated state: every recorded value came from an observation
* no fabricated verification: the Phase 4 verifier is the only thing that may
  write `VERIFIED`
* no permission escalation: the recovery ceiling cannot be raised by a plan

---

## 16. Tests

```bash
# unit + regression (no desktop interaction)
python -m unittest discover -s tests -t .

# Phase 5 only
python -m unittest tests.test_goals tests.test_goal_execution

# real Windows, whole goals against the live desktop
NEO_WINDOWS_INTEGRATION=1 python -m unittest tests.test_goals_integration -v
```

[tests/test_goals.py](../tests/test_goals.py) — the goal model, the bounds, retry
policy, planning validation, bounded proposing, and goal history.

[tests/test_goal_execution.py](../tests/test_goal_execution.py) — ordered
execution, dependencies, observed-state references, **truthfulness**, bounded
recovery, cancellation, pause/resume, confirmation refusal, and the static
security scans. The one to read first is
`test_a_successful_call_with_an_unobservable_effect_is_not_a_goal_success`.

[tests/test_goals_integration.py](../tests/test_goals_integration.py) — three
real goals on the live desktop:

| Goal | What it proves |
|---|---|
| **A** Notepad: open → verify window → set text → verify text | two dependent verified steps, the second using the handle the first reported |
| **B** Calculator: open → verify window → focus → verify foreground | a real `VERIFIED` focus against the live foreground lock |
| **C** type into Notepad, then close it | Notepad's save dialog keeps the window, `close_window` reports SUCCESS, and the goal reports **NOT_VERIFIED** — never success |

Goal C is the one that matters. It is the proof that Phase 5 trusts Phase 4
rather than the action's own good intentions.

### Test isolation

Windows that existed before the suite started are recorded at import and are
never acted on and never closed. Only windows the suite opened are cleaned up.
Notepad is single-instance, so the window under test is usually the user's own;
text written into it is read back and restored afterwards. When Windows refuses
foreground activation because the user is working, the test skips with the exact
reason rather than weakening the check. A goal that cannot be exercised on this
machine says so and skips — it does not pass by asserting something weaker.

---

## 17. Known limitations

* **No natural-language planner.** A goal is planned from an explicit step list,
  a whitelisted recipe, or a bounded proposer seam. "Open Notepad and put hello
  in it" does not become a plan by being read.
* **The planner vocabulary is one action deep.** Recipes and explicit plans use
  `windows_control` and its `operation` parameter; there is no second-level
  "goal action".
* **Pause and cancel cannot interrupt a running OS call.** Nothing in NEO can, and
  Phase 5 does not pretend otherwise.
* **A confirmed step is not independently verified.** The Phase 2 gate runs the
  authorized work on its own thread and the task is closed with the action's own
  report; that path does not run the Phase 4 verifier. The step is recorded as
  `COMPLETED` with a note saying so, never as `VERIFIED`.
* **Recovery cannot change the plan.** No adaptive replanning, no new operations,
  no model-invented strategies.
* **One confirmation at a time**, because `core/confirm.py` holds one token.
* **`max_goal_seconds` is checked between steps and attempts**, not inside a
  Windows call.
* Python 3.11–3.13 and macOS/Linux remain unverified for this phase, exactly as
  for Phases 3 and 4.

---

## 18. What Phase 6+ is

Phase 5 executes a plan it was given. Everything that decides *which* plan, and
everything that changes one after it starts, is deliberately absent:

| Capability | Phase |
|---|---|
| model-backed goal decomposition from natural language | 6 |
| bounded adaptive replanning with a model in the loop | 6+ |
| richer tools ("search the web and summarise") as goal actions | 6 |
| long-term semantic memory, embeddings, a vector store | 6+ |
| proactive / background activity | later |
| autonomous credentials, finance, messaging, deletion | not planned; these need Phase 7 policy and are refused until then |
| self-modifying source, self-replication, mobile, robotics, smart home | out of scope |