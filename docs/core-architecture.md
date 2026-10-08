# NEO core architecture (Phase 2)

This document describes the task and execution core that sits underneath the
existing assistant. It describes **what the code in this tree does today** —
not what later phases will add.

Phase 2 introduced task and execution lifecycle. Later phases added policy,
confirmation tokens, verification, goals, and live-tool adapters around that
same path. This document describes the current architecture and calls out
remaining Phase 7 limitations.

```text
USER
  ↓
NEO INTERFACE            ui.py — HUD, activity log, confirm banner
  ↓
NEO CORE                 main.py — NeoLive session loop, tool adapters
  ↓
TASK MANAGER             core/task_manager.py — lifecycle, states, cancellation
  ↓
EXECUTION LAYER          core/execution.py — policy, confirmation, results
  ↓
ACTION / TOOL REGISTRY   core/action_loader.py, core/plugin_loader.py  (authoritative)
  ↓
REAL PC / OS / BROWSER / FILE SYSTEM
```

The model reasons about what should happen. NEO's core owns the task, the
execution layer invokes an approved capability, and the operating system does
the work.

---

## Modules

| File | Responsibility |
|---|---|
| [core/task_models.py](../core/task_models.py) | `Task`, `TaskStatus`, the legal transitions, `TaskError`/`ErrorKind`, `TaskContext` |
| [core/events.py](../core/events.py) | `EventType`, `Event`, in-process `EventBus` |
| [core/task_store.py](../core/task_store.py) | Task history persistence (`state/tasks.json`), atomic save, suspicious loader |
| [core/task_manager.py](../core/task_manager.py) | The only writer of task state; lifecycle, cancellation, reconciliation |
| [core/execution.py](../core/execution.py) | `ExecutionRequest` / `ExecutionResult`, authorization, confirmation, result classification, and task updates |
| [core/security.py](../core/security.py) | Static deny-by-default capability policy, risk classification, redaction, request fingerprints |
| [core/confirm.py](../core/confirm.py) | The single UI-token confirmation gate and resolution callback |
| [core/goals/](../core/goals/) | Phase 5 — goals, bounded plans, ordered steps, verified continuation, bounded recovery. See [docs/goals.md](goals.md) |
| [tests/](../tests/) | Automated tests for all of the above, plus Phase 1 regression checks |

## Task

A task is a record of one request. It is not a plan, not a conversation turn,
not a memory, and not a promise that the request can be resumed later.

| Field | Meaning |
|---|---|
| `task_id` | uuid4 hex — genuinely unique, not a counter or a timestamp |
| `user_request` | short human-readable "what was asked" (never executed) |
| `status` | one of the six canonical states |
| `created_at` / `started_at` / `completed_at` | wall-clock epoch floats |
| `current_step` | current step identifier; free-form model step text is not persisted here |
| `current_action` | the registered action bound to the task |
| `result` | action result, or a redacted placeholder for sensitive/external results |
| `error` | `TaskError{message, kind, detail}` when it did not succeed |
| `metadata` | invocation info and the structured execution result |

## Task states

```text
PENDING → RUNNING
PENDING → CANCELLED

RUNNING → PAUSED
RUNNING → COMPLETED
RUNNING → FAILED
RUNNING → CANCELLED

PAUSED  → RUNNING
PAUSED  → CANCELLED
```

`COMPLETED`, `FAILED` and `CANCELLED` are terminal. Every other move raises
`TaskStateError` with the from/to pair attached — state is never silently
rewritten. `PAUSED → COMPLETED` is deliberately absent: pausing does not stop an
action that is already running, so when a result arrives for a paused task the
execution layer resumes it first and then applies the outcome.

`start_task()` requires `PENDING` and `resume_task()` requires `PAUSED`, so a
resume can never quietly start something that was never paused.

## Task Manager

`core/task_manager.py` — create, get, list, start, pause, resume, cancel,
complete, fail, plus `context_for()`, `current_task()`, `set_action()`,
`record_result()` and `mark_awaiting_confirmation()`.

It owns task state and nothing else. It never touches the operating system,
never calls a tool and never talks to a model. All mutations take one lock, so a
cancel arriving from the UI while an action runs on an executor thread is safe.

## Execution request and result

```python
ExecutionRequest(action, arguments, task_id, step, requested_by, tool_call_id)
ExecutionResult(status, action, task_id, message, data, error, verified)
```

`arguments` stay structured data. They are never rendered into Python source,
never handed to the interpreter and never used to build a command line. A
malformed request is refused before any registry is consulted.

Canonical statuses: `SUCCESS`, `FAILED`, `NOT_SUPPORTED`, `NOT_AVAILABLE`,
`REQUIRES_CONFIRMATION`, `CANCELLED`.

The execution layer authorizes before invoking a name resolved against
`actions/` first, then `plugins/` — the precedence the app already had. The
existing registries remain authoritative.

### Truthful success

An action returns a sentence. Some sentences are explicit refusals and are
mapped exactly:

| The action returned | Result |
|---|---|
| `[CONFIRMATION_PENDING] …` | `REQUIRES_CONFIRMATION` |
| `[CONFIRMATION_UNAVAILABLE] …` / the gate's "I have not done it" wording | `FAILED` (`AUTHORIZATION_UNAVAILABLE`) |
| `[CONFIRMATION_FAILED] …` | `FAILED` (`INTERNAL_ERROR`) |
| `NOT_SUPPORTED: …` | `NOT_SUPPORTED` |
| `NOT_AVAILABLE: …` | `NOT_AVAILABLE` |
| `Tool 'x' failed: …` / `The 'x' plugin failed: …` | `FAILED` (`ACTION_FAILED`) |
| `Action 'x' is not available.` / `Plugin 'x' …` / `Unknown tool/action: …` | `NOT_AVAILABLE` (`UNKNOWN_ACTION`) |
| anything else | `SUCCESS`, `data["legacy_message"] = true` |

Prose is never pattern-matched. The last row is the honest limit of the existing
tools: the action ran through its own real code path and reported completion
without raising. Such a result does not claim independent verification. Phase 4
verification exists for actions that declare a structured expectation; actions
without one remain `NOT_AVAILABLE` for verification. Coverage is limited; see
[docs/verification.md](verification.md).

### Errors

`ErrorKind` distinguishes: `INVALID_REQUEST`, `UNKNOWN_ACTION`,
`INVALID_ARGUMENTS`, `AUTHORIZATION_REQUIRED`, `AUTHORIZATION_DENIED`,
`AUTHORIZATION_UNAVAILABLE`, `ACTION_UNAVAILABLE`, `ACTION_NOT_SUPPORTED`,
`ACTION_FAILED`, `TASK_CANCELLED`, `INTERNAL_ERROR`, `INTERRUPTED`.

Failures stay failures: an unknown tool returns an explicit `NOT_AVAILABLE`
result, a handler that raises becomes `FAILED` (the registry's crash guard
returns a `Tool 'x' failed: ExceptionType.` sentence, which the adapter maps
back), and the layer itself never raises into the conversation loop.

## Events

`TASK_CREATED`, `TASK_STARTED`, `SECURITY_AUDIT`, `ACTION_STARTED`, `ACTION_COMPLETED`,
`ACTION_FAILED`, `TASK_PAUSED`, `TASK_RESUMED`, `TASK_CANCELLED`,
`TASK_COMPLETED`, `TASK_FAILED`.

Each event carries type, task id, timestamp, action, status and structured data.
Delivery is synchronous and in-process; a subscriber that raises is logged and
skipped, because an observer must never break the action that emitted the event.
The bus keeps a small ring buffer in memory — events are not persisted.

## Cancellation

Cancellation is real, and it is honest about what it can do:

* **Cancelled while PENDING** — the action is never invoked. The task goes
  straight to `CANCELLED`.
* **Cancelled while RUNNING** — the task's cancellation flag is set, the task
  becomes `CANCELLED`, and nothing further starts for it. A Python call that is
  already inside an action cannot be interrupted, so this is reported as such:
  the result is `CANCELLED` with `data["completed_after_cancellation"] = true`
  and a message saying the action finished anyway. No thread is killed and no
  process is terminated.
* **Cancelled while PAUSED** — same, with no action in flight.
* An action may opt in to cooperative cancellation by declaring a
  `cancel_event` parameter; it then receives the task's `threading.Event` and
  can stop early. `data["interruptible"]` reports which of the two happened.
* Re-cancelling an already-cancelled task is a no-op; cancelling a finished task
  is refused (`TaskStateError`).

## Task context

`TaskContext` carries the task id, its status, its cancellation primitive, the
current action and the invocation info. It is created per execution and passed
as an argument — never a global — and it cannot mutate task state (the Task
Manager is the only writer).

## Persistence

`state/tasks.json`: id, request, status, timestamps, action, the result message
(redacted for sensitive/external actions), the error, and core metadata.
Written atomically
(temp file + replace) so an interrupted save cannot corrupt live state; capped
at 500 records, newest kept.

**Execution is not resumable.** No process handle, no partial plan, no retry
queue. A task that was `RUNNING` or `PAUSED` when NEO stopped is loaded as
`FAILED` / `INTERRUPTED` on the next start, with a message saying so, and the
user is told how many tasks were affected. Nothing is retried.

An unreadable file is moved aside as `tasks.corrupt-<timestamp>.json` and
reported; a single malformed record is skipped and reported. Corruption is never
repaired into something that looks like a successful task. Task history is not
memory: long-term user memory remains in `memory/memory_manager.py`.

## Authorization (Phase 7, partial)

```text
Execution request
      ↓
config.policy.config_failure()           ← invalid/missing config → SAFE_BLOCKED
      ↓                                     (no execution, no prompt)
Static AuthorizationPolicy               ← core/security.py (facts + provisional verdict)
      ↓
config.policy.resolve()                  ← the single effective ALLOW / DENY
      ↓
deny + report        |        allow silently
      ↓
Authorized execution → verification
```

Nothing in a model request can authorize itself. `core/security.py`
*classifies* every request (deny by default, least privilege, a model-supplied
`confirmed` field grants nothing); `config.policy.resolve()` is the one place
ALLOW or DENY is decided, and denial in either input wins. Every non-allow
resolves to deny + report, never deny + ask. `core/confirm.py` remains the
single confirmation service for when prompts are explicitly re-enabled, but
the normal execution path never reaches it — and a missing, unreadable,
malformed, partial, or contradictory policy document blocks execution
(`SAFE_BLOCKED`) rather than restoring the prompt.

An action that parks a confirmation leaves its task `RUNNING` with
`metadata["awaiting_confirmation"]` set. If the user confirms, the gate runs the
real work off the Qt thread and the execution layer closes the task with the
outcome it reports (`COMPLETED`, or `FAILED` if the work raised); declining or
expiry cancels the task (`AUTHORIZATION_DENIED`). If a second action parks a
confirmation, the gate's single pending token replaces the first one, and the
superseded task is closed as `AUTHORIZATION_UNAVAILABLE` rather than left
waiting forever.

## Configuration — one authoritative source per concern

There is exactly one configuration document set for authorization, and it is
loaded and validated by one module:

| Concern | Authoritative source |
|---|---|
| Authorization policy | `config/profile.json`, `config/permissions.json`, `config/security.json` — the three documents in `config/policy.DOCUMENTS`, each validated against `config/schema/*.schema.json` by the loader itself |
| What capabilities exist | `core/capabilities.py` (read-only inventory; the registries `core/action_loader.py` / `core/plugin_loader.py` remain the dispatch authority) |
| Who may act in code | `core/plugin_trust.py` + `plugins/.neo-plugin-trust.json` (exact SHA-256 plus an explicit capability allowlist; malformed manifest → no review) |
| Assistant settings | `config/neo_settings.json` (no credential ever appears here) |
| Model provider credential | `core/secret_store.py` (Windows DPAPI or an environment variable); the model itself is `core/gemini.py` |

`agents.json`, `providers.json`, and `world-model.json` do **not** exist in this
tree and nothing references them; creating them would duplicate concerns that
already have a single owner:

* **No `agents.json`.** NEO is a single-agent assistant. "Agent authority" is
  two booleans with one home — `permissions.policy.agentMayGrant: false` and
  `security.plugins.allowSelfAuthorization: false` — asserted by
  `config.policy._posture_contradictions()` and pinned by the schemas. There is
  no sub-agent registry to configure.
* **No `providers.json`.** There is one model provider, reached through
  `core/gemini.py`, with settings in `config/neo_settings.json` and its key in
  `core/secret_store.py`. A provider registry file would be a second copy of
  the same concern.
* **No `world-model.json`.** `core/verification/world.py` documents itself as
  explicitly *not* a world model: it is bounded runtime observation state with
  provenance (OBSERVED / INFERRED / UNKNOWN / STALE), not persisted knowledge
  and not configuration. Nothing about it belongs in a config document.

## Integration with the existing system

* **`main.py`** — every model-requested tool call, including live-session tools
  (`screen_process`, `close_camera`, `save_memory`, `recall_memory`, `undo`,
  `system_status`, `manage_monitor`, `shutdown_neo`), goes through
  `_run_registered_tool()` → Task Manager → Execution Layer → the existing
  action registry. Live tools use internal, non-advertised adapters, retaining
  their original model declarations without adding a second registry.
* **UI** — one subscriber logs a cancellation line, and startup reports tasks
  interrupted by a previous run. Everything else already surfaces through the
  action's own log lines and what NEO says. A richer task view is Phase 8; the
  event stream and `TaskManager.list_tasks()` are the interface it will use.
* **Which tools use the new contract** — all 17 discovered actions and any
  plugin go through the boundary and get a structured result. They are
  *compatibility-migrated*: their return strings are classified by the adapter,
  so none needed rewriting.

## Running the tests

```bash
python -m unittest discover -s tests -t . -v
```

No test dependency beyond the standard library. No test writes to the
repository: task history always goes to a temporary file.

## Where later phases plug in

| Phase | Plug-in point |
|---|---|
| 3 (Windows control) | new `actions/*.py` — they are discovered and get the boundary for free; declare `cancel_event` to be cooperatively cancellable |
| 4 (world model + verification) | `ExecutionResult.verified` and `data`, plus `Task.metadata["execution"]`; emit verification events on the same bus |
| 5 (goal-oriented execution) | **done** — [core/goals/](../core/goals/) composes `TaskManager` per step and routes every step through `ExecutionLayer`; see [docs/goals.md](goals.md) |
| 5b (bounded plan adjustment) | `Planner.propose()` is the seam a model-backed planner plugs into; validation and bounds already exist |
| 6 (memory) | separate store; task history is deliberately not memory |
| 7 (security policy) | [core/security.py](../core/security.py) authorizes before dispatch; see [security.md](security.md) |
| 8 (HUD) | subscribe to `EventBus` and read `list_tasks()` |

## Goals (Phase 5)

Phase 5 sits *above* this layer and changes none of it. A `Goal` owns an ordered,
validated `Plan`; each `Step` is executed by creating a real `Task` through
`TaskManager` and calling the same `ExecutionLayer`, so every goal step appears
in task history, on the event bus, and under the same cancellation and
confirmation rules as any other task.

```text
GOAL / PLAN / STEP        core/goals/
  ↓  (one real Task per attempt)
TASK MANAGER              core/task_manager.py
  ↓
EXECUTION LAYER           core/execution.py
  ↓
VERIFICATION              core/verification/   ← Phase 4 decides each step's outcome
```

A goal is `COMPLETED` only when every required step was `VERIFIED` (or ran with
nothing observable to check). `execution SUCCESS + verification NOT_VERIFIED`
yields a goal of `NOT_VERIFIED`, never `COMPLETED`. Full description in
[docs/goals.md](goals.md).

## Current limitations

* A running action cannot be interrupted; cancellation stops the task, not the
  call inside it (Phase 3/5 can add cooperative checks per action).
* Only one confirmation can be pending at a time, because the gate has one
  token; a superseded request is cancelled explicitly.
* Task history redacts common sensitive arguments and withholds results from
  sensitive-data and external-communication actions; this is not an exhaustive
  data-loss-prevention boundary.
* `SECURITY_AUDIT` events remain in the in-process event ring; durable audit
  storage and a complete plugin trust workflow do not exist.
* Phase 7 prompt-injection defenses, comprehensive security-aware verification,
  and the complete attack-test matrix remain unfinished. See [security.md](security.md).
