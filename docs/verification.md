# Verification (Phase 4)

Phase 3 let NEO act on the machine. Phase 4 lets it check whether the action
produced the state it was supposed to produce — and, when it cannot tell, to say
so instead of claiming success.

```text
Task → ExecutionRequest → action → real Windows
     → observe → compare against an expectation
     → VERIFIED / NOT_VERIFIED / NOT_AVAILABLE / AMBIGUOUS / STALE
     → ExecutionResult (execution_status, verification_status, final_status)
```

The rule this phase exists to enforce:

> **"I sent the command" and "the requested state exists" are different claims,
> and only the second one is worth reporting to the user.**

---

## 1. Layout

```text
core/verification/
    observation.py   reading real state, with provenance on every value
    world.py         a minimal bounded snapshot of what was just observed
    expectations.py  structured expectations, chosen by code
    verifier.py      bounded polling, comparison, honest outcomes
```

It reuses the Phase 3 Windows adapter (`core/windows/control.py`) for every
read. There is one Windows implementation in this project, and verification does
not get a second one to disagree with it.

## 2. Observation and provenance

Every value read for a check is an `Observation`:

| field | meaning |
|---|---|
| `source` | which subsystem answered: `windows_win32`, `windows_uia`, `windows_apps` |
| `observed_at` | when it was read |
| `target` | what it was about |
| `kind` | window, control value, toggle state, … |
| `value` | what Windows said, or `None` |
| `freshness` | `current`, `stale`, `unknown` |
| `sensitivity` | `safe`, or `sensitive_withheld` |
| `error_kind` | why it could not be read, when that is the case |

There are no confidence scores. A number invented to look intelligent would say
nothing about where a fact came from; `source` and `observed_at` say everything
needed.

**Absence is an observation.** "No window matches this description" is `value:
False` with no error, because Windows did answer. A lookup that could not be
answered — ambiguous, refused, OS error — carries an `error_kind` instead. The
distinction matters: conflating them is how "the window closed" gets verified by
a lookup that never happened. That bug existed during development and the real
Windows tests caught it.

## 3. World state

`WorldState` is a bounded record of what was just observed — not a world model,
not memory, not embeddings, and it plans nothing.

Each entry is one of four states:

* **observed** — read from the machine, with its source and timestamp
* **inferred** — derived by a rule that the entry states in words
* **unknown** — asked for, not available; the reason is kept
* **stale** — observed earlier; the value is kept but is no longer served

`mark_stale()` ages entries, and `get()` refuses to return a stale one. Nothing
is deleted, so "we saw this earlier" is never lost to "we cannot see it now".

## 4. Expectations

An expectation is a structured record, chosen by ordinary Python from a fixed
vocabulary, based on which operation ran and which parameters were passed.

**The model never writes one.** A caller picks `focus_window`; which fact has to
be true afterwards is decided in `expectations.py`. There is no `exec()`, no
`eval()`, no shell command, and no code path from model text to a check.

| operation | expectation | how it is checked |
|---|---|---|
| `launch_app` | the window exists | re-ask Windows whether it is there |
| `app_running` | the process is alive | read-only process check |
| `focus_window` | it is the foreground window | compare against the live foreground handle |
| `close_window` | it is gone | observe **absence**, not "the call returned" |
| `set_value` | the value reads back as written | read the control's Value |
| `toggle` | the toggle state it reported | read the state; compare with the pre-state |
| `select` / `expand` / `collapse` | the state it reported | read the state |
| `invoke` | **none** | a button can mean anything |
| `click`, `press_keys`, coordinates | **none** | no universal rule exists |

`preconditions()` capture state *before* an action runs, which is what makes
"this toggle actually changed" a question with an answer rather than a
tautology.

## 5. Outcomes

| status | meaning |
|---|---|
| `VERIFIED` | the expected state was observed |
| `NOT_VERIFIED` | it was looked for, within the time bound, and was not there |
| `AMBIGUOUS` | more than one target matched, so none can be said to have changed |
| `STALE` | the control was gone when NEO looked |
| `NOT_AVAILABLE` | nothing observable to check — no rule, no pattern, or a withheld secret |
| `VERIFICATION_FAILED` | the check itself could not run |
| `CANCELLED` | cancellation stayed truthful while waiting |

## 6. Truthful results

`ExecutionResult` now separates three things:

```text
status              what the execution reported
verification_status what an independent look found
final_status        what a caller should branch on  (result.outcome)
verified            True only when something was checked and found true
```

The only change verification is allowed to make is `SUCCESS` → `NOT_VERIFIED`.
It can never turn a failure into a success.

```text
execution SUCCESS + verified      → final SUCCESS       verified=True
execution SUCCESS + unverified    → final NOT_VERIFIED  verified=False
execution SUCCESS + not checkable → final SUCCESS       verified=False
execution FAILED                  → final FAILED        (never rescued)
```

A `NOT_VERIFIED` result carries `ErrorKind.NOT_VERIFIED` in the shared taxonomy
and says why in plain words. The model is told *"I did the action and could not
confirm the result"* — never a bare "done".

## 7. Timeouts, staleness, cancellation

* **Bounded.** Every check has a finite timeout and poll interval, defaults are
  6 s / 0.4 s, and an expectation carries its own bound which the verifier
  respects. Polling never loops forever and never invents a pass at the end.
* **Re-observed.** Each attempt reads the machine again. A remembered HWND is
  never compared against a remembered title — handles are revalidated and
  controls re-resolved, because Windows recycles handles and applications redraw.
* **Cancellation-aware.** Waits check `cancel_event` between attempts and return
  `CANCELLED`. No thread is ever killed.
* **Asynchronous UI.** Launch and close are polled, because a window that is
  closing may take a moment to disappear.

## 8. Sensitive data

Phase 3's protection is unchanged and is not bypassed here:

* password fields are flagged from `IsPassword` and never read;
* a refused read produces an observation with **no value** — there is no branch
  that attaches the secret afterwards;
* sensitive expectations return `NOT_AVAILABLE` with the reason, so a password
  field is never "verified" by reading it;
* observations travel into task history, events and world state carrying
  `sensitivity`, and the withheld value is not in any of them.

## 9. Events

Three additions to the existing event bus, and no others:

* `VERIFICATION_STARTED` — a check was about to run, with the expectation
* `VERIFICATION_COMPLETED` — it reached a conclusion (`VERIFIED`, or "there is
  nothing to check")
* `VERIFICATION_FAILED` — it concluded the expected state was not there

A check that found nothing to check is a *completed* verification, not a failed
one; the distinction matters to anything reading the history.

## 10. What is actually verified

**VERIFIED on this machine, against real Windows:**

* a launched application's window exists and Windows can address it
* a focused window really is the foreground window
* a written text value reads back exactly as written
* a closed window is gone rather than merely hidden
* an application that is running is running, read-only
* an ambiguous control cannot be verified
* a value that was never written is not verified
* an operation with no rule reports `NOT_AVAILABLE`

**NOT VERIFIED, and not claimed:**

* that a button did what its label promised (`invoke` has no rule)
* that a typed message was sent, a file was saved, a purchase completed
* anything at all about applications with no accessibility metadata
* anything about macOS or Linux — there is no adapter there yet

## 11. Limitations

* Verification knows only the checks listed above. A richer rule set would mean
  application-specific knowledge, which this phase deliberately refuses to
  invent.
* Notepad, Calculator and Explorer behave differently; only the first two have
  been driven. Window handles can die between polls on a busy desktop, and the
  tests say so rather than hiding it.
* Windows' foreground lock refuses activation while the user is working; NEO now
  retries a few times and then reports `ACCESS_DENIED` instead of pretending.
* The world state is a snapshot, not a history. It says what is true now, and
  nothing about how it got that way.
* Screenshot and vision capture are still observation, not interpretation: a
  screenshot is not used here to decide whether something worked.

## 12. Phase 5

Phase 5 is where NEO starts deciding what to do next: goal decomposition,
multi-step execution, and choosing between tools. It is now built, in
[docs/goals.md](goals.md), and it consumes this package rather than replacing
it.

The difference in one line:

```text
Phase 4  action → observe → verify → report the truth
Phase 5  goal   → plan several actions → run them → verify each → stop or continue
```

What Phase 5 takes from here, unchanged:

* `verify()` and `Status` — a step's outcome is decided by the same engine, and
  `NOT_VERIFIED`, `AMBIGUOUS`, `STALE`, `NOT_AVAILABLE` and `CANCELLED` mean
  exactly what they meant before.
* `expected_after()` / `expectation_for` — the action still owns its own
  verification contract, and a plan cannot weaken it.
* `WorldState` — captured per goal and refreshed during a bounded recovery.
* Every bound in `verifier.py` still bounds each step's verification.

What Phase 5 adds on top, and what it does **not** take:

* `execution SUCCESS + verification NOT_VERIFIED` now decides a *goal*, not just
  a call: the step is `NOT_VERIFIED`, the goal is `NOT_VERIFIED`, and the steps
  that depended on it never run.
* Retry and recovery are decided from the real `ErrorKind` taxonomy and are
  bounded per step and per goal. They re-observe and repeat the same step; they
  never replan.
* Planning exists now, but it is bounded and validated against the registries.
  Nothing in this package plans, and nothing in it should.