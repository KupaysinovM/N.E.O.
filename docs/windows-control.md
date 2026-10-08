# Windows control (Phase 3)

NEO can now list, inspect and operate real Windows windows and controls through
Windows UI Automation and Win32, and every one of those operations runs as an
ordinary task through the Phase 2 execution layer.

This document describes what is implemented, what is deliberately absent, and
where the boundaries are. Nothing here is a claim about applications NEO has not
actually driven: different applications publish very different accessibility
information, and the tables below say which ones were verified.

---

## 1. Architecture

```text
NEO Task
   ↓
ExecutionRequest  (core/execution.py)
   ↓
ExecutionLayer — policy, status, task state, events, cancellation, confirmation
   ↓
windows_control action  (actions/windows_control.py)
   ↓
Windows façade  (core/windows/control.py)   ← the only module callers use
   ├── win32.py    real window/process primitives (pywin32)
   ├── uia.py      UI Automation sessions and patterns (pywinauto/comtypes)
   ├── apps.py     allowlisted application resolution and launch (no shell)
   ├── input.py    validated keyboard and mouse primitives (pyautogui)
   ├── models.py   NEO's own UIElement / WindowInfo / ProcessInfo
   ├── identifiers.py  element matching and unambiguous resolution
   ├── keys.py     key-name vocabulary and combination validation
   ├── sensitive.py   password-field protection and redaction
   └── errors.py   Windows error kinds mapped onto the shared taxonomy
```

`core/windows/` is the platform boundary. Nothing outside it imports `win32gui`,
`comtypes` or `pywinauto`; a macOS or Linux adapter can be added beside it
without the task and execution layers noticing. `core/windows/__init__.py`
exposes `IS_WINDOWS`, `is_supported()` and `unavailable_reason()`, and every
façade operation returns `NOT_AVAILABLE` with an explanation off Windows rather
than pretending to work.

## 2. Models

NEO never passes a pywinauto object around. Discovery converts every wrapper
into its own dataclass at the boundary (`uia.UiaSession.to_element`).

**`UIElement`** — `runtime_id`, `control_type`, `name`, `automation_id`,
`class_name`, `framework_id`, `enabled`, `visible`, `offscreen`, `focused`,
`bounds`, `capabilities`, `process_id`, `window_handle`, `depth`, plus the
security fields `sensitive` and `sensitive_reason`. Missing values are `None`.
A field Windows does not publish is never guessed.

**`WindowInfo`** — `handle`, `title`, `process_id`, `process_name`,
`class_name`, `enabled`, `visible`, `minimized`, `maximized`, `bounds`,
`is_active`.

**`ProcessInfo`** — read-only: pid, name, status, CPU and memory where the OS
publishes them. Phase 3 has no process-killing operation.

## 3. Element identification

A control is addressed by whatever the application actually publishes:
`automation_id`, `name`, `control_type`, `class_name`, and optionally
`index` when the caller has knowingly accepted a position among matches.

* **No field is treated as universally unique.** `automation_id` is preferred,
  `name` is frequently duplicated (real Notepad publishes more than one
  `Minimize`), so a name alone can be ambiguous.
* **Ambiguity is refused, not resolved.** More than one candidate raises
  `ELEMENT_AMBIGUOUS` and lists the closest candidates. `index` is validated
  always; an out-of-range index is refused rather than clamped, and an index is
  never silently applied when only one candidate matched.
* **No fake stable IDs.** `element_id` is a handle for passing one result to a
  later call in the same conversation. It is documented as such, and
  `identity_note` says so on every element.

## 4. Discovery

`list_controls` walks the window's tree breadth-first with hard bounds:
`max_depth` (default and maximum 12), `limit` (maximum 300), optional
`control_type`, `named_only` and `visible_only` filters. The desktop is never
walked as a whole — a window handle, a depth and a result limit are required,
because an unbounded tree would be thousands of controls the model cannot use.

`desktop_snapshot` returns a bounded read-only view: the active window, the
top-level windows (default 8) and a small control sample for the active window.
It is raw Windows state for later phases, not a world model.

## 5. Operations

28 operations, all reachable through the single `windows_control` action with an
`operation` parameter.

**Windows:** `list_windows`, `active_window`, `locate_window`, `focus_window`,
`window_state` (minimize / maximize / restore / normal), `close_window`

**Controls:** `list_controls`, `find_control`, `invoke`, `toggle`, `select`,
`expand`, `collapse`, `focus_control`, `set_value`, `get_value`

**Input:** `press_keys`, `type_text`, `click`, `move_mouse`, `scroll`, `drag`,
`cursor_position`

**Applications and processes:** `launch_app`, `app_running`, `list_processes`,
`process_info`, `desktop_snapshot`

Interaction patterns used: Invoke, Toggle, Value, SelectionItem,
ExpandCollapse, Text, SetFocus. A control that does not expose the pattern
yields `NOT_SUPPORTED` / `UNSUPPORTED_CONTROL` — NEO does not fall back to
clicking it silently.

## 6. Fallback hierarchy

```text
1. UI Automation patterns        invoke a real Button, not a pixel
2. keyboard / mouse primitives   validated key names, bounds-checked coordinates
3. screenshot + vision           unchanged from the existing vision path
```

Browser work is deliberately **not** here: `actions/browser_control.py`
(Playwright) stays authoritative for DOM, and UI Automation is for desktop UI.

## 7. Application launching

`launch_app` resolves a name through an explicit alias table, the system's own
executable lookup, or an absolute path to an existing executable, then starts it
with `subprocess.Popen([target], shell=False)`. There is no command string, no
PowerShell, and no interpretation step between what the model says and what is
executed. Scripts are refused; a name that resolves to nothing is
`APPLICATION_NOT_FOUND`.

The report says what was started and which window appeared. It never says the
application did anything useful.

*Windows 11 hands applications off.* `notepad.exe` and `calc.exe` are stubs that
exit immediately and another process owns the window. NEO matches the new window
by the program that owns it, against a snapshot taken before the launch, so a
window that was already open is never reported as something this call created.
Where a Store app is drawn inside a shared host window
(`ApplicationFrameHost.exe`), NEO prefers the window that actually publishes an
accessible control tree and records `chosen_because` explaining which signal
decided it. On Windows 11 Calculator this matters: the calculator's own process
creates a window with no controls at all.

## 8. Security boundaries

* **No arbitrary command executor.** There is no `run_command(command: str)`
  tool. Launch uses an allowlist; nothing a model writes becomes a command line.
* **No arbitrary Python.** `exec()` / `eval()` remain absent; a model-written
  "run this" request is simply an unknown operation.
* **Confirmation stays authoritative.** `close_window` is the only gated
  operation, and it goes through the existing `core/confirm.py` gate. If the
  gate cannot ask — no interface bound, or the banner failed — the action ends
  `FAILED` / `AUTHORIZATION_UNAVAILABLE` instead of parking a task that could
  never be resolved.
* **Sensitive fields.** A control Windows marks as a password field is flagged
  from `IsPassword`, and heuristics only ever add to that on value-bearing
  types. Sensitive values are withheld from discovery results, refused on read
  (`ACCESS_DENIED`), and redacted from summaries. Writing one is refused unless
  the caller passes `authorized_sensitive` — a parameter that is deliberately
  **not** in the tool declaration, so nothing the model writes can set it.
* **Input is validated, not interpreted.** Key names come from a fixed
  vocabulary of 97 aliases plus the modifiers `ctrl shift alt win command`,
  maximum 4 keys per combination, 4000 characters per text entry, and control
  characters are rejected. There is no raw-keycode escape hatch. Coordinates are
  bounds-checked against the real screen and `FAILSAFE` stays on.
* **Read-only process information.** There is no kill operation in Phase 3.

## 9. Error taxonomy

Windows failures use the shared `ErrorKind` enum rather than a parallel system:
`WINDOW_NOT_FOUND`, `ELEMENT_NOT_FOUND`, `ELEMENT_AMBIGUOUS`,
`ELEMENT_DISABLED`, `ELEMENT_STALE`, `UNSUPPORTED_CONTROL`,
`INVALID_ARGUMENT`, `TIMEOUT`, `ACCESS_DENIED`, `PROCESS_NOT_FOUND`,
`APPLICATION_NOT_FOUND`, `OS_ERROR`, `CANCELLED`.

Each maps onto an execution status: not-found and not-found-application →
`NOT_AVAILABLE`; unsupported control → `NOT_SUPPORTED`; everything else →
`FAILED`; cancellation → `CANCELLED`.

## 10. Timeouts, stale elements, cancellation

* **Timeouts.** Win32 calls run with a 5 s deadline, UI Automation with 8 s.
  Both run the call on a worker thread with a deadline and report `TIMEOUT` when
  it expires. Threads are never killed — a hung application can delay a call,
  but it cannot take NEO's process with it.
* **Stale elements.** An element whose window closed or redrew is reported as
  `ELEMENT_STALE`, never retried onto a different element.
* **Cancellation.** Every operation accepts the Phase 2 `cancel_event` and
  checks it before doing anything. A task cancelled before dispatch executes
  nothing. A running UI Automation call cannot be interrupted; the result says
  so plainly instead of pretending the call was killed.

## 11. What is NOT implemented

* The façade does not own a comprehensive world model. The execution layer
  applies fixed, action-declared expectations where available; an invocation
  response alone is not proof that the application responded.
* No planner, no retries, no recovery, no replanning, no autonomous multi-step
  execution. Primitives only; a caller decides what to call next.
* No continuous desktop polling or proactive intelligence.
* No embeddings or vector memory.
* A central Phase 7 policy now authorizes before dispatch, but prompt-injection
  defenses, complete sensitive-data controls, and the attack-test matrix remain
  unfinished. See [docs/security.md](security.md).
* No registry editing, no PowerShell executor, no firewall or security changes.
* No process termination.
* No macOS or Linux adapter (the seam exists; the adapter does not).

## 12. Capability status

**SUPPORTED** — verified against real Windows on the development machine:
window enumeration and titles, active window, focus, minimize/maximize/restore,
control discovery with capabilities, Invoke, Value set/get, menu item discovery,
keyboard entry and combinations, mouse primitives, application launch for
Calculator and Notepad, read-only process information, desktop snapshot,
ambiguity refusal, stale-element reporting, confirmation gating.

**PARTIALLY SUPPORTED** — depends entirely on what the application publishes:

* Applications that expose no accessibility tree (older games, some Electron
  and custom-drawn UIs) can only be reached through keyboard/mouse, and only by
  coordinates that may change between runs.
* Window state is read through `IsIconic` and `GetWindowPlacement`; some
  virtual desktops and shell surfaces report surprising titles (the desktop
  foreground window can have an empty caption — that is reported as-is).
* Store-app host windows are identified by which window publishes controls, not
  by process name, because the host process is shared with other applications.
* Text entry uses the Value/Text pattern where available and simulated keys
  otherwise; applications that intercept raw keys may behave differently.
* Drag is a bounds-checked mouse drag, not a UIA drag-and-drop pattern.

**NOT SUPPORTED** — returns an explicit status rather than a guess:

* Any Windows Automation pattern beyond the nine listed above.
* Reading or writing a password field without explicit authorization.
* Windows that cannot be identified unambiguously (`ELEMENT_AMBIGUOUS`).
* Applications with no UIA metadata and no stable layout.
* Anything requiring arbitrary command execution, registry writes, or elevated
  privileges.

## 13. Tests

```bash
# unit + regression (no desktop interaction)
python -m unittest discover -s tests -t .

# real Windows integration — opt-in, launches Calculator and Notepad
NEO_WINDOWS_INTEGRATION=1 python -m unittest tests.test_windows_integration -v
```

The integration module records every window that existed before it started and
never acts on or closes one of them: Notepad and Calculator are single-instance,
so "the window I just launched" and "the window that was already open" are the
same window. Only windows the tests opened are closed again.