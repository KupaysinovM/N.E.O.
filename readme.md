## Phase 7 — Security, Permissions & Trust Architecture

**Goal:** Make NEO safe to operate across all the capabilities Phase 6 is bringing together.

Phase 7 must build a centralized security/authorization layer around the existing architecture.

### Scope

1. **Capability risk classification**

   * Read-only
   * Low-risk reversible
   * External communication
   * Sensitive-data access
   * Destructive
   * Irreversible
   * System-level

2. **Central authorization policy**

   * No capability decides its own security policy.
   * No model-generated `confirmed=true`.
   * No legacy Mark action can bypass NEO authorization.
   * Deny by default for unknown/high-risk operations.

3. **Human confirmation**

   * Central confirmation service.
   * UI-issued authorization tokens.
   * Single-use/short-lived tokens.
   * Bind authorization to the exact capability + operation + relevant target.
   * Prevent replay or substitution.

4. **Permission escalation**

   * A goal cannot silently acquire additional privileges.
   * New capability/risk boundary requires a new policy decision.
   * Previously authorized read access must not imply permission to send/delete/modify.

5. **Prompt-injection defense**
   Treat all external content as **data, not authority**:

   * webpages
   * browser content
   * emails
   * messages
   * documents
   * clipboard
   * screenshots
   * downloaded files
   * tool output

6. **Sensitive-data boundaries**

   * Passwords
   * API keys
   * tokens
   * cookies
   * private messages
   * financial information
   * credential fields
   * sensitive documents
   * protected clipboard contents

   Prevent accidental exposure to model context, logs, memory, screenshots, and telemetry.

7. **Plugin trust**

   * Classify plugins.
   * Validate plugin capabilities.
   * Prevent arbitrary plugin privilege escalation.
   * No plugin gets security authority simply because it is installed.

8. **Security audit trail**
   Record:

   * request
   * goal/step
   * capability
   * target
   * risk
   * authorization decision
   * confirmation
   * execution
   * verification
   * failure/recovery

9. **Security-aware verification**
   Verification must not itself leak sensitive information.

10. **Attack testing**
    Deliberately test:

* fake confirmation
* prompt injection
* malicious webpage
* malicious document
* malicious clipboard
* unauthorized capability
* privilege escalation
* confirmation replay
* forged verification
* sensitive-data leakage
* malicious plugin behavior

### Hard restrictions

No:

* arbitrary Python
* arbitrary shell
* security bypass
* credential extraction
* automatic privilege escalation
* self-modifying security policy
* model-controlled authorization

### Definition of Done

NEO can combine Phase 6's capabilities while having **one authoritative security boundary** between reasoning and execution.

### Repository-verified implementation status

This is a code-and-test status, not a claim that every roadmap acceptance test
has passed:

* **Phases 1–6 — SUBSTANTIALLY IMPLEMENTED.** The repository contains the task
  and execution core, Windows-control and verification layers, bounded goals
  and replanning, and the Phase 6 capability/memory integrations. Their real
  desktop, voice, and end-to-end limits remain those documented in
  [docs/goals.md](docs/goals.md), [docs/windows-control.md](docs/windows-control.md),
  and [docs/verification.md](docs/verification.md).
* **Phase 7 — PARTIAL / IN PROGRESS.** The centralized policy, confirmation
  boundary, and initial audit/data-retention controls described below are
  implemented and tested. The remaining security work is not verified complete.
* **Phases 8–17 — ROADMAP, NOT VERIFIED COMPLETE.** Existing features may
  overlap later phases, but the repository does not establish that their
  definitions of done have been met.

The full standard-library test suite reports **667 tests, 42 skipped, and no
failures**, on both Python 3.13.16 and 3.14.8. The focused Phase 7 security
module reports **67 passed**; the dashboard security module reports **21
passed**. The real-Windows opt-in modules were also rerun on this host; see
[docs/security.md](docs/security.md) for the individual results and the
timing-sensitive exceptions that remain.

### Phase 7 implementation status — PARTIAL

Implemented and tested:

* `core/security.py` provides a static, deny-by-default policy using the
  existing capability inventory. Unknown capabilities and all plugins are
  denied; model-supplied `confirmed` arguments do not grant access.
* File-backed and live-session model tools share the existing
  `TaskManager → ExecutionLayer → ActionRegistry` path. Live adapters are
  registered internally and are not advertised as duplicate model tools.
* Risky operations use the existing confirmation UI with a one-use,
  short-lived interface token. Authorization is tied to an HMAC fingerprint of
  the exact arguments; confirmation replay and argument substitution do not
  authorize another request.
* Sensitive/external action results are withheld from task history; registry-
  caught exception text is reduced to an exception type, and audit events avoid
  raw arguments.
* Tool results are bounded, recognized credential/token/private-key patterns
  and sensitive structured fields are redacted, and result strings are
  JSON-encoded under an explicit untrusted-data provenance label before being
  returned to the model. The central authorization policy remains independent
  of those results; external communication and destructive actions still need
  UI confirmation.
* Generated file/media analysis and YouTube summaries are redacted before
  returning or persisting. File-processing failures and YouTube failures no
  longer echo exception text; private filenames and YouTube request arguments
  are omitted from those local logs. Main-session error messages pass through
  the pattern redactor, and full raw tracebacks are not printed there.
* File, flight-page, and video-transcript model prompts encode external content
  as untrusted data; recognizable credential patterns are redacted before
  submission. The `file_processor` `run` operation is denied centrally and
  returns `NOT_SUPPORTED` even if its handler is called directly; it cannot
  run source code.
* The memory-write path rejects recognized secret-shaped values and sensitive
  credential fields rather than persisting them; prompt and recall formatting
  also omit recognized sensitive values already on disk.
* Plugin discovery enumerates `.py` files without importing or executing them.
  Since there is no isolated trusted plugin host, discovered Python plugins are
  disabled rather than granted process privileges.
* Browser automation uses a separate NEO-owned persistent profile in Chrome
  and Firefox rather than a user's regular browser profile. The active
  microphone state and confirmation UI disclose when audio, screen/webcam
  images, clipboard contents, or selected media are sent to the configured
  model. The local HUD log sink redacts recognizable sensitive patterns.
* Authorization and execution/verification outcomes are persisted in a local
  SQLite HMAC chain. A journal write failure before dispatch fails closed.
  Record edits and partial tail truncation are detected on read/append; this is
  not protection against an attacker who controls the current user account.
  Goal recovery/replanning events are also recorded without free-form step text.
  Audit key and journal ACLs are now restricted to the current user, SYSTEM,
  and local Administrators on Windows; their actual ACL entries were checked.
* The system prompt explicitly treats external content and tool output as data,
  stored memory values are JSON-encoded in the prompt, tool responses are
  labelled as untrusted data, and the optional dashboard receives transcript
  metadata without transcript text. Automatic session transcript summarization
  and replay into proactive prompts/briefings have been removed; the unused
  summary persistence/consumption helpers were also removed. Previously saved
  summaries may remain locally but are not read by the current application path.
* The remote dashboard requires TLS before starting or opening firewall access.
  It fails closed if local certificate setup fails, advertises HTTPS URLs, masks
  the one-time key input, rate-limits PIN/QR/device-token failures, and adds
  no-store, no-referrer, and browser security headers.
* Dashboard session and persistent-device credentials are now HttpOnly,
  SameSite cookies with matching server-side expiry; session cookies are Secure
  under HTTPS. Cookie-authenticated writes require a same-origin Origin, and
  WebSocket handshakes validate both the session cookie and Origin. Dashboard
  bearer credentials are no longer put in JavaScript storage or URLs. QR PINs
  travel in the URL fragment, are removed from browser history, and are
  exchanged by POST. The browser no longer uses the unauthenticated CBC
  message cipher or downloads CryptoJS; command transport requires TLS, and
  legacy encrypted payloads are rejected. A nonce-based script CSP is
  exercised by a real Chrome loopback test.
* Unsupported operations for the audited file, Windows-control, computer
  control, and explicit computer-settings action names are denied before
  invocation.
* Windows text-entry cancellation, credential-field refusal, disabled-control
  refusal, and invalid-method refusal are checked before importing UI
  Automation, so rejected writes do not initialize COM or reach an OS write.

Still incomplete or not verified:

* Prompt-injection handling is still partly model-instruction based. Tool
  outputs are now sanitized, provenance-wrapped data, and the authorization
  boundary cannot be overridden by their contents; this does not prove model
  resistance to every attack carried by pages, documents, messages, clipboard,
  screenshots, downloaded files, or tool output.
* Plugins remain disabled. There is no constrained plugin runtime or explicit
  trust/capability-review workflow; enabling arbitrary Python plugins inside
  NEO's process would grant them NEO's full privileges.
* The durable local audit chain does not protect against replacement/deletion
  by the current user, an administrator, or machine-level malware. ACL tests
  verified that inherited non-owner access is removed for the audit key and
  journal. A test demonstrates that joint replacement of the local key and
  journal is accepted as a new valid chain. No external append-only service or
  independent hardware trust anchor is configured.
* Sensitive-data handling is stronger but not comprehensive: static patterns
  and labeled structured fields are redacted at the model tool-result boundary;
  recognizable credential patterns in file text are also redacted before file
  content is submitted to the model. Generated summaries are redacted before
  local persistence, and recognized values are redacted at the HUD and main
  session error-log boundaries. New memory writes refuse recognized secrets,
  and transcript summarization/replay is removed. Old summaries can remain on
  disk but are not read by the current application path. Semantic
  private-content classification, screenshot OCR, and every third-party or
  legacy logging path are not comprehensively covered. Raw audio/image data is
  still sent when the user activates the relevant feature and confirms where
  required. Confirmation fingerprints bind the full request, but sensitive
  argument values are not displayed in the HUD for user review.
* Dashboard TLS startup failure and HTTPS URL selection are unit-tested, and a
  local HTTPS loopback integration test runs on this Windows host. Real Chrome
  exercised login, QR-fragment login, persistent-device reconnect, HttpOnly
  cookie invisibility, and an authenticated command. An actual phone-to-desktop
  TLS session and Windows certificate lifecycle/client-trust behavior have not
  been verified. The browser test accepts the local self-signed certificate;
  actual client trust acceptance remains unverified.
* Action-specific logging and error handling outside the file-processing,
  YouTube, main-session, and HUD paths above is not comprehensively audited;
  some legacy capabilities and third-party libraries may still retain or
  disclose sensitive details.
* The common text redactor also masks recognizable email addresses, phone
  numbers, IBANs, and credential-bearing URL query values. This is still
  pattern-based and does not identify private meaning from arbitrary prose,
  images, or audio.
* The 67-test Phase 7 security module exercises source-labelled synthetic
  injection payloads at the common tool-result boundary, a malicious local
  text-file fixture through the real file-processing path, local malicious
  HTML acquired through browser automation in isolated headless Chrome, a
  synthetic clipboard-read fixture, typed-command and persistence redaction,
  denied capabilities, fake/forged/replayed confirmation, plugin side effects,
  audit tampering/truncation/joint-replacement limits, and verification
  privacy. Dashboard security tests also verify
  that browser auth responses do not contain bearer tokens, HTTPS session
  cookies carry Secure/HttpOnly/SameSite attributes, expired sessions and
  device cookies are rejected server-side, cross-origin cookie requests and
  WebSockets are denied, and dashboard credentials do not appear in URLs. A
  live local TLS-socket and Chrome tests exercise login, QR-fragment login,
  device reconnect, CSP script execution, and the protected command path.
  The clipboard content is injected at
  the OS-read seam; actual user clipboard contents are neither read nor
  modified. Browser-action log lines and Playwright navigation errors are
  redacted before they reach the console or the HUD, so a page URL's
  credential-bearing query values are not reproduced there. The real Windows
  ACL checks and local Chrome/TLS dashboard tests ran. The opt-in desktop
  modules were run on this host: the goal integration module passed 6/6 on
  four consecutive runs, the verification integration module passed 13/13, and
  the window-control module passed 23/23 in some runs and reported exactly one
  timing-sensitive desktop exception in others. No phone or externally trusted
  client was available. Both the documented Python 3.13.16 line and the
  existing Python 3.14.8 runtime passed the full 667-test suite (42 skips
  each).

See [docs/security.md](docs/security.md) for the implemented boundary,
evidence, and remaining work.

---

# Phase 8 — Full NEO Assistant Integration

**Goal:** Turn the capability inventory inherited from Mark LV into a coherent NEO assistant instead of a collection of imported features.

Phase 6 audits and adapters should already exist. Phase 8 finishes the actual integration.

### Integrate and verify

* Gemini Live voice
* automatic TTS response
* wake word
* push-to-talk
* echo protection
* session continuity
* voice/language selection
* browser
* web search
* screen vision
* webcam vision
* file processing
* filesystem capabilities
* reminders
* system monitoring
* weather
* clipboard intelligence
* video/media
* messaging
* desktop control
* application control
* memory
* undo
* proactive components
* HUD/avatar
* plugins
* model fallback

### Critical voice pipeline

```text
User speaks
 ↓
Audio
 ↓
STT / Gemini Live
 ↓
Intent
 ↓
Goal / Plan
 ↓
Security
 ↓
Execution
 ↓
Observation
 ↓
Verification
 ↓
Response
 ↓
TTS
 ↓
Audio
```

Fix the currently known automatic-voice-response problem here.

Manual TTS working while automatic TTS doesn't is **not acceptable as the final assistant experience**.

### Phase 8 implementation status — IN PROGRESS

Verified in this repository:

* **The automatic voice-response boundary.** `NeoLive.speak()` is the
  narration path handed to every action as `handler_ctx["speak"]` and the one
  `speak_error()` reports through, so *every* call of it happens while a tool
  is in flight and the server is waiting for the `function_response` that
  follows. It used to answer that by sending `role: user` with
  `turn_complete=True` — a message the user never said, racing the response a
  moment later. That is exactly how an automatic reply to a tool run is lost
  while a typed command, which goes through the same code with no tool in
  flight, still works. A tool-call depth guard now sends nothing to the
  session while a tool runs: the words go to the HUD, where progress already
  lands, and the model gets the outcome from the tool result itself.
  `tests/test_voice_pipeline.py` proves it with 5 tests — narration during a
  tool reaches the HUD and never the conversation, a failed tool is reported
  once and never as a user turn, the guard is released when a call raises and
  on nested dispatch, and narration outside a tool still completes its turn
  exactly as before. Disabling the guard fails 3 of the 5.

* **Silent policy authorization — one decision, no asking.**
  `config/profile.json`, `config/permissions.json` and `config/security.json`
  declare `authorizationMode: silent_policy`, `userApprovalPrompts: false` and
  `interactivePrompts: false`. `config/policy.py` validates all three against
  the schemas in `config/schema/` and owns the single effective authorization
  decision: `resolve()` combines the risk classification from
  `core/security.py` (facts + a provisional verdict) with the configured
  categories, and denial in either input wins. `core/security.py` keeps its
  exact classify behavior — deny by default, least privilege, a model-supplied
  `confirmed` field grants nothing — but no longer decides alone: a
  `REQUIRE_CONFIRMATION` verdict is "a human would have been asked", and the
  one explicit, deterministic conversion to ALLOW happens only inside
  `resolve()`, only when the request is in policy with behavior `execute`.
  The four capability states are distinguished — exists (registry), in
  policy, out of policy (disabled category, `outOfPolicy: deny`, or an
  operation on the category's `deniedOperations`), and unknown — and every
  non-allow resolves to deny + report: never deny + ask. The decision is made
  once per request in `core/execution.py`, audited before anything runs, and
  the legacy `core/confirm.py` banner is reachable only when the configuration
  itself re-enables prompts, so it cannot compete with the autonomous policy.
  The guard fails **closed**, not open and not "toward the banner": a missing,
  unreadable, malformed, schema-invalid, partial, or contradictory policy
  document authorizes nothing and does **not** resurrect the human check.
  `config.policy.config_failure()` names the problem and `core/execution.py`
  blocks the request outright — SAFE_BLOCKED: no execution, no prompt, and the
  configuration failure itself is the report. Every prompt switch is
  `const: false` in the three schemas, so no schema-valid configuration can
  request prompts either; the only way the legacy gate is reached is an
  explicit override of `prompts_enabled()`.
  Vision follows the same rule instead of a human grant: `screen_process` is
  CLASSIFICATION → POLICY → ALLOW / DENY → EXECUTE, with no first-time
  approval, and the legacy `CapabilityGrantStore` is consulted only inside the
  prompt subsystem.
  With no banner to park behind, content that still carries the
  `[UNTRUSTED DATA: ...]` provenance label is refused outright rather than
  deferred — `modelMayRequest: true` and `modelMayGrant: false` still hold.
  `tests/test_policy_config.py` proves it with 31 tests: allowed operations
  execute silently on first and later uses, denied and unknown operations are
  blocked with the confirmation gate mocked as a tripwire, `confirmed: true`
  and agent-claimed grants change nothing, a disabled category cannot execute,
  the classifier and the policy cannot widen each other, every audit record
  for one request carries the same single decision, untrusted content cannot
  flip a deny, and verification still runs after an allow. Sabotage checks:
  making a broken configuration fall back to prompting fails 8 of them (4
  proving the prompt gate was actually reached); re-entering the vision grant
  machinery on the normal path fails 3; making `resolve()` always allow fails
  11; injecting the legacy confirmation branch into normal execution fails 11.
  In every case reverting the sabotage returns the suite to green. The
  confirmation gate itself keeps its own contract tests through
  `@with_prompts`, because
  `autonomy.userChangesPolicyExplicitly` means a user can still turn prompts
  back on — those test the legacy subsystem, not the autonomous path.

Not verified, and not claimed:

* Whether Gemini actually speaks after a function response. That needs a live
  API session; no such run has been made.
* The rest of the voice pipeline end to end — wake word, push-to-talk, echo
  tail, session continuity and resumption, voice/language selection — and the
  capability list above travelling through the NEO architecture rather than a
  legacy path. Only what has tests is claimed.

The full standard-library suite reports **667 tests, 42 skipped, and no
failures** on both Python 3.13.16 and 3.14.8, including the 9 new policy tests:
five configuration-failure cases (missing, malformed, invalid schema,
contradictory, partial — all blocked without a prompt), three vision cases
(policy authorization with no human grant), and the configuration-architecture
invariant.

### Definition of Done

A user can interact with NEO naturally and its major inherited capabilities travel through the **NEO architecture**, not an old parallel Mark execution path.

---

# Phase 9 — Persistent Semantic Memory & Personal Context

Phase 6 only creates the **bounded memory adapter**.

Phase 9 builds the real long-term memory system.

### Scope

* Persistent semantic memory
* Embeddings/vector retrieval
* Structured memories
* Episodic/session memory
* User preferences
* Project context
* Important relationships/context
* Memory relevance scoring
* Provenance
* Confidence
* Recency
* Memory correction
* Forget/delete
* Contradiction handling
* Memory deduplication
* Cross-session recall
* Memory privacy/security

### Critical rule

**Memory is not truth.**

Fresh observation beats old memory.

Example:

> Memory: “User uses Chrome.”

Current observation:

> Firefox is active.

NEO must use Firefox for the current task.

### Definition of Done

NEO can remember useful long-term context across sessions without allowing stale or incorrect memory to override reality.

---

# Phase 10 — Cross-Device NEO

**Goal:** Extend NEO from a PC assistant into a unified personal digital environment.

### Scope

* Windows ↔ Android
* Device registry
* Device capabilities
* Device state
* Secure pairing
* Authentication
* Cross-device notifications
* Clipboard synchronization
* File handoff
* Task/goal handoff
* Context synchronization
* Remote commands
* Phone interaction
* Calls/messages where explicitly authorized
* Device-aware planning

Example:

> “Continue this on my phone.”

NEO should know what “this” is because the goal/context belongs to NEO, not one device.

### Definition of Done

A goal can move between devices without losing state or security context.

---

# Phase 11 — Proactive Intelligence

**Goal:** NEO stops being purely request-driven.

Architecture:

```text
Observe
 ↓
Detect relevant condition
 ↓
Evaluate relevance
 ↓
Security policy
 ↓
Decide
 ↓
Notify / act
 ↓
Verify
 ↓
Record
```

### Capabilities

* Smart reminders
* Deadline awareness
* Important notification detection
* System-health alerts
* Background task monitoring
* Follow-ups
* Contextual suggestions
* Recurring workflows
* Project monitoring
* Time-aware behavior
* User-configurable proactive rules

### Important constraint

**Proactive ≠ annoying.**

NEO should have policies for:

* urgency
* importance
* frequency
* quiet periods
* user preferences
* interruption cost

---

# Phase 12 — Deep Goal Autonomy

Phase 6 gives NEO bounded multi-step execution.

Phase 12 moves toward **long-horizon goals**.

### Scope

* Hierarchical goals
* Subgoals
* Long-running workflows
* Dynamic dependencies
* Resource awareness
* Goal prioritization
* Competing goals
* Adaptive planning
* Checkpoints
* Interrupt/resume
* Persistent goal state
* More sophisticated recovery
* Partial completion
* Deferred work

Example:

> “Prepare everything I need for my IELTS exam next month.”

NEO should be capable of breaking that into authorized subgoals, tracking them over time, handling interruptions, and reporting what remains.

### Restrictions

Still:

* bounded
* authorized
* observable
* verifiable
* cancellable
* truthful

No unrestricted “do whatever you think is necessary.”

---

# Phase 13 — Reliability, Recovery & Self-Diagnostics

Phase 4/5 already introduced verification and bounded recovery.

Phase 13 makes reliability **system-wide and persistent**.

### Scope

* Capability health monitoring
* Dependency health
* Model health
* Device health
* Plugin health
* Automatic diagnostics
* Failure classification
* Fallback capability selection
* Degraded modes
* Persistent checkpoints
* Crash recovery
* Resumable goals
* Rollback
* Recovery verification
* Safe shutdown
* Startup recovery

Example:

```text
Goal interrupted
      ↓
Restore checkpoint
      ↓
Check current world
      ↓
Detect stale state
      ↓
Re-observe
      ↓
Determine safe continuation
      ↓
Resume / replan / stop
```

### Definition of Done

NEO can survive real failures instead of simply reporting:

> “Task failed.”

and leaving the user to reconstruct everything manually.

---

# Phase 14 — NEO Interface / HUD

Only now do we make the **real NEO interface** the primary surface.

Not another Mark HUD copy.

### HUD should expose actual NEO state

* Current goal
* Current step
* Plan
* Active capability
* World state
* Verification status
* Permission status
* Confirmation requests
* Recovery
* Errors
* Memory/context
* Device state
* Proactive events
* Execution history

### Voice + UI + keyboard

All three should operate on the **same underlying NEO state**.

No separate “voice assistant logic.”

---

# Phase 15 — Productization & Downloadable NEO

This is where NEO stops feeling like a development project.

### Scope

* Windows installer
* Real executable
* First-run setup
* Gemini/API credential setup
* Permission onboarding
* Device pairing
* Configuration
* Startup
* Update mechanism
* Versioning
* Logging controls
* Privacy controls
* Reset/recovery
* Uninstall
* Dependency packaging
* Crash handling

### Critical requirement

**No terminal-first experience.**

User installs NEO and launches NEO.

---

# Phase 16 — Full NEO Validation

This is the final torture test.

### Capability tests

Not:

> “Can it open Notepad?”

Those remain regression tests.

Instead:

> “Can NEO complete a real multi-capability workflow?”

Examples:

**Research workflow**

```text
User request
→ web research
→ browser
→ extract information
→ files
→ create result
→ verify
→ report
```

**Communication workflow**

```text
Understand request
→ compose
→ security check
→ confirmation
→ send
→ verify
→ report
```

**Computer workflow**

```text
Observe PC
→ understand state
→ plan
→ interact
→ verify
→ recover if needed
```

### Attack testing

* Prompt injection
* Malicious websites
* Malicious documents
* Fake tool output
* Credential leakage
* Confirmation bypass
* Unauthorized actions
* Plugin abuse
* Memory poisoning
* Stale-world-state attacks
* Verification spoofing
* Cross-device authorization attacks

### Reliability

Test:

* network loss
* model failure
* process crash
* application crash
* device disconnect
* stale UI
* interrupted goal
* restart
* resume
* partial completion
* recovery failure

---

# Phase 17 — NEO 1.0

Final architecture:

```text
                         ┌───────────────┐
                         │     USER      │
                         └───────┬───────┘
                                 ↓
                       ┌───────────────────┐
                       │   NEO INTERFACE   │
                       │ voice / HUD / UI  │
                       └────────┬──────────┘
                                ↓
                    ┌───────────────────────┐
                    │ Intent + Context      │
                    │ + Persistent Memory   │
                    └───────────┬───────────┘
                                ↓
                       ┌────────────────┐
                       │ Goal / Planner │
                       └───────┬────────┘
                               ↓
                       ┌────────────────┐
                       │  ORCHESTRATOR  │
                       └───────┬────────┘
                               ↓
                     ┌────────────────────┐
                     │ SECURITY / POLICY  │
                     └─────────┬──────────┘
                               ↓
                  ┌──────────────────────────┐
                  │ CAPABILITIES / DEVICES  │
                  └────────────┬─────────────┘
                               ↓
                           EXECUTE
                               ↓
                         OBSERVATION
                               ↓
                         VERIFICATION
                               ↓
                         WORLD STATE
                               ↓
                    FEEDBACK / RECOVERY
                               │
                               └──────→ ORCHESTRATOR
```

### NEO 1.0 requirements

* Real downloadable application
* No fake functionality
* No mock devices
* No fabricated success
* No arbitrary model code execution
* No uncontrolled shell execution
* Central security
* Real PC control
* Real voice
* Real vision
* Real memory
* Real multi-capability workflows
* Cross-device operation
* Proactive intelligence
* Deep but bounded autonomy
* Verification everywhere it matters
* Recovery
* Persistent state
* Honest failure reporting

---

## The corrected roadmap in one line

**Phase 6:** Understand + orchestrate capabilities
**Phase 7:** Secure them
**Phase 8:** Integrate the full assistant
**Phase 9:** Remember long-term
**Phase 10:** Become cross-device
**Phase 11:** Become proactive
**Phase 12:** Become deeply autonomous
**Phase 13:** Become resilient
**Phase 14:** Build the real NEO interface
**Phase 15:** Ship it
**Phase 16:** Try to break it
**Phase 17:** NEO 1.0

And **Phase 6's current implementation confirms why this is the better sequence**: it's already adding NL planning, adaptive replanning, real PC control improvements, capability integration, multi-capability workflows, world-state improvements, and the memory seam. Repeating those as future phases would just make the roadmap longer without making NEO better.
