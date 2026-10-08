# NEO security and authorization (Phase 7)

**Status: PARTIAL / IN PROGRESS.** This document describes the implementation
currently in this repository; it is not a Phase 7 completion claim.

## Execution boundary

Every model-requested action is represented by a task and sent through the
existing execution boundary:

```text
Model tool request
  → TaskManager
  → ExecutionLayer
  → configuration health: config.policy.config_failure()
      invalid / missing / partial / contradictory → SAFE_BLOCKED
      (deny, execute nothing, prompt nobody) and stop
  → risk classification (core/security.py — facts + a provisional verdict)
  → authorization policy decision: ALLOW / DENY
      (config/policy.resolve() — the single effective decision)
  → confirmation gate only when the configuration re-enables prompts
  → existing ActionRegistry or PluginRegistry
  → verification and result classification
  → task update
```

File-backed capabilities are discovered by `core/action_loader.py`. Live-session
tools in `main.py` are adapters registered in that same `ActionRegistry` with
`advertise=False`; they do not create another registry or a second model tool
declaration. Their handlers return to the existing live-session implementation
only after `ExecutionLayer` dispatches them. The internal dispatch flag is an
application argument, not part of a model-exposed tool schema.

## Policy behavior

`core/security.py` classifies capabilities using the existing
`core/capabilities.py` inventory and operation-specific rules:

* Unknown actions and unclassified plugins are denied before invocation.
* Plugin discovery parses `.py` metadata through Python's AST without importing
  or executing a plugin. It classifies malformed metadata, reserved-security
  capability claims, core-capability collisions, unreviewed files, and files
  reviewed by exact SHA-256 plus an explicit capability allowlist in
  `plugins/.neo-plugin-trust.json`. A review must list every declared
  capability exactly once, so a hash match with a missing, broader, or malformed
  allowlist grants no review status. A review record is evidence only: it does
  not enable the plugin. Python plugin code runs with NEO's full process
  privileges, so all discovered Python plugins remain disabled until a
  constrained host exists. A malformed or changed manifest simply grants no
  review status.
* Prohibited arbitrary-code/development capabilities are denied.
  `file_processor` source-code execution is also denied by policy and returns
  `NOT_SUPPORTED` from the handler, including when called outside the normal
  execution boundary.
* Read-only and reversible low-risk operations can be allowed by the static
  policy. Medium/high-risk capabilities and selected destructive, system,
  external-communication, and sensitive-data operations are classified
  `REQUIRE_CONFIRMATION` — "a human would have been asked under prompt-based
  security" — which the configured policy then resolves silently: in policy →
  execute, anything else → deny and report. The classification is a fact, not
  a second authority, and it never becomes a prompt on the normal path.
* Invalid live-tool operations and missing required mutation arguments are
  denied rather than sent to a handler.
* Unknown operations are denied for the audited file, Windows-control,
  computer-control, and explicit computer-settings action names.
* A model-provided `confirmed` field has no authorization effect.

The production policy is static. Test-only policy overrides are available to
exercise boundary behavior; the application does not load policy changes from
model output.

## Confirmation

**The normal execution path no longer prompts, and exactly one decision is
effective there.** `config/permissions.json` declares
`authorizationMode: silent_policy` with `userApprovalPrompts: false`, and
`config/security.json` declares `interactivePrompts: false`. Every request is
decided once, by `config/policy.resolve()`, from two inputs combined as a
conjunction in which denial in either input wins:

* a `DENY` from the risk classification (unknown action, unregistered or
  prohibited capability, unsupported operation, untrusted registry) → DENY;
* content still carrying the `[UNTRUSTED DATA: ...]` provenance label → DENY,
  because the model may ask but may not grant;
* a scope other than `in_policy` (category disabled, `outOfPolicy: deny`,
  operation on the category's `deniedOperations`, or no category covering the
  name) → DENY + report;
* `in_policy` with configured behavior `execute` → ALLOW, executed silently
  and then verified. This is the one explicit, deterministic place where a
  `REQUIRE_CONFIRMATION` classification becomes an allowance: the user's own
  standing configuration answers what the prompt would have asked, identically
  on first and later uses.

`core/security.py` classifies every request exactly as before — deny by
default, least privilege, and a model-supplied `confirmed` field grants
nothing — but it no longer decides alone: it can withhold, never widen, and
the policy can withhold even when the classifier would allow. The guard fails
closed, not open and not "toward the banner": a missing, unreadable, malformed,
schema-invalid, partial, or contradictory policy document authorizes nothing
and does **not** resurrect the human check. `config.policy.config_failure()`
names the problem and `core/execution.py` blocks the request outright —
SAFE_BLOCKED: no execution, no interactive prompt, and the configuration
failure itself is the report. Because every prompt switch is `const: false` in
the three schemas, no schema-valid configuration can request prompts either;
the only way the legacy gate is reached is an explicit override of
`prompts_enabled()`.

`core/confirm.py` remains the single confirmation service for when prompts are
turned on — `autonomy.userChangesPolicyExplicitly` is a documented setting —
and keeps its own contract tests. During normal execution the branch that
reaches it is never taken, so it cannot compete with the autonomous policy.

**Vision is policy-authorized, never grant-authorized.** `screen_process`
(screen or webcam) is decided exactly like every other capability:
CLASSIFICATION → POLICY → ALLOW / DENY → EXECUTE. There is no "first-time
vision approval" requirement and no human grant in the normal path. The
15-minute `SCREEN_VISION` / `WEBCAM_VISION` `CapabilityGrantStore` grant exists
only inside the legacy prompt subsystem — it spared a user repeated *prompts*,
and with no prompts there is nothing left for it to save. `core/execution.py`
consults it only when `prompts_enabled()` is true; when the configuration is
valid and autonomous, no grant is created, resolved, or required. A vision
capability executes only when it exists, is registered, is in policy, is not
denied by the classifier, carries no untrusted-labelled content, and its
execution requirements are met — otherwise DENY + report, never deny + ask.
`tests/test_policy_config.py::VisionIsPolicyAuthorizedWithoutAnyHumanGrant`
proves it, including that `capability_grant_spec` is never called on the normal
path and that no grant appears in the security audit trail.
The interface creates
an opaque random token, the pending request has a 90-second expiry, and the UI
must return that exact token to resolve it. Missing, stale, substituted, and
replayed tokens do not run the stored callback. The pending callback closes over
the exact request arguments and checks a thread-local execution receipt before
gated action code can proceed.

The request fingerprint is a process-keyed HMAC, not a plaintext argument dump.
The HUD shows the capability, operation, selected non-sensitive target fields,
and a short fingerprint. Sensitive argument values are intentionally withheld;
this prevents display/log exposure but also means the user cannot review the
full content being authorized. Improving that consent preview safely remains
open work.

## Data retention and audit

* Tool-call logging and clipped task arguments use `redact()` for common
  credential, message, document, query, path, URL, and target fields.
* Model-provided free-form step text is not copied into task progress or
  security audit events.
* Results classified as sensitive-data access or external communication are
  replaced with a generic result before task history is written. Structured
  verification details are removed from that history.
* Exceptions caught by the action/plugin registries expose the exception type,
  not exception text, in their normal log and return paths.
* `untrusted_data()` JSON-encodes text with an explicit provenance label.
  Retrieved memory values use this encoding in the system prompt, the model
  prompt says external content/tool output is never authoritative, and tool
  responses carry `data_origin: untrusted_data`. Screenshot prompts label image
  contents as untrusted. This is defense-in-depth, not a guarantee that a model
  will resist every injection.
* File-processing, flight-page parsing, and YouTube transcript summarization
  encode source content under the untrusted-data boundary. Recognized
  credential patterns are redacted before file text, structured JSON/tabular
  previews, flight-page text, or transcripts are submitted to the model.
  Screenshot prompts explicitly identify the image as untrusted. This is
  pattern-based and does not semantically classify private prose or image
  contents.
* Generated file/media analysis and YouTube summaries are redacted before
  returning to the model or being persisted. File-processing error responses
  expose the exception type rather than exception text; file names are omitted
  from file-processing logs.YouTube action logs omit request arguments and
exception details. Browser-action log lines — and the navigation-error text
Playwright quotes a URL into — are redacted before printing, so a page URL's
credential-bearing query values do not reach the console or the HUD sink.
Main-session exception logging redacts recognized values and no longer prints
raw tracebacks. These controls reduce accidental leakage, but do not classify
arbitrary private prose.
* `LogWidget.append_log()` redacts recognizable sensitive patterns at the HUD
  sink. The live microphone control discloses when audio is streamed to Gemini;
  muted state discloses that no audio is sent. Confirmation detail states when
  screen/webcam images, clipboard contents, or selected image/audio media are
  sent to the configured model.
* Browser automation uses a separate persistent NEO profile for Chrome and
  Firefox rather than a user's regular browser profile. This prevents
  automation pages from sharing the normal profile's cookies and extensions;
  separate sign-in may be required.
* Before any function response re-enters the model, `tool_result_payload()`
  redacts sensitive structured fields and recognized credentials, API tokens,
  private-key blocks, SSN-like values, payment-card-like numbers, email
  addresses, phone numbers, IBANs, and credential-bearing URL query values;
  it bounds output length and JSON-encodes the result under a source label.
  These are pattern matches, not semantic private-data classification. The
  static execution policy does not accept function-result contents, prompt
  text, or a model-supplied `confirmed` field as authorization.
* Memory writes reject recognized secret-shaped values and sensitive
  credential-field names. Existing memory values with recognized sensitive
  patterns remain on disk but are omitted from prompt/recall output.
* Optional dashboard log messages contain only speaker, timestamp, and
  character count; transcript text is withheld.
* `core/security_audit.py` persists authorization, confirmation, execution,
  verification, failure-kind, goal/task identifiers, operation, and keyed
  target/step digests in a local SQLite journal. Raw arguments and free-form
  step text are not persisted. Records are chained with HMAC-SHA256. A journal
  append failure before dispatch prevents the handler from running. A
  separately HMAC-protected checkpoint detects record edits and partial tail
  truncation. Goal recovery/replanning events are recorded without persisting
  free-form step text. On Windows, audit artifacts have inherited permissions
  removed and an explicit DACL for the current user, SYSTEM, and local
  Administrators (Windows may also expose the special OWNER RIGHTS SID); the
  store fails closed if it cannot apply these ACLs. On Unix-like systems, audit
  files are set to mode 0600 and checked.

The audit journal is tamper-evident for retained records while its key remains
trustworthy; it is not tamper-resistant against an attacker who can replace
both the journal and key, delete the whole journal, or control the current
account or an administrator. The Windows ACL policy was verified against the
actual security identifiers on temporary test artifacts. This workspace has no
existing default audit journal/key to inspect. Store creation applies the
verified ACL policy; if a write fails after an action has already run, NEO
reports audit storage unavailable but cannot undo that action.

Sensitive content still has exposure paths that are not comprehensively
controlled. Automatic session transcript summarization and replay into
proactive prompts/briefings have been removed from the main application path.
The unused session-summary persistence and consumption helpers have also been
removed. Previously persisted summaries can remain locally but are not read by
the current application path. Private messages, financial content, sensitive
documents, screenshots, and all telemetry/model-context paths are not
semantically or comprehensively classified. Tool-output sanitization is
rule-based: unknown formats, images without OCR, private prose without
recognizable credential patterns, and patterns not included in the detector
can still expose sensitive data. Raw audio/image inputs are still submitted
when the user activates the capability and confirms where required; no local
semantic-content classifier exists. The HUD withholds sensitive arguments
from the consent preview, limiting what the user can review before approval.
Third-party libraries and legacy action-specific logging outside the paths
listed above have not been audited exhaustively.

The dashboard requires TLS before starting or opening firewall access, returns
HTTPS URLs, rate-limits failed PIN, QR-key, and device-token attempts, masks
the one-time key input, and adds no-store, no-referrer, and browser security
headers. Session and persistent-device credentials are HttpOnly, SameSite
cookies (Secure over HTTPS) with server-side 12-hour and 30-day expiries.
Cookie-authenticated state-changing HTTP requests require an exact same-origin
Origin; WebSocket session handshakes also validate Origin. Session credentials
are no longer returned to JavaScript, stored in Web Storage, or sent in
WebSocket/download URLs. The QR PIN is carried in a URL fragment, removed from
history by the landing page, and exchanged through a rate-limited POST.

The previous unauthenticated AES-CBC message layer and CryptoJS CDN/download
path have been removed. Dashboard commands now rely on the mandatory TLS
transport; legacy `enc` command payloads are rejected instead of decrypted or
silently treated as plaintext. A per-response nonce CSP authorizes the
dashboard's inline scripts without enabling `unsafe-inline` for scripts, and
button handlers are registered from those scripts rather than HTML attributes.
This reduces injection opportunities but does not make same-origin script
execution harmless: an active script can still issue authenticated requests
within the browser session.

Failure to generate a local TLS certificate prevents remote dashboard startup
rather than falling back to HTTP. A local real TLS-socket test now performs
login, verifies Secure/HttpOnly/SameSite cookie attributes, and accesses the
cookie-protected home page. There is still no real phone-to-desktop TLS or
WebSocket/client-certificate-trust test; clients must accept the
installation-local self-signed certificate.

## Evidence and remaining work

The Phase 7 security module reports **67 tests passed**. It includes central
allow/deny decisions, forged and replayed confirmation, plugin
import-side-effect prevention, untrusted memory encoding and sensitive-memory
write refusal, dashboard transcript withholding, audit persistence and
tamper/truncation/joint-replacement behavior, fail-closed audit storage,
recovery-event recording, non-executing plugin classification and hash-pinned
review records, tool-result provenance/redaction across named
external-content channels, task-history redaction, pre-model credential and
recognized contact/financial identifier scrubbing, local file/transcript/
YouTube-summary persistence, source-labelled synthetic injection payloads,
local malicious HTML in isolated headless Chrome, a clipboard fixture at the
OS-read seam, browser log redaction, and sensitive error/log suppression. A
malicious webpage's
content cannot authorize an outgoing message: even with `confirmed=True`, the
real execution path denies it under the untrusted-content rule and does not
invoke the handler. The fixture did not read or modify the user's clipboard.

The dashboard security module reports **21 tests passed**. A real local TLS
socket and Chrome exercised login, QR-fragment login, persistent-device
reconnect, HttpOnly cookie invisibility, CSP script handling, and the
authenticated command path. It also covers Secure/HttpOnly/SameSite cookie
attributes, expired credentials, origin checks, and dashboard credential
exposure. The real Windows ACL test checked temporary journal/key artifacts
against the current user SID, SYSTEM, and Administrators and rejected
additional principals beyond the documented OWNER RIGHTS exception. This
workspace has no existing default audit journal/key to inspect; no separate
phone or externally trusted client was available for the TLS/phone campaign.

The cross-version standard-library suite currently reports **667 tests, no
failures, 42 skipped**, on both Python **3.13.16** and **3.14.8**. The focused
67-test Phase 7 module and the 21-test dashboard security module pass inside
that run. The 3.13.16 runtime and its dependencies are installed in a temporary
user-scoped directory from the official Python release, not added to the system
PATH, and were used for this rerun. The real-Windows opt-in modules were run on
this host with `NEO_WINDOWS_INTEGRATION=1`: the 6-test goal-integration module
came back clean on four consecutive runs, and the window-control and
verification-integration modules were exercised against the live desktop as the
next paragraph records. Existing deprecation warnings from FastAPI/Starlette,
google-genai, and pynvml remain unrelated.

The real-Windows opt-in evidence was rerun on this host rather than quoted from
an earlier session. `tests.test_goals_integration` passed **6 tests** on four
consecutive runs, including the goal that types into Notepad and the goal whose
close is refused verification. `tests.test_verification_integration` passed
**13 tests**. `tests.test_windows_integration` passed **23 tests** in some runs
and reported exactly one failure in others, non-deterministically, across four
full-module invocations: either
`test_ambiguous_controls_are_refused_rather_than_guessed`, which reads a live UI
Automation tree twice and can lose the duplicate it was about to assert on
(it passes 4/4 in isolation), or
`test_calculator_launches_and_exposes_real_controls`, where the packaged
Calculator hand-off to `ApplicationFrameHost.exe` did not publish controls
within the test's window. Both are timing-sensitive readings of a live desktop
rather than product verdicts, and the same run configuration came back clean
when repeated. Running the two window-driving modules in a single process was
less stable than running them separately, which is environment load rather than
a code difference: the failures there were the same Calculator hand-off and
Notepad control-discovery timeouts, and the modules came back clean when run
separately immediately afterwards.

## Causes of remaining gaps

* **Prompt injection:** NEO passes external data to a probabilistic model. JSON
  provenance framing and policy-independent confirmation stop that data from
  directly granting execution authority, but do not technically prevent it
  from influencing the model's next proposal. This requires a model-independent
  planner/action protocol or an explicitly accepted prohibition on model
  interpretation of untrusted content; it cannot be proven by prompt text or
  a finite attack corpus.
* **Sensitive information:** the redactor catches credential patterns and
  common structured contact/financial identifiers. It cannot reliably infer
  private meaning from arbitrary prose, and the current visual/audio
  capabilities submit image/audio bytes without a locally verified
  semantic-sensitive-content classifier. Blocking all such inputs would
  disable those capabilities rather than solve classification. New filters
  narrow this gap but do not close it.
* **Plugin trust:** plugin Python would execute in NEO's full-privilege process.
  Discovery now supplies a non-executing, hash-pinned metadata/capability
  review workflow, but there is no constrained plugin host with a tested
  filesystem, network, and capability boundary. Plugins remain disabled;
  enabling in-process plugins is not a safe fix.
* **Audit replacement:** the journal and HMAC key are both local. A
  same-account or administrator attacker can replace both; a focused test
  demonstrates that the replacement forms a new valid local chain. A trusted
  external append-only service or hardware-backed independent anchor is not
  configured in this desktop environment. Local ACL/HMAC tests do not
  establish non-repudiation.
* **Windows/mobile campaign:** this Windows host verified ACL application on
  real temporary files and exercised local TLS/Chrome. No separate phone,
  trusted client CA installation, actual user clipboard, or external
  malicious-site campaign was available/appropriate. The opt-in desktop UI
  campaign was left unrun to avoid interacting with real user windows. The
  synthetic clipboard tests make no claim to exercise actual clipboard state.
* **Sensitive-data semantics:** no local classifier can infer private meaning
  in arbitrary prose, audio, or images. The fixed patterns and explicit
  transfer disclosures cannot ensure that private prose, image pixels, or
  third-party telemetry are withheld.
* **Legacy logging review:** file-processing/YouTube errors, main-session
  exception logs, and the HUD sink now suppress raw data in the tested cases.
  Other action-specific logging and third-party library sinks are not
  exhaustively traced; a global no-sensitive-data claim would be unsupported.

Phase 7 remains **PARTIAL**. The dashboard token/URL exposure and other
sensitive-data/error logging gaps were fixed and tested. Python 3.13
compatibility and the full local regression suite are now verified. The
remaining architectural and external-trust constraints above mean current
evidence does not support marking Phase 7 COMPLETE.
