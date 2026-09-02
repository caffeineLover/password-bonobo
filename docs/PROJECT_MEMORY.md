# Password Bonobo Project Memory

Last updated: 2026-09-02

## Completed Task 7 review-fix round 2

The remaining QML boundary-parser finding is reproduced red-first with the
exact legal template expression containing `/}/` before a forbidden
`passwordValue` access.  Companion RED cases cover escaped and character-class
braces; a division characterization remains green.  The minimal scanner fix
recognizes regex literals only where the preceding JavaScript token permits an
expression, skips escapes and character classes through the closing slash, and
leaves `/` after an operand visible as division.  All eight focused QML
contract tests and all 51 offscreen desktop tests pass.  Resolved-file qmllint,
Ruff, strict mypy for 106 files under default/win32/darwin/linux, Python
structure, REUSE 169/169, and unstaged/staged whitespace are clean.  The Task 7
report records the exact RED/GREEN evidence and self-review.  Scoped independent
re-review confirms the regex-literal interpolation bypass is addressed with no
new breakage.  Task 7 is complete through `29b6090`; Task 8 remains next.

## Completed Task 7 review-fix round 1

The five requested review repairs are implemented red-first.  QML now retains
the keyboard-selected primitive record key across each model reset and clears
selection to search when that key disappears even if another row remains; the
decision modal focuses Save on open; runtime accessibility tests cover initial
focus, names, and complete tab cycles for Welcome, Unlock, Vault, RecordEditor,
and DecisionDialog.  Record-confirm submission interruptions close the local
secret owner without masking the original `BaseException`, and the QML
identifier scanner preserves template interpolation code while ignoring
literal text.

The mandatory repository-wide mypy RED reproduced the `fakes` / qualified
helper identity conflict.  Normalizing application imports alone remained red,
so the approved fallback adds explicit test-package markers and qualifies the
PasswordSafe helper imports required by that package boundary.  Final
verification reports 83 application tests and 47 offscreen desktop tests
passing, all 637 PasswordSafe tests collecting plus a 27-pass/5-skip runtime
sample, resolved-path qmllint and Ruff clean, strict mypy clean for 106 files
under win32, darwin, and linux, Python structure clean, REUSE 169/169, and clean
staged and unstaged whitespace.  The Task 7 report contains exact RED/GREEN,
debugging, implementation, accessibility, and secret-boundary evidence.  Task
7 is complete after the separate review-fix commit; the exact next action is
Task 8.  Provider, URL-audit, mobile, settings, and advanced vault work remain
out of scope.

## Completed Task 7 Qt Quick shell

The approved scope correction supplied primitive controller Add/Edit Confirm,
composition-root wiring, and an executor terminal-callback contract without
opening the QML boundary.  The four-view shell plus scoped decision dialog is
implemented with local concealed inputs, exact five-role record presentation,
complete keyboard actions, accessible names, deterministic tab order, and
focus retention or search fallback across model resets.  The executor now
serializes terminal lock after idle, draining, or ordinary active work while
closing admission and canceling queued ownership first.

The prescribed absent-resource RED, controller/composition REDs, shutdown
ordering REDs, boundary-parser RED, and filtered-selection focus RED were all
observed.  Final verification reports resolved-path `qmllint` clean, 38
offscreen desktop tests passing, Ruff clean, strict scoped desktop mypy clean
for 17 files, Python structure clean, REUSE 166/166, and clean staged and
unstaged whitespace.  The repository-wide mypy command and three platform
forms retain the pre-existing duplicate-module failure reproduced at clean
`d436908`; the Task 7 report contains exact evidence.  Task 7 is complete; the
exact next action is Task 8.  Provider, URL-audit, mobile, settings, and
advanced features remain out of scope.

## Completed Task 6 review-fix round 1

Review fix round 1 addresses all four Important findings from commit `8f07415`.
Immutable command envelopes now classify shutdown draining, worker start and
shutdown admission are atomic, the executor tracks the active envelope, queued
ownership is canceled, and only active save/dirty-suspend work is awaited.
The argument-free shutdown signal lets tests prove admission is closed before
checking rejection.  Passphrase replacement emits exactly once; lock, close,
terminal-result, and controller-shutdown paths synchronously wipe retained
input and notify only on a presence transition.

The required regressions were observed RED with five failures, plus one separate
controller-shutdown failure.  Focused controller tests now pass 10, and the
complete offscreen desktop suite passes 22.  Scoped Ruff, strict mypy over 15
files, Python structure, REUSE 156/156, and whitespace checks pass.  The Task 6
report contains exact commands, outputs, implementation details, and self-review.
This checkpoint is included in the separate review-fix commit.  Scoped
independent re-review confirms all four Important findings are addressed with
no new breakage or out-of-scope observation.  Task 6 is complete through
`be51cb3`; the exact next action is Task 7, followed by Task 8.

## Completed Task 6 Qt adapter checkpoint

Task 6 adds the reset-only five-role record model, primitive snapshot controller, one-worker facade executor,
synchronous GUI-thread clipboard/browser calls, nonce-owned finite clipboard lifetime, and monotonic single-submit
idle locking.  Shutdown rejects new work, deterministically cancels queued secret ownership, and waits for the active
save/suspend boundary.  The passphrase Qt getter is always empty; mutable input is cleared before submission and paths,
decision identities, URLs, domain objects, and raw errors never become controller/model state.

The required absent-adapter RED reported four collection errors.  A separate red-first self-review regression exposed
queued ownership cleanup and now passes.  Final verification reports 18 offscreen desktop tests passing, scoped Ruff
clean, strict mypy clean for 15 files, Python structure clean, REUSE 156/156, and clean whitespace.  The full command,
output, file, and review record is in the Task 6 report.  The exact next action is Task 7 QML resources and workflows;
Task 8 CI/deployment remains approved after Task 7.  Provider, URL-audit, and mobile work remain out of scope.

## Completed Task 5 review-fix round 1

The Task 5 review repair corrects commit `0902a02`'s bounded shutdown and
diagnostic defects: desktop teardown now invokes the facade's terminal
`lock(snapshot.generation)` operation, which suspends a dirty session before
engine destruction; import-boundary diagnostics now contain only an import
identifier; and base-import failures raise a fixed status message without raw
subprocess output.  Dirty-session and diagnostic regressions were observed RED
before the production edits.

Last verified: the desktop main/import-boundary/package/wheel selection passed
with 16 tests; Ruff, strict mypy, Python structure, and `git diff --check`
passed.  The Task 5 report has the detailed commands and outcomes.  Scoped
independent re-review confirms both the dirty-shutdown and safe-diagnostic
findings are addressed with no new breakage.  Task 5 is complete through
`5e4e7ac`; the exact next action is Task 6.  QML resources and CI workflow work
remain assigned to Tasks 7 and 8 respectively.

## Completed Task 5 desktop foundation

Task 5 of the approved vault-application desktop vertical slice adds the
optional `desktop` PySide6 6.11 package extra, `desktop-test` pytest-qt group,
`password-bonobo` GUI entry point, both Hatch wheel packages, and regenerated
lock resolution.  The new `bonobo_desktop` package has no eager PySide6 import;
its composition-root skeleton configures Qt identity, fails closed for an
unavailable QML root or Botan library, creates separate private working and
recovery directories, composes `VaultService.with_botan` with
`VaultApplication`, and requests facade lock during shutdown.

The required RED first failed collection because PySide6 was absent.  A second
RED exposed that the provenance gate ignored optional extras; it now treats
desktop extras as direct runtime requirements.  The desktop/package/wheel
selection passes 13 tests with the desktop extra and test group; provenance
tests pass 15.  Base core/desktop package imports pass under Python 3.14 with
site packages disabled.  Fresh build, wheel, provenance, REUSE (145/145), Ruff,
strict mypy (91 files), Python structure, and whitespace checks pass.  The
full report is `.superpowers/sdd/2026-09-01-vault-application-desktop-vertical-slice/task-5-report.md`.

Task 5 is committed as the current desktop-foundation checkpoint.  The immediate
next action is continue only with approved Task 6.  Later approved work remains
Tasks 7 and 8; provider coordination, URL-audit work, mobile UI, and QML
workflows remain out of scope.

## Completed Task 4 transaction-boundary revision

The user approved a narrow architectural revision for the two remaining Task 4
findings.  The approved design addendum is
`docs/superpowers/specs/2026-09-02-pending-session-transaction-boundaries-design.md`.
It requires every retained-handle slot scan to finish under the existing bound
and pass a final current-path identity check before absence or selection is
trusted.  It also requires explicit discard to distinguish pre-commit failure
from post-commit destination-lock teardown so an irreversible successful
discard cannot leave the facade holding a dead selector.

The executable repair plan is
`docs/superpowers/plans/2026-09-02-pending-session-transaction-boundaries.md`.
Repair round 4 began from clean base `7fe0e98`.  The pre-change focused
Task 4 suite passed 148 tests with 2 expected skips in 138.24 seconds.  The
retained-anchor matrix and deterministic decoy ABA regressions are now RED:
the prescribed selection reports 14 failures and 67 deselections in 22.81
seconds because no completed scan performs final current-path authorization.

The one closed final-anchor helper now authorizes all three scan helpers after
exhaustion.  Its 14 targeted cases pass, and the complete pending-session and
storage-fault selection passes 102 tests with 2 expected skips in 136.76
seconds.  The committed-discard RED first reported 2 failures with 5 precommit
cases passing; the real-service facade RED then reported 2 failures because it
published a storage failure and retained the dead selector.  The minimal
discard-only reconciliation records commit after exact removal and ignores only
later destination-lock teardown.  Direct, precommit-retry, and facade cases
pass 9 tests in 13.77 seconds.

Repair-round verification is complete.  The focused suite passes 121 tests with
2 expected skips in 145.48 seconds; the selected suite passes 289 with 9 skips
in 176.35 seconds; and the exact-DLL full suite passes 837 with 14 skips in
242.18 seconds at 80% coverage.  Autopep8 diff, Ruff, strict mypy for all 86
files under win32, darwin, and linux, Python structure, compatibility (66
behaviors, 45 features, 55 oracles), provenance, Bandit, pip-audit, REUSE
140/140, tracked-file and whitespace checks, source/wheel build, and wheel
inspection pass.  The repair is committed as `42f209e`.  Scoped independent
re-review confirms both the final retained-anchor authorization and committed-
discard reconciliation findings are addressed, with no new breakage or out-of-
scope observations.  Task 4 is therefore complete.  The exact next action is
Task 5, the optional PySide6 desktop package, followed by Tasks 6 through 8 in
order.

## Completed Task 4 review-fix round 3

The final independent review round reports one retained-directory enumeration
Critical, one commit-authority Important, one replacement-ownership Important,
and one mandatory process-lock error-projection gap.  They are compatible with
the approved design.  RED/GREEN implementation is complete: the pending store
streams a retained publication anchor with a strict 256-entry ceiling; POSIX
enumerates the directory descriptor and Windows uses typed
`FileIdBothDirectoryInfo` records from the retained handle with bounded parsing.
Deterministic replace-enumerate-restore ABA probes for alias open/suspend, the
entry ceiling, and malformed native records pass (5).  An internal exact-absence
sentinel lets suspension restore an active dirty session only after a complete
enumeration positively confirms the stable slot is missing; all three typed
storage uncertainty reasons retain the committed selector and lock the session
(4).  Replacement normalization and BUSY publication now occur inside the
transferred-secret ownership scope; the new cases and prior validation,
reentrant, and deferred-owner cases pass (10).  Process-lock acquire/chmod,
unlock, and close failures now propagate through one lifecycle aggregator;
publish/open/discard/verify project raw path-bearing acquisition errors, and
post-publication teardown failures reconcile to a committed selector (10).  An
adversarial self-review found that a generator context manager could retain a
raw lock error in implicit exception context; the final boundary object projects
only path-free exceptions and the complete diagnostic-chain regressions pass
(11).

Final verification is GREEN.  The combined focused Task 4 suite passes 148
tests with 2 expected Windows capability skips in 138.41 seconds; the approved
selected suite passes 267 with 9 expected skips in 145.05 seconds; and the fresh
exact-DLL Botan suite passes 815 with 14 expected skips in 212.15 seconds at 80%
coverage.  Ruff, autopep8 diff, strict mypy for all 86 files under win32,
darwin, and linux, Python structure, compatibility (66 behaviors, 45 features,
55 oracles), provenance, Bandit, pip-audit, REUSE 138/138, tracked-file and
whitespace checks, source/wheel build, and wheel inspection pass.  The separate
non-amended final repair commit is `1f928fc` (`fix: close final suspended-session
review gaps`).  The Task 4 report records the complete final-round RED/GREEN,
architecture, ownership, failure-invariant, verification, and adversarial
self-review evidence.  Immediate next action is controller final review of Task
4.  Later approved work remains Tasks 5 through 8 in order.

## Completed Task 4 review-fix round 2

Independent re-review confirms every round-1 finding closed and rejects the
current Task 4 range for three remaining mandatory boundaries: pending guards
and locks are path-locator rather than source-identity based; a failure after
pending publication can lose an authoritative selector and wedge the frozen
session; and several service/facade early validation paths retain a transferred
valid passphrase.  These findings are compatible with the approved design.

The approved repair keeps stable slot publication and resume bound to the exact
original path locator, while deriving an additional private cross-process guard
from the captured device/file identity.  Open and suspension will scan and
validate all source-bound slots under that identity guard so hard-link aliases
cannot bypass or publish a second slot.  Every post-publication suspension
failure will query the exact new selector: authoritative state is reconciled to
a locked session and committed marker, while absent state aborts the frozen
snapshot and leaves the true dirty session active.  Valid transferred secrets
will be owned by outer cleanup around all named validation and `BaseException`
paths, without closing a replacement secret intentionally retained behind an
active dirty decision.  Immediate next actions are add and observe the complete
RED matrix, implement each boundary in security order, then run the full Task 4
verification and commit separately without amending.  Later approved work
remains Tasks 5 through 8 in order.

The complete round-2 matrix is now RED/GREEN.  Three identity regressions first
proved alias open, alias initial suspension, and cross-process alias guards all
bypassed the original path lock; they now share a private device/file-ID lock
while stable slots remain bound to the exact path locator.  Two
post-publication regressions first lost an authoritative selector on retarget
cleanup failure and propagated a capture `BaseException`; both now reconcile to
a locked committed marker, while the already-removed selector case aborts the
frozen snapshot and remains mutable.  Four service and ten facade ownership
cases first retained valid secrets and now close them on all tested early
validation/phase/`BaseException` paths while preserving the deliberately
deferred replacement owner.  The combined focused set passes 128 tests with 2
expected Windows capability skips, and the approved selected suite passes 245
with 9 expected skips.  A final self-review tightened the validated identity
scan to constant descriptor space; the focused set remained green afterward.
Ruff, autopep8 diff, strict mypy for all 86 files under win32, darwin, and linux,
Python structure, compatibility (66 behaviors, 45 features, 55 oracles),
provenance, Bandit, pip-audit, REUSE 138/138, tracked-file and whitespace checks,
source/wheel build, and wheel inspection pass.  The final post-refactor
exact-DLL full suite passes 793 tests with 14 expected skips in 191.84 seconds.
The Task 4 report records the complete round-2 RED/GREEN matrix, ownership and
failure invariants, exact verification, files, and self-review.  The separate
non-amended repair commit is `ea8bf93` (`fix: bind pending sessions to source
identity`).  Immediate next action is commit this documentation checkpoint,
then controller review of Task 4.  Later approved work remains Tasks 5 through
8 in order.

## Completed Task 4 review-fix round 1

Independent review rejected `ac87962` with one Critical selector-CAS gap,
nine Important transaction/ownership gaps, and one mandatory raw-path exception
gap.  All findings are compatible with the approved Task 4 design.  The complete
red-first matrix is now recorded: the combined focused run has 16 expected
failures with 59 passes and 2 Windows capability skips, and two additional
targeted REDs prove committed live-snapshot cleanup currently escapes as
`KeyboardInterrupt` and retained Windows child DACL validation is not invoked.

The coherent repair is implemented: a source-keyed cross-process pending guard,
exact retained-slot expected-selector compare-and-swap, source-bound open/verify/discard,
descriptor-backed authentication with retained identity and handle-based Windows
privacy, CAS rollback with old-artifact verification, explicit post-commit
reconciliation for suspend/save/discard, cumulative copy bounds, unconditional
secret cleanup, and closed enumeration errors.  Focused pending/storage/facade
tests pass (78 with 2 expected capability skips in 87.07 seconds), the approved
selected suite passes (226 with 9 expected platform skips in 117.37 seconds),
and the fresh exact-DLL Botan suite passes (774 with 14 expected skips in 183.31
seconds). Ruff, autopep8 diff,
strict mypy for all 86 files under win32/darwin/linux, Python structure,
compatibility, provenance, Bandit, pip-audit, REUSE 138/138, tracked-file and
whitespace checks, source/wheel build, and wheel inspection all pass. The Task 4
report records RED/GREEN and architecture evidence for every review finding.
The separate non-amended repair commit is `2245e31` (`fix: harden suspended
session reconciliation`). Immediate next action is controller review of Task 4;
later approved work remains Tasks 5 through 8 in order.

## Completed Task 4 checkpoint

Task 4 is complete on `feature/vault-application-desktop` from base `491802a`.
The coherent Task 4 commit contains this checkpoint.  The initial focused RED
failed collection only because `SuspendedSession` and the suspension APIs were
absent.  Subsequent RED cycles exposed Windows sharing constraints, pathname
replacement during candidate cleanup, and a combined post-commit source change
plus pending-cleanup failure that left the live save snapshot wedged.  The final
implementation uses separate read and replace descriptor phases, exact anchored
cleanup, and clears the service commit flag before rollback so every failed
preflight retains a mutable dirty session.

The private pending store now publishes one bounded authenticated encrypted
artifact through a stable path-derived locator and a random 256-bit path-free
selector.  It reuses the protected-directory, descriptor identity, bounded I/O,
file/directory synchronization, and exact-cleanup primitives; rejects malformed,
ambiguous, replaced, symlink/reparse, ownership, ACL, size, and digest state; and
atomically retains either the old or new visible slot.  Suspend never changes the
source.  Resume reauthenticates both unchanged source and pending ciphertext,
binds publication to the original full baseline, retains pending identity until
successful save cleanup, and closes the caller passphrase on every path.  The
facade keeps source and suspended metadata private, supports clean lock and dirty
suspend, fails safely while locked on resume, requires explicit pending discard,
and clears owned clipboard content at terminal transitions.

Final verification is GREEN: focused Task 4 tests are 37 passed with 2 Windows
symbolic-link capability skips; the required writer/storage/service/application
selection is 207 passed with 9 expected platform skips; and the canonical
Botan-backed full suite is 755 passed with 14 expected skips.  Autopep8, Ruff,
strict mypy for win32/darwin/linux (86 files each), Python structure,
compatibility (66 behaviors, 45 features, 55 oracles), provenance, Bandit,
pip-audit, REUSE (138/138), tracked-file, source/wheel build, wheel inspection,
and staged/unstaged whitespace checks pass.  The Task 4 report is in the approved
SDD workspace.  Immediate next action is controller review of the Task 4 commit;
later approved work remains Tasks 5 through 8 in order.

## Completed Task 3 checkpoint

Task 3 of the vault-application desktop vertical slice is committed as
`2817994` on `feature/vault-application-desktop`, from base `38231e6`.  The
worktree was clean before work began.  The new focused record-command and
secret-action tests first failed during collection as expected because the
public `RecordDraft` contract and recording ports did not exist; they now pass
(9).
The Task 3 facade adds safe search, revision-bound immutable drafts, explicit
password/username copy, URL browser actions, closed platform failure reasons,
and clipboard cleanup on terminal transitions.  Existing PasswordSafe treats
URLs as public text fields, so URL buffers are converted only transiently in
the private command and are passed to `SetTextField`; URL browser actions use a
short-lived application lease and never enter a projection.  The application
suite passes (50), as does the relevant application/PasswordSafe
session-secret/service selection (74); Ruff, focused mypy, Python structure,
and whitespace checks pass.  Exact strict mypy passes on win32, darwin, and
linux for 83 files each.  The required Botan-backed full suite passes with 712
tests and 12 expected skips in 107.56 seconds.  The Task 3 report is present in
the approved SDD workspace.  The final post-report static, structure, and diff
checks passed before commit.  Immediate next action: continue only with
approved Task 4.  Later approved work remains Tasks 4 through 8 in order.

Review fix round 1 is committed as `fd797a6`.  A newly added red regression showed
that adding the first record to an empty vault returned a safe unexpected result
because the facade inferred the revision from an empty per-record map.  The
facade now reads and privately captures the current public session revision for
initial projection, refresh, drafts, and zero-record add validation; no revision
reaches a DTO or snapshot.  The regression passes, as do the application plus
relevant PasswordSafe selection (76), strict mypy on win32/darwin/linux (83
files each), Ruff, Python structure, whitespace, and the Botan-backed full
suite (713 passed, 12 expected skips, 107.48 seconds).  Immediate next action:
commit the Task 3 review-fix round 2 change, then continue only with approved
Task 4.

Review-fix round 2 is committed as `c2455b0`.  The red regressions proved
that a new draft created by `begin_edit(None)` could use a later out-of-band
session revision and that a directly fabricated new draft was accepted.  The
facade now privately captures the current revision by draft generation at
`begin_edit(None)`, consumes and validates it before one add mutation, and
clears pending captures on every published generation.  The capture never
enters `RecordDraft`, a snapshot, or any diagnostic.  The focused record-command
tests pass (8), as do application plus relevant PasswordSafe session/service
tests (75), Ruff, Python structure, whitespace, and strict mypy on
win32/darwin/linux (83 files each).  The canonical Botan-backed full suite
passes with 715 tests and 12 expected skips in 109.39 seconds.  The Task 3
report is updated in the approved SDD workspace; the final post-documentation
structure and whitespace checks passed.  Immediate next action: continue only
with approved Task 4.  Later approved work remains Tasks 4 through 8 in order.

Review-fix round 3 is committed as `bd7f5da`.  It removes projection-wide
revision authorization in favor of private draft captures keyed by the active
generation and safe record key.  A capture is created only by `begin_edit`, is
consumed before either no-op cancellation or one add/apply mutation, and is
cleared on every published generation.  Red tests proved direct fabricated
existing drafts, externally stale existing drafts, and canceled-draft capture
reuse were all accepted before the fix; the focused record-command suite now
passes (11), application plus relevant PasswordSafe session/service tests pass
(78), and all required static checks are green.  The canonical Botan-backed
full suite passes with 718 tests and 12 expected skips in 109.57 seconds.
The Task 3 report is updated in the approved SDD workspace.  Independent final
re-review approved the complete Task 3 range with no remaining Critical,
Important, or Minor findings.  Exact next action: continue only with approved
Task 4.  Later approved work remains Tasks 4 through 8 in order.

## Purpose and resume protocol

This is the repository's sole persistent continuation record.  Read it completely before resumed or substantial work,
then reconcile it with Git and the current files.  Update it after every meaningful checkpoint and before interruption.
Keep the current task, last proven result, exact next actions, later approved work, risks, and durable decisions here.
Do not store raw transcripts, credentials, machine-specific research paths, or history already recoverable from Git.

This file is Markdown-only.  Do not create a second project-memory location or a LaTeX/PDF derivative.

## Completed Task 2 checkpoint

Task 2 of the approved vault-application desktop vertical slice is committed as
`6f0a89c` on `feature/vault-application-desktop`.  Review-fix round 1 is
committed as `ffdf1f4` for failures raised after terminal session operations,
with its checkpoint committed as `6d9bc70`.
The fix adds fault injection tests and conservatively fails closed rather than
republishing an old unlocked snapshot after a lock/discard may have mutated its
private session.  The committed task adds the serialized UI-independent lifecycle facade,
safe public command exports, and headless fake-service tests.  The binding
replacement rule is proved: an open from dirty unlocked state returns an
`AWAITING_DECISION` replacement token without calling the service; resolving
it attempts authentication before old-work discard, so a failure retains the
original dirty session with only a safe failure.  The full Windows suite with
the established verified Botan DLL reports 698 passed and 12 expected skips in
107.88 seconds.  Focused application/service tests report 51 passed; application
Ruff, structure, and the exact repository-wide strict mypy checks pass under
Windows, macOS, and Linux for 79 source files.  The Task 1-only fabricated
`RecordView` factory now lives in the Task 2 application fakes rather than
creating a second module path in PasswordSafe test helpers.  Independent
re-review approved Task 2 with no remaining Critical, Important, or Minor
findings.  Immediate next actions: continue only with approved Task 3.
Review-fix fault tests passed
(16) and focused application/service tests passed (56); Ruff, Python
structure, `git diff --check`, and strict mypy on Windows, macOS, and Linux
(79 files each) passed.  The exact Botan-backed full suite passed 703 tests
with 12 expected skips in 107.99 seconds.  Later approved work remains Tasks
3 through 8 in order.

## Completed Task 1 checkpoint

Task 1 of the approved vault-application desktop vertical slice has completed implementation and verification on
`feature/vault-application-desktop`.  It adds the UI-independent non-secret DTOs, safe PasswordSafe error projection,
and deterministic record/search projection under `src/bonobo_core/application/`, with companion application tests and
a fabricated `RecordView` helper that binds one object for the handle-to-key regression.

The initial red run failed collection because `bonobo_core.application` did not exist.  The focused suite now reports 25
passing tests, with 100% coverage of the new error mapper; Ruff, strict mypy, and the Python structure gate pass.  The
final Windows/CPython 3.14.7 suite, using the verified Botan 3.13 DLL from the parent checkout, collected 699 tests and
reported 687 passed with 12 expected platform-specific skips in 106.67 seconds.  Task 1 is committed as
`feat: define safe application projections`; its full report is in the matching SDD workspace.  The immediate next
action is to continue the approved vertical-slice plan with Task 2 only; do not begin unrelated provider, URL-audit,
or mobile work.

## Immediate checkpoint

Branch `feature/lossless-passwordsafe-core` completed and independently committed Task 13 of the approved lossless
PasswordSafe core plan at `a91977d`. Task 14 was independently committed at `73431ea`. Its build driver exposes
the five exact Windows x86-64, macOS arm64, Linux x86-64, Android arm64, and iOS arm64 profiles. Desktop profiles install
shared libraries; mobile profiles install static libraries and optionally compile/link a raw Twofish FFI probe. Android
requires the exact NDK API 28 compiler before source acquisition. iOS requires macOS and fixed iPhoneOS `xcrun`
discovery. Dedicated hosted Android and iOS jobs exercise those gates, while the desktop matrix builds and tests with
its resolved host library. The first hosted run passed Android and exposed the four platform failures summarized below.
Task 15 implementation, release verification, and independent review were committed at
`5e1d5d7`. The safe demonstration, operational guide, root status, contributor validation, legal note, and REUSE
coverage complete the approved lossless PasswordSafe core plan.

Local `main` uses `origin` at `https://github.com/caffeineLover/password-bonobo.git`. The remote's unrelated
initial GPLv3 `LICENSE` commit `7cb8203` was fetched and joined to the completed local history by merge commit `11f0ea7`.
That earlier `963441d` checkpoint passed 645 tests with 12 expected platform-specific skips and 79% coverage in
107.71 seconds, plus Ruff, strict mypy, Python structure, Bandit, REUSE, provenance, tracked-file, and whitespace gates.
The pushed `origin/main` history contains the diagnostic, strict-typing, and Linux Botan-discovery repairs recorded
below.

Hosted run `33549509896` then passed Android arm64 but failed the iOS smoke link, macOS strict mypy, Ubuntu host-library
discovery, and Windows test suite. Diagnostic repair `caec5f5` is integrated and pushed on `main`. Its follow-up hosted
run `33555795740` passed Android and exposed bounded causes for every remaining job: Ubuntu produces versioned and
unversioned `libbotan-3.so` files under `lib/`; iOS omits the C++ runtime while linking the Botan static archive;
macOS reports the expected 23 platform-stub mypy errors; and the hosted Windows environment rejects private artifact
preparation across 157 tests. Commit `403f638` resolves the macOS failure with narrow typed native-module facades while
preserving the runtime modules and flags. It is integrated and pushed on `main` with checkpoint `68c1317`.

Hosted run `33576400850` confirms pushed commit `f32bd0b` fixes Ubuntu's shared-library discovery: the build and all
static checks pass and pytest now runs. Android passes. iOS retains the missing C++ runtime link failure. The desktop
pytest results expose three bounded platform issues: Ubuntu reports 2 failures after 645 passes and 19 skips; macOS
reports 153 failures after 496 passes and 17 skips; Windows reports 157 failures after 500 passes and 9 skips.

The lossless-core implementation range on `feature/lossless-passwordsafe-core` is `a0f9a22..5e1d5d7`.

Checkpoint `669506e` consolidated the retired split identity/state/decisions/verification records into this file and
deleted the obsolete folder.  It also made `docs/superpowers/specs/` Markdown-only, removed its TeX/PDF derivatives,
updated the policy/tool/tests/plans/REUSE metadata, and passed the verification recorded below.

`tools/verify_passwordsafe_interop.py` reads a fabricated passphrase only from standard input, emits ordered redacted
hash evidence, performs bounded exact comparison, and permits only an explicit `record:N:title` delta. Four encrypted
fixture/manifest pairs now exist under `tests/fixtures/synthetic/passwordsafe/`: Bonobo `0x0311`, Password Safe 3.72.1
`0x0311`, Gorilla `6728e85` `0x0300`, and an independent official-format `0x0302` unknown-field fixture. Their exact
encrypted hashes are recorded and gate-checked in the linked manifests and compatibility oracle catalog.

Bonobo opened all three external fixtures; strict no-edit and title-only comparisons passed, including exact unknown
header `0xE0` and record `0xE1` preservation. Password Safe and Gorilla opened the Bonobo fixture. Paired transactions
from each external client's normalized baseline changed only the title outside writer-owned fields. Password Safe
adds/reorders headers and updates Last Save Time. Gorilla writes only `0x0300`, adds empty Preferences, and reorders
standard record fields. The plan was corrected from its false Gorilla `0x0302` assumption; no Bonobo validation was
weakened.

The compatibility gate now requires the exact four paired stems, authorities, format levels, independently pinned
encrypted digests, closed manifest schema, and oracle links using bounded reads. It also pins the complete transaction
record digest, closes its external-artifact schema, and verifies the exact unique client/source/hash relationships. The
verifier hashes the exact authenticated snapshot, eliminating a later path-replacement binding. A real Botan test
authenticates all four checked-in fixtures and regenerates every ordered redacted entry. That test uses the established
`BONOBO_TEST_BOTAN_LIBRARY` contract and fails rather than skips in CI. The desktop workflow now builds the pinned host
Botan library and supplies its resolved output path to the suite.

The provenance gate enforces reviewed producer/version/distribution facts for the eight paired artifacts and the
redacted transaction record. It separately gates exact Password Safe archive, Tclkit executable, and Gorilla checkout
identities, filenames, origins, terms, distribution status, evidence, and review state. Tclkit aggregate terms remain
truthfully `NOASSERTION` with review pending; neither producer binary is distributed.

The independent review reported no Critical issues. Its first pass identified five Important evidence gaps, all fixed
through real-fixture authentication, independent digest pins, authenticated-snapshot hashing, closed schemas, the
redacted transaction record, and this reconciled memory. Its follow-up identified the formerly optional/wrongly named
Botan CI contract and insufficient transaction/producer identity gates; both are now corrected as described above.
The final pass reported no Critical or Important findings; its sole Minor wording correction is incorporated.

## Product contract and authoritative documents

Password Bonobo is an original, local-file-first password manager with a fully typed Python core and
platform-appropriate clients.  It targets Windows, macOS, Linux, Android, ChromeOS through Android, and iOS; BSD
portability remains a goal pending qualification.  User-selected operating-system providers may synchronize local
vault files, but Bonobo has no account system, cloud vault, or synchronization service.

Loss of credentials or user-authored metadata is unacceptable.  PasswordSafe files are lossless documents, including
stable identifiers, supported standard fields, and preservable unknown bytes.  Bonobo-authored material is
GPL-3.0-or-later.  The possible iOS distribution exception remains unresolved and grants no current permission.

- [Program design](specs/password-bonobo-python-reimplementation-design.md)
- [Repository-foundation specification](specs/password-bonobo-repository-foundation-compatibility-dossier-spec.md)
- [URL-audit design](specs/password-bonobo-url-audit-design.md)
- [Lossless PasswordSafe core design](superpowers/specs/2026-08-23-lossless-passwordsafe-core-design.md)
- [Active implementation plan](superpowers/plans/2026-08-23-lossless-passwordsafe-core.md)
- [Source-provenance policy](legal/source-provenance-policy.md)
- [Dependency and asset ledger](legal/dependency-asset-provenance-ledger.md)
- [Compatibility matrix](compatibility/gorilla/feature-parity-matrix.md)
- [Black-box test oracles](compatibility/gorilla/test-oracles.md)

## Completed state

- The repository foundation includes Python 3.14 packaging, Git and tracked-file policy, security and dependency gates,
  REUSE/GPL metadata, clean-room provenance, contributor hold, and three-platform CI.
- Gorilla evidence is tied to the read-only external commit
  `6728e85c05ac25357b8f19f541487b9d26a97402`.  The neutral contract has 66 behaviors, 45 feature rows, and 55
  synthetic oracles.  Gorilla post-save loss is Excluded; Bonobo's transactional no-loss contract is authoritative.
- Tasks 1 through 4 pin/build Botan 3.13.0 and implement typed secret ownership, Twofish, derivation, wrapping, CBC,
  HMAC, and randomness.
- Tasks 5 through 8 implement bounded encrypted snapshots/payloads, ordered lossless documents, schemas/custom fields,
  authenticated parsing, validated serialization, and exact candidate comparison.
- Tasks 9 through 11 implement revision-safe sessions, protected-record rules, atomic publication, encrypted recovery,
  external-change detection, and the reviewed public `VaultService` create/open/save/rotate/export/recovery API.
- Task 12 adds typed Hypothesis strategies, exact round-trip/targeted-edit properties, hostile-length allocation proofs,
  a dependency-free deterministic fuzz corpus/runner, and a bounded-memory encrypted-only large-vault proof.
- Task 13 adds independently produced Bonobo, Password Safe, Gorilla, and specification fixtures; authenticated
  redacted manifests; exact no-edit/title-edit transaction evidence; and gated producer provenance.
- Task 14 adds exact desktop/mobile Botan target profiles, fail-closed cross-toolchain discovery,
  Windows MSVC environment bootstrapping, mobile compile/link probes, and dedicated hosted workflow jobs.
- Task 15 adds a non-overwriting public-service demonstration using only fixed fabricated data, its real-Botan
  subprocess coverage, and exact operating guidance for the delivered core and its security boundaries.

Key checkpoints: continuity `4013f8a`; Task 11 `8c2b30e`; Task 12/workflow `08c2107`; Gorilla derivatives `b77077c`;
legal Markdown-only `2be2512`; specifications Markdown-only `925e8c6`; plans Markdown-only `3df88b4`; single memory
and approved-design Markdown-only `669506e`; Task 13 interoperability `a91977d`; Task 14 platform gates `73431ea`.
Task 15 delivery is `5e1d5d7`.

## Last proven verification

The 2026-09-01 Task 13 baseline on Windows/CPython 3.14.7 collected 609 tests and reported 597 passed, 12
platform-specific skips, and 79% coverage in 105.87 seconds.  The property/resource/large-vault selection passed 16
tests; the fuzz integration pair passed; the deterministic runner processed 10,000 inputs across four corpus seeds.
The large-vault test stayed below `4 * max_inline_payload_bytes + 8 * io_chunk_bytes` and found no fabricated plaintext
marker in private working or recovery artifacts.

At the 2026-09-01 single-memory/approved-design checkpoint, all 26 document-policy tests passed.  Ruff and strict mypy
passed for the two changed Python files; the Python structure checker, provenance, tracked-file policy, and staged and
unstaged whitespace checks passed; REUSE 3.3 classified 103/103 files.  Filesystem inspection found zero TeX/PDF files
in every Markdown-only directory, no split-memory directory, no HANDOFF artifact, and no stale split-memory reference.
Hosted CI has not yet been observed after publication; these are local results.

The final 2026-09-01 Windows/CPython 3.14.7 full suite explicitly used the resolved Botan test library, collected 635
tests, and reported 623 passed, 12 platform-specific skips, 79% coverage, and zero failures in 104.01 seconds. The
focused Botan-build, interop, compatibility, and provenance selection passed 65 tests, including real Botan
authentication, complete ordered-manifest regeneration for all four fixtures, exact transaction/provenance gates, and
the authenticated-snapshot path-replacement test. The compatibility regression selection passed another 20 tests
after two narrowly scoped Bandit `B105` false-positive suppressions for public `password_safe_*` metadata values.

Autopep8 produced no staged-checkpoint drift. Ruff and strict mypy passed 69 source files. The Python structure,
tracked-file, compatibility, provenance, Bandit, and pip-audit gates exited zero; compatibility reports 66 behaviors,
45 features, and 55 oracles. Pip-audit found no known third-party vulnerabilities and skipped only the local unpublished
`password-bonobo` project. REUSE 3.3 classified 114/114 files. The source distribution and wheel built successfully,
and the wheel gate accepted `password_bonobo-0.1.0-py3-none-any.whl`. Whitespace checks are clean.

Task 14's 2026-09-01 Windows checkpoint built the minimized pinned Botan 3.13.0 `ffi,twofish` host shared library from
source using an isolated, discovered x64 MSVC developer environment. The resulting
`build/botan-task14-host/bin/botan-3.dll` reported Botan 3.13.0. With that exact DLL configured, the focused build and
PasswordSafe selection collected 566 tests and reported 554 passed, 12 platform-specific skips, and zero failures in
102.26 seconds. The 35 build-driver tests, Ruff, strict mypy, Python structure checker, parsed workflow schema,
provenance gate, and REUSE 114/114 check all passed. Android/iOS toolchain behavior is unit-tested locally but awaits
hosted execution on the declared runners. Independent review caught and corrected Clang language selection leaking
from the generated C source onto the static archive; the command now enforces `-x c` for the source and resets with
`-x none` before the archive. Red-first regression coverage locks that boundary. Final review reported no Critical or
Important findings; its sole Minor note is that workflow tests use substring assertions, while a separate YAML parse
confirmed the jobs are structurally valid.

Task 15's final 2026-09-01 Windows/CPython 3.14.7 release candidate used the resolved Botan 3.13.0 DLL, collected 657
tests, and reported 645 passed, 12 expected platform-specific skips, 79% coverage, and zero failures in 106.11 seconds.
Three subprocess tests completed a real create/save/reopen/lock cycle and proved preexisting destination and private
workspace paths remain untouched; a fourth test proves hidden terminal input fails closed. Autopep8 introduced no
unstaged drift. Ruff, strict mypy over 71 Python files, Python structure, compatibility,
provenance, tracked-file, Bandit, pip-audit, REUSE 117/117, source-distribution build, wheel build, wheel inspection,
and staged/unstaged whitespace checks all passed. The only pip-audit skip is the unpublished local project.
Independent review reported no Critical or Important findings. Its sole remaining Minor note is that the private-
directory rollback path is implemented but not directly fault-injected by the example tests.

The 2026-09-01 native-diagnostics repair added four red-first boundary regressions and passed all 39 build-driver tests.
The full Windows/CPython 3.14.7 suite used the previously verified Botan 3.13 DLL and reported 649 passed, 12 expected
platform-specific skips, 79% coverage, and zero failures in 110.35 seconds. Autopep8, Ruff, strict mypy over 71 files,
Python structure, compatibility, provenance, tracked-file, Bandit, pip-audit, REUSE 118/118, source-distribution build,
wheel build, wheel inspection, and whitespace checks all exited zero. The diagnostic commit is integrated and pushed
as `caec5f5`; follow-up hosted run `33555795740` completed with Android passing and the four remaining bounded failures
recorded above. Independent review first identified missing cross-toolchain path redaction, an overly broad
artifact-name filter, retained tab controls, and over-redaction of relative `make` text; red-first tests and
implementation corrections closed all four. Follow-up review reported no Critical, Important, or Minor findings.

The 2026-09-01 cross-platform strict-typing repair reproduced all 23 macOS errors and now passes strict mypy over all
70 files under explicit Darwin, Windows, and Linux profiles. A red Windows DACL regression exposed an accidental
`O_BINARY` lookup on `msvcrt`; retaining that flag on the typed `os` facade restored runtime behavior. The focused
snapshot, storage, and Botan-build selection passed 92 tests with 7 expected skips. The full Windows/CPython 3.14.7
suite used the verified Botan DLL and reported 649 passed, 12 expected skips, 79% coverage, and zero failures in
107.13 seconds. Autopep8 produced no residual drift; Ruff, Python structure, Bandit, REUSE 119/119, whitespace, and all
three mypy profiles passed. Independent review identified and resolved one Important loss of `WinDLL` constructor
checking plus one Minor stale-memory wording issue. Follow-up review found no remaining Critical or Important issue.
Commit `403f638` was then fast-forwarded into local `main`; the merged result repeated the full suite with 649 passed,
12 expected skips, 79% coverage, and zero failures in 108.08 seconds. The completed worktree and local feature branch
were removed after that green run.

The 2026-09-01 Linux Botan-discovery repair added a red regression for the exact `libbotan-3.so`,
`libbotan-3.so.13`, and `libbotan-3.so.13.13.0` hosted artifact set. The minimal selection rule prefers the one canonical
linker filename only when every other candidate is a same-directory numeric soname companion. The versioned-only
single-candidate fallback and genuine ambiguity rejection remain covered. All 44 build-driver tests pass. The full
Windows/CPython 3.14.7 suite reports 654 passed, 12 expected skips, 79% coverage, and zero failures in 108.88 seconds.
Autopep8, Ruff, Python structure, Bandit, REUSE 119/119, whitespace, and strict mypy under Darwin, Windows, and Linux
profiles pass. Independent review identified and closed an Important fail-open case for malformed or cross-platform
leftovers plus its Minor missing fallback coverage. Follow-up review found no remaining Critical or Important issue.
Commit `f32bd0b` was fast-forwarded into local `main` after a fresh pre-merge run reported 654 passed, 12 expected
skips, 79% coverage, and zero failures in 109.87 seconds. The merged `main` tree repeated that result in 108.46 seconds.
The clean worktree and merged `fix/linux-botan-discovery` branch were then removed.

Hosted run `33576400850` then proved the discovery repair and bounded the next desktop work. macOS rejects private
objects before artifact creation; its two real native ACL probes expose the same verifier failure. Windows rejects the
fresh `0o700` directory because the elevated runner can make `BUILTIN\\Administrators`
the owner even though CPython's protected DACL contains only owner rights, SYSTEM, and Administrators. Ubuntu's first
failure expects `StorageError` where a successful directory retarget correctly raises `ExternalModificationError`.
Its second failure exposes an inode-reuse ABA: cleanup can unlink a replacement candidate when the original inode was
released and immediately reused.

The desktop repair retains an open candidate identity through authentication and failure cleanup, accepts the
administrator owner only while preserving the protected Windows DACL and exact ACE allowlist, corrects the successful
POSIX retarget regression to require `ExternalModificationError`, and initially isolated the macOS pytest temporary
root. A red Windows native regression proved the ownership boundary before implementation. Review then identified and
closed one Important `BaseException` descriptor-leak path during guard validation or candidate removal; two red-first
interruption regressions cover both boundaries, and follow-up review found no remaining Critical or Important code
issue. Commit `6605e04` is integrated and pushed. Its merged `main` suite reports 657 passed, 12 expected skips, 79%
coverage, and zero failures in 108.18 seconds. Autopep8, Ruff, Python structure, YAML parsing, compatibility, provenance,
tracked-file, Bandit, pip-audit, REUSE 119/119, source/wheel build, wheel inspection, whitespace, and strict mypy under
Darwin, Windows, and Linux profiles all pass.

Hosted run `33582756604` proves the Ubuntu and Windows desktop jobs and Android cross-build now pass. macOS still fails
because the temporary-root theory was wrong, and iOS retains the known C++ runtime link failure. Apple Libc source shows
that `acl_get_fd_np` represents an absent ACL property as `NULL` with `errno=ENOENT`; the verifier incorrectly treated
all null returns as failures. Worktree branch `fix/macos-no-acl-sentinel` adds a red regression for that exact safe
sentinel, continues rejecting null with any other errno and every actual/anomalous ACL, and removes the ineffective
temporary-root workaround. The snapshot security file passes 50 tests with 7 platform skips. All three strict mypy
profiles and the current-head full suite pass: 658 passed, 12 expected skips, 79% coverage, and zero failures in 109.93
seconds. Review found no Critical or Important issue; its Minor request for explicit wrong-errno and invalid-pointer
cases is incorporated, and the expanded snapshot selection passes 54 tests with 7 platform skips. Commit `3c5b538` is
integrated and pushed. Its merged suite reports 662 passed, 12 expected skips, 79% coverage, and zero failures in
107.85 seconds. Hosted run `33583601745` proves every desktop job and Android pass. Its only failure is the iOS link,
where the Botan archive leaves `___cxa_guard_release`, `___cxa_throw`, `___gxx_personality_v0`, and `std::__1` symbols
unresolved.

Worktree branch `fix/ios-cxx-runtime` adds red-first command coverage requiring `-lc++` immediately after the Botan
static archive only for `ios-arm64`; Android remains unchanged. The minimal implementation now satisfies both focused
regressions and all 44 build-driver tests. Independent review reports no Critical, Important, or Minor findings.
Commit `6989c2f` is integrated and pushed, with verification checkpoint `d290682`. The pre-merge full
Windows/CPython 3.14.7 suite uses the
verified Botan 3.13 DLL and reports 662 passed, 12 expected skips, 79% coverage, and zero failures in 109.53 seconds.
Ruff, Python structure, Bandit, compatibility, provenance, tracked-file, REUSE 119/119, whitespace, and strict mypy
under Windows, Darwin, and Linux profiles all pass. Pip-audit finds no known third-party vulnerabilities and skips only
the unpublished local project; the source distribution build, wheel build, and wheel inspection all pass. The merged
`main` tree repeats the full suite with 662 passed, 12 expected skips, 79% coverage, and zero failures in 109.63 seconds;
Ruff and Python structure also pass on the merged tree.

Hosted run `33584473400` passes all five jobs: the Windows, macOS, and Ubuntu quality suites plus Android and iOS arm64
cross-build/link probes. This is the first hosted run with every declared platform gate green. The merged iOS worktree
and local branch are removed. The proposed O3 continuation design is
`docs/superpowers/specs/2026-09-01-vault-application-desktop-foundation-design.md`; its first executable vertical-slice
plan is `docs/superpowers/plans/2026-09-01-vault-application-desktop-vertical-slice.md`. The design selects a
UI-independent `bonobo_core.application` facade with a thin `bonobo_desktop` PySide6/Qt Quick adapter and treats dirty
idle lock as authenticated encrypted suspension. All 26 Markdown/document-policy tests pass for these artifacts.
Documentation-only follow-up run `33585101442` keeps both mobile jobs green but exposes missing REUSE annotations for
the two new O3 Markdown files on every desktop job; the files themselves and all preceding quality steps pass. The
current correction adds those exact files to the existing aggregate GPL-3.0-or-later annotation before Task 1 begins.

Local command form uses `python -m uv` because the `uv` console executable is not discoverable on this Windows PATH.
REUSE uses `--no-multiprocessing` because Python 3.14 Windows worker startup was unstable while single-process checks
the same metadata.

## Durable decisions and boundaries

- Gorilla implementation material remains outside this repository.  Product work uses approved specifications,
  official format documentation, neutral observations, and synthetic tests; no upstream expression enters the product.
- Compatibility hashes are evidence indexes, not substitutes for exact comparisons.  Unknown-field preservation and
  authenticated transactional publication remain mandatory.
- External contributions remain closed until contributor terms and any iOS exception rights are resolved.
- Wheels declare GPL-3.0-or-later and both wheel/source distributions carry the exact GPL text and typing marker.
- Markdown is canonical.  Never generate, regenerate, verify, or retain LaTeX/PDF derivatives without explicit
  document-level user instructions.  The generator requires repeated `--document` selections and has no all-document
  mode.
- This file plus `docs/compatibility/gorilla/`, `docs/legal/`, `docs/specs/`, `docs/superpowers/plans/`, and
  `docs/superpowers/specs/` are Markdown-only until the user explicitly reverses a boundary.
- Shared standards below `E:\home\Code\Code Agent Prompts\docs\prompts\` are read-only and never repository content.

## Active risks

- The App Store distribution exception, contributor permissions, dependency eligibility, and current Apple terms are
  unresolved and block external contributions and an iOS distribution build.
- Some Gorilla behaviors remain Unverified and cannot establish parity until black-box evidence is reviewed.
- Future binary/mobile dependencies require Python 3.14 and platform requalification.
- Task 14's mobile gates provide compile/link evidence only. They cannot resolve the pending iOS distribution terms or
  establish execution on physical Android/iOS devices.
- Hosted run `33584473400` proves all three desktop jobs and both mobile cross-build/link jobs pass. Native packaged
  desktop applications, QML workflows, and physical-device mobile execution remain unqualified.

## Exact continuation order after this checkpoint

1. Execute vertical-slice Task 5 red-first in the existing isolated O3 worktree.
2. Continue Tasks 6 through 8 in order under the selected subagent-driven workflow.
3. Do not start provider coordination, URL-audit behavior, or mobile clients.
