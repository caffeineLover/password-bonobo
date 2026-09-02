# Task 6 Report: Adapt snapshots and commands to Qt

Date: 2026-09-02

Branch: `feature/vault-application-desktop`

Starting checkpoint: `4c17640`

## Outcome

Task 6 adds reset-only record projection, primitive snapshot state, serialized facade execution, synchronous
GUI-thread platform adapters, and monotonic idle locking.  No QML, deployment, provider, URL-audit, or mobile work was
added.

The controller publishes only the closed record model and primitive phase, label, dirty, selected-key, failure-key,
decision-presence, and passphrase-presence values.  The passphrase getter always returns an empty string; input is
copied into mutable UTF-8 storage, cleared before submission, transferred to `SecretBuffer`, and deterministically
closed if submission is rejected or canceled before execution.  Paths and opaque decision tokens remain only inside
Python command closures.

`FacadeExecutor` owns one `QThreadPool` with `maxThreadCount(1)`.  Frozen command envelopes preserve submission order,
return snapshots through Qt signals, and project escaped failures to an argument-free signal.  Shutdown rejects new
work, cancels queued ownership callbacks, and waits for the operation that already entered the facade boundary.

`QtClipboardPort` and `QtBrowserPort` use blocking queued invocation when called from the facade worker.  Clipboard
bytes and URL bytes are copied into temporary bytearrays only inside the GUI-thread operation and wiped in `finally`.
Clipboard content carries a fresh 32-byte Bonobo MIME nonce and is cleared only while that nonce remains current.
`IdleLockController` uses `QElapsedTimer` as the time authority, resets only for qualifying application input events,
and submits its lock callback once per controller lifetime.

## Files

Created:

- `src/bonobo_desktop/models.py`
- `src/bonobo_desktop/controller.py`
- `src/bonobo_desktop/tasks.py`
- `src/bonobo_desktop/clipboard.py`
- `src/bonobo_desktop/browser.py`
- `src/bonobo_desktop/lifecycle.py`
- `tests/desktop/test_models.py`
- `tests/desktop/test_controller.py`
- `tests/desktop/test_clipboard.py`
- `tests/desktop/test_lifecycle.py`

Updated:

- `src/bonobo_desktop/main.py` reuses an existing Qt application singleton so the Task 5 startup probe remains
  composable with the new Qt test session.
- `REUSE.toml` covers the new source, tests, and this report.
- `docs/PROJECT_MEMORY.md` records the active and completed checkpoint.

## TDD evidence

### Required absent-adapter RED

Command:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_models.py tests/desktop/test_controller.py tests/desktop/test_clipboard.py tests/desktop/test_lifecycle.py -q
```

Output and status:

```text
ERROR tests/desktop/test_models.py
ERROR tests/desktop/test_controller.py
ERROR tests/desktop/test_clipboard.py
ERROR tests/desktop/test_lifecycle.py
Interrupted: 4 errors during collection
EXIT_CODE=1
```

Each error was the expected `ModuleNotFoundError` for an absent Task 6 adapter module.

### First implementation run and focused GREEN

Command:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_models.py tests/desktop/test_controller.py tests/desktop/test_clipboard.py tests/desktop/test_lifecycle.py -q
```

First output:

```text
F............                                                            [100%]
FAILED tests/desktop/test_models.py::test_record_model_roles_are_closed_and_non_secret
1 failed, 12 passed in 2.51s
EXIT_CODE=1
```

The runtime returned `QByteArray` values rather than the brief's exact `bytes` role names.  After the single boundary
correction, the same command produced:

```text
.............                                                            [100%]
13 passed in 2.42s
EXIT_CODE=0
```

### Shutdown ownership RED/GREEN found during self-review

Command:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_controller.py::test_executor_shutdown_cancels_queued_command_ownership -q
```

RED output:

```text
FAILED tests/desktop/test_controller.py::test_executor_shutdown_cancels_queued_command_ownership
TypeError: FacadeExecutor.submit() got an unexpected keyword argument 'canceled'
1 failed in 1.41s
EXIT_CODE=1
```

GREEN output after adding pending-only cancellation callbacks:

```text
.                                                                        [100%]
1 passed in 1.36s
EXIT_CODE=0
```

### Integration correction

The first complete `tests/desktop` run produced 16 passes and one failure because the Task 5 `main()` probe attempted
to construct a second `QGuiApplication` after pytest-qt created the session singleton.  Reusing the existing singleton
when present fixed that integration boundary without changing normal process startup.  The same pass also surfaced
the expected initial Qt naming/type-check diagnostics; required framework camelCase names received narrow `noqa`
comments, overrides use `typing.override`, and the brief's bytes-valued role map uses a documented cast at the PySide
stub boundary.

## Final verification

Exact Task 6 test command:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop -q
```

Output:

```text
..................                                                       [100%]
18 passed in 2.50s
EXIT_CODE=0
```

Exact Ruff command:

```powershell
python -m uv run ruff check src/bonobo_desktop tests/desktop
```

Output:

```text
All checks passed!
EXIT_CODE=0
```

Exact strict mypy command:

```powershell
python -m uv run mypy src/bonobo_desktop tests/desktop
```

Output:

```text
Success: no issues found in 15 source files
EXIT_CODE=0
```

Additional gates:

```text
python -m uv run python tools/check_python_structure.py src/bonobo_desktop tests/desktop
EXIT_CODE=0

python -m uv run reuse lint
Files with copyright information: 156 / 156
Files with license information: 156 / 156
EXIT_CODE=0

git diff --check
EXIT_CODE=0
```

Tests coordinate worker, shutdown, expiry, and GUI delivery with `threading.Event`, Qt signals, or pytest-qt signal
waits; no sleeps are used.

## Self-review

- Role mutation check: removing or swapping any approved role changes model outputs; adding a role violates the exact
  closed role-name assertion.
- Concurrency mutation check: raising pool concurrency or bypassing the queue makes the blocked two-command test report
  overlap or order failure.
- Shutdown mutation check: removing pending cancellation retains queued ownership; returning before active completion
  fails the drain assertion.
- GUI-affinity mutation check: direct worker access records a non-GUI thread and fails both platform adapter tests.
- Clipboard mutation check: unconditional clear erases the replacement test value; missing expiry leaves owned content.
- Idle mutation check: a non-input reset or repeated expired submission fails deterministic manual-clock assertions.
- Controller mutation check: retaining input after submission, exporting decision identity, passing an integer rather
  than `RecordKey`, or emitting extra snapshot signals violates focused behavior.

The only deliberate typing seam is `RecordListModel.roleNames`: PySide's generated stub specifies `QByteArray`, while
the approved test and Qt Python runtime contract require bytes-valued role names.  The method keeps the framework
override type and uses one documented cast around a fresh bytes dictionary.  No unresolved Task 6 concern remains.

## Review-fix round 1

Review fix round 1 starts from Task 6 commit `8f07415` and addresses all four Important findings without taking the
deferred Minor suggestions.  Immutable command envelopes now carry an explicit shutdown-drain policy.  Worker start
and shutdown admission are serialized under the executor guard, the executor tracks the exact active envelope and
task, queued ownership is canceled, and shutdown waits on that task's completion event only when the active envelope
is classified as durability work.  Save, dirty lock/suspend, and save-close resolution receive that classification;
open, search, copy, browser, clean lock, and other non-save operations do not.

The executor emits the argument-free `shutdownStarted` signal only after command admission is closed.  The shutdown
rejection regression uses pytest-qt's event-loop-aware signal wait before attempting a second submission, eliminating
the prior scheduling race.  A separate event-controlled regression holds an active non-durability command and proves
shutdown returns before that command is released.  All worker tests use events or signals and contain no sleeps.

Passphrase replacement now emits `passphraseChanged` exactly once after the previous mutable buffer is wiped and the
replacement is installed.  Manual/idle lock clears and notifies before submission.  Close intent, non-cancel close
resolution, accepted terminal snapshots, and the controller's explicit shutdown entry point also wipe retained input;
the latter closes executor admission only after the wipe.  The locked-state regression observes the cleared primitive
presence property inside the lock submission boundary and receives only the setter and clear notifications.

### Files changed

- `src/bonobo_desktop/tasks.py`: immutable drain classification, atomic active-envelope tracking, admission-closed
  signal, queued cancellation, and durability-only completion waiting.
- `src/bonobo_desktop/controller.py`: save/suspend classification plus passphrase replacement, terminal, and shutdown
  wiping/notification behavior.
- `tests/desktop/test_controller.py`: deterministic shutdown-policy, synchronized rejection, passphrase notification,
  lock wipe, and controller-shutdown regressions.
- `docs/PROJECT_MEMORY.md`: active and final review-fix checkpoint.
- This report: exact repair chronology and verification evidence.

### RED evidence

Command:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_controller.py -q
```

Output and status against unchanged production code:

```text
..FFFFF..                                                                [100%]
FAILED test_executor_shutdown_drains_active_work_and_rejects_new_commands
  AttributeError: 'FacadeExecutor' object has no attribute 'shutdownStarted'
FAILED test_executor_shutdown_does_not_drain_active_non_durability_work
  AttributeError: 'FacadeExecutor' object has no attribute 'shutdownStarted'
FAILED test_executor_shutdown_cancels_queued_command_ownership
  TypeError: FacadeExecutor.submit() got an unexpected keyword argument 'drain_on_shutdown'
FAILED test_controller_emits_passphrase_notification_after_replacement
  assert 0 == 1
FAILED test_controller_clears_passphrase_before_lock
  AssertionError: assert True is False
5 failed, 4 passed in 1.49s
EXIT_CODE=1
```

The controller-shutdown regression was then added before production work and run independently:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_controller.py::test_controller_shutdown_clears_passphrase -q
```

```text
FAILED tests/desktop/test_controller.py::test_controller_shutdown_clears_passphrase
AttributeError: 'DesktopController' object has no attribute 'shutdown'
1 failed in 1.42s
EXIT_CODE=1
```

### Focused GREEN

The first implementation run left two test failures because a raw `threading.Event.wait` on the GUI test thread
prevented queued Qt signal delivery.  Replacing those two waits with `qtbot.waitSignal` preserved the required
admission-closed synchronization while allowing the Qt event loop to deliver the signal.  No production behavior was
changed for this test correction.

Command:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_controller.py -q
```

Final output:

```text
..........                                                               [100%]
10 passed in 1.42s
EXIT_CODE=0
```

### Complete verification

Offscreen desktop suite:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop -q
```

```text
......................                                                   [100%]
22 passed in 2.75s
EXIT_CODE=0
```

Task 6 Ruff:

```powershell
python -m uv run ruff check src/bonobo_desktop tests/desktop
```

```text
All checks passed!
EXIT_CODE=0
```

Task 6 strict mypy:

```powershell
python -m uv run mypy src/bonobo_desktop tests/desktop
```

```text
Success: no issues found in 15 source files
EXIT_CODE=0
```

Structure, REUSE, and unstaged whitespace gates:

```powershell
python -m uv run python tools/check_python_structure.py src/bonobo_desktop tests/desktop
python -m uv run reuse lint
git diff --check
```

```text
Structure: EXIT_CODE=0
REUSE Specification 3.3: 156 / 156 files have copyright and license information; EXIT_CODE=0
Whitespace: EXIT_CODE=0
```

The local REUSE 3.3 CLI does not support the historical `--no-multiprocessing` option; its attempted use failed at
argument parsing, so the required standard `reuse lint` command above was run and passed.

### Self-review

- Shutdown admission and worker start share one lock, so a dequeued task either becomes the single tracked active
  envelope before shutdown observes it or is canceled without entering the facade.
- The active task completion event is set after executor ownership is released on success, closed failure, or queued
  cancellation.  No pool-wide wait remains; a non-durability operation can still finish naturally after shutdown has
  returned, while queued operations cannot start.
- Only save, dirty lock/suspend, and save-close resolution request draining.  The clean lock path is deliberately not
  classified as durability work.
- Passphrase clearing is synchronous before lock, close intent, non-cancel resolution, and controller shutdown.
  Accepted locked/empty snapshots provide a second idempotent terminal safeguard without duplicate notification.
- New Qt signals remain argument-free, and no path, URL, UUID, password, note, email, custom field, exception text,
  domain handle, revision, or decision identity enters controller/model state.
- GUI-thread clipboard/browser lease marshalling, clipboard nonce ownership, and idle single-submit behavior are
  unchanged and covered by the complete desktop suite.

No unresolved review-fix concern remains.
