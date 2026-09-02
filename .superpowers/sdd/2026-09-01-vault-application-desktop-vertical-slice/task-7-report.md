# Task 7 Report: Qt Quick Workflow and Accessibility Contract

Date: 2026-09-02

Status: COMPLETE

## Outcome

Task 7 implements the approved Welcome, Unlock, Vault, and RecordEditor views
plus the scoped DecisionDialog. The shell loads from package-owned QML files,
receives only one `DesktopController` context object, and operates through the
existing five-role record model. Create/Open/Unlock, search, Save/Lock,
Add/Edit Confirm, copy username/password, open website, and close decisions are
wired through primitive controller operations.

The approved scope corrections also close two composition gaps. The controller
converts primitive editor input into private generation-bound `RecordDraft`,
`RecordKey`, and `SecretBuffer` objects inside a serialized Python command. The
composition root now creates the Qt platform ports, facade, executor, and
controller before loading QML. Executor shutdown accepts one closed terminal
callback so the final facade lock never races active work.

## Implementation and files

- `src/bonobo_desktop/qml/Main.qml` selects the top-level view only from the
  primitive application phase and hosts the decision dialog.
- `WelcomeView.qml` and `UnlockView.qml` keep concealed input local, clear it
  before command submission, and expose keyboard-reachable Create/Open/Unlock.
- `VaultView.qml` provides search, dirty status, record selection, all scoped
  record actions, Ctrl+S/Ctrl+L/Ctrl+F, Enter activation, retained-list focus,
  and search fallback when filtering removes the selected row.
- `RecordEditor.qml` keeps its draft and password local, prefills only the
  non-secret roles, clears the password before Confirm and on every close path,
  and rejects Escape without a controller mutation.
- `DecisionDialog.qml` exposes only Save/Discard/Cancel and maps Escape to the
  non-mutating cancel choice.
- `qml/qmldir` declares exactly the six approved components.
- `src/bonobo_desktop/resources.py` resolves the installed package QML
  directory and `Main.qml` local-file URL without importing Qt at base import.
- `src/bonobo_desktop/controller.py` adds primitive `confirmRecord`; all draft,
  key, generation, and secret ownership remains private to Python.
- `src/bonobo_desktop/main.py` composes the service, platform ports, facade,
  executor, controller, and engine in fail-closed order and injects only
  `desktopController` before load.
- `src/bonobo_desktop/tasks.py` atomically closes admission, cancels queued
  ownership, and runs one terminal callback either idle, after draining active
  durability work, or from ordinary active-work finalization. Callback failures
  remain closed and repeat shutdown is inert.
- `tests/desktop/test_qml_contract.py` compiles every component and lexes exact
  code identifiers after removing strings/comments, so a legitimate resource
  string containing `path` is not a false positive while forbidden member
  bindings are detected.
- `tests/desktop/test_keyboard_workflow.py` drives real offscreen QML keyboard,
  accessibility, modal-cancel, secret-clear, and focus behavior.
- `tests/desktop/test_controller.py` covers primitive edit/add confirmation and
  deterministic shutdown terminal ordering.
- `tests/desktop/test_main.py` proves the sole context object is installed
  before QML load.
- `REUSE.toml` covers all new code-native assets and tests.
- `docs/PROJECT_MEMORY.md` records this checkpoint and exact continuation.

No bitmap art, deployment/CI, provider, URL-audit, mobile, settings, or
advanced group/history/policy work was added.

## RED evidence

The prescribed resource RED was run before any QML files existed:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_qml_contract.py tests/desktop/test_keyboard_workflow.py -q
```

```text
1 failed, 1 passed, 4 errors
FileNotFoundError: ... src/bonobo_desktop/qml/Main.qml
```

Primitive adapter tests were added before controller implementation. The
focused run reported two failures because `DesktopController.confirm_record`
did not exist. The composition test was likewise RED before `main.py` wiring:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_controller.py -k "confirms_existing_record or confirms_new_record" -q
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_main.py::test_desktop_main_injects_only_controller_before_qml_load -q
```

```text
Controller: 2 failed; AttributeError: 'DesktopController' object has no attribute 'confirm_record'
Composition: 1 failed; expected ['context', 'load'], observed ['load', 'delete']
```

The shutdown race found during self-review received three event-driven RED
regressions before the executor change:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_controller.py -k 'terminal_callback or terminal_after_active' -q
```

```text
3 failed, 13 deselected
TypeError: FacadeExecutor.shutdown() takes 1 positional argument but 2 were given
```

The identifier parser and filtered-selection focus contracts were separately
observed RED:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_qml_contract.py::test_qml_boundary_parser_ignores_strings_but_finds_member_bindings -q
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_keyboard_workflow.py::test_model_reset_restores_search_when_selection_is_filtered_out -q
```

```text
Parser: 1 failed; NameError: name '_qml_identifiers' is not defined
Focus: 1 failed; assert search.hasActiveFocus()
```

## GREEN and final verification

Resolved-path QML lint is clean:

```powershell
$qmlFiles = (Get-ChildItem -LiteralPath 'src\bonobo_desktop\qml' -Filter '*.qml').FullName
python -m uv run --extra desktop pyside6-qmllint $qmlFiles
```

```text
EXIT_CODE=0
```

The brief's literal wildcard spelling does not expand under PowerShell; the
wrapper prints `Failed to open file src/bonobo_desktop/qml/*.qml` while
returning zero. The resolved-path invocation above is the meaningful lint gate
and checked every QML file.

Complete desktop suite:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop -q
```

```text
38 passed in 2.88s
EXIT_CODE=0
```

Static and structure checks:

```powershell
python -m uv run ruff check src tests tools
python -m uv run mypy src/bonobo_desktop tests/desktop
python -m uv run python tools/check_python_structure.py src/bonobo_desktop tests/desktop
```

```text
Ruff: All checks passed!
Mypy: Success: no issues found in 17 source files
Structure: EXIT_CODE=0
```

The literal repository-wide mypy command and its three platform forms remain
RED at clean `d436908` as well as this change. The repository has no test
package markers: committed application tests import `fakes`, while committed
desktop tests import `tests.application.fakes`, so mypy assigns the same file
both `fakes` and `tests.application.fakes`. An archived clean `d436908` run
reproduced that duplicate-module diagnostic. Adding test package markers or
changing global mypy mapping is outside the approved Task 7 scope. The mandated
attempts and established scoped desktop gate were:

```powershell
python -m uv run mypy src tests tools
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
python -m uv run mypy src/bonobo_desktop tests/desktop
```

```text
Global/profile runs: Source file found twice under different module names: "fakes" and "tests.application.fakes"
Scoped desktop run: Success: no issues found in 17 source files
```

Final staged repository gates:

```powershell
python -m uv run reuse lint
git diff --check
git diff --cached --check
```

```text
REUSE Specification 3.3: 166 / 166 files have copyright and license information
Unstaged whitespace: EXIT_CODE=0
Staged whitespace: EXIT_CODE=0
```

## Accessibility and secret-boundary self-review

- Every scoped button has a nonempty runtime accessibility name,
  `activeFocusOnTab`, an explicit next tab target, default Qt Controls visible
  focus styling, and a mnemonic. Text inputs and the record list are named and
  included in explicit focus cycles.
- Ctrl+S saves, Ctrl+L locks, Ctrl+F focuses search, and Enter activates the
  selected record. Real offscreen tests exercise each path.
- Escape closes RecordEditor without a facade call and clears its local secret.
  DecisionDialog Escape submits only the cancel choice.
- Qt retains focus on an existing selected list row through reset. When a
  filter empties the model, `onCountChanged` returns focus to search; both
  branches have real offscreen regression coverage.
- QML receives only primitive controller properties and the exact `key`,
  `title`, `group`, `username`, and `protected` roles. The composition test
  verifies no facade, service, session, executor, or platform port is injected.
- Passphrase and password fields are local concealed controls. They are cleared
  before submission and never rebound from controller state. The controller
  immediately copies record-password input into an owned mutable buffer, drops
  its immutable argument reference, and guarantees owner closure on success,
  failure, queue cancellation, or admission rejection.
- The QML identifier gate rejects domain identities, paths, UUIDs, secret
  values, and raw diagnostic bindings by exact code token. Strings and comments
  are removed first, satisfying the no-raw-substring preflight ruling.
- Shutdown lock is serialized behind active facade work; queued secret owners
  are canceled before terminal handling, and failures expose no text.

## Concerns

The repository-wide mypy duplicate-module baseline remains the only gate
concern; Task 7 adds no new import route and its scoped strict check passes.
PowerShell wildcard behavior for `pyside6-qmllint` is also documented above.
No remaining Task 7 functional, accessibility, secret-boundary, or shutdown
concern was found in the final diff review.
