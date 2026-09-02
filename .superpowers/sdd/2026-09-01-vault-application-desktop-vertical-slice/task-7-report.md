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

## Review-fix round 1

This separate repair closes the four Important review findings and the
confirmed mandatory mypy deficit against Task 7 commit `4697a2b`.

### RED evidence

The literal mandatory typing gate reproduced the conflicting helper identity
before import normalization:

```powershell
python -m uv run mypy src tests tools
```

```text
pyproject.toml: error: Source file found twice under different module names: "fakes" and "tests.application.fakes"
Found 1 error in 1 file (errors prevented further checking)
EXIT_CODE=1
```

The template-interpolation and controller-owner regressions were added before
the production changes and run with:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest -q tests/desktop/test_qml_contract.py tests/desktop/test_controller.py -k "template_interpolation or record_password"
```

```text
FAILED test_qml_boundary_parser_finds_forbidden_member_inside_template_interpolation
  AssertionError: assert 'passwordValue' in frozenset({'Text', 'text'})
FAILED test_controller_closes_record_password_when_executor_submission_raises
  assert False; SecretBuffer(closed=False)
2 failed, 1 passed, 19 deselected
EXIT_CODE=1
```

The multi-record focus and complete-view accessibility regressions were added
before their QML changes and run with:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
python -m uv run --extra desktop --group desktop-test python -m pytest -q tests/desktop/test_keyboard_workflow.py -k "another_filtered or complete_tab_cycle"
```

```text
FAILED test_model_reset_clears_selection_when_another_filtered_record_remains
  pytestqt.exceptions.TimeoutError: search focus was not restored
FAILED test_decision_dialog_has_accessible_complete_tab_cycle
  pytestqt.exceptions.TimeoutError: decisionSaveButton had no initial focus
2 failed, 4 passed, 5 deselected
EXIT_CODE=1
```

The four passing cases in that RED are material: Welcome, Unlock, Vault, and
RecordEditor already completed their newly asserted initial-focus, access-name,
visibility, and full forward-tab cycles.  DecisionDialog was the isolated
missing initial-focus branch.

### Systematic focus debugging

An initial controller-owned retained-row implementation caused a reproducible
native Windows access violation at QML window exposure.  Removing only the
`ListView.onIsCurrentItemChanged` call into a Python slot eliminated that
crash; reintroducing the call behind a zero-interval timer reproduced it on a
Down-key selection.  The stable implementation therefore keeps presentation
selection local: `modelAboutToBeReset` freezes delegate selection updates, a
zero-interval QML timer waits until the reset finishes, and the
`DelegateModel.items` group is scanned by the retained primitive `key`.  No
Python call occurs during model/view selection churn.  The regression selects
the second row by keyboard, filters it out while the first row remains, and
requires index `-1` plus search focus.

### Implementation and files

- `VaultView.qml` now retains by the exact existing `key` role on every model
  reset, restores the matching row, and clears local selection and focuses
  search whenever the key is absent regardless of remaining row count.
- `DecisionDialog.qml` defers initial focus until the opened modal is stable,
  then focuses its first allowed action, Save.
- `controller.py` guards executor submission with `BaseException` cleanup,
  suppresses cleanup failure only while preserving the original exception,
  and retains the existing admission-rejection behavior.
- `test_qml_contract.py` replaces the raw template-removal regex with a small
  code scanner that excludes strings/comments/template text while recursively
  preserving `${...}` expressions, including nested braces and templates.
- `test_keyboard_workflow.py` uses only fabricated records and exercises access
  names, initial visible focus, and deterministic complete tab cycles across
  Welcome, Unlock, Vault, RecordEditor, and DecisionDialog.
- `test_controller.py` covers rejected admission, raised submission, and a
  cleanup failure that must not mask the original interruption.
- The five `tests/application/test_*.py` helper imports now use the single
  qualified `tests.application.fakes` identity.
- Consistent imports alone remained RED.  The minimal evidenced fallback adds
  `tests/__init__.py`, `tests/application/__init__.py`, and
  `tests/passwordsafe/__init__.py`, then mechanically qualifies the existing
  PasswordSafe test-helper imports under `tests.passwordsafe`.  No production
  package or mypy configuration changed.  `REUSE.toml` covers the three new
  package markers.
- `docs/PROJECT_MEMORY.md` records this completed review checkpoint.

### GREEN verification

Focused ownership and masking regressions:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest -q tests/desktop/test_controller.py -k "record_password or secret_cleanup"
```

```text
3 passed, 16 deselected in 1.53s
EXIT_CODE=0
```

Resolved-file QML lint:

```powershell
$qmlFiles = (Get-ChildItem -LiteralPath 'src\bonobo_desktop\qml' -Filter '*.qml').FullName
python -m uv run --extra desktop pyside6-qmllint $qmlFiles
```

```text
EXIT_CODE=0
```

Affected application and complete offscreen desktop runtime suites:

```powershell
python -m uv run python -m pytest tests/application -q
$env:QT_QPA_PLATFORM = 'offscreen'
python -m uv run --extra desktop --group desktop-test python -X faulthandler -m pytest tests/desktop -q
```

```text
Application: 83 passed in 7.17s
Desktop: 47 passed in 3.18s
EXIT_CODE=0
```

The broader helper-import boundary was collected and sampled at runtime:

```powershell
python -m uv run python -m pytest --collect-only -q tests/passwordsafe
python -m uv run python -m pytest -q tests/passwordsafe/test_fuzz.py tests/passwordsafe/test_round_trip.py tests/passwordsafe/test_storage_external_change.py tests/passwordsafe/test_service.py
```

```text
637 tests collected in 2.20s
27 passed, 5 skipped in 29.46s
EXIT_CODE=0
```

Repository-wide strict typing now passes literally and under every required
profile:

```powershell
python -m uv run mypy src tests tools
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
```

```text
Success: no issues found in 106 source files
Success: no issues found in 106 source files
Success: no issues found in 106 source files
Success: no issues found in 106 source files
EXIT_CODE=0
```

Static, structure, licensing, and whitespace gates:

```powershell
python -m uv run ruff check src tests tools
python -m uv run python tools/check_python_structure.py src tests tools
python -m uv run reuse --no-multiprocessing lint
git diff --check
git diff --cached --check
```

```text
Ruff: All checks passed!
Structure: EXIT_CODE=0
REUSE Specification 3.3: 169 / 169 files have copyright and license information
Unstaged whitespace: EXIT_CODE=0
Staged whitespace: EXIT_CODE=0
```

### Accessibility and secret-boundary self-review

- Each focusable control in all four views and both scoped modals has a
  nonempty runtime accessible name, opts into tab focus, becomes the actual
  visible active-focus item at its deterministic stop, and returns to the
  initial item after one complete cycle.  Save receives focus whenever the
  decision modal opens.
- Selection restoration reads only the already-approved primitive `key` role;
  the other four roles remain `title`, `group`, `username`, and `protected`.
  Missing selection never aliases a remaining row and always returns focus to
  search.
- The boundary scanner still ignores legitimate resource/prose strings and now
  catches forbidden identifiers inside template interpolation code.  QML has
  no domain object, locator, UUID, secret-value, exception, or raw message
  binding.
- Passphrases and record passwords remain concealed local inputs, are cleared
  before submission, and are never rebound.  Record-password ownership is
  closed on worker failure, queue cancellation, rejection, or a raised submit;
  cleanup failure cannot replace the original `BaseException`.
- Ctrl+S, Ctrl+L, Ctrl+F, Enter, and Escape behavior is unchanged.  Editor
  cancellation remains local and mutation-free; shutdown serialization and
  terminal callback rules are untouched.

### Concerns

No remaining review-fix concern was found.  The earlier report statement that
repository-wide mypy was an out-of-scope baseline is superseded by the explicit
review authorization and the green package-identity repair above.  The QML
reset restore is intentionally deferred by one Qt event so the reset has fully
settled; runtime tests wait on the resulting focus state rather than elapsed
time.

## Review-fix round 2

This separate repair closes the remaining QML boundary-parser finding against
review-fix commit `3518167` without changing the product shell or its QML
surface.

### RED evidence

The exact legal regex-literal bypass was added before scanner changes and run
with:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_qml_contract.py::test_qml_boundary_parser_finds_forbidden_member_after_regex_literal_brace -q
```

```text
FAILED test_qml_boundary_parser_finds_forbidden_member_after_regex_literal_brace
  AssertionError: assert 'passwordValue' in frozenset({'Text', 'text'})
1 failed in 0.49s
EXIT_CODE=1
```

Companion cases for escaped and character-class braces were also added before
implementation.  The complete focused file established their RED state and
the division characterization's pre-existing GREEN state:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_qml_contract.py -q
```

```text
FAILED test_qml_boundary_parser_finds_forbidden_member_after_regex_literal_brace
FAILED test_qml_boundary_parser_finds_forbidden_member_after_escaped_regex_brace
FAILED test_qml_boundary_parser_finds_forbidden_member_after_regex_class_brace
3 failed, 5 passed in 0.57s
EXIT_CODE=1
```

All three failures returned only `Text` and `text`, proving that a `}` inside a
regex pattern incorrectly ended the template interpolation before the later
forbidden member access.

### Implementation and files

- `tests/desktop/test_qml_contract.py` now recognizes a JavaScript regex
  literal only when the preceding lexical token permits an expression.  A
  slash following an identifier, number, string, template, regex, or closing
  delimiter remains division syntax.
- The regex scan treats escaped characters and complete character classes as
  pattern content, stops only at an unescaped slash outside a class, consumes
  alphabetic flags, and falls back to operator handling for an unterminated
  candidate rather than swallowing the remaining source.
- Four regressions cover the exact `/}/` bypass, an escaped `\}`, a class-held
  `}`, and preservation of both division operands plus the later forbidden
  member.
- `docs/PROJECT_MEMORY.md` records the completed repair checkpoint.  No QML or
  product source file changed.

### GREEN verification

The final focused scanner and complete QML contract file passes:

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_qml_contract.py -q
```

```text
8 passed in 0.52s
EXIT_CODE=0
```

Resolved-file QML lint and the complete offscreen desktop suite pass:

```powershell
$qmlFiles = (Get-ChildItem -LiteralPath 'src\bonobo_desktop\qml' -Filter '*.qml').FullName
python -m uv run --extra desktop pyside6-qmllint $qmlFiles
$env:QT_QPA_PLATFORM = 'offscreen'
python -m uv run --extra desktop --group desktop-test python -X faulthandler -m pytest tests/desktop -q
```

```text
QML lint: EXIT_CODE=0
Desktop: 51 passed in 3.11s
EXIT_CODE=0
```

Repository-wide lint, default and three-platform strict typing, structure,
licensing, and whitespace pass:

```powershell
python -m uv run ruff check src tests tools
python -m uv run mypy src tests tools
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
python -m uv run python tools/check_python_structure.py src tests tools
python -m uv run reuse --no-multiprocessing lint
git diff --check
git diff --cached --check
```

```text
Ruff: All checks passed!
Mypy default: Success: no issues found in 106 source files
Mypy win32: Success: no issues found in 106 source files
Mypy darwin: Success: no issues found in 106 source files
Mypy linux: Success: no issues found in 106 source files
Structure: EXIT_CODE=0
REUSE Specification 3.3: 169 / 169 files have copyright and license information
Unstaged whitespace: EXIT_CODE=0
Staged whitespace: EXIT_CODE=0
```

### Boundary self-review and concerns

- The exact valid expression
  `` `${/}/.test(value) ? desktopController.passwordValue : 0}` `` now exposes
  `passwordValue` to the forbidden-identifier intersection.
- Regex contents remain non-code to the boundary gate, including escaped
  delimiters and character classes.  Division operands remain code and cannot
  be hidden by blindly consuming from one slash to a later slash.
- The QML surface, five record roles, local-secret lifecycle, shortcuts,
  accessibility behavior, and shutdown serialization are untouched.
- The scanner is deliberately a bounded lexical gate rather than a JavaScript
  parser.  Its conservative expression-context state covers literals,
  operands, delimiters, operators, and regex-prefix keywords needed to
  distinguish this boundary; no remaining Task 7 concern was found.
