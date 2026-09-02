# Vault Application and Desktop Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a secure, testable vertical slice that creates or opens a vault, projects/searches records, edits and
saves one record, performs explicit secret actions, suspends dirty state for lock, and exposes the workflow through a
keyboard-accessible PySide6/Qt Quick desktop shell.

**Architecture:** `bonobo_core.application` owns UI-independent state, commands, safe DTOs, and platform protocols while
continuing to delegate all vault mutation/publication to `VaultService`. `bonobo_desktop` serializes facade calls on one
worker, adapts snapshots to Qt models, and keeps QML declarative and domain-free. Dirty lock uses a new authenticated,
private pending-session artifact rather than saving or discarding edits.

**Tech Stack:** Python 3.14, existing typed PasswordSafe core and Botan 3.13.0, PySide6 `>=6.11.2,<6.12`, Qt Quick/QML,
pytest, pytest-qt, Ruff, strict mypy, Bandit, REUSE, uv, and native `pyside6-deploy` dry runs.

**Spec:** `docs/superpowers/specs/2026-09-01-vault-application-desktop-foundation-design.md`

## Global Constraints

- Never expose a path, URL, UUID, password, note, email, custom field, or raw exception through application snapshots,
  logs, QML models, or test diagnostics.
- Only `VaultService` may authenticate, serialize, or publish PasswordSafe documents.
- Every accepted edit carries both the current application generation and `RevisionToken`.
- Dirty lock must durably authenticate private encrypted pending state before releasing the live session.
- The source vault remains unchanged on lock, cancel, authentication failure, stale revision, or adapter failure.
- PySide6 imports are confined to `bonobo_desktop`; `bonobo_core.application` stays reusable by mobile clients.
- Use only fabricated values and `.example.invalid` URLs in tests.
- Use red-green-refactor TDD, independently review each task, and update `docs/PROJECT_MEMORY.md` at every checkpoint.
- Keep `docs/superpowers/plans/` and `docs/superpowers/specs/` Markdown-only.

## File structure

- `src/bonobo_core/application/types.py`: non-secret state, command, decision, and record DTOs.
- `src/bonobo_core/application/errors.py`: closed safe failure taxonomy and exception mapping.
- `src/bonobo_core/application/ports.py`: clipboard and browser protocols for the vertical slice.
- `src/bonobo_core/application/projection.py`: record projection and deterministic search.
- `src/bonobo_core/application/facade.py`: serialized application state machine.
- `src/bonobo_core/passwordsafe/pending.py`: durable encrypted pending-session storage.
- `src/bonobo_desktop/main.py`: desktop composition root.
- `src/bonobo_desktop/deploy.py`: absolute-import deployment wrapper.
- `src/bonobo_desktop/file_dialog.py`: Python-owned GUI-thread native vault selection.
- `src/bonobo_desktop/controller.py`: QObject command adapter.
- `src/bonobo_desktop/models.py`: Qt record-list model.
- `src/bonobo_desktop/tasks.py`: single-worker facade executor.
- `src/bonobo_desktop/clipboard.py`, `browser.py`, `lifecycle.py`: Qt platform ports.
- `src/bonobo_desktop/qml/`: welcome, unlock, vault, editor, and confirmation views.
- `tests/application/`: headless application and pending-session tests.
- `tests/desktop/`: offscreen Qt/QML, model, controller, keyboard, and adapter tests.

---

### Task 1: Define safe application contracts and record projection

**Files:**
- Create: `src/bonobo_core/application/__init__.py`
- Create: `src/bonobo_core/application/types.py`
- Create: `src/bonobo_core/application/errors.py`
- Create: `src/bonobo_core/application/projection.py`
- Create: `tests/application/test_types.py`
- Create: `tests/application/test_projection.py`
- Modify: `tests/passwordsafe/helpers.py`

**Interfaces:**
- Consumes: `RecordView`, `RecordHandle`, `RevisionToken`, and typed `PasswordSafeError` subclasses.
- Produces: `ApplicationPhase`, `ApplicationSnapshot`, `RecordSummary`, `RecordKey`, `DecisionToken`,
  `ApplicationFailure`, `ApplicationFailureReason`, `project_records`, and `search_records`.

- [ ] **Step 1: Write failing closed-contract tests**

```python
def test_application_snapshot_rejects_secret_or_path_fields() -> None:
    assert {field.name for field in fields(ApplicationSnapshot)} == {
        "generation", "phase", "display_label", "dirty", "records", "selected", "failure", "decision"
    }


def test_projection_exposes_only_non_secret_record_summary() -> None:
    summary = project_records((fabricated_record_view(),), {fabricated_record_view().handle: RecordKey(1)})[0]
    assert summary == RecordSummary(RecordKey(1), "Alpha Portal", "Research", "sample-user", False)
    assert "example.invalid" not in repr(summary)
```

- [ ] **Step 2: Run the new tests and confirm collection fails**

Run: `python -m uv run python -m pytest tests/application/test_types.py tests/application/test_projection.py -q`

Expected: FAIL because `bonobo_core.application` does not exist.

- [ ] **Step 3: Implement immutable closed DTOs and safe error mapping**

```python
class ApplicationPhase(StrEnum):
    EMPTY = "empty"
    BUSY = "busy"
    UNLOCKED_CLEAN = "unlocked-clean"
    UNLOCKED_DIRTY = "unlocked-dirty"
    LOCKED = "locked"
    AWAITING_DECISION = "awaiting-decision"


@dataclass(frozen=True, slots=True)
class RecordSummary:
    key: RecordKey
    title: str
    group: str
    username: str
    protected: bool


@dataclass(frozen=True, slots=True)
class ApplicationSnapshot:
    generation: int
    phase: ApplicationPhase
    display_label: str
    dirty: bool
    records: tuple[RecordSummary, ...]
    selected: RecordKey | None
    failure: ApplicationFailure | None
    decision: DecisionToken | None
```

Use exhaustive `isinstance` mapping from public PasswordSafe exceptions to stable reasons; the fallback reason is
`UNEXPECTED`, and no mapper includes `str(error)`.

- [ ] **Step 4: Implement deterministic projection and search**

`project_records` assigns facade-owned `RecordKey` values and sorts by `(group.casefold(), title.casefold(), key)`.
`search_records(records, query, case_sensitive=False)` matches only title, group, and username and returns the original
relative order.

- [ ] **Step 5: Prove projection does not mutate or expose sensitive fields**

Run: `python -m uv run python -m pytest tests/application/test_types.py tests/application/test_projection.py -q`

Expected: PASS, including property cases with fabricated URL, note, email, password, UUID, and unknown fields absent
from DTO representation.

- [ ] **Step 6: Run structure and typing gates, then commit**

```powershell
python -m uv run ruff check src/bonobo_core/application tests/application
python -m uv run mypy src/bonobo_core/application tests/application
python -m uv run python -m tools.check_python_structure src/bonobo_core/application tests/application
git add src/bonobo_core/application tests/application tests/passwordsafe/helpers.py
git commit -m "feat: define safe application projections"
```

### Task 2: Add the serialized facade lifecycle and decisions

**Files:**
- Create: `src/bonobo_core/application/facade.py`
- Create: `tests/application/test_facade_lifecycle.py`
- Create: `tests/application/fakes.py`
- Modify: `src/bonobo_core/application/__init__.py`

**Interfaces:**
- Consumes: Task 1 DTOs, `VaultService.create`, `VaultService.open`, `VaultService.save`, `VaultSession.lock`, and
  `VaultSession.discard_and_lock`.
- Produces: `VaultApplication.snapshot`, `create`, `open`, `save`, `request_close`, `resolve_close`, and `lock_clean`.

- [ ] **Step 1: Write failing lifecycle tests with a fake service**

```python
def test_failed_replacement_retains_dirty_active_session(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    before = app.snapshot
    fake_service.open_error = AuthenticationError(AuthenticationReason.MISMATCH)
    result = app.open(Path("fabricated-other.psafe3"), SecretBuffer.from_text("fabricated"), "Other")
    assert result.phase is ApplicationPhase.UNLOCKED_DIRTY
    assert result.records == before.records
    assert result.failure is not None


def test_dirty_close_requires_single_use_decision(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    pending = app.request_close(app.snapshot.generation)
    assert pending.phase is ApplicationPhase.AWAITING_DECISION
    canceled = app.resolve_close(pending.decision, CloseChoice.CANCEL)
    assert canceled.phase is ApplicationPhase.UNLOCKED_DIRTY
    with pytest.raises(ApplicationCommandError, match="decision is stale"):
        app.resolve_close(pending.decision, CloseChoice.DISCARD)
```

- [ ] **Step 2: Run the lifecycle file and verify red failures**

Run: `python -m uv run python -m pytest tests/application/test_facade_lifecycle.py -q`

Expected: FAIL because `VaultApplication` is undefined.

- [ ] **Step 3: Implement one lock-protected state machine**

```python
class VaultApplication:
    def __init__(self, service: VaultServiceLike) -> None:
        self._lock = RLock()
        self._service = service
        self._session: VaultSessionLike | None = None
        self._generation = 0
        self._snapshot = empty_snapshot()
        self._decision: _PendingDecision | None = None

    @property
    def snapshot(self) -> ApplicationSnapshot:
        with self._lock:
            return self._snapshot
```

Each public command validates the expected generation, installs a `BUSY` snapshot, performs exactly one service
operation, and either commits a new snapshot or restores the previous snapshot plus a safe failure. Decision tokens use
128 bits from injected randomness, compare with `secrets.compare_digest`, and are invalidated by every accepted command.

- [ ] **Step 4: Cover save, discard, cancel, stale view, and resource closure**

Add tests that assert passphrase buffers close on success and `BaseException`, save failures retain dirty state, clean
lock calls `session.lock`, discard calls `discard_and_lock`, and no raw exception/path appears in any DTO or `repr`.

- [ ] **Step 5: Run application lifecycle and full PasswordSafe service tests**

Run: `python -m uv run python -m pytest tests/application/test_facade_lifecycle.py tests/passwordsafe/test_service.py -q`

Expected: PASS.

- [ ] **Step 6: Run strict typing under three platforms and commit**

```powershell
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
git add src/bonobo_core/application tests/application
git commit -m "feat: add vault application lifecycle"
```

### Task 3: Add search, record drafts, and explicit secret actions

**Files:**
- Create: `src/bonobo_core/application/ports.py`
- Create: `src/bonobo_core/application/records.py`
- Create: `tests/application/test_record_commands.py`
- Create: `tests/application/test_secret_actions.py`
- Modify: `src/bonobo_core/application/facade.py`
- Modify: `src/bonobo_core/application/types.py`

**Interfaces:**
- Consumes: `VaultSession.records`, `apply`, `add`, `delete`, `reveal`, `SetTextField`, `SetSecretField`, and Task 1
  projection functions.
- Produces: `RecordDraft`, `ClipboardPort`, `BrowserPort`, `set_search`, `begin_edit`, `commit_edit`, `copy_username`,
  `copy_password`, and `open_website`.

- [ ] **Step 1: Write failing revision and secret-boundary tests**

```python
def test_confirming_record_draft_commits_exactly_one_revision(application: VaultApplication) -> None:
    draft = application.begin_edit(RecordKey(1), application.snapshot.generation)
    changed = replace(draft, title="Alpha Portal Renamed")
    result = application.commit_edit(changed, SecretBuffer.from_text("fabricated-passphrase"))
    assert result.dirty is True
    assert result.records[0].title == "Alpha Portal Renamed"
    assert application.test_session_change_count == 1


def test_copy_password_closes_lease_and_snapshot_never_contains_secret(
    application: VaultApplication, clipboard: RecordingClipboard
) -> None:
    result = application.copy_password(RecordKey(1), application.snapshot.generation)
    assert clipboard.copied == b"fabricated-password"
    assert clipboard.last_lease_closed is True
    assert "fabricated-password" not in repr(result)
```

- [ ] **Step 2: Run the new tests and confirm missing-interface failures**

Run: `python -m uv run python -m pytest tests/application/test_record_commands.py tests/application/test_secret_actions.py -q`

Expected: FAIL because the draft and port interfaces do not exist.

- [ ] **Step 3: Implement ports and immutable draft metadata**

```python
class ClipboardPort(Protocol):
    def copy(self, value: SecretLease, *, lifetime_seconds: int) -> None: ...
    def clear_owned(self) -> None: ...


class BrowserPort(Protocol):
    def open(self, value: SecretLease) -> bool: ...


@dataclass(frozen=True, slots=True)
class RecordDraft:
    key: RecordKey | None
    generation: int
    title: str
    group: str
    username: str
    protected: bool
```

Passwords are never fields on `RecordDraft`; `commit_edit` accepts a separate `SecretBuffer | None`. URL edits and
launches use separate secret-buffer arguments/actions so they cannot enter snapshots or draft representation.

- [ ] **Step 4: Implement search and revision-bound record commands**

Resolve `RecordKey` to its private `RecordHandle`, require generation equality, pass the captured revision to the
session command, replace projections only after success, and close every supplied secret in `finally`. A canceled editor
does not call the session.

- [ ] **Step 5: Implement explicit copy and browser operations**

Call `session.reveal` only inside a lease context, pass that lease directly to the port, clear the clipboard on lock or
close, and translate port failures to `CLIPBOARD_UNAVAILABLE` or `BROWSER_UNAVAILABLE` without including the value.

- [ ] **Step 6: Run focused and full application tests, then commit**

```powershell
python -m uv run python -m pytest tests/application -q
python -m uv run ruff check src/bonobo_core/application tests/application
python -m uv run mypy src/bonobo_core/application tests/application
git add src/bonobo_core/application tests/application
git commit -m "feat: add safe application record actions"
```

### Task 4: Persist and resume dirty locked sessions as encrypted artifacts

**Files:**
- Create: `src/bonobo_core/passwordsafe/pending.py`
- Create: `tests/passwordsafe/test_pending_sessions.py`
- Create: `tests/application/test_dirty_lock.py`
- Modify: `src/bonobo_core/passwordsafe/service.py`
- Modify: `src/bonobo_core/passwordsafe/session.py`
- Modify: `src/bonobo_core/passwordsafe/__init__.py`
- Modify: `src/bonobo_core/application/facade.py`

**Interfaces:**
- Consumes: authenticated `EncryptedCandidate`, original `FileBaseline`, private-directory helpers, and session crypto
  state.
- Produces: `SuspendedSession`, `VaultService.suspend`, `VaultService.resume`, `VaultService.discard_suspended`, and
  dirty-capable `VaultApplication.lock`/`unlock`.

- [ ] **Step 1: Write failing storage and application regressions**

```python
def test_dirty_suspend_is_authenticated_private_and_leaves_source_unchanged(
    service: VaultService, opened_session: VaultSession
) -> None:
    before = opened_session.path.read_bytes()
    suspended = service.suspend(opened_session)
    assert opened_session.locked is True
    assert opened_session.path.read_bytes() == before
    assert suspended.size > 0
    assert not hasattr(suspended, "path")


def test_resume_rejects_source_changed_after_suspend(
    service: VaultService, suspended: SuspendedSession, passphrase: SecretBuffer
) -> None:
    replace_source_with_valid_other_revision()
    with pytest.raises(ExternalModificationError):
        service.resume(source_path(), passphrase, suspended)
```

- [ ] **Step 2: Run pending-session tests and verify red failures**

Run: `python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py tests/application/test_dirty_lock.py -q`

Expected: FAIL because suspension APIs are absent.

- [ ] **Step 3: Implement path-free suspended metadata and a private slot store**

```python
@dataclass(frozen=True, slots=True)
class SuspendedSession:
    identifier: str
    sha256: str
    source_sha256: str
    size: int
```

Use random 256-bit artifact identifiers, stable source locators, protected private directories, exclusive creation,
descriptor-first writes, file and directory synchronization, exact identity cleanup, bounded reads, and atomic slot
replacement. Reject symlinks, reparse points, ACL/owner failures, wrong identifiers, size/digest mismatch, and multiple
visible slots exactly as the recovery store does.

- [ ] **Step 4: Implement service suspension and resume**

`suspend` freezes one session revision, writes an encrypted candidate with existing session crypto state, reopens and
exact-compares it, commits it to the pending store bound to the original source baseline, and only then closes the live
session. `resume` captures the current source, requires its baseline digest and size to match suspended metadata,
authenticates the pending artifact with the supplied passphrase, and constructs a session whose publication target and
baseline are the unchanged source. `discard_suspended` removes only the selected stable artifact and slot.

- [ ] **Step 5: Fault-inject every publication and cleanup boundary**

Cover preparation, write, authentication, slot publication, file sync, directory sync, post-publication validation,
source retarget, wrong passphrase, external modification, cleanup `BaseException`, and inode/file-ID replacement. Assert
that each failure leaves either the old valid pending artifact or the new valid one, never a visible partial artifact.

- [ ] **Step 6: Run security, writer, storage, service, and application tests**

Run: `python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py tests/passwordsafe/test_snapshots.py tests/passwordsafe/test_storage_faults.py tests/passwordsafe/test_writer_fail_closed.py tests/passwordsafe/test_service.py tests/application -q`

Expected: PASS with only existing platform-specific skips.

- [ ] **Step 7: Run all static gates and commit**

```powershell
python -m uv run ruff check src tests tools
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
python -m uv run bandit -c pyproject.toml -r src tools
git add src/bonobo_core tests/application tests/passwordsafe
git commit -m "feat: suspend dirty vault sessions securely"
```

### Task 5: Establish the optional PySide6 desktop package

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `src/bonobo_desktop/__init__.py`
- Create: `src/bonobo_desktop/main.py`
- Create: `src/bonobo_desktop/deploy.py`
- Create: `src/bonobo_desktop/resources.py`
- Create: `tests/desktop/test_import_boundary.py`
- Create: `tests/desktop/test_main.py`
- Modify: `tests/foundation/test_package_contract.py`
- Modify: `tests/foundation/test_wheel_contract.py`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`

**Interfaces:**
- Consumes: `VaultApplication`, Qt for Python 6.11, and existing Botan resolution.
- Produces: `password-bonobo` GUI entry point and `bonobo_desktop.main.main(argv: Sequence[str] | None) -> int`.

- [ ] **Step 1: Write failing dependency and import-boundary tests**

```python
def test_application_core_never_imports_desktop_or_pyside() -> None:
    assert forbidden_imports(Path("src/bonobo_core/application")) == ()


def test_desktop_main_fails_safely_when_qml_root_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resources, "main_qml_url", lambda: QUrl())
    assert main(["password-bonobo"]) == 1
```

- [ ] **Step 2: Run package tests and confirm red failures**

Run: `python -m uv run python -m pytest tests/desktop tests/foundation/test_package_contract.py tests/foundation/test_wheel_contract.py -q`

Expected: FAIL because the desktop package and optional dependency are absent.

- [ ] **Step 3: Add reproducible desktop dependencies and package metadata**

Add project extra `desktop = ["PySide6>=6.11.2,<6.12"]`, dependency group
`desktop-test = ["pytest-qt>=4.5,<5"]`, GUI script `password-bonobo = "bonobo_desktop.main:main"`, and both source
packages to Hatch wheel configuration. Regenerate `uv.lock` with `python -m uv lock` and record PySide6/Shiboken/Qt
license, source, version range, distribution purpose, and review state in the provenance ledger.

- [ ] **Step 4: Implement a safe composition-root skeleton**

Lazily import every Qt adapter, create `QApplication`, set organization/application names before settings access,
create private working/recovery directories, compose `VaultService.with_botan`, construct `VaultApplication`, load QML
from packaged resources, return 1 when no root object loads, and ensure shutdown requests facade lock before destroying
the engine. Keep an absolute-import direct-execution wrapper for deployment tooling.

- [ ] **Step 5: Run import, wheel, provenance, and license gates**

```powershell
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_import_boundary.py tests/desktop/test_main.py tests/foundation/test_package_contract.py tests/foundation/test_wheel_contract.py -q
python -m uv build
python -m uv run python -m tools.check_wheel dist
python -m uv run python -m tools.check_provenance
python -m uv run reuse --no-multiprocessing lint
```

- [ ] **Step 6: Commit the desktop package foundation**

```powershell
git add pyproject.toml uv.lock src/bonobo_desktop tests/desktop tests/foundation docs/legal/dependency-asset-provenance-ledger.md
git commit -m "build: add PySide6 desktop foundation"
```

### Task 6: Adapt snapshots and commands to Qt

**Files:**
- Create: `src/bonobo_desktop/models.py`
- Create: `src/bonobo_desktop/controller.py`
- Create: `src/bonobo_desktop/tasks.py`
- Create: `src/bonobo_desktop/clipboard.py`
- Create: `src/bonobo_desktop/browser.py`
- Create: `src/bonobo_desktop/lifecycle.py`
- Create: `src/bonobo_desktop/file_dialog.py`
- Create: `tests/desktop/test_models.py`
- Create: `tests/desktop/test_controller.py`
- Create: `tests/desktop/test_clipboard.py`
- Create: `tests/desktop/test_lifecycle.py`
- Create: `tests/desktop/test_file_dialog.py`

**Interfaces:**
- Consumes: Task 1–4 facade/DTOs and Qt `QAbstractListModel`, `QObject`, `QThreadPool`, `QClipboard`,
  `QDesktopServices`, `QFileDialog`, and `QElapsedTimer`.
- Produces: `RecordListModel`, `DesktopController`, `FacadeExecutor`, `QtClipboardPort`, `QtBrowserPort`, and
  `IdleLockController`, and `QtVaultFileDialog`.

- [ ] **Step 1: Write failing model-role and serialization tests**

```python
def test_record_model_roles_are_closed_and_non_secret(qtbot: QtBot) -> None:
    model = RecordListModel()
    model.replace((RecordSummary(RecordKey(1), "Alpha", "Research", "sample-user", False),))
    assert set(model.roleNames().values()) == {b"key", b"title", b"group", b"username", b"protected"}


def test_executor_never_runs_two_facade_commands_concurrently(recording_facade: RecordingFacade) -> None:
    executor = FacadeExecutor(recording_facade)
    submit_two_blocked_commands(executor)
    assert recording_facade.maximum_concurrency == 1
```

- [ ] **Step 2: Run desktop adapter tests and confirm red failures**

Run: `python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_models.py tests/desktop/test_controller.py tests/desktop/test_clipboard.py tests/desktop/test_lifecycle.py -q`

Expected: FAIL because the Qt adapters are absent.

- [ ] **Step 3: Implement reset-only models and a snapshot-driven controller**

The list model exposes exactly five roles. The controller exposes primitive non-secret properties, emits one
`snapshotChanged` signal after each accepted result, clears passphrase properties before submitting commands, maps QML
record keys back to `RecordKey`, and never catches/publishes raw exception text.

- [ ] **Step 4: Implement one-worker execution and shutdown draining**

Queue immutable command closures on a one-thread pool, return results to the GUI thread by queued signals, reject new
work after shutdown begins, and block process exit only until the active save/suspend operation returns. Tests control
the worker with events rather than sleeps.

- [ ] **Step 5: Implement clipboard, browser, and idle adapters**

Clipboard writes a random Bonobo MIME nonce, clears only when that nonce remains current, and wipes temporary mutable
copies. Browser converts the explicit leased UTF-8 value to `QUrl` only inside the operation and returns a boolean.
Idle tracking uses a monotonic deadline and qualifying application input events only while unlocked; expiry submits
facade lock once, and successful unlock rearms it. Native create/open selection runs on the GUI thread and keeps every
filesystem locator outside QML.

- [ ] **Step 6: Run offscreen adapter tests and commit**

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop -q
python -m uv run ruff check src/bonobo_desktop tests/desktop
python -m uv run mypy src/bonobo_desktop tests/desktop
git add src/bonobo_desktop tests/desktop
git commit -m "feat: adapt vault application state to Qt"
```

### Task 7: Build the Qt Quick workflow and accessibility contract

**Files:**
- Create: `src/bonobo_desktop/qml/Main.qml`
- Create: `src/bonobo_desktop/qml/WelcomeView.qml`
- Create: `src/bonobo_desktop/qml/UnlockView.qml`
- Create: `src/bonobo_desktop/qml/VaultView.qml`
- Create: `src/bonobo_desktop/qml/RecordEditor.qml`
- Create: `src/bonobo_desktop/qml/DecisionDialog.qml`
- Create: `src/bonobo_desktop/qml/qmldir`
- Create: `tests/desktop/test_qml_contract.py`
- Create: `tests/desktop/test_keyboard_workflow.py`
- Modify: `src/bonobo_desktop/resources.py`

**Interfaces:**
- Consumes: `DesktopController`, `RecordListModel`, and packaged Qt resources.
- Produces: the welcome/unlock/vault/edit/decision vertical slice with complete keyboard operation.

- [ ] **Step 1: Write failing QML load and closed-binding tests**

```python
def test_every_qml_component_loads_offscreen(qml_engine: QQmlApplicationEngine) -> None:
    for component in packaged_qml_components():
        loaded = QQmlComponent(qml_engine, component)
        assert loaded.status() is QQmlComponent.Status.Ready, loaded.errorString()


def test_qml_never_names_forbidden_domain_or_secret_properties() -> None:
    assert qml_forbidden_tokens() == ()
```

The forbidden set includes `VaultSession`, `RecordHandle`, `RevisionToken`, `SecretBuffer`, `path`, `uuid`, `urlValue`,
`passwordValue`, `notesValue`, and raw exception/message bindings.

- [ ] **Step 2: Run QML tests and verify missing-resource failures**

Run: `python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop/test_qml_contract.py tests/desktop/test_keyboard_workflow.py -q`

Expected: FAIL because QML resources are absent.

- [ ] **Step 3: Implement the four-view shell**

Bind top-level view selection only to `ApplicationPhase`. Welcome exposes Create/Open; Unlock clears its concealed input
on submit; Vault shows search, dirty status, records, Save/Lock/Add/Edit/Copy/Open actions; RecordEditor uses local draft
state and explicit Confirm/Cancel; DecisionDialog exposes only the choices allowed by its decision kind.

- [ ] **Step 4: Implement keyboard and accessibility behavior**

Every actionable control receives an access name, visible focus indication, deterministic tab order, and mnemonic or
shortcut. Escape cancels a modal without mutation; Ctrl+S saves; Ctrl+L locks; Ctrl+F focuses search; Enter activates
the selected record. After model reset, focus returns to search or the retained selected row.

- [ ] **Step 5: Run QML lint, offscreen workflow, and static checks**

```powershell
python -m uv run --extra desktop pyside6-qmllint src/bonobo_desktop/qml/*.qml
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest tests/desktop -q
python -m uv run ruff check src tests tools
python -m uv run mypy src tests tools
```

- [ ] **Step 6: Commit the usable shell**

```powershell
git add src/bonobo_desktop/qml src/bonobo_desktop/resources.py tests/desktop
git commit -m "feat: add accessible Qt Quick vault shell"
```

### Task 8: Qualify native packaging and close the vertical slice

**Files:**
- Create: `pysidedeploy.spec`
- Create: `src/bonobo_desktop/deploy.py`
- Create: `tests/desktop/test_deployment_contract.py`
- Modify: `.github/workflows/foundation.yml`
- Modify: `README.md`
- Modify: `docs/PROJECT_MEMORY.md`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`

**Interfaces:**
- Consumes: completed desktop entry point and Qt's `pyside6-deploy`.
- Produces: native dry-run evidence on Windows, macOS, and Linux plus complete local/repository verification.

- [ ] **Step 1: Write failing deployment/workflow contract tests**

```python
def test_deployment_spec_names_only_required_qt_modules() -> None:
    spec = read_deployment_spec()
    assert spec.input_file == "src/bonobo_desktop/deploy.py"
    assert set(spec.modules) == {"Core", "Gui", "Qml", "Quick", "QuickControls2", "Widgets"}


def test_desktop_ci_installs_extra_and_runs_offscreen_smoke() -> None:
    workflow = load_foundation_workflow()
    assert every_desktop_job_qualifies_qml_and_deploy(workflow)
```

- [ ] **Step 2: Run contract tests and confirm red failures**

Run: `python -m uv run python -m pytest tests/desktop/test_deployment_contract.py -q`

Expected: FAIL because deployment configuration and CI steps are absent.

- [ ] **Step 3: Add deterministic native deployment dry runs**

Configure the executable wrapper, project root, output directory, QML resources, app name, and exact Qt modules. Add
desktop matrix steps that install the `desktop` extra and `desktop-test` group, run offscreen QML tests, and execute
`pyside6-deploy --dry-run -c pysidedeploy.spec`. The wrapper receives direct-execution smoke coverage without building
or launching an artifact. Mobile cross-build jobs continue installing only core/dev dependencies.

- [ ] **Step 4: Run the full local release gates**

```powershell
python -m uv run autopep8 --in-place --recursive src tests tools
git diff --exit-code -- src tests tools
python -m uv run ruff check src tests tools
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
$env:BONOBO_TEST_BOTAN_LIBRARY = "build/botan-task14-host/bin/botan-3.dll"
$env:QT_QPA_PLATFORM = "offscreen"
python -m uv run --extra desktop --group desktop-test python -m pytest
python -m uv run python -m tools.check_python_structure src tests tools
python -m uv run python -m tools.check_compatibility
python -m uv run python -m tools.check_provenance
git ls-files -z | python -m uv run python -m tools.check_tracked_files
python -m uv run bandit -c pyproject.toml -r src tools
python -m uv run pip-audit
python -m uv run reuse --no-multiprocessing lint
python -m uv build
python -m uv run python -m tools.check_wheel dist
```

Expected: every command exits zero; pytest has only declared platform-specific skips.

- [ ] **Step 5: Independently review, correct findings, and reverify**

Request review against the design's secret boundary, dirty-lock invariants, stale-generation behavior, QML bindings,
clipboard ownership, shutdown sequencing, package contents, and all O3 vertical-slice acceptance criteria. Add red-first
regressions for every accepted finding and repeat the relevant focused and full gates.

- [ ] **Step 6: Commit and obtain hosted proof**

```powershell
git add pysidedeploy.spec .github/workflows/foundation.yml tests/desktop README.md docs/PROJECT_MEMORY.md docs/legal/dependency-asset-provenance-ledger.md
git commit -m "ci: qualify desktop vault foundation"
git push origin main
gh run watch --exit-status
```

Expected: Windows, macOS, Linux, Android, and iOS jobs all pass; the three desktop jobs also pass QML load and native
deployment dry-run checks.

## Self-review result

- Spec coverage: the plan covers the first four delivery increments and the complete vertical-slice acceptance path.
  Advanced groups, password policies/history, preferences/recent files, recovery UI, and CSV exchange remain explicit
  later O3 increments; O4/O5/mobile work remains excluded.
- Placeholder scan: every implementation and verification step is explicit and executable.
- Type consistency: `ApplicationSnapshot`, `RecordSummary`, `RecordKey`, `DecisionToken`, `VaultApplication`,
  `SuspendedSession`, `ClipboardPort`, and `BrowserPort` retain the same names and direction across tasks.
