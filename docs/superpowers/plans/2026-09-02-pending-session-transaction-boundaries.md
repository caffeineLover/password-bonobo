# Pending-Session Transaction-Boundary Revision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two remaining Task 4 transaction-boundary findings by authorizing every retained-directory scan
against the current pathname and treating post-commit discard lock teardown as successful.

**Architecture:** Keep the existing retained-handle, bounded enumeration, stable selector, and closed-error designs.
Separate scan collection from final anchor authorization in the three pending lookup helpers, and track discard commit
outside the destination-lock context so only pre-commit failures remain retryable.

**Tech Stack:** Python 3.14, typed PasswordSafe core, pytest, Ruff, strict mypy, Bandit, REUSE, uv, and Botan 3.13.0.

**Spec:** `docs/superpowers/specs/2026-09-02-pending-session-transaction-boundaries-design.md`

## Global Constraints

- Do not change the public suspension API, encrypted artifact format, selector schema, or Task 5 interfaces.
- Enumerate only through the retained POSIX directory descriptor or Windows directory handle and retain the 256-entry
  ceiling and constant-space behavior.
- Finish each complete scan before calling `anchor.stable()` and interpreting absence, ambiguity, or a selected match.
- Treat `False`, exceptions, and other final-anchor uncertainty as
  `StorageError(StorageReason.VERIFICATION_FAILED)` with no raw cause, context, path, or selector exposure.
- A discard failure before irreversible deletion retains retryable state; lock teardown after committed deletion returns
  success and lets the facade clear its private selector.
- Keep the pending-directory, specification, plan, and project-memory documents Markdown-only.
- Use fabricated data only and preserve the existing `.example.invalid` test boundary.

---

### Task 1: Authorize retained scans and reconcile committed discard

**Files:**
- Modify: `src/bonobo_core/passwordsafe/pending.py`
- Modify: `tests/passwordsafe/test_pending_sessions.py`
- Modify: `tests/application/test_dirty_lock.py`
- Modify: `docs/PROJECT_MEMORY.md`
- Modify: `.superpowers/sdd/2026-09-01-vault-application-desktop-vertical-slice/progress.md` (ignored execution ledger)
- Modify: `.superpowers/sdd/2026-09-01-vault-application-desktop-vertical-slice/task-4-report.md` (ignored report)

**Interfaces:**
- Consumes: `_PublicationAnchor.iter_child_names()`, `_PublicationAnchor.stable()`, `_ClosedPendingBoundary`,
  `_destination_lock`, `_source_has_pending_locked`, `_publication_previous_locked`, `_find_locked`, and
  `_discard_locked`.
- Produces: unchanged `PendingSessionStore.guard_open`, `publish`, `open`, `verify`, and `discard` behavior with final
  retained-anchor authorization and committed-discard reconciliation.

- [ ] **Step 1: Add deterministic RED tests for final retained-anchor authority**

Add a small anchor wrapper that delegates every operation except `stable()` and can return `False` or raise a raw
path-bearing `OSError` on the final authorization call. Add tests which create one real pending slot and prove all of
these paths fail with a closed `StorageError(StorageReason.VERIFICATION_FAILED)` while leaving the authoritative slot
intact:

```python
@pytest.mark.parametrize(
    "operation, scan_outcome",
    [
        ("guard-open-alias", "positive-match"),
        ("publish-alias", "positive-match"),
        ("publish-new", "absence"),
        ("open", "selected-match"),
        ("verify", "selected-match"),
        ("discard", "selected-match"),
    ],
)
def test_complete_pending_scans_require_final_current_anchor_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    scan_outcome: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    alias = tmp_path / "fabricated-source-alias.psafe3"
    os.link(source, alias)
    private_path = tmp_path / "pending-private"
    production_open = pending_module._open_private_anchor

    def open_failing_anchor(path: Path) -> _PublicationAnchor:
        return _FinalIdentityFailingAnchor(production_open(path), private_path)

    monkeypatch.setattr(pending_module, "_open_private_anchor", open_failing_anchor)
    with pytest.raises(StorageError) as captured, service._pending.guard_open(alias):
        raise AssertionError(f"{operation}:{scan_outcome} unexpectedly entered")
    assert captured.value.reason is StorageReason.VERIFICATION_FAILED
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(private_path) not in repr(captured.value)
    assert suspended.identifier not in repr(captured.value)
```

For `False` and raised-error variants, assert `captured.value.__cause__ is None`,
`captured.value.__context__ is None`, and that neither the private pending path nor the suspended identifier appears in
`str` or `repr`. Reuse the existing retained-handle ABA harness to add decoy-before-anchor-open and
real-directory-before-final-check regressions for alias open and alias initial suspension; assert exactly one visible
slot remains.

- [ ] **Step 2: Run the anchor-authority tests and verify the expected RED failures**

Run:

```powershell
python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py -q -k "final_current_anchor or decoy_before_anchor"
```

Expected: FAIL because `_source_has_pending_locked` returns early and none of `_source_has_pending_locked`,
`_publication_previous_locked`, or `_find_locked` performs a final `anchor.stable()` authorization.

- [ ] **Step 3: Implement one closed final-anchor authorization helper and use it after every complete scan**

Add a private helper whose only successful result is a literal stable `True`:

```python
#### Require the retained directory to remain authoritative after a complete scan.
####
def _require_current_anchor(anchor: _PublicationAnchor) -> None:
    try:
        stable = anchor.stable()
    except BaseException:
        raise StorageError(StorageReason.VERIFICATION_FAILED) from None
    if stable is not True:
        raise StorageError(StorageReason.VERIFICATION_FAILED)
```

Refactor `_source_has_pending_locked` to accumulate a boolean and close every `_LocatedPending` without returning from
inside the loop. Refactor `_publication_previous_locked` and `_find_locked` to call `_require_current_anchor(anchor)`
only after their bounded iterators are exhausted, before interpreting absence, ambiguity, or transferring a selected
result. Preserve constant descriptor space in `_source_has_pending_locked` and `_publication_previous_locked`; retain
only the one selected `_LocatedPending` required by `_find_locked` and reject a second match immediately.

- [ ] **Step 4: Run the complete pending-session security selection and verify GREEN**

Run:

```powershell
python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py tests/passwordsafe/test_storage_faults.py -q -x
```

Expected: PASS with only the existing Windows capability skips.

- [ ] **Step 5: Add RED tests for discard commit versus destination-lock teardown**

Extend the production lock-fault seam so `unlock` and descriptor `close` can fail after `_discard_locked` has removed
the selected slot and artifact. Prove direct store discard returns success and the application clears its private
selector:

```python
@pytest.mark.parametrize("stage", ["unlock", "close"])
def test_committed_discard_ignores_destination_lock_teardown_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    _install_process_lock_fault(monkeypatch, stage, tmp_path / "pending-working" / ".fabricated-private.lock")

    service.discard_suspended(source, suspended)

    with pytest.raises(StorageError):
        service._pending.verify(source, suspended)
```

Add a facade regression that performs the same post-commit fault through `VaultApplication.discard_suspended` and
asserts a locked, failure-free snapshot whose subsequent replacement does not require another discard. Preserve and
extend the existing pre-commit acquisition/chmod/lookup/removal fault tests to assert they still fail closed and retain
the selector for an exact retry.

- [ ] **Step 6: Run the discard tests and verify the expected RED failures**

Run:

```powershell
python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py tests/application/test_dirty_lock.py -q -k "committed_discard or failed_explicit_discard"
```

Expected: FAIL because `_ClosedPendingBoundary` currently re-raises destination-lock teardown failures even after
`_discard_locked` irreversibly commits deletion.

- [ ] **Step 7: Track discard commit outside the destination-lock context**

Restructure only `PendingSessionStore.discard` so mutation success survives lock-scope teardown:

```python
committed = False
failure: BaseException | None = None
try:
    with self._lock, _destination_lock(self._snapshot_directory, source):
        located = self._find_locked(source, suspended)
        self._discard_locked(located)
        committed = True
except BaseException as error:
    failure = error
if committed:
    return
if failure is not None:
    _raise_closed_pending_error(failure)
```

Retain the existing `located` cleanup ownership and `_ClosedPendingBoundary` behavior needed to remove raw cause and
context. Set `committed` only after `_discard_locked` returns. Do not apply this reconciliation rule to publish, open,
verify, guard acquisition, or a failure inside `_discard_locked`.

- [ ] **Step 8: Run focused and selected Task 4 suites**

Run:

```powershell
python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py tests/passwordsafe/test_storage_faults.py tests/application/test_dirty_lock.py -q -x
python -m uv run python -m pytest tests/passwordsafe/test_pending_sessions.py tests/passwordsafe/test_snapshots.py tests/passwordsafe/test_storage_faults.py tests/passwordsafe/test_writer_fail_closed.py tests/passwordsafe/test_service.py tests/application -q -x
```

Expected: PASS with only declared platform-specific skips.

- [ ] **Step 9: Run static, security, legal, build, and exact-Botan full gates**

Run:

```powershell
python -m uv run autopep8 --diff --recursive src tests tools
python -m uv run ruff check src tests tools
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
python -m uv run python -m tools.check_python_structure src tests tools
python -m uv run python -m tools.check_compatibility
python -m uv run python -m tools.check_provenance
git ls-files -z | python -m uv run python -m tools.check_tracked_files
python -m uv run bandit -c pyproject.toml -r src tools
python -m uv run pip-audit
python -m uv run reuse --no-multiprocessing lint
python -m uv build
python -m uv run python -m tools.check_wheel dist
git diff --check
$env:BONOBO_TEST_BOTAN_LIBRARY = "E:\home\Code - Github\Password Bonobo\build\botan-task14-host\bin\botan-3.dll"
python -m uv run python -m pytest -q
```

Expected: every command exits zero; pytest reports only declared platform-specific skips.

- [ ] **Step 10: Record the round, commit, and request independent review**

Update the original vertical-slice ledger and Task 4 report with the RED/GREEN evidence, exact verification results,
files, decisions, and self-review. Reconcile `docs/PROJECT_MEMORY.md` to the repository and Git state, then commit the
coherent repair separately from prior Task 4 commits:

```powershell
git add src/bonobo_core/passwordsafe/pending.py tests/passwordsafe/test_pending_sessions.py tests/application/test_dirty_lock.py docs/PROJECT_MEMORY.md
git commit -m "fix: close pending transaction boundaries"
```

Generate a review package over the repair base through the new head and request a scoped independent re-review of the
two original findings plus regression, security, typing, and test quality. Do not begin Task 5 until that review has no
Critical or Important findings.

## Self-review result

- Spec coverage: final current-path authority covers positive match, absence, ambiguity, and selected-return paths;
  discard reconciliation covers both pre-commit retry and post-commit success at unlock and close teardown.
- Placeholder scan: no `TBD`, `TODO`, ellipsis, deferred implementation, or unspecified test action remains.
- Type consistency: the plan retains every public signature and uses the existing `_PublicationAnchor`,
  `SuspendedSession`, `StorageError`, `StorageReason`, and application snapshot types without renaming or widening them.
