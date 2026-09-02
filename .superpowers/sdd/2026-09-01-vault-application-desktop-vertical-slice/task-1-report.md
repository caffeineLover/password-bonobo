# Task 1 Report — Safe Application Contracts and Record Projection

## Implementation

- Added `bonobo_core.application` as a UI-independent public package with immutable, slotted DTOs: `ApplicationPhase`,
  `ApplicationSnapshot`, `RecordKey`, `DecisionToken`, and `RecordSummary`.
- Added a closed `ApplicationFailureReason` taxonomy and `ApplicationFailure` presentation DTO.  The internal mapper
  maps every public `PasswordSafeError` leaf with `isinstance` and maps public-base or arbitrary exceptions to
  `UNEXPECTED`; it never reads or includes exception text.
- Added deterministic projection from facade-owned `RecordHandle` mappings and Unicode-casefolded search limited to
  title, group, and username.  Projection never copies a `RecordView` URL.
- Added a reusable fabricated `RecordView` helper with a sensitive URL.  The regression binds one fabricated object once
  and uses that same object for its handle-to-key mapping and projection input.

## TDD evidence

### RED

`python -m uv run python -m pytest tests/application/test_types.py tests/application/test_projection.py -q`

The initial run failed collection as required because `bonobo_core.application` did not exist.  The expected error was
`ModuleNotFoundError: No module named 'bonobo_core.application'`.

### GREEN

The focused command after implementation reported `25 passed in 1.27s`.  It covers the closed snapshot fields and public
exports, immutable summary DTOs, every public PasswordSafe error leaf plus both unexpected fallbacks, deterministic
projection sorting, case-sensitive and casefolded search, identity mapping, and generated URL non-disclosure.

## Verification

- `python -m uv run ruff check src/bonobo_core/application tests/application` — passed.
- `python -m uv run mypy src/bonobo_core/application tests/application` — `Success: no issues found in 6 source files`.
- `python -m uv run python -m tools.check_python_structure src/bonobo_core/application tests/application` — passed.
- `BONOBO_TEST_BOTAN_LIBRARY=E:\home\Code - Github\Password Bonobo\build\botan-task14-host\bin\botan-3.dll python -m uv run python -m pytest` — `687 passed, 12 skipped in 106.67s`; 699 tests collected on Windows/CPython 3.14.7.
- `git diff --check` — passed.

## Files changed

- `src/bonobo_core/application/__init__.py`
- `src/bonobo_core/application/types.py`
- `src/bonobo_core/application/errors.py`
- `src/bonobo_core/application/projection.py`
- `tests/application/test_types.py`
- `tests/application/test_projection.py`
- `tests/passwordsafe/helpers.py`
- `docs/PROJECT_MEMORY.md`

## Self-review

Reviewed every new DTO and public export against the task boundary.  The public package contains no `RecordHandle`,
`RevisionToken`, path, URL, UUID, secret, or raw exception-text field.  The error mapper is closed over the public core
taxonomy and uses a safe generic fallback.  Projection uses the caller-provided identity mapping and only emits the five
permitted summary fields; sort and search ordering are covered explicitly.

## Concerns

No implementation concerns.  This isolated worktree has no local Botan build artifact, so the final full suite used the
verified parent-checkout Botan 3.13 DLL recorded in project memory.
