# Cross-Platform Strict Typing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make strict mypy validate the complete repository under Windows, Darwin, and Linux typeshed profiles without
weakening native security behavior or adding blanket/type-error suppressions.

**Architecture:** Each module that consumes an operating-system-specific dynamic API will define a narrow structural
`Protocol` for exactly the members it calls and cast the imported module once at that untyped native boundary. Runtime
imports, platform branches, native API ownership, native flags, and error handling remain unchanged. The existing GitHub
Actions operating-system matrix remains the permanent hosted regression gate.

**Tech Stack:** CPython 3.14, strict mypy 1.20, standard-library `ctypes`/`msvcrt`/`fcntl`, pytest 9, Ruff, and Bandit.

**Spec:** `docs/superpowers/specs/2026-08-23-lossless-passwordsafe-core-design.md`

## Global Constraints

- Do not use blanket mypy exclusions or platform-wide ignored diagnostics.
- Remove the two now-platform-dependent `fcntl` ignores rather than adding Darwin-specific ignores.
- Keep Windows `WinDLL` calling conventions, descriptor ownership, DACL checks, and lock behavior unchanged.
- Keep POSIX advisory-lock behavior unchanged.
- Pass strict mypy for `--platform win32`, `--platform darwin`, and `--platform linux` over `src tests tools`.
- Follow the repository's Python declaration comments, three-blank-line spacing, and strict typing rules.

---

### Task 1: Type Native Module Boundaries Across All Hosted Platforms

**Files:**
- Modify: `src/bonobo_core/passwordsafe/_windows_security.py`
- Modify: `src/bonobo_core/passwordsafe/storage.py`
- Modify: `tools/build_botan.py`
- Modify: `tests/passwordsafe/test_snapshots.py`
- Modify: `docs/PROJECT_MEMORY.md`

**Interfaces:**
- Consumes: imported standard-library modules whose stubs expose members only on their native platform.
- Produces: private protocols for the used `ctypes`, `msvcrt`, and `fcntl` members and typed module-boundary aliases.

- [x] **Step 1: Reproduce the hosted failure locally**

Run: `python -m uv run mypy --platform darwin src tests tools`

Expected: 23 errors in `_windows_security.py`, `storage.py`, `build_botan.py`, and `test_snapshots.py`, matching hosted
run `33549509896`.

- [x] **Step 2: Add narrow typed native-module facades**

In `_windows_security.py`, model the callable `WinDLL`, `get_last_error`, and `set_last_error` members plus the exact
`msvcrt` descriptor members and the Windows-only `os.O_BINARY` flag. In `storage.py`, model `flock`/`LOCK_EX`/`LOCK_UN` and
`locking`/`LK_LOCK`/`LK_UNLCK`. In `build_botan.py`, model only `WinDLL`. Replace direct member access through these
private aliases without changing arguments, flags, branches, return values, or error handling. Reuse the production
Windows ctypes facade in Windows-only tests.

- [x] **Step 3: Verify strict typing under all hosted profiles**

Run:

```powershell
python -m uv run mypy --platform win32 src tests tools
python -m uv run mypy --platform darwin src tests tools
python -m uv run mypy --platform linux src tests tools
```

Expected: all three commands report success for 70 source files.

- [x] **Step 4: Run behavioral and repository-quality verification**

Run:

```powershell
$env:BONOBO_TEST_BOTAN_LIBRARY = 'E:\home\Code - Github\Password Bonobo\build\botan-task14-host\bin\botan-3.dll'
python -m uv run python -m pytest
python -m uv run ruff check src tests tools examples
python -m uv run python -m tools.check_python_structure src tests tools examples
python -m uv run bandit -c pyproject.toml -r src tools examples
python -m uv run reuse --no-multiprocessing lint
```

- [x] **Step 5: Record hosted/local evidence, review, and commit**

Update project memory with the pushed diagnostics commit, current hosted run, exact cross-platform mypy result, full
test result, and next CI repair. Request independent review and correct every Critical or Important issue before commit.

```powershell
git add REUSE.toml docs/PROJECT_MEMORY.md docs/superpowers/plans/2026-09-01-cross-platform-strict-typing.md `
  src/bonobo_core/passwordsafe/_windows_security.py src/bonobo_core/passwordsafe/storage.py `
  tools/build_botan.py tests/passwordsafe/test_snapshots.py
git commit -m "ci: type native platform boundaries"
```

---

## Final Spec-Coverage Checklist

- Darwin-mode mypy reproduces the original 23 hosted errors before implementation and reports zero afterward.
- Windows and Linux profiles also report zero, preventing a host-specific typing fix from breaking another matrix leg.
- Native runtime calls and security-sensitive flags are unchanged; only their static module boundary is modeled.
- No blanket exclusion or platform-dependent ignore is introduced.
