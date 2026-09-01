# Native Build Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make failed Botan configure, compile, discovery, and mobile-link gates emit enough bounded, path-redacted
evidence to diagnose hosted failures without exposing caller-controlled absolute paths.

**Architecture:** `tools.build_botan` will convert captured native-tool output into one normalized diagnostic suffix.
The conversion will redact every known build/toolchain path, remove unsafe control characters, prefer the tail where
linkers normally report their cause, and enforce a fixed output bound. Shared-library discovery will report only a
bounded allowlist of relative Botan artifact names from fixed installation tiers.

**Tech Stack:** CPython 3.14, `subprocess`, `pathlib`, pytest 9, strict mypy, Ruff, Bandit, and GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-23-lossless-passwordsafe-core-design.md`

## Global Constraints

- Keep the existing fixed public error categories and append diagnostics only when safe native evidence exists.
- Never emit the verified source/cache directory, caller-selected output path, compiler path, SDK path, or library path.
- Emit no more than 2,048 diagnostic characters and no untrusted terminal control characters.
- Do not change the target profiles, build commands, library-selection result, or mobile smoke-link semantics.
- Follow the repository's required Python declaration comments, three-blank-line spacing, and strict typing rules.

---

### Task 1: Add the Safe Native Diagnostic Boundary

**Files:**
- Modify: `tools/build_botan.py`
- Test: `tests/foundation/test_botan_build.py`
- Modify: `docs/PROJECT_MEMORY.md`

**Interfaces:**
- Consumes: `subprocess.CompletedProcess[str]`, known private `Path` values, and installed Botan output tiers.
- Produces: `_native_failure_message(category, result, private_paths) -> str` and bounded discovery evidence appended to
  `BotanBuildError` messages.

- [x] **Step 1: Write failing behavior tests**

Add a mobile-link test whose synthetic compiler returns nonzero stderr containing an actionable undefined-symbol line,
absolute compiler/output/library paths, ANSI control sequences, and more than 2,048 characters. Assert that the raised
message retains the tail cause, contains none of the paths or escape bytes, and stays within the bound. Add configure and
compile propagation cases, plus a shared-library discovery case containing an allowlisted `lib64/libbotan-3.so.3` name.

- [x] **Step 2: Run the focused tests and verify RED**

Run: `python -m uv run python -m pytest tests/foundation/test_botan_build.py -k "diagnostic or reports_installed" -v`

Expected: failures show that production currently discards subprocess output and reports no discovery evidence.

- [x] **Step 3: Implement the minimal safe formatter and connect each failure boundary**

Add a private formatter that joins captured stdout/stderr, normalizes line endings, replaces known path variants with
stable labels, removes non-newline control characters, keeps the final 2,048 characters, and appends it to the stable
category. Use it for configure, compile, and mobile-link failures. Add a fixed-tier, allowlisted, count-limited relative
artifact inventory to the existing shared-library discovery failure.

- [x] **Step 4: Run focused and repository-quality verification**

Run:

```powershell
python -m uv run python -m pytest tests/foundation/test_botan_build.py -v
python -m uv run ruff check tools/build_botan.py tests/foundation/test_botan_build.py
python -m uv run mypy tools/build_botan.py tests/foundation/test_botan_build.py
python -m uv run python -m tools.check_python_structure tools tests
python -m uv run bandit -c pyproject.toml -r tools
```

- [x] **Step 5: Update durable memory and commit the coherent repair**

Record the hosted run, confirmed diagnostic-loss root cause, verified local checks, and the next hosted rerun action.

```powershell
git add REUSE.toml docs/PROJECT_MEMORY.md docs/superpowers/plans/2026-09-01-native-build-diagnostics.md `
  tools/build_botan.py tests/foundation/test_botan_build.py
git commit -m "ci: expose safe native build diagnostics"
```

---

## Final Spec-Coverage Checklist

- The subprocess regression tests cover configure, compile, and mobile-link failure boundaries.
- The diagnostic tests independently prove actionable evidence survives while paths, control bytes, and excess length do
  not.
- The discovery regression exposes only bounded relative Botan artifact evidence and leaves selection behavior unchanged.
- The focused test, lint, type, structure, security, and memory gates are explicit.
