# Password Bonobo Foundation Verification

Last updated: 2026-08-22

## Overview and current state

This record distinguishes executed local checks from hosted service state.  The complete local release gate and
document review passed against the staged whole-branch remediation candidate.  Hosted CI has not yet run because this
branch introduces the workflow; its Windows, macOS, and Linux jobs remain to be observed after publication.

## CI action pin evidence

Official, read-only Git refs were observed directly on 2026-08-22:

| Official repository | Ref and object kind | Observed SHA |
|---|---|---|
| `actions/checkout` | `refs/tags/v4` | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/checkout` | `refs/tags/v4.4.0` | `11d5960a326750d5838078e36cf38b85af677262` |
| `astral-sh/setup-uv` | `refs/tags/v6`, annotated object | `d0d8abe699bfb85fec6de9f7adb5ae17292296ff` |
| `astral-sh/setup-uv` | `refs/tags/v6^{}`, peeled commit | `d0cc045d04ccac9d8b7881df0226f9e82c39688e` |
| `astral-sh/setup-uv` | `refs/tags/v6.8.0`, release commit | `d0cc045d04ccac9d8b7881df0226f9e82c39688e` |

The workflow pins the full commit SHA `d0cc045d04ccac9d8b7881df0226f9e82c39688e`, not the annotated tag object's
SHA or a floating ref.  This follows GitHub's official action-hardening guidance to pin third-party actions to a
[full-length commit SHA][github-action-hardening].
Evidence command form:

```powershell
git ls-remote https://github.com/actions/checkout.git refs/tags/v4 refs/tags/v4.4.0
git ls-remote https://github.com/astral-sh/setup-uv.git refs/tags/v6 'refs/tags/v6^{}' refs/tags/v6.8.0
```

[github-action-hardening]:
  <https://docs.github.com/actions/security-guides/security-hardening-for-github-actions>

## Local executed gates

The staged-index gate consists of:

```powershell
uv sync --locked --all-groups
uv run autopep8 --in-place --recursive src tests tools
git diff --exit-code -- src tests tools
uv run ruff check src tests tools
uv run mypy src tests tools
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools
uv run python -m tools.check_compatibility
uv run python -m tools.check_provenance
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools
uv run pip-audit
uv run reuse --no-multiprocessing lint
uv build
uv run python -m tools.check_wheel dist
uv run python -m tools.generate_documents --verify
git diff --cached --check
```

Result: all commands passed on Windows with CPython 3.14.7 and uv 0.12.5.  Ruff and strict mypy reported no issues;
pytest 9.1.1 passed 61 tests with 74% measured coverage; the structure, compatibility, provenance, NUL-delimited
tracked-file, and optional local SDD evidence audits reported no violations.  The compatibility contract has 66
behaviors, 45 features, and 55 oracles.
Bandit reported zero issues; pip-audit found no known third-party vulnerabilities; exact REUSE classified 62 of 62
files; both distributions built; the wheel and source distribution each carried the exact GPL text and typing marker;
document verification passed; and the staged diff check was clean.  The local package's expected not-on-PyPI
pip-audit skip is not a third-party omission.

## Generated-document review

Sixteen substantive Markdown documents have exact, regenerated same-basename LaTeX sources.  The tracked verifier
found 16 of 16 generated sources byte-identical after physical line-ending normalization.  Every document received at
least two XeLaTeX passes; eight required the bounded third pass requested by the compiler.  The final page counts are:

| Document | Pages |
|---|---:|
| Behavior dossier | 20 |
| Feature-parity matrix | 5 |
| Test oracles | 18 |
| Upstream baseline | 2 |
| App Store exception plan | 1 |
| Dependency and asset provenance ledger | 8 |
| Source-provenance policy | 2 |
| Canonical memory; decisions, project, state, and verification records | 1; 2, 1, 1, 2 |
| Program design | 9 |
| Repository-foundation specification | 6 |
| URL-audit design | 13 |
| Implementation plan | 24 |

Result: 115 PDF pages and 115 rendered page images were generated.  The 49 pages affected by the whole-branch
remediation were visually inspected page by page, with full-resolution inspection of all eight ledger pages and both
one-page memory records.  The final logs have no overflow, missing-glyph, undefined-reference, or rerun warnings.
Markdown and LaTeX have no lines over 120 characters or drafting tokens.  Listing wrapping and the landscape
wide-table treatment were explicitly reconfirmed; section headings and introductions stay with their wide tables.
There are no observed clipping, overlap, hierarchy, glyph, widow, or page-transition defects.  Review PDFs, build
files, and page images remain ignored and uncommitted.

## Environment and external boundary

The local validation environment uses Windows, PowerShell, uv, and CPython 3.14.  REUSE uses its supported
single-process mode to avoid the observed Python 3.14 Windows multiprocessing startup crash while evaluating the same
metadata.  No local gate requires or reads the external Gorilla checkout.  The separate boundary check verifies only
its approved origin, exact detached commit `6728e85c05ac25357b8f19f541487b9d26a97402`, and clean status; no upstream
test is run.
