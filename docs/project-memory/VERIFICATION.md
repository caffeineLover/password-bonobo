# Password Bonobo Foundation Verification

Last updated: 2026-09-01

## Overview and current state

This record distinguishes executed local checks from hosted service state.  The complete local release gate and
document review passed against the staged whole-branch remediation candidate.  Hosted CI has not yet run because this
branch introduces the workflow; its Windows, macOS, and Linux jobs remain to be observed after publication.

## Lossless-core Task 11 checkpoint

The public service-facade checkpoint passed locally on Windows with CPython 3.14.7 on 2026-09-01.  The complete suite
collected 590 tests and reported 578 passed with 12 platform-specific skips.  The focused service, public API, and
package-contract selection reported 19 passed.  Ruff, strict mypy, the Python structure checker, REUSE 3.3 lint, and
the provenance ledger checker reported no violations.  A clean build produced exactly
`password_bonobo-0.1.0-py3-none-any.whl` and `password_bonobo-0.1.0.tar.gz`; the distribution checker passed.

The focused service evidence covers create/edit/save/reopen, passphrase consumption and rotation, legacy export,
recovery discovery and explicit restore, no-replace creation, external-change save abort without loss of session work,
and rejection of incompatible unknown fields before an export destination is created.  Hosted CI remains unobserved;
this is a local checkpoint rather than the Task 15 release gate.

Independent review added regression evidence that save completion requires authenticated publication, recovery is
bound to one destination even when vaults share a passphrase, record handles remain stable across saves in one session,
same-version exports preserve unknown fields exactly, passphrase rotation preserves stronger iteration policies, and
destination-preparation failures remove encrypted writer candidates.  Final review also verified that storage faults
reported after atomic replacement reconcile the live session to the committed revision, old-owner cleanup cannot
corrupt that live revision, and still-live retired plaintext owners remain reachable for deterministic retry.  The
reviewer reported no remaining Critical or Important findings.

## Lossless-core Task 12 checkpoint

The parser-resilience checkpoint passed locally on Windows with CPython 3.14.7 on 2026-09-01.  The complete suite
collected 597 tests and reported 585 passed with 12 platform-specific skips at 79% measured coverage.  The exact
property/resource/large-vault selection reported 16 passed with 501 deselected, and the fuzz integration pair passed.
The deterministic runner processed 10,000 inputs across four committed hexadecimal corpus seeds without a deadline,
untyped exception, or temporary-artifact failure.

Hypothesis 6.167.1 is locked under the approved `>=6.161,<7` direct development constraint and recorded as MPL-2.0,
not distributed.  Generated cases cover every supported format version, unusual known/unknown field order, duplicate
optionals, mandatory records, 0x0311 custom properties, targeted edits, bounded opaque payloads, and hostile uint32
length declarations.  A public open/no-edit-save test preserves an attachment larger than the 1 MiB inline threshold,
stays below `4 * max_inline_payload_bytes + 8 * io_chunk_bytes`, creates encrypted recovery, and finds no fabricated
plaintext marker in private working or recovery artifacts.

Ruff, strict mypy across 67 source files, the Python structure checker, the 66/45/55 compatibility contract, and the
provenance checker reported no violations.  REUSE 3.3 classified all 124 files.  Bandit found no issues, pip-audit
found no known third-party vulnerabilities, and the local package was the sole expected not-on-PyPI skip.  A clean
build produced the wheel and source distribution, and the distribution contract checker passed.

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
git diff --cached --check
```

Document generation is not a repository-wide release gate.  When the user explicitly requests a derivative, its
separate gate names every source with `--document` and verifies only that selection.

Result: all commands passed on Windows with CPython 3.14.7 and uv 0.12.5.  Ruff and strict mypy reported no issues;
pytest 9.1.1 passed 61 tests with 74% measured coverage; the structure, compatibility, provenance, NUL-delimited
tracked-file, and optional local SDD evidence audits reported no violations.  The compatibility contract has 66
behaviors, 45 features, and 55 oracles.
Bandit reported zero issues; pip-audit found no known third-party vulnerabilities; exact REUSE classified 62 of 62
files; both distributions built; the wheel and source distribution each carried the exact GPL text and typing marker;
document verification passed; and the staged diff check was clean.  The local package's expected not-on-PyPI
pip-audit skip is not a third-party omission.

## Generated-document review

This section records the historical 2026-08-22 review; it is not a requirement to retain or regenerate every listed
derivative.  On 2026-09-01 the repository adopted explicit per-document opt-in and removed the Gorilla LaTeX and PDF
derivatives while retaining their Markdown authorities.

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
