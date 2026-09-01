# Password Bonobo Foundation Decisions

Last updated: 2026-08-22

## Overview and current state

These durable decisions govern later Password Bonobo subprojects.  Approved specifications and enforced repository
configuration remain authoritative when they provide more detail.

## 2026-08-22 - Clean-room compatibility boundary

Gorilla implementation material remains outside Bonobo.  Product work uses approved Bonobo specifications, official
format documentation, neutral compatibility observations, and approved synthetic tests.  This protects the original
implementation boundary and prevents upstream expression from becoming product structure.

## 2026-08-22 - Immutable Gorilla evidence baseline

Compatibility evidence is tied to commit `6728e85c05ac25357b8f19f541487b9d26a97402` in an external, detached,
read-only checkout.  A different revision requires a new pin, provenance review, and dossier delta.

## 2026-08-22 - Python 3.14 and repository tools

The foundation targets CPython `>=3.14,<3.15`, Hatchling, uv, autopep8, Ruff, strict mypy, pytest, Bandit, pip-audit,
and REUSE.  Mobile and binary dependencies must be requalified before their platform subprojects adopt them.

## 2026-08-22 - Git boundary and product-free foundation

The Bonobo Git repository excludes generated PDFs, local environments, logs, vault-like files outside a future
synthetic-fixture allowlist, shared standards, temporary files, and upstream source trees.  The initial `bonobo_core`
package intentionally exposes identity only; product behavior belongs to later approved subprojects.

## 2026-08-22 - Enforcing formatter and license gates

Formatting runs autopep8 in place and then requires a scoped clean diff.  REUSE lint runs with
`--no-multiprocessing` because repeated Python 3.14 Windows runs showed default worker startup instability while the
single-process mode checks identical metadata.  Every new tracked path is explicitly classified before license lint.

## 2026-08-22 - Generated-document policy

Substantial documentation has canonical Markdown and committed same-basename LaTeX.  A shared Pandoc header preserves
listing and table wrapping.  The tracked generator verifies exact Pandoc output, performs at least two XeLaTeX passes
and a bounded third when the compiler requests it, and emits an ignored manifest, logs, PDFs, and optional page renders.
Review PDFs and rendered pages remain ignored, visually checked, and never committed.

## 2026-09-01 - Explicit opt-in document derivatives

Markdown is the canonical default.  LaTeX and PDF derivatives are generated, regenerated, or verified only when the
user explicitly names each document; the tool requires a repeated `--document` selection and has no repository-wide
operation.  Existing non-Gorilla LaTeX is preserved until the user directs otherwise.  The Gorilla compatibility
directory is Markdown-only and contains no retained LaTeX or PDF derivatives.  This decision supersedes the automatic
all-substantive-document portion of the 2026-08-22 policy while retaining ignored-output and visual-review safeguards
for explicitly requested derivatives.

## 2026-08-22 - Compatibility and no-loss authority

Observed Gorilla data loss is an Excluded characterization, not a passing cross-client contract.  Bonobo must persist
conflict resolution or deletion transactionally before close; if publication cannot complete, it must retain explicit
staged or conflicted work and block silent discard.  A typed compatibility check enforces closure, critical authority,
and the clean-room expression boundary.

## 2026-08-22 - Release provenance and distribution content

The paired dependency and asset ledger records direct and transitive Python packages, build tools, workflow actions,
document tools, and repository assets.  Its checker prevents stale or incomplete coverage without converting pending
review into approval.  Built wheels must declare GPL-3.0-or-later.  Both source distribution and wheel must contain the
repository's GPL text and package typing marker, with exact license bytes.

## 2026-08-22 - External contribution hold

External contributions remain closed until contributor terms can preserve GPL-3.0-or-later licensing and any approved
iOS distribution-exception rights.  The current exception plan is neither license text nor distribution approval.
