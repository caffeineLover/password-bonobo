# Password Bonobo Project Memory

Last updated: 2026-09-01

## Overview and current state

Password Bonobo is an original, local-file-first password manager with a typed Python core and platform-appropriate
clients.  The repository foundation and neutral compatibility dossier are locally verified.  Branch
`feature/lossless-passwordsafe-core` has completed Tasks 1 through 11 of the approved lossless PasswordSafe core plan:
Botan-backed cryptography, secret ownership, ordered lossless documents, schema and custom fields, authenticated
reading, validated writing, revision-safe sessions, transactional local storage with encrypted recovery, and the first
reviewed public service facade.

The package is now version `0.1.0`.  `VaultService` supports new-vault creation, open/save, master-passphrase rotation,
version-targeted export, recovery discovery, and explicit recovery restore while retaining authenticated baseline and
lossless-document guarantees.  Task 12 is now active and Tasks 13 through 15 still own interoperability, platform CI,
documentation, and the release checkpoint.  Do not begin client or URL-audit behavior ahead of that boundary.

## Active work and exact continuation order

Task 11 is complete at implementation commit `8c2b30e` plus its final project-memory checkpoint.  Independent review
reported no Critical or Important findings.  On 2026-09-01, the resumed session reconfirmed a clean starting tree and a
full baseline of 578 passed with 12 platform-specific skips under CPython 3.14.7.  The current maintenance checkpoint
consolidates all future handoffs into this Markdown file, removes every `HANDOFF` artifact plus generated
`PROJECT_MEMORY` formats, and excludes this live memory from exact LaTeX/PDF generation.  Its focused generator test was
observed failing before implementation and then passed.  The first exact `--write` run then exposed a distinct
Git-discovery defect: cached paths for unstaged deletions were returned after the files no longer existed, causing
`discover_document_specs()` to open deleted `docs/HANDOFF.md`.  The root cause is confirmed by `git ls-files` returning
all three deleted tracked paths while `Test-Path` reports false; add a regression for unstaged paired deletions, filter
discovery to existing files, observe red/green, and rerun the exact generator before proceeding.  That regression was
observed failing with the same `FileNotFoundError` and now passes after the minimal existence filter; the exact
`--write` rerun completed for 17 paired documents and its manifest contains zero `HANDOFF` or `PROJECT_MEMORY` sources.
The non-mutating verification then completed for the same 17-document corpus.  The complete continuity gate reports 580
passed and 12 platform-specific skips, Ruff clean, strict mypy clean across 60 source files, structure clean, provenance
current, compatibility at 66 behaviors/45 features/55 oracles, tracked-file policy clean, REUSE 3.3 at 113/113 files,
and a clean whitespace check.  The current action is to inspect and commit this standalone continuity checkpoint, then
begin Task 12 Step 1.  That checkpoint is commit `4013f8a`; Task 12 Step 1 is now active, beginning with the exact
Hypothesis development-dependency addition and complete lock/provenance review.

Task 12 Step 1 resolved Hypothesis 6.167.1 with the approved `>=6.161,<7` constraint.  The lock delta adds exactly the
direct `hypothesis` package; its `sortedcontainers` dependency was already represented in the lock and ledger.  The
ledger now records Hypothesis as direct development, MPL-2.0, not distributed, with lock and installed-metadata
evidence.  The provenance check was first observed failing only for the missing Hypothesis row, then passed after the
row was added; all 10 focused provenance tests and `uv lock --check` pass.  Regenerate the paired ledger LaTeX before
the Task 12 checkpoint.  The current action is Task 12 Step 2: inspect existing test authorities/helpers, then add the
smallest independent failing property and attacker-length resource tests.  Those tests now exist and their first run
failed during collection only because the planned `strategies` module does not exist; this is the expected Step 2 red
state.  Step 3 is current: implement the typed strategy module, then rerun both tests and resolve only real behavioral
failures exposed by generated cases.  The strategy module now generates all supported versions, unusual mandatory-field
order, known/unknown fields, duplicate optionals, bounded opaque attachments, 0x0311 custom properties, and selected
title edits.  The authenticated reader/writer/session property and attacker-length memory property both pass 12
examples.  One intermediate failure was confined to reused `tmp_path` state; isolating each Hypothesis example fixed
the harness without production changes.  Task 12 Step 4 is current: add failing fuzz-target/runner tests, then implement
typed-error, deadline, deterministic mutation, corpus replay, and temporary-artifact enforcement.

Step 4 now has two passing focused tests plus a four-seed committed hexadecimal corpus; a 100-input deterministic run
passes with deadline and leak enforcement.  Step 5's first normal-coverage run reported a 4,379,073-byte peak for a
2 MiB opaque attachment against an artificially strict 393,216-byte test configuration.  Systematic phase isolation
showed that the large allocations came from coverage bytecode instrumentation: the same test without coverage peaked
at 298,644 bytes during open and 543,324 bytes during save, so the core did not materialize the attachment.  The test
now follows the approved formula with the default 1 MiB inline and 64 KiB I/O budgets (4,718,592-byte bound) and uses
an attachment just over 1 MiB.  That corrected proof passes under normal coverage in 39.74 seconds, including public
open, no-edit save, recovery creation, lock, bounded traced memory, and absence of its plaintext marker from private
working and recovery artifacts.  The current action is to execute the complete focused PasswordSafe
generative/resource suite, followed by the deterministic 10,000-input fuzz gate.  The exact focused suite passes all
16 selected tests with 501 deselected in 44.33 seconds.  On this Windows shell, focused runs that import repository
tools must use `python -m uv run python -m pytest` (the approved CI form remains `uv run python -m pytest`); invoking
the `pytest` console script directly omits the repository root from `sys.path`.  The 10,000-input gate is now current.
The deterministic 10,000-input gate passes across all four corpus seeds.  Checkpoint hardening has added exact REUSE
metadata for all 11 new files; REUSE 3.3 reports 124/124 classified, Ruff is clean, strict mypy is clean across 67
files, the structure checker is clean, the compatibility contract remains 66/45/55, provenance is current, and the
lock resolves 57 packages.  The paired provenance ledger LaTeX has been regenerated (the ledger is now nine pages).
The current action is to rerun the fuzz integration test after static-only corrections, then run the full test,
security, package, document, tracked-file, and staged-diff gates before recording and committing Task 12.
The corrected fuzz integration pair passes, and the complete suite now reports 585 passed with 12 platform-specific
skips (597 collected) in 101.94 seconds at 79% measured coverage.  The current action is the remaining Bandit,
pip-audit, build/wheel, final document, tracked-file, and diff gates; after those pass, update the durable state and
verification records with Task 12 evidence, regenerate their paired LaTeX, and commit the independent checkpoint.
Bandit reports zero issues, pip-audit reports no known third-party vulnerabilities (with only the expected local
not-on-PyPI package skip), both distributions build, and the wheel contract passes.  `STATE.md` now records Task 12 as
complete and Task 13 as next; `VERIFICATION.md` now owns the exact resilience evidence.  The current action is to
regenerate the changed state and verification LaTeX, run exact document verification, stage the Task 12 checkpoint,
run tracked-file and staged-diff gates, inspect the staged patch, and commit it.

The user interrupted that bulk regeneration and approved a bounded document-workflow change before rebooting.  The
running generator was stopped before it completed.  Preserve existing non-Gorilla `.tex` files for now, but change
generation and verification from repository-wide discovery to explicit per-document selection: no routine command may
recreate LaTeX or PDF for an unnamed document.  Delete exactly the four tracked Gorilla LaTeX files and four ignored
Gorilla PDFs under `docs/compatibility/gorilla/`; retain their canonical Markdown.  Update tests first, then the
generator, project `AGENTS.md`, durable state/verification wording, and REUSE metadata so this opt-in contract is
enforced.  After the workflow change passes focused and policy checks, resume the nearly complete Task 12 checkpoint:
explicitly regenerate only any document the user has named (none are currently named), stage the intended files, run
tracked-file and staged-diff gates plus any tests affected by the workflow change, inspect, and commit.  Do not run the
old all-document `--write` or `--verify` command after restart.

The explicit-selection contract now has a recorded red/green cycle: the two new focused tests first failed because the
CLI accepted no selection and discovery accepted no path list, then passed after `--document` became required and
generation/coverage/discovery were restricted to the named Markdown sources.  The four verified tracked Gorilla `.tex`
files were removed with `git rm`; the four verified ignored Gorilla PDFs were deleted and are not recoverable except by
regeneration from their still-retained Markdown.  Immediate next work after restart: update the remaining document
tests (especially the old whole-repository pair assertion), `AGENTS.md`, REUSE, and durable memory wording; run the
focused document test file, Ruff, mypy, structure, REUSE, and no-argument CLI regression; confirm the Gorilla directory
contains only Markdown; then resume the Task 12 staging/checkpoint sequence described above.

The workflow documentation and policy are now updated in `AGENTS.md` 0.4.0, `README.md`, `DECISIONS.md`, `STATE.md`,
and `VERIFICATION.md`; REUSE no longer classifies the removed Gorilla derivatives.  All 16 focused document tests pass,
including the required explicit CLI selection and the repository Gorilla Markdown-only assertion.  The directory now
contains exactly its four `.md` authorities and no `.tex` or `.pdf`.  Immediate next work after restart: run Ruff,
strict mypy, structure, REUSE, provenance, tracked-file, and diff checks; inspect the complete Task 12 plus workflow
patch; update this memory with exact results; then commit the independent checkpoint.  No document generator command
is required because the user has named no document for derivative generation.

The fast post-change gates pass: Ruff is clean, strict mypy is clean across 67 source files, structure is clean,
provenance is current, and REUSE 3.3 classifies all 120 remaining files.  The only remaining checkpoint work after
restart is to inspect the complete diff, stage the exact Task 12 and approved workflow files, run the NUL-delimited
tracked-file gate plus `git diff --cached --check`, rerun the full suite if the staged inspection reveals any code/test
change beyond the already verified generator patch, update this memory, and commit.  Task 13 begins only after that
commit.  Do not generate any LaTeX or PDF unless the user explicitly names its Markdown source.

Continue in this exact order:

1. Finish and verify the continuity checkpoint: update the paired generated sources affected by durable-state edits,
   run the focused document-generation tests, structure check, REUSE lint, and document verification, inspect Git, and
   commit this checkpoint independently.
2. Execute Task 12 Step 1: add Hypothesis `>=6.161,<7`, update the lock and dependency provenance, review the complete
   transitive lock delta, and run the provenance checks.
3. Execute Task 12 Steps 2 and 3 test-first: add failing property/resource tests, confirm their expected failures, then
   implement typed strategies for supported versions, ordered known/unknown fields, duplicates, mandatory records,
   custom properties, targeted edits, and bounded synthetic payloads.
4. Execute Task 12 Step 4 test-first: add the dependency-free fuzz target, deterministic seed corpus, and mutation
   runner with typed-failure, deadline, and temporary-artifact enforcement.
5. Execute Task 12 Step 5 test-first: prove opaque large-field open/no-edit-save memory bounds and absence of plaintext
   fragments in temporary and recovery storage.
6. Run Task 12 focused generative/fuzz/resource gates, the deterministic 10,000-iteration corpus run, the full quality
   suite, and document/provenance/build checks; update this file with exact evidence and commit Task 12 independently.

After Task 12, continue Tasks 13, 14, and 15 from the approved plan in order: independent synthetic interoperability,
platform/release automation and operational documentation, then the final complete-core release checkpoint.  Do not
start client applications, provider coordination, or URL-audit behavior before Task 15 closes.

In the current shell, invoke uv as `python -m uv` because the module is installed but the `uv` console executable is not
discoverable on `PATH`.  Update this section before and after every meaningful step above, before long-running gates,
and immediately before any interruption; always record the last proven result and the next unambiguous action.

## Required read order

Before substantial work, read this file completely, then read these durable records in order:

1. [Project identity](project-memory/PROJECT.md) for the product contract and authoritative design links.
2. [Current state](project-memory/STATE.md) for completed core work, active risks, and the next approved scope.
3. [Decisions](project-memory/DECISIONS.md) for clean-room, tooling, licensing, and generated-document constraints.
4. [Verification](project-memory/VERIFICATION.md) for executed local gates, CI pins, and hosted-CI limitations.

Approved specifications and enforced configuration remain authoritative.  Update this summary and its owning record
when state changes; exclude raw transcripts, task logs, credentials, machine-specific external paths, and copied
upstream content.

## Durable boundaries

- Gorilla implementation material stays in the separate read-only research checkout and never enters Bonobo product
  code, fixtures, documentation, CI, or builds.
- Credential and user-authored metadata loss is unacceptable; unknown-field preservation is a core data contract.
- Bonobo-authored material is GPL-3.0-or-later.  External contributions remain closed while contributor permissions and
  any App Store distribution exception are unresolved.
- The tracked exact generator produces review PDFs and renders.  Canonical Markdown and same-basename LaTeX are
  committed for substantive documents; this live project memory is an explicit Markdown-only exception.  PDFs,
  manifests, logs, and renders remain ignored.
- The compatibility contract distinguishes Excluded Gorilla loss characterization from Bonobo's authoritative
  transactional no-loss behavior; the typed compatibility gate must remain green as the dossier evolves.
