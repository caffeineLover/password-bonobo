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

While the final status was being inspected, the user committed the Gorilla LaTeX deletions as `b77077c` and the full
Task 12 plus explicit-selection workflow as `08c2107`.  Those commits were preserved exactly; the working tree was
then confirmed clean.  Task 12 is therefore closed.  After restart, begin Task 13 from the approved plan: reread this
file and the linked durable records, inspect Task 13's exact fixture/manifest requirements, and proceed test-first with
independent synthetic interoperability evidence.  Do not run document generation or verification unless the user
explicitly names each Markdown source, and never retain Gorilla `.tex` or `.pdf` derivatives.

The user then strengthened the legal-document rule: `docs/legal/` is Markdown-only, with neither LaTeX nor PDF retained.
Two focused regressions were observed failing first under the initial PDF-only restriction: the generator still
accepted a legal source and the repository still contained three ignored legal PDFs.  Those PDFs are now deleted.  The
current action is to update the red test to require no legal `.tex` either, confirm that red state against the three
tracked LaTeX files, then enforce the Markdown-only directory, remove those exact tracked files, update policy wording,
rerun all document/static/policy gates, and commit this bounded checkpoint.

That strengthened test failed for the exact expected reasons: the generator reported only `PDF-disabled`, and all
three tracked legal `.tex` files remained.  The generator now treats both `docs/legal/` and
`docs/compatibility/gorilla/` as Markdown-only directories; all three legal LaTeX files were removed with `git rm`, and
REUSE/policy wording was updated.  The three ignored legal PDFs had already been deleted.  The current action is to run
the complete document test file, static and policy gates, confirm `docs/legal/` contains exactly its three Markdown
authorities, inspect/stage the patch, update this memory with exact evidence, and commit.

The complete 18-test document suite now passes, as do Ruff, strict mypy across 67 files, structure, and REUSE 3.3 for
117 files.  Provenance then exposed a separate Task 12 omission previously masked while the fuzz corpus was untracked:
the four committed `.hex` seeds had no repository-asset ledger rows.  The canonical legal Markdown ledger now describes
and inventories those four Bonobo-authored synthetic seeds; no legal derivative was created.  The current action is to
rerun provenance and the remaining staging gates, then commit the legal Markdown-only checkpoint and provenance repair.

Provenance is current again and all 10 provenance tests pass.  The broader foundation suite reports 84 passed; Bandit
reports zero issues.  `docs/legal/` contains exactly its three `.md` authorities, with no `.tex` or `.pdf`; the Gorilla
directory remains Markdown-only as well.  Ruff, mypy, structure, and REUSE were already green for this patch.  The
current action is to stage the exact policy, generator, test, ledger, memory, and three legal-LaTeX deletion changes;
run tracked-file and staged whitespace checks; inspect the staged patch; and commit this bounded checkpoint.

The legal Markdown-only policy, three tracked LaTeX deletions, generator/test enforcement, and fuzz-corpus provenance
repair are committed as `2be2512`.  The three ignored legal PDFs were deleted before that commit.  All recorded gates
above are green, and no LaTeX or PDF was generated.  After restart or continuation, reconcile a clean tree and proceed
with Task 13 Step 1 in the exact order below.

The user has now made `docs/specs/` Markdown-only as well and reiterated the global rule: never generate any LaTeX or
PDF without explicit document-level instructions.  The directory currently contains three Markdown authorities, three
tracked LaTeX derivatives, and three ignored PDFs.  The current action is test-first: add generator-rejection and
repository-absence regressions, observe their expected failures, add `docs/specs/` to the Markdown-only boundary,
delete the exact six derivatives, update AGENTS/README/DECISIONS/REUSE, run the focused and policy gates, and commit.

The two new specification regressions failed for exactly the intended reasons: the generator accepted an explicitly
selected specification, and the directory still held three tracked `.tex` files.  `docs/specs/` is now part of the
generator's Markdown-only directory set, and policy/REUSE metadata is updated.  The current action is to remove the
three exact tracked LaTeX and three exact ignored PDF files, then rerun the complete document and static/policy gates.

All six specification derivatives are now removed and `docs/specs/` contains exactly its three Markdown authorities.
The complete document suite reports 20 passed; Ruff, strict mypy across 67 files, structure, provenance, Bandit, and
REUSE 3.3 for 114 files all pass.  No derivative was generated.  The current action is to stage the exact policy,
generator, test, memory, REUSE, and three specification-LaTeX deletion changes; run tracked-file and staged whitespace
checks; inspect the patch; and commit this bounded Markdown-only checkpoint.

The specifications Markdown-only policy, three tracked LaTeX deletions, six-file derivative removal, and enforced
generator/test boundary are committed as `925e8c6`.  All recorded gates above are green, and no derivative was
generated.  Resume Task 13 Step 1 after reconciling a clean tree.

The user has now made `docs/superpowers/plans/` Markdown-only and reiterated that no LaTeX or PDF may be generated
without explicit document-level instructions.  It currently contains two Markdown plans, two tracked LaTeX files, and
two ignored PDFs.  The current action is to record failing generator/repository regressions, add the plans directory to
the Markdown-only boundary, delete those exact four derivatives, update policy/REUSE metadata, run focused and policy
gates, and commit promptly.

The two plan regressions failed for the exact intended reasons: the generator accepted a selected plan, and two tracked
plan `.tex` files remained.  The plans directory is now enforced as Markdown-only and policy/REUSE metadata is updated.
The current action is to delete the exact two tracked LaTeX files and two ignored PDFs, then run the focused/static
policy gates and commit.

The four plan derivatives are removed and the directory contains exactly its two Markdown plans.  The complete
document suite reports 22 passed; Ruff, strict mypy across 67 files, structure, provenance, and REUSE 3.3 for 112 files
all pass.  No derivative was generated.  The current action is to stage, run tracked-file/whitespace checks, inspect,
and commit this Markdown-only checkpoint.

Continue in this exact order:

1. Reconcile `git status`, commits `b77077c` and `08c2107`, and the four Markdown-only Gorilla records against this
   memory; rerun a gate only if the checkout differs from the recorded clean state.
2. Execute Task 13 Steps 1 and 2 test-first: create failing manifest/authority/provenance tests for the four exact
   fixture stems, then prove the failure is only the intentionally absent fixtures and manifests.
3. Execute Task 13 Step 3: implement the safe interoperability manifest extractor/comparator with standard-input
   fabricated passphrases, ordinal/type/length/SHA-256 output, typed-value redaction, and one explicitly named edit.
4. Execute Task 13 Steps 4 and 5: independently produce the four synthetic vaults and ordered manifests, then perform
   only disposable no-edit/title-edit transactions at each declared client compatibility level.
5. Update only the canonical compatibility and provenance Markdown plus their typed gates and REUSE metadata; Task 13
   plan references to Gorilla `.tex` and repository-wide document commands are superseded by the user-approved
   Markdown-only/explicit-selection policy.
6. Run Task 13 focused tests, compatibility, provenance, tracked-file, REUSE, static, and full-suite gates; record exact
   evidence here and commit independently.  Then continue Tasks 14 and 15 in order.

Do not start client applications, provider coordination, or URL-audit behavior before Task 15 closes.

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
- Markdown is canonical by default.  The tracked generator requires explicit user-approved `--document` selections;
  no unnamed document receives LaTeX, PDF, manifest, or render work.  Existing LaTeX outside named Markdown-only
  boundaries remains preserved until the user directs otherwise; this live memory is also Markdown-only.
- The Gorilla compatibility, legal, specifications, and implementation-plan directories are Markdown-only until the
  user explicitly reverses that policy; the generator rejects their selections and none retain derivatives.
- The compatibility contract distinguishes Excluded Gorilla loss characterization from Bonobo's authoritative
  transactional no-loss behavior; the typed compatibility gate must remain green as the dossier evolves.
