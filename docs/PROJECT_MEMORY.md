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
begin Task 12 Step 1.

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
