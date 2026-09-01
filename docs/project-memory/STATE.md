# Password Bonobo Current State

Last updated: 2026-09-01

## Overview and current state

Branch `feature/lossless-passwordsafe-core` has a complete, locally verified repository foundation and compatibility
dossier plus the first twelve implementation checkpoints of the approved lossless PasswordSafe core plan.  The typed
core can authenticate, parse, mutate, serialize, and transactionally publish supported PasswordSafe V3 vaults through
a reviewed public service facade.  The package version is `0.1.0`.

## Completed foundation artifacts

- Git, Python 3.14 packaging, source-structure, tracked-file, security, dependency, REUSE, GPL-3.0-or-later, reporting,
  clean-room provenance, contribution-hold, and iOS-exception foundations.
- A detached external Gorilla baseline record pinned at `6728e85c05ac25357b8f19f541487b9d26a97402`.
- A neutral dossier with 66 behaviors, a 45-row feature matrix, and 55 synthetic black-box test oracles.  Gorilla's
  post-save loss behavior is an Excluded characterization; Bonobo's transactional no-loss oracle remains authoritative.
- Typed clean-room and exact compatibility-closure checks, a checked dependency/asset provenance ledger, an exact
  document generator/verifier, and wheel/source-distribution asset assertions.
- Three-platform CI and an explicit-selection LaTeX/PDF review workflow for user-named documents, with canonical
  Markdown-only Gorilla compatibility records and `docs/PROJECT_MEMORY.md` routing future agents to four focused
  records.

## Completed lossless-core checkpoints

- Tasks 1 through 4 pin and build Botan 3.13.0, expose typed domain and secret primitives, bind the fixed Twofish ABI,
  and implement PasswordSafe key derivation, wrapping, CBC, HMAC, and randomness.
- Tasks 5 through 8 implement encrypted snapshots, bounded payload owners, the ordered lossless document model, official
  field schemas and custom properties, quarantined authenticated parsing, validated serialization, and exact candidate
  reopen comparison.
- Tasks 9 and 10 implement revision-safe sessions, explicit secret leases, protected-record rules, atomic local
  publication, external-change detection, and one encrypted recovery revision.
- Task 11 adds minimal fresh-envelope and no-replace publication primitives, authenticated baseline advancement, and
  `VaultService` create/open/save/passphrase-rotation/export/recovery operations without exposing raw internal types.
- Task 12 adds typed Hypothesis document strategies, exact round-trip and targeted-edit properties, attacker-length
  allocation proofs, a dependency-free parser fuzz target and deterministic corpus runner, and a public large-vault
  open/no-edit-save proof for bounded memory and encrypted-only private artifacts.
- Independent review regressions prove publication evidence is required before a session becomes clean, recoveries are
  destination-bound, handles remain stable within a live session, same-version unknown fields export losslessly,
  passphrase rotation cannot weaken iterations, early destination failures remove encrypted candidates, post-replace
  failures reconcile the live session to committed disk state, and still-live retired owners remain retryable.
- Task 11 is recorded by implementation commit `8c2b30e` and its final project-memory checkpoint; final independent
  review reported no Critical or Important findings.

## Active work

Task 13 is next after the Task 12 resilience checkpoint: establish independent synthetic interoperability fixtures and
manifests for Bonobo 0x0311, current PasswordSafe, and the pinned Gorilla baseline.  Preserve the established API,
security, and clean-room boundaries, and commit each approved checkpoint independently.

## Active risks

- The App Store distribution exception, contributor permissions, dependency eligibility, and current Apple terms remain
  unresolved and block external contributions and an iOS distribution build.
- Some Gorilla behaviors remain explicitly Unverified; they do not establish parity until black-box evidence is
  reviewed and the dossier and matrix are updated.
- Python 3.14 support for future binary and mobile dependencies must be requalified in the owning subproject.
- Hosted CI has not run; only its complete local equivalent has passed.  Derivative review artifacts are regenerated
  only for documents the user explicitly names.
- Independent interoperability fixtures, mobile cross-build gates, and final operational documentation remain
  incomplete in Tasks 13 through 15.

## Next approved scope

Finish **Lossless PasswordSafe core** Tasks 13 through 15.  Do not start desktop/mobile clients, provider coordination,
or URL-audit behavior until this core passes its complete release gate.
