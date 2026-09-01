# Password Bonobo Current State

Last updated: 2026-08-31

## Overview and current state

Branch `feature/lossless-passwordsafe-core` has a complete, locally verified repository foundation and compatibility
dossier plus the first ten implementation checkpoints of the approved lossless PasswordSafe core plan.  Internal typed
modules can authenticate, parse, mutate, serialize, and transactionally replace supported PasswordSafe V3 vaults, but
the package still exposes no service facade and retains version `0.0.0`.

## Completed foundation artifacts

- Git, Python 3.14 packaging, source-structure, tracked-file, security, dependency, REUSE, GPL-3.0-or-later, reporting,
  clean-room provenance, contribution-hold, and iOS-exception foundations.
- A detached external Gorilla baseline record pinned at `6728e85c05ac25357b8f19f541487b9d26a97402`.
- A neutral dossier with 66 behaviors, a 45-row feature matrix, and 55 synthetic black-box test oracles.  Gorilla's
  post-save loss behavior is an Excluded characterization; Bonobo's transactional no-loss oracle remains authoritative.
- Typed clean-room and exact compatibility-closure checks, a checked dependency/asset provenance ledger, an exact
  document generator/verifier, and wheel/source-distribution asset assertions.
- Three-platform CI and reproducible Markdown, LaTeX, ignored review-PDF, and page-render workflows, with canonical
  `docs/PROJECT_MEMORY.md` routing future agents to four focused records.

## Completed lossless-core checkpoints

- Tasks 1 through 4 pin and build Botan 3.13.0, expose typed domain and secret primitives, bind the fixed Twofish ABI,
  and implement PasswordSafe key derivation, wrapping, CBC, HMAC, and randomness.
- Tasks 5 through 8 implement encrypted snapshots, bounded payload owners, the ordered lossless document model, official
  field schemas and custom properties, quarantined authenticated parsing, validated serialization, and exact candidate
  reopen comparison.
- Tasks 9 and 10 implement revision-safe sessions, explicit secret leases, protected-record rules, atomic local
  publication, external-change detection, and one encrypted recovery revision.
- The latest completed checkpoint is commit `32e2d82` (`feat: add transactional local vault storage`).

## Active work

Task 11 is next.  Its original file map assumes creation, passphrase rotation, independent export, and baseline
advancement primitives that Tasks 7 through 10 do not expose.  The user approved a minimal Task 11 amendment covering
`reader.py`, `writer.py`, `storage.py`, and `session.py` before the service facade is assembled.  Implement the amendment
with failing tests first, preserve the existing security boundaries, and commit Task 11 independently as planned.

## Active risks

- The App Store distribution exception, contributor permissions, dependency eligibility, and current Apple terms remain
  unresolved and block external contributions and an iOS distribution build.
- Some Gorilla behaviors remain explicitly Unverified; they do not establish parity until black-box evidence is
  reviewed and the dossier and matrix are updated.
- Python 3.14 support for future binary and mobile dependencies must be requalified in the owning subproject.
- Hosted CI has not run; only its complete local equivalent has passed.  Ignored review PDFs must be regenerated from
  committed Markdown and LaTeX.
- The public facade, generative and fuzz evidence, independent interoperability fixtures, mobile cross-build gates, and
  final operational documentation remain incomplete in Tasks 11 through 15.

## Next approved scope

Finish **Lossless PasswordSafe core** Tasks 11 through 15.  Do not start desktop/mobile clients, provider coordination,
or URL-audit behavior until this core passes its complete release gate.
