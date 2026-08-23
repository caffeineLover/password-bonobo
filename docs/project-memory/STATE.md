# Password Bonobo Current State

Last updated: 2026-08-22

## Overview and current state

Branch `foundation/compatibility-dossier` has a complete, locally verified repository foundation and compatibility
dossier.  Product behavior remains unimplemented: the typed package exposes identity only and cannot open, edit,
save, or audit a vault.

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

## Active risks

- The App Store distribution exception, contributor permissions, dependency eligibility, and current Apple terms remain
  unresolved and block external contributions and an iOS distribution build.
- Some Gorilla behaviors remain explicitly Unverified; they do not establish parity until black-box evidence is
  reviewed and the dossier and matrix are updated.
- Python 3.14 support for future binary and mobile dependencies must be requalified in the owning subproject.
- Hosted CI has not run; only its complete local equivalent has passed.  Ignored review PDFs must be regenerated from
  committed Markdown and LaTeX.

## Next approved subproject

The next approved subproject is **Lossless PasswordSafe core**: typed parsing/writing, validation, unknown-field
preservation, transactional local files, and conformance, fuzz, and round-trip suites.
