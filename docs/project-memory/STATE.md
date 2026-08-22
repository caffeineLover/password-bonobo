# Password Bonobo Current State

Last updated: 2026-08-22

## Overview and current state

The repository is on branch `foundation/compatibility-dossier`.  The repository foundation and compatibility dossier
are complete and locally verified.  Product behavior remains unimplemented: the typed package exposes identity only
and cannot open, edit, save, or audit a vault.

## Completed foundation artifacts

- Git, packaging, Python 3.14, source-structure, tracked-file, security, dependency, and REUSE policy foundations.
- GPL-3.0-or-later licensing, security reporting, clean-room provenance, contribution hold, and iOS-exception planning.
- A detached external Gorilla baseline record pinned at `6728e85c05ac25357b8f19f541487b9d26a97402`.
- A neutral dossier with 66 behaviors, a 44-row feature matrix, and 53 synthetic black-box test oracles.
- A three-platform CI definition and reproducible Markdown, LaTeX, and ignored review-PDF workflow.
- A canonical `docs/PROJECT_MEMORY.md` future-agent entry point routing to the four focused durable records.

## Active risks

- The App Store distribution exception, contributor permissions, dependency eligibility, and current Apple terms remain
  unresolved and block external contributions and an iOS distribution build.
- Some Gorilla behaviors remain explicitly Unverified; they do not establish parity until black-box evidence is
  reviewed and the dossier and matrix are updated.
- Python 3.14 support for future binary and mobile dependencies must be requalified in the owning subproject.
- The introduced GitHub Actions workflow has not yet run on the hosted service; only its complete local equivalent has
  passed.
- Generated review PDFs are intentionally ignored and must be regenerated from committed Markdown and LaTeX sources.

## Next approved subproject

The next approved subproject is **Lossless PasswordSafe core**.  It owns typed PasswordSafe parsing, writing,
validation, unknown-field preservation, transactional local files, and conformance, fuzz, and round-trip suites.
