# Password Bonobo Project Memory

Last updated: 2026-08-22

## Overview and current state

Password Bonobo is an original, local-file-first password manager with a typed Python core and platform-appropriate
clients.  Its repository foundation and neutral compatibility dossier are locally verified.  Product behavior remains
unimplemented: the package cannot open, edit, save, or audit a vault.  CI targets Windows, macOS, and Linux but has not
yet run.

The next approved subproject is **Lossless PasswordSafe core**.  It owns typed parsing and writing, validation,
unknown-field preservation, transactional local files, and conformance, fuzz, and round-trip tests.  Do not begin
client or URL-audit behavior ahead of that boundary.

## Required read order

Before substantial work, read this file completely, then read these durable records in order:

1. [Project identity](project-memory/PROJECT.md) for the product contract and authoritative design links.
2. [Current state](project-memory/STATE.md) for completed foundation work, active risks, and the next approved scope.
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
  committed; PDFs, manifests, logs, and renders remain ignored.
- The compatibility contract distinguishes Excluded Gorilla loss characterization from Bonobo's authoritative
  transactional no-loss behavior; the typed compatibility gate must remain green as the dossier evolves.
