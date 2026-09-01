# Password Bonobo Project Memory

Last updated: 2026-08-31

## Overview and current state

Password Bonobo is an original, local-file-first password manager with a typed Python core and platform-appropriate
clients.  The repository foundation and neutral compatibility dossier are locally verified.  Branch
`feature/lossless-passwordsafe-core` has completed Tasks 1 through 10 of the approved lossless PasswordSafe core plan:
Botan-backed cryptography, secret ownership, ordered lossless documents, schema and custom fields, authenticated
reading, validated writing, revision-safe sessions, and transactional local storage with encrypted recovery.

The core is not yet publicly usable.  Task 11 must assemble the service facade and public exports, followed by the
property/fuzz/resource, interoperability, platform-CI, documentation, and release checkpoints in Tasks 12 through 15.
Do not begin client or URL-audit behavior ahead of that boundary.

## Active work

Resume from clean commit `32e2d82` on `feature/lossless-passwordsafe-core`.  The complete baseline on 2026-08-31 was
556 passed and 12 platform-specific skips under CPython 3.14.7.  In the current shell, invoke uv as `python -m uv`
because the module is installed but the `uv` console executable is not discoverable on `PATH`.

Task 11's approved facade cannot be implemented safely against the current Tasks 7 through 10 interfaces: they can
open and rewrite an existing vault and replace an existing destination, but they cannot create a new destination,
rotate salt and passphrase material, perform an independent export, or advance a session's published baseline.  The
user approved amending Task 11 to add the minimal supported primitives in `reader.py`, `writer.py`, `storage.py`, and
`session.py` before implementing `service.py`.  Continue test-first and do not bypass private constructors or duplicate
security-sensitive publication logic in the facade.

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
  committed; PDFs, manifests, logs, and renders remain ignored.
- The compatibility contract distinguishes Excluded Gorilla loss characterization from Bonobo's authoritative
  transactional no-loss behavior; the typed compatibility gate must remain green as the dossier evolves.
