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
lossless-document guarantees.  Tasks 12 through 15 still own property/fuzz/resource evidence, interoperability,
platform CI, documentation, and the release checkpoint.  Do not begin client or URL-audit behavior ahead of that
boundary.

## Active work

Task 11 is complete at implementation commit `8c2b30e` plus the reboot handoff checkpoint containing this record.  Its
test-first amendment added minimal
new-envelope reading/writing, no-replace publication, and published-baseline advancement primitives before assembling
`service.py`; the facade does not bypass private constructors or duplicate publication logic.  The complete local test
suite on 2026-09-01 was 578 passed and 12 platform-specific skips under CPython 3.14.7.  Independent review drove
additional proofs for publication-only save completion, destination-bound recovery, stable in-session handles,
same-version unknown-field export, iteration-policy preservation, early candidate cleanup, committed-state adoption
after a post-replace storage report, and retryable cleanup of still-live retired plaintext owners.  The final reviewer
reported no Critical or Important findings.  The 19-test focused facade/public/package selection, Ruff, strict mypy,
structure, REUSE, provenance, source/wheel builds, and distribution inspection passed; the full suite and static gates
were rerun after the final review fix.  Task 12 is next after optionally repeating the packaging/security gates recorded
in [the reboot handoff](HANDOFF.md).  In the current shell, invoke uv as `python -m uv` because the module is installed
but the `uv` console executable is not discoverable on `PATH`.

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
