# Password Bonobo Project Memory

Last updated: 2026-09-01

## Purpose and resume protocol

This is the repository's sole persistent continuation record.  Read it completely before resumed or substantial work,
then reconcile it with Git and the current files.  Update it after every meaningful checkpoint and before interruption.
Keep the current task, last proven result, exact next actions, later approved work, risks, and durable decisions here.
Do not store raw transcripts, credentials, machine-specific research paths, or history already recoverable from Git.

This file is Markdown-only.  Do not create a second project-memory location or a LaTeX/PDF derivative.

## Immediate checkpoint

Branch `feature/lossless-passwordsafe-core` has completed Tasks 1 through 12 of the approved lossless PasswordSafe core
plan.  Task 13 is next.

The current maintenance checkpoint consolidates the retired split identity/state/decisions/verification records into
this file and deletes that obsolete folder.  It also makes `docs/superpowers/specs/` Markdown-only by removing its one
tracked LaTeX file and one ignored PDF.  Complete this checkpoint in order:

Current working-tree state: consolidation, deletions, policy/tool/test changes, stale-plan cleanup, and the complete
checkpoint verification are finished.  The independent checkpoint commit and recording its hash here remain; no
Task 13 implementation has started.

1. Enforce the single-memory and approved-design Markdown-only boundaries with failing-then-passing regressions.
2. Preserve the unique project identity, state, decisions, verification, risks, and links in this concise file.
3. Delete the retired split-memory files and approved-design derivatives; update all live references and REUSE.
4. Run the complete document suite, Ruff, strict mypy, structure, provenance, REUSE, tracked-file, and whitespace gates.
5. Inspect and commit the checkpoint independently, record its commit here, then begin Task 13 Step 1.

## Product contract and authoritative documents

Password Bonobo is an original, local-file-first password manager with a fully typed Python core and
platform-appropriate clients.  It targets Windows, macOS, Linux, Android, ChromeOS through Android, and iOS; BSD
portability remains a goal pending qualification.  User-selected operating-system providers may synchronize local
vault files, but Bonobo has no account system, cloud vault, or synchronization service.

Loss of credentials or user-authored metadata is unacceptable.  PasswordSafe files are lossless documents, including
stable identifiers, supported standard fields, and preservable unknown bytes.  Bonobo-authored material is
GPL-3.0-or-later.  The possible iOS distribution exception remains unresolved and grants no current permission.

- [Program design](specs/password-bonobo-python-reimplementation-design.md)
- [Repository-foundation specification](specs/password-bonobo-repository-foundation-compatibility-dossier-spec.md)
- [URL-audit design](specs/password-bonobo-url-audit-design.md)
- [Lossless PasswordSafe core design](superpowers/specs/2026-08-23-lossless-passwordsafe-core-design.md)
- [Active implementation plan](superpowers/plans/2026-08-23-lossless-passwordsafe-core.md)
- [Source-provenance policy](legal/source-provenance-policy.md)
- [Dependency and asset ledger](legal/dependency-asset-provenance-ledger.md)
- [Compatibility matrix](compatibility/gorilla/feature-parity-matrix.md)
- [Black-box test oracles](compatibility/gorilla/test-oracles.md)

## Completed state

- The repository foundation includes Python 3.14 packaging, Git and tracked-file policy, security and dependency gates,
  REUSE/GPL metadata, clean-room provenance, contributor hold, and three-platform CI.
- Gorilla evidence is tied to the read-only external commit
  `6728e85c05ac25357b8f19f541487b9d26a97402`.  The neutral contract has 66 behaviors, 45 feature rows, and 55
  synthetic oracles.  Gorilla post-save loss is Excluded; Bonobo's transactional no-loss contract is authoritative.
- Tasks 1 through 4 pin/build Botan 3.13.0 and implement typed secret ownership, Twofish, derivation, wrapping, CBC,
  HMAC, and randomness.
- Tasks 5 through 8 implement bounded encrypted snapshots/payloads, ordered lossless documents, schemas/custom fields,
  authenticated parsing, validated serialization, and exact candidate comparison.
- Tasks 9 through 11 implement revision-safe sessions, protected-record rules, atomic publication, encrypted recovery,
  external-change detection, and the reviewed public `VaultService` create/open/save/rotate/export/recovery API.
- Task 12 adds typed Hypothesis strategies, exact round-trip/targeted-edit properties, hostile-length allocation proofs,
  a dependency-free deterministic fuzz corpus/runner, and a bounded-memory encrypted-only large-vault proof.

Key checkpoints: continuity `4013f8a`; Task 11 `8c2b30e`; Task 12/workflow `08c2107`; Gorilla derivatives `b77077c`;
legal Markdown-only `2be2512`; specifications Markdown-only `925e8c6`; plans Markdown-only `3df88b4`.

## Last proven verification

Task 12's complete Windows/CPython 3.14.7 suite collected 597 tests and reported 585 passed, 12 platform-specific
skips, and 79% coverage in 101.94 seconds.  The property/resource/large-vault selection passed 16 tests; the fuzz
integration pair passed; the deterministic runner processed 10,000 inputs across four corpus seeds.  The large-vault
test stayed below `4 * max_inline_payload_bytes + 8 * io_chunk_bytes` and found no fabricated plaintext marker in
private working or recovery artifacts.

At the 2026-09-01 single-memory/approved-design checkpoint, all 26 document-policy tests passed.  Ruff and strict mypy
passed for the two changed Python files; the Python structure checker, provenance, tracked-file policy, and staged and
unstaged whitespace checks passed; REUSE 3.3 classified 103/103 files.  Filesystem inspection found zero TeX/PDF files
in every Markdown-only directory, no split-memory directory, no HANDOFF artifact, and no stale split-memory reference.
Hosted CI has not yet been observed after publication; these are local results.

Local command form uses `python -m uv` because the `uv` console executable is not discoverable on this Windows PATH.
REUSE uses `--no-multiprocessing` because Python 3.14 Windows worker startup was unstable while single-process checks
the same metadata.

## Durable decisions and boundaries

- Gorilla implementation material remains outside this repository.  Product work uses approved specifications,
  official format documentation, neutral observations, and synthetic tests; no upstream expression enters the product.
- Compatibility hashes are evidence indexes, not substitutes for exact comparisons.  Unknown-field preservation and
  authenticated transactional publication remain mandatory.
- External contributions remain closed until contributor terms and any iOS exception rights are resolved.
- Wheels declare GPL-3.0-or-later and both wheel/source distributions carry the exact GPL text and typing marker.
- Markdown is canonical.  Never generate, regenerate, verify, or retain LaTeX/PDF derivatives without explicit
  document-level user instructions.  The generator requires repeated `--document` selections and has no all-document
  mode.
- This file plus `docs/compatibility/gorilla/`, `docs/legal/`, `docs/specs/`, `docs/superpowers/plans/`, and
  `docs/superpowers/specs/` are Markdown-only until the user explicitly reverses a boundary.
- Shared standards below `E:\home\Code\Code Agent Prompts\docs\prompts\` are read-only and never repository content.

## Active risks

- The App Store distribution exception, contributor permissions, dependency eligibility, and current Apple terms are
  unresolved and block external contributions and an iOS distribution build.
- Some Gorilla behaviors remain Unverified and cannot establish parity until black-box evidence is reviewed.
- Future binary/mobile dependencies require Python 3.14 and platform requalification.
- Tasks 13 through 15 still own independent interoperability, platform/cross-build gates, operational documentation,
  and the complete release checkpoint.

## Exact continuation order after this checkpoint

1. Task 13 Steps 1 and 2: create failing manifest/authority/provenance tests for exact fixture stems
   `bonobo-0311`, `passwordsafe-current`, `gorilla-6728e85`, and `official-unknown-0302`; prove failure is only absent
   fixtures/manifests.
2. Task 13 Step 3: implement the safe manifest extractor/comparator using standard-input fabricated passphrases,
   ordinal/type/length/SHA-256 output, typed-value redaction, and one explicitly named field edit.
3. Task 13 Steps 4 and 5: independently produce the four synthetic vaults and ordered manifests, then perform only
   disposable no-edit/title-edit transactions at each declared compatibility level.
4. Update canonical compatibility/provenance Markdown, typed gates, and REUSE.  Any plan reference to deleted
   derivatives or automatic document generation is superseded by the explicit Markdown policy above.
5. Run focused interop, compatibility, provenance, tracked-file, REUSE, static, security, package, and full-suite gates;
   record exact evidence here and commit Task 13 independently.
6. Continue Tasks 14 and 15 in order.  Do not start client applications, provider coordination, or URL-audit behavior
   before Task 15 closes.
