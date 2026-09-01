# Password Bonobo Project Memory

Last updated: 2026-09-01

## Purpose and resume protocol

This is the repository's sole persistent continuation record.  Read it completely before resumed or substantial work,
then reconcile it with Git and the current files.  Update it after every meaningful checkpoint and before interruption.
Keep the current task, last proven result, exact next actions, later approved work, risks, and durable decisions here.
Do not store raw transcripts, credentials, machine-specific research paths, or history already recoverable from Git.

This file is Markdown-only.  Do not create a second project-memory location or a LaTeX/PDF derivative.

## Immediate checkpoint

Branch `feature/lossless-passwordsafe-core` completed and independently committed Task 13 of the approved lossless
PasswordSafe core plan at `a91977d`. Task 14 was independently committed at `73431ea`. Its build driver exposes
the five exact Windows x86-64, macOS arm64, Linux x86-64, Android arm64, and iOS arm64 profiles. Desktop profiles install
shared libraries; mobile profiles install static libraries and optionally compile/link a raw Twofish FFI probe. Android
requires the exact NDK API 28 compiler before source acquisition. iOS requires macOS and fixed iPhoneOS `xcrun`
discovery. Dedicated hosted Android and iOS jobs exercise those gates, while the desktop matrix builds and tests with
its resolved host library. Task 15 implementation, release verification, and independent review were committed at
`5e1d5d7`. The safe demonstration, operational guide, root status, contributor validation, legal note, and REUSE
coverage complete the approved lossless PasswordSafe core plan. Hosted results have not yet been observed.

Local `main` now tracks `origin/main` at `https://github.com/caffeineLover/password-bonobo.git`. The remote's unrelated
initial GPLv3 `LICENSE` commit `7cb8203` was fetched and joined to the completed local history by merge commit `11f0ea7`.
The merged result passed 645 tests with 12 expected platform-specific skips and 79% coverage in 107.71 seconds, plus
Ruff, strict mypy, Python structure, Bandit, REUSE, provenance, tracked-file, and whitespace gates. Nothing has been
pushed; local `main` remains ahead of `origin/main`.

The lossless-core implementation range on `feature/lossless-passwordsafe-core` is `a0f9a22..5e1d5d7`.

Checkpoint `669506e` consolidated the retired split identity/state/decisions/verification records into this file and
deleted the obsolete folder.  It also made `docs/superpowers/specs/` Markdown-only, removed its TeX/PDF derivatives,
updated the policy/tool/tests/plans/REUSE metadata, and passed the verification recorded below.

`tools/verify_passwordsafe_interop.py` reads a fabricated passphrase only from standard input, emits ordered redacted
hash evidence, performs bounded exact comparison, and permits only an explicit `record:N:title` delta. Four encrypted
fixture/manifest pairs now exist under `tests/fixtures/synthetic/passwordsafe/`: Bonobo `0x0311`, Password Safe 3.72.1
`0x0311`, Gorilla `6728e85` `0x0300`, and an independent official-format `0x0302` unknown-field fixture. Their exact
encrypted hashes are recorded and gate-checked in the linked manifests and compatibility oracle catalog.

Bonobo opened all three external fixtures; strict no-edit and title-only comparisons passed, including exact unknown
header `0xE0` and record `0xE1` preservation. Password Safe and Gorilla opened the Bonobo fixture. Paired transactions
from each external client's normalized baseline changed only the title outside writer-owned fields. Password Safe
adds/reorders headers and updates Last Save Time. Gorilla writes only `0x0300`, adds empty Preferences, and reorders
standard record fields. The plan was corrected from its false Gorilla `0x0302` assumption; no Bonobo validation was
weakened.

The compatibility gate now requires the exact four paired stems, authorities, format levels, independently pinned
encrypted digests, closed manifest schema, and oracle links using bounded reads. It also pins the complete transaction
record digest, closes its external-artifact schema, and verifies the exact unique client/source/hash relationships. The
verifier hashes the exact authenticated snapshot, eliminating a later path-replacement binding. A real Botan test
authenticates all four checked-in fixtures and regenerates every ordered redacted entry. That test uses the established
`BONOBO_TEST_BOTAN_LIBRARY` contract and fails rather than skips in CI. The desktop workflow now builds the pinned host
Botan library and supplies its resolved output path to the suite.

The provenance gate enforces reviewed producer/version/distribution facts for the eight paired artifacts and the
redacted transaction record. It separately gates exact Password Safe archive, Tclkit executable, and Gorilla checkout
identities, filenames, origins, terms, distribution status, evidence, and review state. Tclkit aggregate terms remain
truthfully `NOASSERTION` with review pending; neither producer binary is distributed.

The independent review reported no Critical issues. Its first pass identified five Important evidence gaps, all fixed
through real-fixture authentication, independent digest pins, authenticated-snapshot hashing, closed schemas, the
redacted transaction record, and this reconciled memory. Its follow-up identified the formerly optional/wrongly named
Botan CI contract and insufficient transaction/producer identity gates; both are now corrected as described above.
The final pass reported no Critical or Important findings; its sole Minor wording correction is incorporated.

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
- Task 13 adds independently produced Bonobo, Password Safe, Gorilla, and specification fixtures; authenticated
  redacted manifests; exact no-edit/title-edit transaction evidence; and gated producer provenance.
- Task 14 adds exact desktop/mobile Botan target profiles, fail-closed cross-toolchain discovery,
  Windows MSVC environment bootstrapping, mobile compile/link probes, and dedicated hosted workflow jobs.
- Task 15 adds a non-overwriting public-service demonstration using only fixed fabricated data, its real-Botan
  subprocess coverage, and exact operating guidance for the delivered core and its security boundaries.

Key checkpoints: continuity `4013f8a`; Task 11 `8c2b30e`; Task 12/workflow `08c2107`; Gorilla derivatives `b77077c`;
legal Markdown-only `2be2512`; specifications Markdown-only `925e8c6`; plans Markdown-only `3df88b4`; single memory
and approved-design Markdown-only `669506e`; Task 13 interoperability `a91977d`; Task 14 platform gates `73431ea`.
Task 15 delivery is `5e1d5d7`.

## Last proven verification

The 2026-09-01 Task 13 baseline on Windows/CPython 3.14.7 collected 609 tests and reported 597 passed, 12
platform-specific skips, and 79% coverage in 105.87 seconds.  The property/resource/large-vault selection passed 16
tests; the fuzz integration pair passed; the deterministic runner processed 10,000 inputs across four corpus seeds.
The large-vault test stayed below `4 * max_inline_payload_bytes + 8 * io_chunk_bytes` and found no fabricated plaintext
marker in private working or recovery artifacts.

At the 2026-09-01 single-memory/approved-design checkpoint, all 26 document-policy tests passed.  Ruff and strict mypy
passed for the two changed Python files; the Python structure checker, provenance, tracked-file policy, and staged and
unstaged whitespace checks passed; REUSE 3.3 classified 103/103 files.  Filesystem inspection found zero TeX/PDF files
in every Markdown-only directory, no split-memory directory, no HANDOFF artifact, and no stale split-memory reference.
Hosted CI has not yet been observed after publication; these are local results.

The final 2026-09-01 Windows/CPython 3.14.7 full suite explicitly used the resolved Botan test library, collected 635
tests, and reported 623 passed, 12 platform-specific skips, 79% coverage, and zero failures in 104.01 seconds. The
focused Botan-build, interop, compatibility, and provenance selection passed 65 tests, including real Botan
authentication, complete ordered-manifest regeneration for all four fixtures, exact transaction/provenance gates, and
the authenticated-snapshot path-replacement test. The compatibility regression selection passed another 20 tests
after two narrowly scoped Bandit `B105` false-positive suppressions for public `password_safe_*` metadata values.

Autopep8 produced no staged-checkpoint drift. Ruff and strict mypy passed 69 source files. The Python structure,
tracked-file, compatibility, provenance, Bandit, and pip-audit gates exited zero; compatibility reports 66 behaviors,
45 features, and 55 oracles. Pip-audit found no known third-party vulnerabilities and skipped only the local unpublished
`password-bonobo` project. REUSE 3.3 classified 114/114 files. The source distribution and wheel built successfully,
and the wheel gate accepted `password_bonobo-0.1.0-py3-none-any.whl`. Whitespace checks are clean.

Task 14's 2026-09-01 Windows checkpoint built the minimized pinned Botan 3.13.0 `ffi,twofish` host shared library from
source using an isolated, discovered x64 MSVC developer environment. The resulting
`build/botan-task14-host/bin/botan-3.dll` reported Botan 3.13.0. With that exact DLL configured, the focused build and
PasswordSafe selection collected 566 tests and reported 554 passed, 12 platform-specific skips, and zero failures in
102.26 seconds. The 35 build-driver tests, Ruff, strict mypy, Python structure checker, parsed workflow schema,
provenance gate, and REUSE 114/114 check all passed. Android/iOS toolchain behavior is unit-tested locally but awaits
hosted execution on the declared runners. Independent review caught and corrected Clang language selection leaking
from the generated C source onto the static archive; the command now enforces `-x c` for the source and resets with
`-x none` before the archive. Red-first regression coverage locks that boundary. Final review reported no Critical or
Important findings; its sole Minor note is that workflow tests use substring assertions, while a separate YAML parse
confirmed the jobs are structurally valid.

Task 15's final 2026-09-01 Windows/CPython 3.14.7 release candidate used the resolved Botan 3.13.0 DLL, collected 657
tests, and reported 645 passed, 12 expected platform-specific skips, 79% coverage, and zero failures in 106.11 seconds.
Three subprocess tests completed a real create/save/reopen/lock cycle and proved preexisting destination and private
workspace paths remain untouched; a fourth test proves hidden terminal input fails closed. Autopep8 introduced no
unstaged drift. Ruff, strict mypy over 71 Python files, Python structure, compatibility,
provenance, tracked-file, Bandit, pip-audit, REUSE 117/117, source-distribution build, wheel build, wheel inspection,
and staged/unstaged whitespace checks all passed. The only pip-audit skip is the unpublished local project.
Independent review reported no Critical or Important findings. Its sole remaining Minor note is that the private-
directory rollback path is implemented but not directly fault-injected by the example tests.

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
- Task 14's mobile gates provide compile/link evidence only. They cannot resolve the pending iOS distribution terms or
  establish execution on physical Android/iOS devices.
- Hosted desktop/mobile Task 14 jobs have not yet been observed after publication.

## Exact continuation order after this checkpoint

1. The next approved subproject is a separate design and plan for the vault application core and
   desktop foundation. Do not start provider coordination, URL-audit behavior, or mobile clients first.
