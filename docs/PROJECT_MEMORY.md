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
its resolved host library. The first hosted run passed Android and exposed the four platform failures summarized below.
Task 15 implementation, release verification, and independent review were committed at
`5e1d5d7`. The safe demonstration, operational guide, root status, contributor validation, legal note, and REUSE
coverage complete the approved lossless PasswordSafe core plan.

Local `main` uses `origin` at `https://github.com/caffeineLover/password-bonobo.git`. The remote's unrelated
initial GPLv3 `LICENSE` commit `7cb8203` was fetched and joined to the completed local history by merge commit `11f0ea7`.
That earlier `963441d` checkpoint passed 645 tests with 12 expected platform-specific skips and 79% coverage in
107.71 seconds, plus Ruff, strict mypy, Python structure, Bandit, REUSE, provenance, tracked-file, and whitespace gates.
The pushed `origin/main` history contains the diagnostic, strict-typing, and Linux Botan-discovery repairs recorded
below.

Hosted run `33549509896` then passed Android arm64 but failed the iOS smoke link, macOS strict mypy, Ubuntu host-library
discovery, and Windows test suite. Diagnostic repair `caec5f5` is integrated and pushed on `main`. Its follow-up hosted
run `33555795740` passed Android and exposed bounded causes for every remaining job: Ubuntu produces versioned and
unversioned `libbotan-3.so` files under `lib/`; iOS omits the C++ runtime while linking the Botan static archive;
macOS reports the expected 23 platform-stub mypy errors; and the hosted Windows environment rejects private artifact
preparation across 157 tests. Commit `403f638` resolves the macOS failure with narrow typed native-module facades while
preserving the runtime modules and flags. It is integrated and pushed on `main` with checkpoint `68c1317`.

Hosted run `33576400850` confirms pushed commit `f32bd0b` fixes Ubuntu's shared-library discovery: the build and all
static checks pass and pytest now runs. Android passes. iOS retains the missing C++ runtime link failure. The desktop
pytest results expose three bounded platform issues: Ubuntu reports 2 failures after 645 passes and 19 skips; macOS
reports 153 failures after 496 passes and 17 skips; Windows reports 157 failures after 500 passes and 9 skips.

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

The 2026-09-01 native-diagnostics repair added four red-first boundary regressions and passed all 39 build-driver tests.
The full Windows/CPython 3.14.7 suite used the previously verified Botan 3.13 DLL and reported 649 passed, 12 expected
platform-specific skips, 79% coverage, and zero failures in 110.35 seconds. Autopep8, Ruff, strict mypy over 71 files,
Python structure, compatibility, provenance, tracked-file, Bandit, pip-audit, REUSE 118/118, source-distribution build,
wheel build, wheel inspection, and whitespace checks all exited zero. The diagnostic commit is integrated and pushed
as `caec5f5`; follow-up hosted run `33555795740` completed with Android passing and the four remaining bounded failures
recorded above. Independent review first identified missing cross-toolchain path redaction, an overly broad
artifact-name filter, retained tab controls, and over-redaction of relative `make` text; red-first tests and
implementation corrections closed all four. Follow-up review reported no Critical, Important, or Minor findings.

The 2026-09-01 cross-platform strict-typing repair reproduced all 23 macOS errors and now passes strict mypy over all
70 files under explicit Darwin, Windows, and Linux profiles. A red Windows DACL regression exposed an accidental
`O_BINARY` lookup on `msvcrt`; retaining that flag on the typed `os` facade restored runtime behavior. The focused
snapshot, storage, and Botan-build selection passed 92 tests with 7 expected skips. The full Windows/CPython 3.14.7
suite used the verified Botan DLL and reported 649 passed, 12 expected skips, 79% coverage, and zero failures in
107.13 seconds. Autopep8 produced no residual drift; Ruff, Python structure, Bandit, REUSE 119/119, whitespace, and all
three mypy profiles passed. Independent review identified and resolved one Important loss of `WinDLL` constructor
checking plus one Minor stale-memory wording issue. Follow-up review found no remaining Critical or Important issue.
Commit `403f638` was then fast-forwarded into local `main`; the merged result repeated the full suite with 649 passed,
12 expected skips, 79% coverage, and zero failures in 108.08 seconds. The completed worktree and local feature branch
were removed after that green run.

The 2026-09-01 Linux Botan-discovery repair added a red regression for the exact `libbotan-3.so`,
`libbotan-3.so.13`, and `libbotan-3.so.13.13.0` hosted artifact set. The minimal selection rule prefers the one canonical
linker filename only when every other candidate is a same-directory numeric soname companion. The versioned-only
single-candidate fallback and genuine ambiguity rejection remain covered. All 44 build-driver tests pass. The full
Windows/CPython 3.14.7 suite reports 654 passed, 12 expected skips, 79% coverage, and zero failures in 108.88 seconds.
Autopep8, Ruff, Python structure, Bandit, REUSE 119/119, whitespace, and strict mypy under Darwin, Windows, and Linux
profiles pass. Independent review identified and closed an Important fail-open case for malformed or cross-platform
leftovers plus its Minor missing fallback coverage. Follow-up review found no remaining Critical or Important issue.
Commit `f32bd0b` was fast-forwarded into local `main` after a fresh pre-merge run reported 654 passed, 12 expected
skips, 79% coverage, and zero failures in 109.87 seconds. The merged `main` tree repeated that result in 108.46 seconds.
The clean worktree and merged `fix/linux-botan-discovery` branch were then removed.

Hosted run `33576400850` then proved the discovery repair and bounded the next desktop work. macOS rejects inherited
extended ACLs present below the hosted temporary directory; its two real native ACL probes fail before private artifact
creation. Windows rejects the fresh `0o700` directory because the elevated runner can make `BUILTIN\\Administrators`
the owner even though CPython's protected DACL contains only owner rights, SYSTEM, and Administrators. Ubuntu's first
failure expects `StorageError` where a successful directory retarget correctly raises `ExternalModificationError`.
Its second failure exposes an inode-reuse ABA: cleanup can unlink a replacement candidate when the original inode was
released and immediately reused. The approved bounded repair is implemented in worktree branch
`fix/desktop-private-artifacts` and awaits final review, integration, publication, and hosted proof.

The desktop repair retains an open candidate identity through authentication and failure cleanup, accepts the
administrator owner only while preserving the protected Windows DACL and exact ACE allowlist, corrects the successful
POSIX retarget regression to require `ExternalModificationError`, and gives only the macOS pytest process a newly
created ACL-free temporary root. Production macOS ACL rejection is unchanged. A red Windows native regression proved
the ownership boundary before implementation. The focused five-test selection passed four tests with one expected
Windows rename skip. Review then identified and closed one Important `BaseException` descriptor-leak path during guard
validation or candidate removal; two red-first interruption regressions cover both boundaries, and follow-up review
found no remaining Critical or Important code issue. The current-head full Windows/CPython 3.14.7 suite reports 657
passed, 12 expected skips, 79% coverage, and zero failures in 108.71 seconds. Autopep8, Ruff, Python structure, YAML
parsing, compatibility, provenance, tracked-file,
Bandit, pip-audit, REUSE 119/119, source/wheel build, wheel inspection, whitespace, and strict mypy under Darwin,
Windows, and Linux profiles all pass.

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
- Hosted run `33576400850` passes Android and proves Ubuntu discovery fixed. Its bounded desktop failures have a locally
  verified repair awaiting publication and hosted proof. iOS still lacks C++ runtime symbols during its static archive
  link.

## Exact continuation order after this checkpoint

1. Review and commit `fix/desktop-private-artifacts`, fast-forward it into `main`, push, and verify all three hosted
   desktop jobs; fix any bounded regression before proceeding.
2. Repair and verify the iOS C++ runtime link, then push and observe the hosted cross-build.
3. After all five hosted jobs pass, begin a separate design and plan for the vault application core and desktop
   foundation. Do not start provider coordination, URL-audit behavior, or mobile clients first.
