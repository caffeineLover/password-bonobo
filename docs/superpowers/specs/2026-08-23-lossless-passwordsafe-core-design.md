# Lossless PasswordSafe Core Design Specification

Date: 2026-08-23

Status: Draft assembled from approved design sections; pending committed-spec review

Target: Password Bonobo lossless PasswordSafe V3 core

## 1. Purpose

This subproject implements the first security-sensitive product capability in Password Bonobo: a fully typed Python
core that can create, authenticate, read, edit, validate, and transactionally save PasswordSafe V3 vaults without
losing credentials or user-authored metadata.

The core is a clean-room implementation.  The official PasswordSafe V3 format specification, the approved Password
Bonobo designs, the neutral compatibility dossier, and independently produced synthetic observations are its
authorities.  Password Gorilla source code, comments, identifiers, tests, and fixtures do not enter product code,
tests, documentation, or build inputs.

Losslessness is a mandatory product invariant.  Derived audit results are replaceable cache, but credentials,
user-authored metadata, unknown fields, field order where compatibility requires it, and declared format level are not.

## 2. Scope

The core provides typed APIs for:

- creating PasswordSafe V3 vaults;
- authenticating and opening supported vaults;
- reading and editing credentials, URLs, metadata, and official custom fields;
- adding, removing, protecting, unprotecting, and reordering records;
- changing a master passphrase and exporting an independent vault;
- saving through a validated local-file transaction;
- retaining and explicitly restoring one encrypted recovery revision; and
- locking and disposing of an authenticated session.

This subproject does not implement:

- desktop or mobile user interfaces;
- URL auditing or archive-first audit cleanup;
- Android Autofill, iOS credential-provider integration, or biometric unlock;
- cloud accounts, cloud APIs, or provider-specific synchronization;
- provider conflict resolution or database merge behavior; or
- typed attachment or passkey editing.

Those capabilities consume this core in later subprojects.  No application or adapter may bypass its validation and
publication contracts.

## 3. Governing Invariants

The implementation must maintain all of the following invariants:

1. Authentication, integrity, parsing, validation, and publication failures leave the source vault unchanged.
2. An editable session exists only after the complete stored HMAC and mandatory document structure are valid.
3. Ordinary saves preserve the existing declared V3 format level.
4. Unknown field type identifiers, plaintext payloads, positions, multiplicity, and record association survive
   unchanged.
5. Editing one known value changes only the targeted field and required writer-owned cryptographic material.
6. No plaintext vault, attachment, recovery file, or temporary file is written to storage.
7. No master passphrase, credential, URL, UUID, vault path, or record identity enters logs or unsafe exceptions.
8. No implicit save occurs during finalization, locking, shutdown, or exception handling.
9. A protected record cannot be edited or deleted until a distinct explicit unprotect mutation succeeds.
10. Botan 3.13 or newer is the only production Twofish implementation.

## 4. Format Compatibility Policy

### 4.1 Supported levels

Bonobo creates new vaults at PasswordSafe V3 level `0x0311`.  It opens and edits declared levels `0x0300` through
`0x0311`, subject to authentication and structural validation.

An ordinary save retains the opened vault's declared level.  Bonobo does not add fields whose introduction level is
newer than that declaration.  A format upgrade is a separate explicit operation and must be lossless.

An authenticated envelope declaring an unknown future V3 level or V4 does not produce an editable session.  Bonobo
reports an unsupported format and retains the original encrypted source.  This avoids assigning present-day semantics
to future mandatory content.

### 4.2 Legacy export

Legacy export is explicit.  Before writing an older profile, the core proves that every field and semantic value is
representable by the target level.  If attachments, passkeys, custom fields, or any other content would be dropped or
rewritten incompatibly, export fails with a typed compatibility error.  There is no lossy fallback.

### 4.3 Field coverage

The first release provides typed views and edits for nonattachment V3 credential data, including:

- UUID, group, title, username, notes, password, URL, email, and AutoType text;
- creation, modification, access, and expiration data;
- password history and password-policy fields;
- run command, click actions, protection, own symbols, policy names, and keyboard shortcut metadata;
- TOTP and other two-factor data;
- credit-card and QR-related data;
- recognized alias and shortcut encodings; and
- official `0x0311` custom text fields and their sensitivity flags.

Header fields receive typed representations appropriate to their specified UUID, text, time, integer, or binary
encoding.  Structured preference and filter text remains losslessly backed by its original field even when only part of
its internal grammar is understood.

Attachment fields `0x25` through `0x29` and passkey fields `0x2A` through `0x2F` are recognized but opaque in the first
release.  Callers may inspect safe presence, size, and type metadata, but cannot read or edit their secret payloads
through ordinary APIs.  They survive saves unchanged.

Unknown, reserved, and application-specific fields are preservable content rather than errors.  No Bonobo-private
PasswordSafe field is introduced.

### 4.4 Meaning of lossless

PasswordSafe encryption is randomized.  A save may change the IV, content key, HMAC key, padding, HMAC, and ciphertext.
Lossless therefore refers to the authenticated plaintext document and its intentional semantic revision, not equality
of encrypted file bytes or random padding.

An ordinary save retains the existing salt and stretching parameters unless the iteration count is below the approved
minimum.  This follows the format's creation-time salt model and lets the session save without retaining the master
passphrase.  A new vault, master-passphrase change, or independent export generates a new salt.

## 5. Component Architecture

The core separates format logic, session behavior, cryptography, and storage publication.  A native client calls the
typed service API; that service coordinates the session and document model, the codec and Botan adapter, and the
transaction coordinator and storage adapter.

The typed Python core owns the document model, parsing state machine, schema validation, semantic edits, authenticated
serialization, failure taxonomy, and transaction orchestration.  A narrow adapter owns calls to Botan's native ABI.
Storage adapters publish only fully validated encrypted candidates.

The public core is synchronous.  Desktop and mobile clients execute it on an appropriate worker or coroutine boundary.
The core imports no UI, network, provider, Android, or Apple framework.

## 6. Lossless Document Model

### 6.1 Ordered raw representation

The parser constructs an ordered document rather than collapsing fields into a dictionary:

```text
VaultDocument
|-- ordered header fields
`-- ordered records
    `-- ordered fields
```

Every field retains:

- its one-byte type identifier;
- its exact plaintext payload;
- its position and multiplicity;
- its header or record association;
- its understood, unknown, or understood-but-malformed classification; and
- its original representation until an explicit edit replaces that field instance.

Typed values are projections over the raw representation.  Merely reading a UUID, timestamp, or UTF-8 value does not
normalize or replace its source field.  A targeted edit creates a replacement for that field instance and leaves all
other instances untouched.

### 6.2 Validation classifications

Mandatory structure is strict.  Invalid or ambiguous Version, header END, record END, UUID, Title, or Password content
prevents an editable session.  A missing mandatory field is never synthesized.

Malformed optional content is retained and reported through structured preservation warnings when doing so is safe.
An edit cannot accidentally select among duplicate fields.  It must name a unique field instance or fail as ambiguous.
Per-field conformance rules define which multiplicities are valid, preservable, or fatal.

### 6.3 Record identity and revisions

User record UUIDs are data, not safe in-session object identifiers.  Duplicate UUIDs can occur during compatibility and
merge workflows.  Each opened record therefore receives an opaque, session-scoped `RecordHandle` independent of its
UUID.

Documents use copy-on-write revisions.  Every accepted add, patch, move, protection change, or removal creates an
explicit change set and revision token.  Dirty state is derived from that change set.  A mutation based on a stale token
fails instead of being redirected to a newer or different record.

## 7. Bounded-Memory and Secret Handling

Opening creates or retains an immutable encrypted snapshot.  Authentication, HMAC calculation, field indexing, and
validation stream through that snapshot.  The parser never relies on a source pathname that another process may change
during the operation.

Small fields use controlled in-memory payload objects.  Large binary, unknown, attachment, and other opaque fields may
use encrypted snapshot spans.  During save, the writer streams those spans through decryption and re-encryption without
creating a plaintext spool file or materializing an entire attachment in memory.

Resource budgets bound:

- outer file and field counts;
- iteration work accepted before explicit caller confirmation;
- individual in-memory payloads;
- aggregate decoded text and metadata;
- custom-field properties; and
- parser bookkeeping.

A legal large attachment remains preservable even when it exceeds available RAM.  A document exceeding a safety budget
fails closed and leaves its encrypted snapshot intact; callers may deliberately supply a stricter policy but cannot
disable structural security invariants.

Passwords, two-factor secrets, sensitive custom values, and potentially sensitive unknown payloads use owned mutable
buffers where Python permits.  They are wiped on replacement, lock, and disposal.  Decoded immutable Python strings are
created only for explicit API operations and are kept short-lived.  Documentation states plainly that CPython cannot
guarantee complete physical memory zeroization.

## 8. Authentication and Cryptography

### 8.1 Production backend

Botan 3.13 or newer is the sole production Twofish backend.  The adapter exposes fixed PasswordSafe operations rather
than user-controlled algorithm names.  It verifies the native ABI and version, then runs Twofish known-answer self-tests
before any vault operation.

Python's reviewed standard cryptographic facilities provide SHA-256, HMAC-SHA-256, constant-time comparison, and
operating-system randomness where their contracts are sufficient.  The core does not invent a primitive or silently
fall back to a test cipher.

### 8.2 Unlock sequence

Unlock performs these stages in order:

1. Validate the fixed envelope size, tag, iteration encoding, and resource bounds.
2. Accept the master passphrase as a mutable UTF-8 byte buffer without Unicode normalization.
3. Derive `P'` from the passphrase, stored salt, and iteration count according to the PasswordSafe specification.
4. Compare the stored `SHA-256(P')` value in constant time.
5. Use Botan Twofish ECB operations to unwrap independent content and HMAC keys.
6. Stream-decrypt fields in CBC order into a quarantined document builder while calculating the specified HMAC.
7. Compare the stored and calculated HMAC values in constant time.
8. Validate declared version, mandatory fields, representations, multiplicity, EOF position, and budgets.
9. Expose an authenticated session only after every stage succeeds.

The raw passphrase buffer is wiped immediately after derivation.  Wrong input and a corrupted password check share a
safe authentication failure category.  HMAC mismatch, truncation, invalid field structure, and unsupported mandatory
content produce no partial or warning-open session.

### 8.3 Session key material

An unlocked session retains only the derived and vault-key material required to decrypt fields and save the current
vault.  It does not retain the raw master passphrase.  All retained key buffers are wiped on lock.

When opening a vault below the approved iteration minimum, the unlock operation derives upgraded wrapping material
while the passphrase is transient.  The first successful save can then harden the iteration count without retaining or
requesting the passphrase again.

### 8.4 Authenticated serialization

Before writing, the codec validates the proposed document against its retained format level.  It then:

- retains the existing salt and approved stretching material for an ordinary save;
- generates fresh independent content and HMAC keys;
- generates a fresh IV and random field padding;
- wraps the new keys with retained `P'`;
- streams ordered plaintext fields into fresh CBC ciphertext;
- calculates the specified HMAC over the plaintext field data; and
- writes the unencrypted EOF marker followed by the stored HMAC.

An IV is never reused with changed plaintext.  Creation, passphrase change, and independent export generate a new salt
and require explicit passphrase input.

## 9. Public API

### 9.1 Primary types

The public package exposes these conceptual types:

- `VaultService` creates, opens, restores, and independently exports vaults.
- `VaultSession` owns authenticated key material, the current document revision, dirty state, and storage baseline.
- `RecordView` presents immutable nonsecret information tied to a revision.
- `RecordPatch` lists explicit intended field changes.
- `RecordHandle` identifies one record within one session even when UUIDs repeat.
- `SecretLease` provides short-lived context-managed secret access.
- `SaveResult` reports the committed identity, iteration hardening, recovery state, and preservation warnings.

The exact module layout remains an implementation-plan concern, but the public surface remains smaller than the
internal parser and field schema.

### 9.2 Mutation behavior

Callers cannot mutate raw dictionaries or internal lists.  Adding, editing, deleting, moving, and changing protection
are explicit operations validated against a revision token.

A protected record rejects ordinary edits and deletion.  Unprotecting is a separate operation; the core never silently
removes protection to satisfy another request.

Locking a dirty session fails with `UnsavedChanges` unless the caller explicitly saves or discards.  Finalizers and
process shutdown never attempt an implicit save.

Secret values do not appear in `RecordView`, object representations, equality diagnostics, or ordinary iteration.
Explicit reveal, copy, edit, Autofill, and future credential-provider operations use bounded `SecretLease` instances.

## 10. Transactional Storage

### 10.1 Preparation and publication boundary

The transaction coordinator separates candidate preparation from publication.  The codec creates a complete encrypted
candidate and authenticates it before any adapter may replace a destination.  This boundary supports direct local files
now and provider compare-and-swap semantics later.

### 10.2 Local open

The local adapter captures an immutable encrypted snapshot and records a strong content hash plus available file
identity and metadata.  Working snapshots live in a caller-supplied private application directory, never beside a
synchronized vault.  Normal lock removes obsolete snapshots; crash leftovers remain encrypted.

### 10.3 Local save sequence

The local adapter performs the following sequence:

1. Create a random temporary file exclusively in the destination directory.
2. Apply restrictive permissions without following symlinks.
3. Stream the complete encrypted candidate, then flush and synchronize it.
4. Reopen, authenticate, parse, and validate the candidate.
5. Compare its complete ordered document with the intended revision, using streaming exact comparisons for unchanged
   large fields.
6. Acquire the strongest available platform file lock.
7. Recheck the destination identity and hash against the opening baseline.
8. Abort with `ExternalModification` if the destination changed.
9. Preserve the prior validated encrypted snapshot as the recovery revision.
10. Atomically replace the destination.
11. Synchronize the containing directory where supported.
12. Verify that the published pathname contains the validated candidate.
13. Advance the session baseline and clear its change set only after publication succeeds.

Temporary candidates are removed after handled failures.  A filesystem without the required atomic replacement
guarantees is unsupported for direct publication, though a separately named validated export remains possible.

### 10.4 Recovery

The first core retains one previous known-good encrypted revision per vault in private application storage.  Recovery
identifiers reveal no vault filename, record data, or path.  Recovery is never silently substituted for a damaged
primary.  The caller must explicitly authorize restoration, and restoration uses the same authenticate,
validate-before-publish, baseline-check, and atomic-replacement sequence.

No local advisory-lock design can defeat every uncooperative process on every filesystem.  The adapter serializes
Bonobo saves and performs the latest practical identity and content check.  Provider revisions, coordinated documents,
and remote conflict resolution remain responsibilities of the provider-safe files subproject.

## 11. Failure Model

The core exposes typed categories rather than platform exception text:

- authentication failure;
- integrity failure;
- malformed content;
- unsupported format or incompatible export target;
- resource limit;
- unavailable or invalid cryptographic backend;
- protected record;
- stale revision;
- unsaved changes;
- external modification;
- storage or publication failure; and
- available encrypted recovery.

Exceptions contain safe stage and remediation metadata only.  They do not contain paths, passphrases, field contents,
record identities, UUIDs, or decrypted fragments.  The caller owns localized user wording.

Logging is optional and injected through the project logging abstraction.  The reusable core configures no handlers.
Messages use the repository's approved levels and contain no security-sensitive data.

## 12. Verification Strategy

Implementation follows test-driven development.  Security-sensitive behavior is not complete when only happy-path
round trips work.

### 12.1 Cryptographic and format tests

Automated tests cover:

- official Twofish known-answer vectors;
- synthetic key-stretching, key-wrapping, CBC, field-block, and HMAC vectors;
- golden fabricated vaults for declared levels `0x0300` through `0x0311`;
- new `0x0311` creation and older-level preservation;
- no-edit and single-known-field-edit semantic round trips;
- weak-iteration hardening without a format-level change;
- wrong passphrase, corrupted password check, HMAC mismatch, truncation, malformed EOF, and trailing content;
- invalid lengths, UTF-8, UUIDs, timestamps, custom properties, and mandatory fields;
- unknown header and record fields, duplicate fields, unusual ordering, aliases, and shortcuts; and
- exact survival of attachments, passkeys, and large unknown fields.

### 12.2 Generative and adversarial tests

Property-based tests generate ordered field sequences, supported documents, targeted mutations, and malformed envelopes.
A parser fuzz target uses a committed nonsensitive seed corpus.  Resource-exhaustion tests exercise excessive iteration
counts, field lengths, record counts, and decoded data without allocating attacker-declared sizes first.

Failure injection covers every candidate-write, flush, validation, baseline-check, recovery, replace, directory-sync,
and cleanup boundary.  Concurrency tests cover stale revisions, protected records, process-local save serialization, and
external changes.

Large-vault tests demonstrate that memory use is bounded independently of opaque attachment size.

### 12.3 Independent interoperability

Cross-client qualification uses only fabricated credentials:

- Bonobo-created vaults open and save in a current Password Safe release and the pinned Gorilla baseline.
- Independently created Password Safe and Gorilla vaults open and save in Bonobo.
- Ordered semantic manifests compare version, UUIDs, every standard field, every unknown type and payload, record order,
  and intended edits.
- Any cross-client normalization is recorded as an external-client observation and never weakens Bonobo's own no-loss
  oracle.

Synthetic encrypted fixtures may be committed only through an explicit test-fixture allowlist and provenance record.
Real vaults and credentials remain prohibited.

### 12.4 Repository gates

Completion requires:

- strict mypy and the repository Python structure checker;
- Ruff formatting and linting;
- unit, property, fuzz-corpus, preservation, transaction, and package tests;
- Bandit, dependency audit, provenance, tracked-file, REUSE, and build checks;
- all existing compatibility and documentation gates;
- Windows, macOS, and Linux CI; and
- Android and iOS Botan cross-build checks even though mobile UI adapters arrive later.

Critical cryptographic, preservation, or transactional tests may not be skipped in a release qualification run.

## 13. Botan Supply Chain and Licensing

Botan begins pinned to an eligible `3.13.x` release with exact source and built-artifact hashes.  Reproducible tooling
builds only required modules and never downloads a native library at application runtime.  Desktop and mobile release
artifacts bundle platform-appropriate signed binaries.

The build verifies the Botan ABI, compiled version, and self-tests.  Security advisories and upgrades are release-blocking
review inputs.  A test backend may implement the internal crypto protocol for isolated state-machine tests, but no test,
legacy, RustCrypto, or home-grown Twofish backend is accepted in production.

Bonobo remains GPL-3.0-or-later.  Botan's BSD-2-Clause license is compatible and its required copyright and license
notices ship with every applicable distribution.

## 14. Documentation and Operations

The subproject updates:

- package and API documentation;
- a safe synthetic example showing how to create, open, edit, save, and lock a vault;
- developer instructions for obtaining or building the pinned Botan dependency;
- an operator-facing explanation of how to run the implemented core;
- the dependency and asset provenance ledger;
- compatibility matrices and test-oracle evidence where implementation closes an existing item; and
- durable project state, decisions, and verification memory.

Substantial documentation has canonical Markdown and same-basename generated LaTeX.  Review PDFs remain ignored and are
rendered for visual inspection before completion.

## 15. Acceptance Criteria

The Lossless PasswordSafe core is complete only when all of the following are true:

1. It creates an authenticated `0x0311` vault that current Password Safe can open.
2. It opens supported fabricated Gorilla and Password Safe V3 vaults.
3. A no-edit save preserves the complete ordered semantic manifest.
4. A targeted edit changes only the requested field and writer-owned cryptographic material.
5. Unknown, optional malformed-but-preservable, attachment, passkey, and custom-property data survives unchanged.
6. HMAC mismatch, malformed mandatory content, and unsupported versions fail closed without output.
7. Every injected prepublication failure leaves the source authoritative and recoverable.
8. A changed destination is not silently overwritten.
9. The raw master passphrase is absent after unlock derivation and all owned mutable secret buffers are wiped on lock.
10. Large opaque fields round-trip with bounded memory and no plaintext temporary file.
11. The approved automated, cross-client, three-desktop-platform, and mobile cross-build gates pass.
12. Documentation, provenance, licensing, and project memory accurately describe the delivered behavior and remaining
    limitations.

## 16. Principal Risks

- PasswordSafe compatibility depends on exact historical representation details.  Golden and cross-client fixtures must
  resolve ambiguity rather than speculative normalization.
- CPython cannot promise complete secret zeroization.  The design minimizes copies, scopes leases, wipes mutable
  buffers, and documents the residual limitation.
- Botan mobile packaging is a distinct engineering risk even though Botan supports Android and iOS.  Cross-build gates
  begin in this subproject so the risk is not deferred until UI work.
- Local filesystems do not provide one universal conditional atomic-replace primitive.  The local adapter reports its
  guarantees honestly, while provider coordination remains a later layer.
- Large opaque-field streaming complicates validation and recovery.  Exact streaming comparisons and fault injection
  are mandatory, not optional performance work.

## 17. References

- [Password Bonobo Python Reimplementation](../../specs/password-bonobo-python-reimplementation-design.md)
- [Password Bonobo Project Memory](../../PROJECT_MEMORY.md)
- [Password Gorilla compatibility test oracles](../../compatibility/gorilla/test-oracles.md)
- [PasswordSafe V3 format specification](https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt)
- [Password Safe release news](https://pwsafe.org/news.shtml)
- [Botan supported platforms](https://botan.randombit.net/handbook/support.html)
- [Botan block-cipher API](https://botan.randombit.net/handbook/api_ref/block_cipher.html)
- [Botan threat model](https://botan.randombit.net/handbook/threat_model.html)
- [Botan security advisories](https://botan.randombit.net/handbook/security.html)
