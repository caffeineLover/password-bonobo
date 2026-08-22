# Password Bonobo Python Reimplementation - Design Specification

Date: 2026-08-22

Status: Approved design, pending implementation planning

Supersedes: The native Tcl implementation target in
[Password Bonobo URL Audit and Cleanup](./password-bonobo-url-audit-design.md).  The approved URL-audit behavior and
safety requirements remain authoritative except where this specification replaces the platform architecture.

## 1. Purpose

Password Bonobo will be a modern, cross-platform password manager with full meaningful Password Gorilla feature
compatibility and a defining URL-audit and credential-cleanup workflow.

The application will be implemented around a fully typed Python core with platform-appropriate clients.
It will preserve PasswordSafe V3 interoperability, remain local-file-first, and avoid a Bonobo-hosted cloud service.

The project will be an original, idiomatic implementation rather than a function-by-function Tcl translation.

## 2. Approved Product Decisions

- Preserve meaningful Password Gorilla features and database behavior without reproducing its visual layout.
- Modernize the user experience on every platform.
- Support Windows, macOS, Linux, and Android as tier-one platforms.
- Support ChromeOS primarily through the Android application, with the Linux application as an optional fallback.
- Treat iOS as an explicit supported target delivered after the secure core and Android path are proven.
- Keep BSD-family portability in the core, with official support dependent on packaging, continuous integration, and
  real-system testing.
- Use a fully typed, UI-independent Python core.
- Permit narrowly scoped Kotlin and Swift code for native user interfaces and operating-system integrations.
- Keep vault storage local-file-first and use operating-system document providers for user-selected synchronization
  locations.
- Operate no Bonobo account system, cloud vault, or synchronization service.
- Make loss of credentials or user-authored metadata unacceptable.
- Treat derived audit results as replaceable state.
- Use GPL-3.0-or-later as the intended project license, subject to dependency and distribution review.

## 3. Licensing and Source Provenance

Password Gorilla declares GPL-2.0-or-later licensing.  Bonobo may study a pinned Gorilla revision for compatibility
research, but no Gorilla implementation will enter a Bonobo product build.

The compatibility workflow will use these boundaries:

1. Preserve the selected upstream Gorilla revision as an untouched, read-only research reference outside the Bonobo
   implementation tree.
2. Record observable features, workflows, edge cases, and compatibility expectations in neutral prose and test cases.
3. Implement Bonobo from the approved specifications, official PasswordSafe format documentation, neutral compatibility
   dossier, and independently designed architecture.
4. Do not copy Gorilla source, comments, identifiers, file organization, control flow, UI assets, translations, or other
   copyrightable expression.
5. Maintain provenance records for imported fixtures, algorithms, dependencies, and third-party assets.

Bonobo-authored code intended for iOS distribution will include a narrowly drafted App Store distribution exception.
Any code not covered by that permission will be excluded from the iOS build.  The final exception, dependency set, and
current Apple terms require review before an iOS release.

Future contributions must be accepted under terms that preserve the project's GPL license and any published distribution
exception.  The repository will document those terms before accepting external contributions.

## 4. Compatibility Contract

Bonobo will treat a PasswordSafe V3 file as a lossless document rather than a simplified collection of known values.

For each header and record, the core will retain:

- Parsed standard fields.
- Stable database and record UUIDs.
- Field ordering and representation where compatibility requires preservation.
- Every unknown field's type identifier and original plaintext field bytes.
- The distinction between standard data, user-authored metadata, and derived application state.

Editing a known value will change only the intended semantic field.  Re-encryption will naturally change ciphertext, but
unknown field type and data bytes must survive the read-write cycle unchanged.

Bonobo will read supported older PasswordSafe V3 files without requiring a format migration.
It will not silently raise a file's declared format level merely because Bonobo opened or saved it.

New user-authored metadata may use standardized custom fields with a Bonobo namespace only after actual Gorilla and
Password Safe round-trip tests prove that the claimed client versions preserve those fields.  When a feature cannot meet
that requirement, Bonobo will store it in an optional separately encrypted metadata document or disable it in strict
interoperability mode.  Important user data will never be placed where a supported client can silently erase it.

Derived URL-audit state will remain in memory for the initial release.  Persistent audit history is not required by this
design.

## 5. System Architecture

### 5.1 Python core

The bonobo_core package will own:

- PasswordSafe V3 parsing, serialization, authentication, and validation.
- Vault sessions, records, groups, policies, history, aliases, shortcuts, and protected entries.
- Unknown-field preservation and extension policy.
- Application use cases and transactional operations.
- URL collection, sanitization, scan orchestration, classification, and cleanup rules.
- Archive creation and validation.
- Provider-independent conflict detection and merge models.
- Typed failure categories and safe diagnostic metadata.

The core will not import desktop, Android, iOS, or cloud-provider user-interface code.

### 5.2 Platform clients

- Desktop will use PySide6 and Qt Quick on Windows, macOS, and Linux.
- Android and ChromeOS will use Kotlin and Jetpack Compose.
- iOS will use Swift and SwiftUI.

Android and iOS will embed CPython and call a narrow in-process application facade.
The facade will expose task-oriented operations and typed data-transfer objects.
Secret values will cross the boundary only for explicit reveal, copy, edit, Autofill, AutoType, or credential-provider
actions.

### 5.3 Platform services

The core will define protocols for:

- Document selection, coordinated access, and provider publication.
- Device-bound secure key storage and biometric authorization.
- Clipboard handling and automatic clearing.
- Browser launching.
- HTTP transport.
- Application lifecycle and idle locking.
- File logging.
- Accessibility-relevant notifications where needed.

Each native client will provide implementations without duplicating domain rules.

### 5.4 Compatibility assets

The compatibility area will contain:

- The neutral Gorilla behavior dossier.
- A feature-parity matrix.
- Synthetic PasswordSafe fixtures.
- Cross-client round-trip expectations.
- Reproducible compatibility test instructions.

No production or test fixture may contain real credentials or personal vault data.

## 6. Document Lifecycle

### 6.1 Opening

1. The native client asks the operating system to select a PasswordSafe document.
2. The provider adapter obtains a complete encrypted snapshot and any available provider revision metadata.
3. Bonobo calculates a SHA-256 fingerprint of the encrypted bytes.
4. Mobile clients place the encrypted snapshot in an app-private working location for offline access.
5. The core authenticates the master password, validates the file, and opens an in-memory session.
6. The client receives non-secret summaries until the user explicitly requests a sensitive operation.

### 6.2 Ordinary edits

1. The user confirms a complete edit form.
2. The core validates the proposed record and updates the in-memory model.
3. Bonobo transactionally writes and validates the encrypted working copy.
4. The provider adapter verifies that the external revision still matches the opening baseline.
5. An unchanged external document may receive the validated new version.
6. An unavailable provider produces Sync pending without losing the encrypted local edit.
7. A changed provider document produces Conflict and is never overwritten automatically.

### 6.3 URL-audit cleanup

Audit deletions remain a staged transaction even though ordinary edits commit when their edit form is confirmed.
Affected rows remain visibly marked Deleted (unsaved) or Archived & deleted (unsaved) until the user explicitly saves.

Closing a session with staged cleanup requires the user to save or discard that cleanup.  Discarding staged cleanup does
not roll back unrelated ordinary edits already committed by the user.

### 6.4 Lock and close

Locking, closing, replacing a vault, or losing authentication will:

- Cancel outstanding URL-audit requests.
- Close or clear sensitive views.
- Clear plaintext and key material as far as the runtime permits.
- Retain only encrypted files and bounded non-sensitive state.

## 7. Provider-Neutral File Synchronization

Bonobo will not implement provider-specific Google Drive, Dropbox, OneDrive, or iCloud accounts.
Users will choose files through native document-provider interfaces or synchronized desktop folders.

For each open document, Bonobo will remember outside the PasswordSafe file:

- The standard database UUID.
- The SHA-256 fingerprint of the encrypted opening snapshot.
- Provider revision, generation, or ETag information when available.
- File size and modification time as secondary signals.

Bonobo will not add a custom PasswordSafe field solely for synchronization numbering.
A custom counter cannot prevent two offline writers from selecting the same next value and may be discarded by another
client.

Before publication, Bonobo will compare the provider document with the recorded baseline.  If it changed, Bonobo will
preserve both valid versions and offer explicit reload, save-as-copy, or UUID-based conflict resolution.

Provider rules include:

- Never rely on a file lock to coordinate different devices.
- Never truncate a provider document in place.
- Validate a complete new vault before provider replacement or upload.
- Use native coordinated-access facilities when the platform provides them.
- Keep bounded, encrypted recovery revisions.
- Display Local changes, Sync pending, Conflict, and Provider unavailable honestly.
- Never silently select a winner based only on timestamps.
- Never place derived audit cache or diagnostic logs beside the synchronized vault.

Providers can observe filenames, sizes, and modification times.
Product documentation will explain that metadata leakage even though PasswordSafe encrypts vault contents.

## 8. URL Audit and Cleanup

The behavior, classifications, review workflow, archive-first deletion transaction, and privacy requirements in the
existing URL-audit specification remain in force.

The Python architecture divides responsibility as follows:

- The core sanitizes URLs, strips query strings and fragments, detects hygiene issues, schedules bounded work, evaluates
  redirects, performs root fallback decisions, detects parking indicators, and classifies observations.
- Desktop uses an asynchronous Python HTTP transport.
- Android uses the native Android HTTP and TLS stack through Kotlin.
- iOS uses URLSession through Swift.

Every transport will return the same normalized observation model, including status, redirect chain, bounded response
prefix, and categorized DNS, connection, timeout, or TLS failure.

Only the sanitized audit URL may cross the transport boundary.  Credentials, record identifiers, group names, titles,
database identity, query values, fragments, and other sensitive record data must not enter requests or HTTP headers.

Results appear incrementally.  Cancellation stops new work and cancels outstanding requests where practical.  Locking or
replacing the vault cancels the scan and destroys sensitive result state.

The original stored URL remains separate from the audit URL and is used only for an explicit browser-opening action.
Archive and deletion actions call core transactions; user-interface code cannot directly delete records or construct
archive files.

## 9. Security Model

The threat model includes:

- A stolen locked device.
- An untrusted file-hosting provider.
- Malicious or compromised websites.
- Stale synchronized files and concurrent writers.
- Sensitive clipboard contents.
- Diagnostic leakage.
- Accidental destructive actions.

Bonobo will:

- Use reviewed cryptographic implementations and documented PasswordSafe algorithms.
- Never invent encryption primitives.
- Never store the master password in plaintext.
- Keep decrypted vault data inside an authenticated session.
- Minimize secret copies and clear mutable buffers where practical.
- Document that CPython cannot guarantee perfect memory zeroization.
- Disable telemetry by default.
- Avoid executing stored URLs, commands, or data without an explicit supported user action.

### 9.1 Biometric unlock

Biometric unlock is optional and explicitly enabled per vault and device:

1. The first unlock requires the master password.
2. Bonobo prepares the minimum vault-unlock material required for later access.
3. A device-bound hardware-backed key wraps that material through Android Keystore or Apple security facilities.
4. Successful biometric or device-owner authentication is required to unwrap it.
5. Wrapped material never enters the PasswordSafe document or synchronization provider.
6. Master-password changes and relevant device-security changes invalidate or replace it.
7. Users can revoke biometric unlock and require the master password again.

Biometric unlock may operate across application restarts after successful enrollment.

### 9.2 Autofill and credential providers

Android Autofill and the iOS credential-provider extension will be native components.  They may receive only the minimum
matching metadata and explicitly requested credential values from an authenticated core session.

These components cannot enumerate decrypted vault contents independently, initiate URL audits, bypass lock policy, or
publish a vault without the same validation and conflict controls as the main application.

### 9.3 Clipboard and diagnostics

Copied secrets will use platform-sensitive clipboard markers and configurable automatic clearing where available.

Runtime logs will be written under the application sandbox's logs directory.
Formatted records will use only INFO, DEBG, WARN, and CRIT severities and will include a timestamp, source, and safe
message.

Logs must not contain credentials, tokens, full URLs, URL paths, query values, vault filenames, entry names, UUIDs, or
other sensitive database content.

## 10. Failure Handling

The core will expose typed failure categories instead of platform exception text.

- Authentication, parsing, validation, archive, and provider failures leave the source vault unchanged.
- Interrupted writes preserve the last validated vault and an encrypted recovery copy.
- External changes block publication and enter conflict resolution.
- Audit failures change classifications only and never mutate records.
- Unsupported or malformed content fails closed while retaining the original encrypted bytes.
- Unexpected termination may leave an encrypted pending working copy but never plaintext recovery data.
- User-facing errors explain the safe next action without exposing sensitive diagnostics.

## 11. Verification Strategy

Core verification will include:

- Strict static type checking.
- Project formatter and linter enforcement.
- Unit tests for domain rules and application use cases.
- Property-based tests for parsing, serialization, and transformations.
- Fuzz testing of PasswordSafe parsing and malformed fields.
- Golden synthetic vaults covering all supported standard and unknown fields.
- Byte-preservation and semantic round trips through Bonobo, Gorilla, and Password Safe.
- Archive reopen and identity verification before deletion.
- Large-vault performance and memory tests.

URL-audit verification will include deterministic local HTTP services and shared transport contract tests for:

- Successful responses and redirects.
- Cross-host redirects.
- Authentication and rate-limit responses.
- Live roots with dead saved paths.
- DNS, connection, timeout, and TLS failures.
- Redirect loops and limits.
- Parked and ambiguous content.
- Cancellation and bounded concurrency.

Provider verification will inject:

- Offline operation.
- Interrupted upload and replacement.
- Provider permission revocation.
- External mutation immediately before save.
- Conflicted copies and version conflicts.
- Disk-full and quota failures.
- Non-atomic provider behavior.

Platform verification will include:

- Continuous integration on Windows, macOS, and Linux.
- Android emulator and physical-device tests.
- Android Keystore, biometric, Autofill, background termination, and ChromeOS tests.
- iOS simulator and physical-device tests.
- Apple document coordination, Keychain, biometric, and credential-provider tests.
- Accessibility, keyboard navigation, screen-reader, and responsive-layout tests.

Every release requires formatter, type checker, static security checks, dependency and license audit, packaging
validation, and the applicable automated and physical-device suites.

## 12. Delivery Decomposition

The program will use separate specifications and implementation plans for these subprojects:

1. Repository foundation and compatibility dossier.
2. Lossless PasswordSafe core.
3. Vault application core and desktop foundation.
4. URL audit and cleanup.
5. Provider-safe files and conflict resolution.
6. Android and ChromeOS.
7. iOS.
8. Parity closure and stable release.

### 12.1 Repository foundation and compatibility dossier

- Establish Git, repository policy, GPL licensing, App Store exception planning, contribution terms, CI skeleton, and
  durable project memory.
- Pin the upstream Gorilla reference without placing it in the product tree.
- Produce the neutral behavior dossier and feature-parity matrix.

### 12.2 Lossless PasswordSafe core

- Implement typed parsing, writing, validation, unknown-field preservation, and transactional local files.
- Establish conformance, fuzz, and round-trip suites before production UI work depends on the core.

### 12.3 Vault application core and desktop foundation

- Implement sessions, records, search, groups, policies, history, protected entries, archive operations, and platform
  protocols.
- Deliver the modern desktop shell and packaging foundation.

### 12.4 URL audit and cleanup

- Adapt the approved audit design to Python classification and native mobile transports.
- Deliver review, archive, staged deletion, cancellation, and safety testing.

### 12.5 Provider-safe files and conflict resolution

- Implement native document providers, encrypted working copies, pending publication, conflict detection, recovery, and
  explicit merge workflows.

### 12.6 Android and ChromeOS

- Deliver the Compose client, embedded Python core, provider integration, biometrics, Autofill, lifecycle safety,
  offline operation, and ChromeOS qualification.
- Android is not complete until biometric unlock and Autofill pass physical-device tests.

### 12.7 iOS

- Deliver the SwiftUI client, embedded Python core, coordinated documents, Keychain and biometrics, credential provider,
  licensing audit, and App Store preparation.

### 12.8 Parity closure and stable release

- Close remaining Gorilla compatibility gaps.
- Complete accessibility, performance, migration documentation, and release audits.

## 13. Program Acceptance Criteria

The program-level design is satisfied when:

1. Existing supported Gorilla PasswordSafe V3 databases open without losing standard, unknown, or user-authored fields.
2. Bonobo saves pass the documented cross-client round-trip matrix.
3. Windows, macOS, and Linux provide a modern interface with meaningful Gorilla feature compatibility.
4. URL audit and cleanup meet the approved classification, privacy, archive, and deletion-safety criteria.
5. External document providers cannot cause silent last-writer-wins overwrites.
6. Ordinary edits survive mobile lifecycle termination in encrypted form.
7. Bulk audit cleanup remains staged until explicit save.
8. Android supports secure offline use, biometric unlock, Autofill, and qualified ChromeOS operation.
9. iOS uses only code and dependencies eligible for its approved distribution terms.
10. No Bonobo cloud service or account is required.
11. Security-sensitive logs, network requests, caches, fixtures, and recovery files contain no prohibited plaintext
    data.
12. Every claimed platform passes its automated, packaging, and required physical-device release gates.

## 14. Known Risks

- Cross-client unknown-field preservation may differ from the PasswordSafe specification and must be verified
  empirically.
- Python embedding and binary dependency packaging are more complex on Android and iOS than on desktop.
- CPython cannot guarantee complete in-memory secret zeroization.
- App Store terms and required exceptions can change before the iOS release.
- Third-party document providers expose inconsistent coordination and conflict capabilities.
- Multiple native presentation layers increase implementation and testing cost.
- Full Gorilla compatibility is a multi-release effort and requires a continuously maintained parity matrix.

These risks justify the phased delivery model and do not relax data-integrity or security requirements.

## 15. References

- Password Gorilla: https://github.com/zdia/gorilla
- PasswordSafe V3 format: https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
- CPython on Android: https://docs.python.org/3.14/using/android.html
- CPython on iOS: https://docs.python.org/3.14/using/ios.html
- Qt supported platforms: https://doc.qt.io/qtforpython-6/overviews/qtdoc-supported-platforms.html
- Android Storage Access Framework:
  https://developer.android.com/guide/topics/providers/document-provider
- Apple shared document coordination:
  https://developer.apple.com/documentation/technologyoverviews/shared-data
- GNU GPLv3 guide: https://www.gnu.org/licenses/quick-guide-gplv3.html
- U.S. Copyright Office Circular 61: https://www.copyright.gov/circs/circ61.pdf
