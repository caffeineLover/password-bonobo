# Vault Application Core and Desktop Foundation Design Specification

Date: 2026-09-01

Status: Proposed continuation design for program subproject O3

## 1. Purpose

This subproject turns the reviewed lossless PasswordSafe engine into a usable application without weakening its
authentication, preservation, revision, or publication boundaries. It adds a UI-independent application facade and a
PySide6/Qt Quick desktop client for Windows, macOS, and Linux.

The first implementation increment must produce a complete vertical slice: create or open a fabricated vault, display
non-secret summaries, search, add or edit a record, explicitly copy or reveal a secret, save, lock, unlock, and close
without data loss. Later tasks in the same subproject add group management, password policies and history, protected
entry workflows, CSV exchange, recovery presentation, preferences, and production packaging.

## 2. Governing requirements

- The PasswordSafe service remains the only component allowed to authenticate, mutate, serialize, or publish a vault.
- The application core imports no PySide6, QML, desktop, Android, iOS, provider, or network implementation.
- The desktop client uses PySide6 and Qt Quick on Windows, macOS, and Linux.
- Secret values cross an application boundary only for explicit reveal, copy, edit, generator, or future credential
  actions. List, group, search, recent-file, error, and log models contain no secret values, URLs, UUIDs, or vault paths.
- A failed or canceled action leaves the active session and source vault unchanged.
- Every mutation uses the current `RevisionToken`; stale UI work fails instead of overwriting a newer revision.
- Unknown fields, format level, ordering, and unsupported opaque payloads retain the lossless-core guarantees.
- Locking clears keys, transient secret views, copied values owned by Bonobo, and raw passphrase input.
- Dirty idle locking neither publishes nor discards edits. It first creates an authenticated encrypted pending-session
  artifact in private application storage and resumes only after reauthentication.
- URLs are launched only from the exact stored value after an explicit action. They never enter summaries or logs.
- No provider coordination, URL audit, biometric unlock, Autofill, AutoType, mobile UI, or cloud account work enters
  this subproject.

## 3. Approaches considered

### 3.1 Direct QML access to `VaultSession`

This is initially small but would expose domain objects and secret-bearing operations to QML, duplicate lifecycle
rules in the presentation layer, and make future Kotlin and Swift clients define a second application contract. It is
rejected.

### 3.2 Qt-owned application controller

A PySide6 controller could centralize behavior while keeping QML thin. This still couples application use cases,
failure mapping, and lifecycle state to desktop types, preventing headless verification and reuse by mobile clients.
It is rejected.

### 3.3 UI-independent facade with a thin Qt adapter

The selected approach adds `bonobo_core.application`, whose immutable DTOs and task-oriented facade own application
state and consume `VaultService`. A separate `bonobo_desktop` package adapts those DTOs to Qt models and invokes the
facade on one serialized worker. QML renders state and emits user intent only.

This creates one reusable application contract, makes the most security-sensitive state transitions testable without
a GUI, and confines Qt object lifetime and platform behavior to the desktop package.

## 4. Component architecture

### 4.1 Application package

`bonobo_core.application` is split by responsibility:

- `types.py`: enums and immutable, path-free, non-secret DTOs.
- `errors.py`: application failure reasons and safe presentation keys.
- `ports.py`: protocols for clipboard, browser, clock, pending-session storage, preferences, and notifications.
- `projection.py`: deterministic group, record-list, selection, and search projections.
- `records.py`: draft validation and revision-bound record commands.
- `passwords.py`: cryptographically secure password-policy and password-history operations.
- `exchange.py`: bounded CSV import/export contracts and warnings.
- `facade.py`: the serialized application state machine and task-oriented public API.

The package may consume public `bonobo_core.passwordsafe` types. It must not reach into raw document internals or call
private service/session methods.

### 4.2 Desktop package

`bonobo_desktop` contains only desktop presentation and platform adapters:

- `main.py`: composition root, private application directories, Botan resolution, Qt startup, and safe exit status.
- `controller.py`: QObject adapter whose slots translate UI intents into facade commands.
- `models.py`: reset-only `QAbstractListModel` adapters for record and group snapshots in the first increment.
- `tasks.py`: a single-worker executor that prevents concurrent access to one facade/session.
- `clipboard.py`, `browser.py`, `lifecycle.py`, and `settings.py`: Qt implementations of application ports.
- `qml/`: declarative welcome, unlock, vault, record editor, confirmation, and settings views.

QML never imports `bonobo_core`, never receives a `VaultSession`, `RecordHandle`, `RevisionToken`, `SecretBuffer`, raw
exception, or filesystem path, and never performs persistence directly.

### 4.3 Packaging boundary

The base distribution remains usable as a headless core. A `desktop` optional extra adds PySide6 and the GUI entry
point uses lazy imports so a core-only installation still imports safely. The build includes both Python packages and
QML resources. Desktop deployment is produced independently on each target OS; packages are never cross-built.

Qt for Python 6.11.2 is the initial qualified line because its published metadata supports Python 3.14 and current
Windows x86-64, macOS universal2, and manylinux x86-64 wheels. The dependency is constrained to `>=6.11.2,<6.12` and
must be requalified before widening. The deployment foundation uses Qt's supported `pyside6-deploy` configuration and
dry-run inspection before installer signing or distribution is attempted.

## 5. Application state model

The facade exposes one immutable `ApplicationSnapshot` after every command. Its phase is one of:

- `EMPTY`: no vault is selected and no authenticated state exists.
- `BUSY`: one serialized operation is running; mutation commands are rejected.
- `UNLOCKED_CLEAN`: an authenticated session exists with no unsaved edits.
- `UNLOCKED_DIRTY`: an authenticated session exists with unsaved edits.
- `LOCKED`: no keys or plaintext document remain; the source may have a private encrypted pending-session artifact.
- `AWAITING_DECISION`: a close, replace, delete, protected-entry, plaintext-export, or recovery action requires an
  explicit decision token.

Snapshots contain only a display label chosen by the caller, dirty/protected flags, counts, safe warnings, current
selection identity, group summaries, and record summaries. An opaque application ID maps to each session-scoped
`RecordHandle`; the handle itself never crosses into QML.

Commands are serialized and compare the snapshot generation plus the underlying `RevisionToken`. Results based on a
stale generation are rejected with `STALE_VIEW`. A busy operation cannot be nested or started concurrently.

## 6. Vault lifecycle

### 6.1 Create and open

The desktop adapter obtains a path from the native file dialog and supplies it directly to the facade without placing
it in a model or log. Passphrase input is converted to a `SecretBuffer`, the Qt input property is cleared immediately,
and the buffer is closed by the command boundary.

Successful create/open replaces the prior session only after the new session is fully authenticated and projected.
Failure retains the old active session. Replacing a dirty session first returns a decision token for save, discard, or
cancel.

### 6.2 Save

Save calls only `VaultService.save`. The facade enters `BUSY`, rejects edits until completion, and adopts the returned
revision only after complete publication. External modification and storage failures retain the dirty session and map
to safe, localized presentation keys.

### 6.3 Manual close and replacement

A clean close locks immediately. A dirty close or vault replacement creates a single-use decision token. `SAVE`
attempts normal publication and closes only after success; `DISCARD` calls `discard_and_lock`; `CANCEL` restores the
unchanged unlocked snapshot. Tokens expire after any other accepted state transition.

### 6.4 Manual and idle lock

A clean lock closes the session and leaves only a path-private recent locator if that preference is enabled. A dirty
lock asks `VaultService.suspend` to serialize and authenticate the current document to a private pending-session store
without replacing the source. Only after that artifact is durably synchronized does the facade close the session.

Unlock reauthenticates both the unchanged source and the pending artifact, verifies the pending artifact is bound to
the source's recorded encrypted baseline, and resumes the pending document against that baseline. Missing, invalid,
or mismatched pending state is never substituted silently; the user may explicitly discard it and open the source.
Successful save or discard removes the pending artifact by stable identity.

## 7. Record, group, search, and secret behavior

Record-list summaries expose only opaque ID, title, group, username, protected state, and non-secret status flags. URL,
email, notes, password, history, custom fields, UUID, and unknown-field metadata remain outside the list projection.

Search is deterministic, Unicode casefolded by default, and limited initially to title, group, and username. An
explicit case-sensitive option is supported. Search changes selection only; it does not mutate the vault or create a
dirty revision.

Groups are projections of dot-separated record group values plus representable empty-group metadata. Rename, move,
and non-empty deletion are planned commands over one revision. Root cannot be renamed or deleted. A confirmed
non-empty deletion moves or removes records only through explicit revision-bound record changes.

Record editing uses immutable drafts. Title and password remain mandatory. Secret edits use `SecretBuffer` and never
an immutable application DTO string. Confirming a draft commits one session revision; canceling commits none.
Protected entries require an explicit single-use confirmation token before mutation, deletion, reveal, copy, or
plaintext export.

Password generation uses the injected cryptographic random source, a validated policy, unbiased sampling, and a
`SecretBuffer` result. Generated values enter a record only through an explicit edit. Password history is updated in
the same revision as a password change when enabled and representable; malformed or ambiguous history fails closed.

## 8. Platform services

### 8.1 Clipboard

The facade obtains a short-lived secret lease only for an explicit copy command and passes it directly to
`ClipboardPort`. The Qt adapter writes text plus a Bonobo-owned MIME nonce, schedules monotonic expiry, and clears only
when that nonce still identifies the current clipboard value. A later clipboard value owned by another application is
never erased. Lock and close request immediate clearing.

### 8.2 Browser

An explicit open action leases the stored URL and calls `BrowserPort.open`. The adapter uses `QDesktopServices` and
returns only a success/failure reason. The URL is absent from diagnostics, error strings, state snapshots, and history.

### 8.3 Idle and lifecycle

A Qt event filter reports qualifying user activity to a monotonic idle controller. Timer expiry requests the facade's
lock transaction. Suspend, session end, and application shutdown use the same operation; the process does not exit
while a save or pending-session synchronization is incomplete.

### 8.4 Preferences and recent files

Preferences are bounded, typed, and stored under the OS application-settings location, never beside a vault. Initial
preferences cover clipboard timeout, idle timeout, recent-file capacity, and case-sensitive search default. Recent
entries are opt-in metadata, bounded, clearable, and exposed to QML as caller-supplied display labels rather than full
paths. No preference write changes a vault.

## 9. Desktop interaction design

The first shell has four top-level views:

1. Welcome: create, open, and optional recent entries.
2. Unlock: selected display label, concealed passphrase input, recovery/pending-state choices, and safe errors.
3. Vault: group rail, searchable record list, non-secret detail surface, explicit copy/reveal/open actions, and a
   persistent dirty indicator.
4. Record editor: revision-bound draft with explicit Save/Cancel and protected-entry confirmation.

Save, lock, create/open replacement, and close are first-class commands. Keyboard order, access names, shortcut
discoverability, focus restoration, scalable text, high-contrast colors, and screen-reader status notifications are
acceptance requirements, not polish work.

## 10. Failure and diagnostic model

The application maps every PasswordSafe exception into a closed `ApplicationFailureReason` and stable presentation
key. It never passes through native exception text. Failure DTOs may include operation kind, retryability, and whether
the active session was retained; they contain no path, filename, record identity, UUID, URL, field value, native
command, or terminal control byte.

Unexpected exceptions close any newly acquired secret/resource, retain the prior committed application snapshot where
possible, emit a generic safe failure, and are re-raised only in test/developer mode after redaction.

## 11. Verification

- Headless facade tests use fake ports and a real fabricated Botan-backed vault for lifecycle boundaries.
- Every state transition has red-first tests for success, cancel, stale generation, typed failure, and resource close.
- Pending-session fault injection covers preparation, authentication, durable publication, resume, cleanup, source
  retarget, and external modification.
- Projection/property tests prove search and group operations do not expose or mutate secret fields.
- Clipboard tests prove expiry, lock clearing, nonce ownership, replacement preservation, and no secret diagnostics.
- Qt tests use the offscreen platform plugin, load every QML component, exercise keyboard workflows, and assert access
  names and focus order.
- The three desktop hosted jobs install the desktop extra and run QML/import smoke tests. Packaging jobs run
  `pyside6-deploy --dry-run` and inspect declared modules/resources on their native OS.
- Existing full lossless, interoperability, mobile cross-build, provenance, Bandit, Ruff, strict mypy, REUSE, wheel,
  and tracked-file gates remain mandatory.

## 12. Delivery increments

1. Application contracts, safe errors, projections, and serialized facade.
2. Encrypted dirty-session suspend/resume and lifecycle decisions.
3. Search and record-edit vertical slice with explicit copy/reveal/browser ports.
4. PySide6 composition root, Qt models, QML shell, keyboard/accessibility tests, and native packaging dry runs.
5. Groups, protected workflows, password policies/history, preferences, recent entries, and recovery presentation.
6. Bounded CSV import/export and explicit plaintext warnings.

Merge/conflict resolution remains owned by O5. URL-audit archive and staged cleanup remain owned by O4. AutoType,
biometrics, Autofill, and credential providers remain owned by later platform subprojects.

## 13. Acceptance criteria

The subproject is complete when:

1. The application facade performs lifecycle and record workflows without any UI dependency or secret-bearing DTO.
2. Dirty lock/resume preserves unsaved edits only in authenticated private encrypted state and never publishes them.
3. Search, groups, policies/history, protected entries, recovery, preferences, and CSV workflows satisfy their approved
   O3 oracles without weakening lossless round trips.
4. The Qt Quick client completes the core fabricated-vault workflow by pointer and keyboard on Windows, macOS, and
   Linux.
5. Clipboard, browser, idle, close, replacement, and error behavior pass fault-injected and native adapter tests.
6. A native deploy dry run and packaged smoke launch pass on all three desktop targets.
7. All existing core, interoperability, mobile cross-build, security, licensing, and repository gates remain green.

## 14. References

- `docs/specs/password-bonobo-python-reimplementation-design.md`
- `docs/superpowers/specs/2026-08-23-lossless-passwordsafe-core-design.md`
- `docs/compatibility/gorilla/feature-parity-matrix.md`
- `docs/compatibility/gorilla/test-oracles.md`
- [Qt for Python](https://doc.qt.io/qtforpython-6/)
- [Qt for Python deployment](https://doc.qt.io/qtforpython-6/deployment/deployment-pyside6-deploy.html)
- [PySide6 package metadata](https://pypi.org/project/PySide6/)
