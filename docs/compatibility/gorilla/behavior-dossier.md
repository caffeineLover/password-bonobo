# Password Gorilla Neutral Behavior Dossier

## Evidence convention

Each statement uses a sequential three-digit `GOR-BEH` identifier. Evidence is recorded as revision, relative path,
line range or test name, evidence kind (`source`, `test`, `help`, `message`, or `observed`), and a neutral behavioral
observation. Source text, source identifiers, control flow, and UI expression are not reproduced.

## Confidence

- `Confirmed`: supported by at least two independent evidence kinds or one executable black-box observation.
- `Supported`: supported by one direct source, test, or user-documentation item.
- `Unverified`: evidence is incomplete, contradictory, or unavailable in the research environment.

## Vault lifecycle

### GOR-BEH-001 - Create a new vault

- Confidence: `Confirmed`.
- Preconditions: The application is running; any earlier unsaved work has been resolved.
- Action: The user requests a new vault and supplies the same master password twice.
- Observable result: An empty, untitled vault becomes active with defaults for format, locking, and automatic saving.
- Data effect: A new in-memory vault replaces the prior active vault; no file exists until a successful save.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:88-95`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1162-1273`; kind: `source`.
- Bonobo note: New-vault state and the first durable save are distinct compatibility events.

### GOR-BEH-002 - Resolve unsaved work before creating a vault

- Confidence: `Confirmed`.
- Preconditions: The active vault contains unsaved changes.
- Action: The user requests a new vault.
- Observable result: The user may save, discard, or cancel; a failed or canceled save leaves the current vault active.
- Data effect: Discarding removes unsaved changes; canceling preserves them in memory.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1166-1193`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:58-59`; kind: `message`.
- Bonobo note: This confirmation is a data-loss boundary separate from ordinary creation.

### GOR-BEH-003 - Open and authenticate a vault

- Confidence: `Confirmed`.
- Preconditions: A readable PasswordSafe file and its master password are available.
- Action: The user selects a file and submits its master password.
- Observable result: Successful authentication replaces the tree with the file's records and reports that it loaded.
- Data effect: File data is loaded into memory without changing the file.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:86-95`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1479-1507`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1670-1702`;
    kind: `source`.
- Bonobo note: Authentication success, record loading, and active-file replacement form one visible open operation.

### GOR-BEH-004 - Reject an inaccessible file before authentication

- Confidence: `Supported`.
- Preconditions: The chosen path is empty, missing, or unreadable.
- Action: The user attempts to open the path.
- Observable result: A specific access error is shown and the open prompt remains available for another attempt.
- Data effect: The active vault and the selected file remain unchanged.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1440-1466`; kind: `source`.
- Bonobo note: Missing and unreadable paths are recoverable open failures, not authentication failures.

### GOR-BEH-005 - Reject a wrong password or unreadable vault body

- Confidence: `Supported`.
- Preconditions: The selected file is readable but authentication or decoding cannot complete.
- Action: The user submits a password.
- Observable result: An open error is shown, the entered password is cleared, and another attempt is allowed.
- Data effect: No decoded records replace the active vault.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1468-1497`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:391-396`;
    kind: `source`.
- Bonobo note: The visible retry behavior matters even though distinct internal failures share one presentation.

### GOR-BEH-006 - Open with a nonfatal integrity warning

- Confidence: `Supported`.
- Preconditions: A version 3 file decrypts but its stored integrity value does not match its contents.
- Action: The user opens the file with the correct master password.
- Observable result: The file opens and a warning says its integrity could not be authenticated.
- Data effect: Decoded data becomes active despite the warning; the file is not changed by opening.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:450-458`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1594-1609`;
    kind: `source`.
- Bonobo note: Static source establishes the nonfatal path, but no executable observation raises confidence further.

### GOR-BEH-007 - Change the master password

- Confidence: `Supported`.
- Preconditions: A vault is active and the current master password is known.
- Action: The user verifies the current password and confirms a replacement password.
- Observable result: Wrong current input is rejected; canceling retains the old password; success marks the vault dirty.
- Data effect: Successful completion changes the in-memory encryption credential pending save.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6577-6612`; kind: `source`.
- Bonobo note: Credential change is not durable until the modified vault is saved.

### GOR-BEH-008 - Save the active vault

- Confidence: `Supported`.
- Preconditions: A file-backed vault contains unsaved changes and its destination is writable.
- Action: The user saves.
- Observable result: Progress is shown. The dirty state clears after the primary write and initial backup succeed,
  before any later enabled-backup attempt.
- Data effect: The selected PasswordSafe version is written to the existing path before either backup outcome.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4377-4380`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4382-4390`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4394-4409`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4420-4435`;
    kind: `source`.
- Bonobo note: Primary output, the initial backup, and a later enabled backup are separate save outcomes.

### GOR-BEH-009 - Save to a different path

- Confidence: `Confirmed`.
- Preconditions: A vault is active, including a newly created vault without a path.
- Action: The user chooses another destination and saves.
- Observable result: Cancel leaves state unchanged; success updates the active path, title, status, and recent files.
- Data effect: A file is created or replaced at the chosen path, and the in-memory vault becomes clean.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4444-4559`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:152-157`; kind: `message`.
- Bonobo note: Path adoption and file creation are observable parts of save-as compatibility.

### GOR-BEH-010 - Handle a read-only save destination

- Confidence: `Confirmed`.
- Preconditions: The active file cannot be opened for writing.
- Action: The user requests save.
- Observable result: A warning offers retry after permissions change or cancellation in favor of saving elsewhere.
- Data effect: Cancel leaves the existing file and dirty in-memory data unchanged.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4331-4346`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:143-146`; kind: `message`.
- Bonobo note: Retry and cancel are data-preserving outcomes distinct from a write attempt that later fails.

### GOR-BEH-011 - Clean up a caught write-stage failure

- Confidence: `Supported`.
- Preconditions: A save has opened temporary output and its format writer reports a caught error.
- Action: The caught write-stage operation fails before replacement begins.
- Observable result: The save reports failure and removes the temporary output.
- Data effect: The prior destination is not replaced by this caught writer failure.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe.tcl:157-180`;
    kind: `source`.
- Bonobo note: Replacement failure and process or system interruption are separate unverified cases in GOR-BEH-065.

### GOR-BEH-012 - Resolve unsaved work before opening another vault

- Confidence: `Supported`.
- Preconditions: The active vault contains unsaved changes.
- Action: The user requests another file.
- Observable result: Save proceeds only on success, discard continues to open, and cancel retains the current vault.
- Data effect: Discard removes unsaved changes before another vault can replace the current one.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1623-1648`; kind: `source`.
- Bonobo note: Switching files has its own destructive confirmation and save-failure guard.

### GOR-BEH-013 - Close with unsaved changes

- Confidence: `Confirmed`.
- Preconditions: The application is closing while the active vault is dirty.
- Action: The user closes the application.
- Observable result: Save, discard, and cancel are offered; failed or canceled save prevents closure.
- Data effect: Discard loses unsaved changes; cancel preserves them in the running process.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4816-4847`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:158-158`; kind: `message`.
- Bonobo note: This is a separate data-loss confirmation from new-vault and open-file transitions.

### GOR-BEH-014 - Close with no unsaved changes

- Confidence: `Supported`.
- Preconditions: The application has no dirty active vault.
- Action: The user closes the application.
- Observable result: Preferences are saved, any scheduled clipboard clearing is completed, and the process exits.
- Data effect: Vault data is unchanged; preference state may be persisted and clipboard content may be cleared.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4849-4869`; kind: `source`.
- Bonobo note: Clean closure has privacy effects even without a vault-data write.

### GOR-BEH-015 - Enter the locked state

- Confidence: `Supported`.
- Preconditions: A vault is active and not already locked.
- Action: The user requests a lock or the idle timer expires.
- Observable result: Clipboard data is cleared, open secondary windows are hidden, and an unlock prompt takes focus.
- Data effect: Decrypted in-memory vault data is retained; the general lock transition does not discard unsaved edits.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4957-4986`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5040-5068`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5088-5117`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `unit-tests/lock-database/lock.test`;
    test: `lock-database-1.1`; kind: `test`.
- Bonobo note: The smoke test exercises lock entry but does not prove every composite interface and data effect.

### GOR-BEH-016 - Unlock or exit from the locked state

- Confidence: `Confirmed`.
- Preconditions: A vault is locked.
- Action: The user submits the master password or requests exit.
- Observable result: Correct input restores hidden windows; wrong input is cleared; exit uses close safeguards.
- Data effect: Unlock preserves in-memory changes; exiting may save or discard them after confirmation.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5119-5175`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:160-165`; kind: `message`.
- Bonobo note: Locked-state exit can still expose the ordinary unsaved-change decision.

### GOR-BEH-017 - Lock after inactivity

- Confidence: `Confirmed`.
- Preconditions: A vault enables idle locking with a positive minute value.
- Action: No activity resets the timer before it expires.
- Observable result: The vault locks; an independent global option may minimize the lock prompt.
- Data effect: Vault data remains in memory and no unsaved change is discarded by the timeout alone.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:382-391`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4919-4935`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4944-4946`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5115-5117`;
    kind: `source`.
- Bonobo note: Timeout, explicit lock, and optional minimization are distinct observable settings.

### GOR-BEH-018 - Enable and locate save backups

- Confidence: `Unverified`.
- Preconditions: A file-backed vault is saved with backup preferences in any state.
- Action: The save completes and backup processing runs.
- Observable result: Help promises optional backups, but the pinned save path appears to request a copy unconditionally.
- Data effect: A same-directory or configured-directory copy may be replaced or timestamped.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:297-301`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4394-4402`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4420-4423`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `unit-tests/backup/backup.test`;
    tests: `backup-1.1`, `backup-1.2`; kind: `test`.
- Bonobo note: A disabled-preference black-box observation is missing, so backup enablement remains contradictory.

### GOR-BEH-019 - Report a backup failure after vault output

- Confidence: `Supported`.
- Preconditions: Primary vault output succeeds and either the initial or later enabled backup fails.
- Action: The user saves directly or through the close confirmation.
- Observable result: An initial backup failure returns before the dirty state clears. A later enabled-backup failure
  returns an error after the dirty state clears. If Close requested the save, either error stops that close attempt.
  On close retry without later edits, only the initial failure prompts again; the later failure then closes
  without another prompt.
- Data effect: The primary file already contains new data in both cases. The later failure follows a successful
  initial backup and leaves the in-memory vault clean despite the reported error.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4394-4402`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4404-4409`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4420-4430`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4611-4624`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4627-4636`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4816-4847`;
    kind: `source`.
- Bonobo note: Retry and close behavior depends on which backup phase failed, not only on the returned error.

### GOR-BEH-020 - Recover a forgotten master password

- Confidence: `Supported`.
- Preconditions: The only master password for an encrypted vault is lost.
- Action: The user attempts recovery without the password.
- Observable result: The user documentation states that no recovery path is available.
- Data effect: The encrypted file remains unchanged and inaccessible.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:98-121`; kind: `help`.
- Bonobo note: Compatibility must not imply an upstream recovery capability that the evidence denies.

### GOR-BEH-021 - Recover after a system failure

- Confidence: `Supported`.
- Preconditions: Changes or a generated password have not been saved when the system fails.
- Action: The user restarts after the interruption.
- Observable result: Unsaved changes may be lost; recovery depends on a separately saved file or prior backup copy.
- Data effect: No automatic journal or recovery file is documented for unsaved in-memory edits.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:780-804`; kind: `help`.
- Bonobo note: Recovery expectations are limited to completed saves and independently available backups.

## Records and groups

### GOR-BEH-022 - Add an entry

- Confidence: `Confirmed`.
- Preconditions: A vault is active and a valid group context is available.
- Action: The user supplies entry content and accepts the edit.
- Observable result: A new tree item appears and completion status is reported.
- Data effect: A record is added in memory and the vault becomes dirty or is saved by automatic-save policy.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2435-2492`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:87-90`; kind: `message`.
- Bonobo note: Entry creation is complete only when accepted content reaches the active vault.

### GOR-BEH-023 - Edit entry fields and timestamps

- Confidence: `Confirmed`.
- Preconditions: An entry is selected.
- Action: The user changes group, title, URL, username, password, or notes and accepts.
- Observable result: Password content starts concealed; changed content replaces the tree item and reports modification.
- Data effect: Fields update; password changes update password-change time; any change updates modification time.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:188-195`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:197-243`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2340-2362`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2375-2429`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2463-2492`;
    kind: `source`.
- Bonobo note: Concealment, user-authored metadata, and timestamp side effects are part of the visible edit contract.

### GOR-BEH-024 - Validate minimum entry identity and group syntax

- Confidence: `Confirmed`.
- Preconditions: An entry edit is open.
- Action: The user accepts an empty title or a malformed hierarchical group name.
- Observable result: URL or username supplies a missing title when available; otherwise feedback blocks acceptance.
- Data effect: No invalid entry mutation is committed while validation fails.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2444-2461`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:87-88`; kind: `message`.
- Bonobo note: Title fallback and validation failure are observable compatibility rules for record identity.

### GOR-BEH-025 - Delete an entry without confirmation

- Confidence: `Supported`.
- Preconditions: An entry is selected.
- Action: The user requests deletion.
- Observable result: The entry disappears immediately and deletion status is reported; no active confirmation is shown.
- Data effect: The record is removed in memory and the vault becomes dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2743-2768`; kind: `source`.
- Bonobo note: The absence of a confirmation makes this a distinct destructive-action compatibility point.

### GOR-BEH-026 - Enforce protected-entry behavior

- Confidence: `Unverified`.
- Preconditions: A record carries or is expected to carry a protection attribute.
- Action: The user attempts editing, deletion, export, merge, or clipboard access.
- Observable result: No protected-entry workflow is established by the pinned field list or entry documentation.
- Data effect: Preservation and enforcement of a protection attribute are not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:15-48`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:186-261`; kind: `help`.
- Bonobo note: Direct format evidence and a user-visible black-box case are missing.

### GOR-BEH-027 - Manage password history

- Confidence: `Unverified`.
- Preconditions: A vault or record contains password-history metadata.
- Action: The user changes, views, restores, or deletes a historical password.
- Observable result: Pinned preferences name history settings, but the pinned entry workflow exposes no result.
- Data effect: Creation, retention, truncation, and deletion of history entries are not established at this revision.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:91-102`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:127-143`;
    kind: `source`.
- Bonobo note: Read/write semantics and user-visible evidence are missing; preference names alone are insufficient.

### GOR-BEH-028 - Resolve alias entries

- Confidence: `Unverified`.
- Preconditions: A PasswordSafe record represents an alias to another record.
- Action: The user opens, edits, copies, deletes, exports, or merges the alias.
- Observable result: No alias-record behavior is documented or identified in the pinned record field model.
- Data effect: Alias identity, target preservation, and target-deletion effects are not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:15-48`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:186-261`; kind: `help`.
- Bonobo note: A format example and executable alias workflow are missing.

### GOR-BEH-029 - Resolve record shortcuts

- Confidence: `Unverified`.
- Preconditions: A PasswordSafe record represents a shortcut to another record.
- Action: The user activates, edits, deletes, exports, or merges the shortcut.
- Observable result: No record-shortcut behavior is documented or identified in the pinned record field model.
- Data effect: Shortcut identity, target preservation, and target-deletion effects are not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:15-48`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:186-261`; kind: `help`.
- Bonobo note: Record shortcuts are distinct from keyboard shortcuts and require separate missing evidence.

### GOR-BEH-030 - Add nested groups

- Confidence: `Confirmed`.
- Preconditions: A vault is active and the proposed hierarchical group name is valid.
- Action: The user adds a group under the root, a selected group, or an entry's parent.
- Observable result: The group appears and its ancestors expand; empty or malformed names are rejected.
- Data effect: A group with no records exists only in the current tree and disappears after save and reopen.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:124-138`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2786-2962`; kind: `source`.
- Bonobo note: Empty groups are transient navigation state, not durable user-authored vault data.

### GOR-BEH-031 - Move entries and groups

- Confidence: `Confirmed`.
- Preconditions: One or more visible non-root items are selected and the destination is valid.
- Action: The user chooses a destination or drags the selection.
- Observable result: Items move into a selected group or the group containing a destination entry.
- Data effect: Entry group fields change; moving a group changes descendant group paths and marks the vault dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:141-182`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:2969-3081`; kind: `source`.
- Bonobo note: Multi-selection is evidenced for drag movement; root and descendant destinations are protected.

### GOR-BEH-032 - Rename a group

- Confidence: `Confirmed`.
- Preconditions: A non-root group is selected.
- Action: The user supplies a valid parent path and nonempty group name.
- Observable result: The group appears at the resulting path; unchanged or invalid requests report without mutation.
- Data effect: Every descendant entry receives the renamed group path and the vault becomes dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3159-3371`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:93-111`; kind: `message`.
- Bonobo note: A rename can also move an entire subtree and is therefore data-affecting.

### GOR-BEH-033 - Delete an empty group

- Confidence: `Supported`.
- Preconditions: A non-root group has no descendants.
- Action: The user requests deletion.
- Observable result: The group disappears without a confirmation.
- Data effect: No stored record is deleted and the vault is not marked dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3090-3127`; kind: `source`.
- Bonobo note: Empty-group deletion differs from destructive group deletion in confirmation and persistence.

### GOR-BEH-034 - Delete a nonempty group

- Confidence: `Confirmed`.
- Preconditions: A selected non-root group contains entries or subgroups.
- Action: The user requests deletion and confirms the destructive action.
- Observable result: Cancel preserves the subtree; confirmation removes the group and all descendants.
- Data effect: All descendant records are deleted in memory and the vault becomes dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3107-3147`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:108-109`; kind: `message`.
- Bonobo note: Recursive deletion is a confirmed data-loss boundary with a default-negative confirmation.

## Navigation and user workflows

### GOR-BEH-035 - Select and activate tree items

- Confidence: `Confirmed`.
- Preconditions: The tree contains groups or entries.
- Action: The user selects an item or activates an entry twice.
- Observable result: Selection changes available actions. Entry activation follows the configured action.
- Data effect: Selection alone changes no vault data; an activated edit can later change data.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:861-932`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:284-295`; kind: `help`.
- Bonobo note: Double activation is configurable and must not be assumed to expose a password.

### GOR-BEH-036 - Search entry fields

- Confidence: `Supported`.
- Preconditions: A vault is active.
- Action: The user searches selected fields with optional case sensitivity or advances to the next match.
- Observable result: Search starts after the current selection, wraps, reveals and selects one match, or reports none.
- Data effect: Search changes selection and expanded groups but does not change vault records.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6989-7292`; kind: `source`.
- Bonobo note: Title, username, password, notes, and URL are independently searchable.

### GOR-BEH-037 - Filter the displayed tree

- Confidence: `Unverified`.
- Preconditions: A vault contains records that could be included or excluded by a criterion.
- Action: The user attempts to filter the visible record set.
- Observable result: The pinned search workflow selects one match but no separate filtering contract is evidenced.
- Data effect: No filtering-related data mutation is established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6989-7292`; kind: `source`.
- Bonobo note: User documentation or an executable filtering observation is missing.

### GOR-BEH-038 - Maintain recent files

- Confidence: `Confirmed`.
- Preconditions: Files have been opened or saved-as and recent-file capacity is nonzero.
- Action: A file succeeds in opening or saving, or the user clears recent-file history.
- Observable result: The file moves to the front; persisted history is capacity-limited and can be cleared.
- Data effect: Preference storage changes; vault contents do not.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:284-289`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1581-1588`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4532-4540`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6134-6146`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6234-6247`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6313-6322`;
    kind: `source`.
- Bonobo note: Zero capacity and explicit clearing are privacy-relevant observable choices.

### GOR-BEH-039 - Apply global, default, and vault preferences

- Confidence: `Confirmed`.
- Preconditions: The relevant preferences scope is available.
- Action: The user accepts global settings, new-vault defaults, export settings, or active-vault settings.
- Observable result: Cancel discards buffered global edits. Clearing recent history is an exception: Cancel does not
  restore the already-cleared live list described by GOR-BEH-038. Defaults affect new vaults; vault settings affect
  the active vault.
- Data effect: Accepted global settings change application preference state outside the vault; clearing recent history
  mutates that live state immediately, while active-vault setting changes make that vault dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:265-271`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:345-348`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:377-380`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5784-5816`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5834-5839`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6134-6165`;
    kind: `source`.
- Bonobo note: Preference cancellation has a deliberate recent-history exception with a distinct privacy effect.

### GOR-BEH-040 - Save automatically after a change

- Confidence: `Confirmed`.
- Preconditions: The active vault enables immediate saving.
- Action: A record or vault setting marks the vault dirty.
- Observable result: An existing file is saved immediately; an untitled vault requests a destination.
- Data effect: Each accepted change may update durable storage without a separate save request.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:393-396`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3773-3792`; kind: `source`.
- Bonobo note: Automatic saving materially changes interruption and undo expectations.

### GOR-BEH-041 - Generate a password from vault policy

- Confidence: `Confirmed`.
- Preconditions: An entry edit is open and the vault has a password policy or a one-entry override.
- Action: The user requests generation.
- Observable result: A password of the chosen length is drawn from enabled character pools; empty pools fail validation.
- Data effect: The edit's password value changes but is not stored until the edit is accepted.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:241-261`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:5326-5629`; kind: `source`.
- Bonobo note: The policy defines an allowed pool; evidence does not promise one character from every enabled class.

### GOR-BEH-042 - Use platform-modified keyboard shortcuts

- Confidence: `Confirmed`.
- Preconditions: The main window has focus and the requested action is available.
- Action: The user presses a documented command key combination.
- Observable result: Control is used on Windows and X11; Command is used on macOS for documented actions.
- Data effect: The invoked action has the same data effect as its non-keyboard path.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:674-686`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:444-454`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:643-658`;
    kind: `source`.
- Bonobo note: Keyboard access is a platform-specific compatibility surface.

### GOR-BEH-043 - Copy a URL by keyboard

- Confidence: `Unverified`.
- Preconditions: An entry with a URL is selected.
- Action: The user uses the documented URL-copy shortcut.
- Observable result: Help assigns a key already assigned to username copy, while the active binding uses another key.
- Data effect: The intended clipboard result cannot be stated confidently from contradictory pinned evidence.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:674-682`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:643-650`; kind: `source`.
- Bonobo note: A black-box keyboard observation on each platform is missing.

### GOR-BEH-044 - Copy and clear entry data through the clipboard

- Confidence: `Confirmed`.
- Preconditions: An entry is selected and contains the requested username, password, or URL.
- Action: The user copies a field or clears the clipboard.
- Observable result: Copy or missing-field status is reported. A nonzero timer and scheduled exit cleanup clear content.
- Data effect: Vault data is unchanged; operating-system clipboard or selection ownership changes.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:210-228`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6660-6700`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4877-4910`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4859-4862`;
    kind: `source`.
- Bonobo note: Missing data, timed clearing, manual clearing, and exit clearing are distinct privacy outcomes.

### GOR-BEH-045 - Auto-copy after an X11 paste

- Confidence: `Confirmed`.
- Preconditions: X11 auto-copy is enabled and the application owns copied username selection data.
- Action: Another application requests the username selection.
- Observable result: Password data is scheduled for the clipboard; clipboard managers can trigger it prematurely.
- Data effect: Vault data is unchanged; clipboard content changes from username to password.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:310-340`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6620-6629`; kind: `source`.
- Bonobo note: The workflow is unavailable on Windows and macOS and is unreliable with some X11 clipboard managers.

### GOR-BEH-046 - Launch a browser for an entry

- Confidence: `Confirmed`.
- Preconditions: The entry has a URL and browser launch configuration is complete.
- Action: The user opens the entry URL directly or uses the configured double-activation action.
- Observable result: The browser receives the URL; an option also copies the username with an adjusted clear timer.
- Data effect: Vault data is unchanged; an external process starts and clipboard content may change.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:528-619`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:7537-7567`; kind: `source`.
- Bonobo note: Launch and optional username copy are separately observable effects.

### GOR-BEH-047 - Report browser-launch failures

- Confidence: `Unverified`.
- Preconditions: URL data, executable configuration, parameter substitution, or operating-system execution is invalid.
- Action: The user requests browser launch.
- Observable result: Static evidence assigns status results to missing URL, configuration, and substitution cases and
  an error result to launch failure, but the missing-URL presentation has not been observed during execution.
- Data effect: Vault data is unchanged and username auto-copy occurs only after successful process launch.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:7537-7567`; kind: `source`.
- Bonobo note: Executable evidence for the missing URL result is missing; the static failure distinctions remain useful.

### GOR-BEH-048 - Perform AutoType

- Confidence: `Unverified`.
- Preconditions: A record contains AutoType content or a vault supplies a default AutoType pattern.
- Action: The user attempts to send credentials to another application.
- Observable result: The pinned data model recognizes AutoType storage, but no user action or output is evidenced.
- Data effect: Record preservation and external keystroke behavior are not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:15-44`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-db.tcl:91-167`;
    kind: `source`.
- Bonobo note: A user-facing workflow, platform behavior, and black-box observation are missing.

## Interchange and edge cases

### GOR-BEH-049 - Export records to CSV

- Confidence: `Confirmed`.
- Preconditions: A vault is active and an export destination can be created.
- Action: The user accepts the optional plaintext warning and exports with selected fields and delimiter.
- Observable result: UTF-8 CSV is written; password and notes inclusion is configurable and completion is reported.
- Data effect: A new unencrypted file containing selected vault data is created or truncated.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:353-369`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:371-374`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3387-3400`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3432-3492`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`;
    location: `unit-tests/csv-export/csv-export.test:48-60`; kind: `test`.
- Bonobo note: The warning can be disabled, so export remains an explicit high-risk data disclosure action.

### GOR-BEH-050 - Import supported CSV columns

- Confidence: `Confirmed`.
- Preconditions: A vault is active and a readable UTF-8 CSV file has a recognized header.
- Action: The user imports one to twelve recognized columns in header-defined order.
- Observable result: Valid rows become entries; missing group or title receives a generated batch default.
- Data effect: Valid records are added in memory and the vault becomes dirty when at least one succeeds.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:924-948`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:950-986`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3532-3547`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3589-3600`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3677-3732`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`;
    location: `unit-tests/csv-import/csv-import.test:120-124`; kind: `test`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`;
    location: `unit-tests/csv-import/csv-import.test:153-188`; kind: `test`.
- Bonobo note: Imported metadata includes identifiers and timestamps, not only visible login fields.

### GOR-BEH-051 - Handle CSV import errors and partial success

- Confidence: `Confirmed`.
- Preconditions: A selected CSV is missing, has invalid headers, or contains malformed rows.
- Action: The user imports it.
- Observable result: File and header failures stop import. Invalid rows are skipped; valid rows continue.
- Data effect: A partially valid file can add records; invalid provisional records are removed.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3526-3587`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3604-3620`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3622-3673`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3677-3702`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3706-3732`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`;
    location: `unit-tests/csv-import/csv-import.test:70-144`; kind: `test`.
- Bonobo note: Import is not all-or-nothing for row-level errors, which is a material data expectation.

### GOR-BEH-052 - Merge another vault

- Confidence: `Confirmed`.
- Preconditions: A master vault is active and another vault can be authenticated.
- Action: The user selects the other vault for merge.
- Observable result: Identical records remain single. New records and conflict pairs are added, and counts are reported.
- Data effect: Added and conflicting records modify the active vault in memory and mark it dirty.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:996-1027`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3834-4169`; kind: `source`.
- Bonobo note: Merge classification ignores selected identity and timestamp fields when testing equivalence.

### GOR-BEH-053 - Resolve a merge conflict field by field

- Confidence: `Confirmed`.
- Preconditions: A merge produced one or more conflict pairs.
- Action: The user chooses or edits every conflicting field and combines the pair.
- Observable result: Combine is unavailable until all differing fields have a choice; passwords begin concealed.
- Data effect: Combining updates one record and deletes its paired duplicate.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:1039-1068`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:8257-8266`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:8319-8354`;
    kind: `source`.
- Bonobo note: Combine mechanics are distinct from the post-save close boundary in GOR-BEH-063.

### GOR-BEH-054 - Leave merge conflicts unresolved

- Confidence: `Supported`.
- Preconditions: Conflict pairs remain after merge.
- Action: The user defers conflicts, performs another merge, saves, or exits.
- Observable result: Deferred pairs remain as ordinary duplicate records; the conflict work list is lost on exit.
- Data effect: Saving preserves both records, while only the temporary association between them is lost.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:1074-1095`; kind: `help`.
- Bonobo note: Loss of conflict-tracking state is not loss of the underlying password records.

### GOR-BEH-055 - Detect and select PasswordSafe file versions

- Confidence: `Confirmed`.
- Preconditions: A readable vault is opened or an active vault is saved.
- Action: The application detects input format or the user changes the active vault's output-format preference.
- Observable result: A file marker selects version 3; other input uses the legacy reader; output may use version 2 or 3.
- Data effect: Saving can upgrade or downgrade the file; file extension does not determine or restrict the format.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:716-750`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe.tcl:54-98`; kind: `source`.
- Bonobo note: Format identity is content-based, while format conversion is an explicit vault preference.

### GOR-BEH-056 - Read a pre-version-2 legacy file with limitations

- Confidence: `Supported`.
- Preconditions: Input lacks the version 3 marker and the expected version 2 description record.
- Action: The user opens it with the correct password.
- Observable result: Basic fields can load; default-user and encoded-group conventions are not supported.
- Data effect: Legacy content is mapped into in-memory records with the documented omissions.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v2.tcl:110-194`;
    kind: `source`.
- Bonobo note: These omissions are explicit legacy limitations and can affect lossless round trips.

### GOR-BEH-057 - Handle unrecognized record fields

- Confidence: `Supported`.
- Preconditions: A version 2 or 3 record contains a field type without specialized interpretation.
- Action: The file is opened and later saved.
- Observable result: No user-facing editor or warning is established for an unrecognized field.
- Data effect: Static evidence indicates that a generic numeric type and value remain available to output, but no
  executable preservation or loss result is established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v2.tcl:234-323`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v2.tcl:508-634`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:218-304`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:636-738`;
    kind: `source`.
- Bonobo note: A same-format save and a format-conversion observation are missing, so confidence remains one-kind.

### GOR-BEH-058 - Reject truncation but warn on authentication mismatch

- Confidence: `Confirmed`.
- Preconditions: A version 3 file has an incomplete header, incomplete field, invalid length, or integrity mismatch.
- Action: The user attempts to open it.
- Observable result: Truncation and invalid lengths stop opening; an integrity mismatch permits opening with warning.
- Data effect: Hard failure rejects decoded records; warning-only failure activates them without changing the file.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:728-730`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:48-111`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:343-376`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe-v3.tcl:435-458`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1594-1609`;
    kind: `source`.
- Bonobo note: Structural and integrity failures deliberately have different visible and data-loading outcomes.

### GOR-BEH-059 - Coordinate concurrent access with a database lock file

- Confidence: `Unverified`.
- Preconditions: Another process has the same vault open or saving.
- Action: The user opens or saves that vault concurrently.
- Observable result: Pinned open and save paths verify access but establish no interprocess lock contract.
- Data effect: Conflict prevention, read-only fallback, overwrite handling, and stale-lock recovery are not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:1447-1466`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4321-4346`; kind: `source`.
- Bonobo note: A two-process black-box observation and stale-lock case are missing.

### GOR-BEH-060 - Interrupt import or merge

- Confidence: `Unverified`.
- Preconditions: A multi-record import or merge is in progress.
- Action: The process, system, or operation is interrupted before normal completion.
- Observable result: Records mutate incrementally, but no cancellation or fault-injection outcome is evidenced.
- Data effect: The amount of retained in-memory or automatically saved partial work is not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3602-3732`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3861-4129`; kind: `source`.
- Bonobo note: Controlled interruption observations with automatic save both enabled and disabled are missing.

### GOR-BEH-061 - Apply platform-specific file and preference locations

- Confidence: `Supported`.
- Preconditions: The application saves vault data or global preferences on a supported desktop platform.
- Action: A save or preference persistence occurs.
- Observable result: On macOS, the preferences directory is used only when present; otherwise the home-file fallback
  is used. Unix vault permissions follow the creation mask, and replacement attempts restore prior access bits.
- Data effect: Preference-file location and Unix vault permissions vary by platform without changing record content.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:818-823`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4354-4360`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4411-4418`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:6277-6287`;
    kind: `source`.
- Bonobo note: The macOS preference fallback and Unix permission behavior are separately supported static outcomes.

### GOR-BEH-062 - Present operation errors without mutating data

- Confidence: `Confirmed`.
- Preconditions: An operation detects a user-correctable error before committing its mutation.
- Action: The failing operation reports its title and neutral explanation.
- Observable result: A modal error requires acknowledgment; status-only messages cover selected nonfatal conditions.
- Data effect: Failed preconditions preserve vault data unless a behavior above states partial success.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:3741-3752`; kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/msgs/en.msg:115-156`; kind: `message`.
- Bonobo note: Generic presentation does not override the operation-specific partial-success and data-loss cases above.

### GOR-BEH-063 - Lose a post-save conflict resolution on close

- Confidence: `Supported`.
- Preconditions: A merge conflict remains after the vault is saved, leaving no earlier unsaved-change indication.
- Action: The user combines the conflict; that mutation updates one record and deletes its duplicate without marking
  the vault dirty, then the user closes without another change.
- Observable result: The conflict tab closes, and application close proceeds without an unsaved-change prompt.
- Data effect: Closing loses the combined field choices and duplicate deletion; the saved file retains the earlier
  conflicting pair.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:1063-1068`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/help.txt:1074-1081`; kind: `help`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:8319-8354`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4816-4847`;
    kind: `source`.
- Bonobo note: This is a destructive-data boundary distinct from deferring and saving both records in GOR-BEH-054.

### GOR-BEH-064 - Lock an untitled vault while backups are enabled

- Confidence: `Supported`.
- Preconditions: An active vault has no file path and global backup-on-save behavior is enabled.
- Action: The user locks and answers the prompt about saving the untitled vault.
- Observable result: Choosing Yes requests a save destination; completed primary output creates the file before the
  backup outcome and lock prompt. Choosing No creates no file. A non-success result is reported, then locking continues.
- Data effect: The Yes path can create the primary file even if a later backup phase reports failure before lock.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4997-5011`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4473-4482`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4492-4515`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4517-4524`;
    kind: `source`.
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/gorilla.tcl:4544-4555`;
    kind: `source`.
- Bonobo note: Untitled-vault lock has a file-creation choice not present in the general lock transition.

### GOR-BEH-065 - Handle replacement failure or external interruption

- Confidence: `Unverified`.
- Preconditions: A vault save has completed temporary output but has not completed destination replacement, or the
  process or system interrupts the save outside the caught writer-error stage.
- Action: Replacement fails, or the process or system stops during staging or replacement.
- Observable result: Cleanup, retry presentation, and application state are not established.
- Data effect: Which of the prior destination, temporary output, or replacement survives is not established.
- Evidence:
  - Revision: `6728e85c05ac25357b8f19f541487b9d26a97402`; location: `sources/pwsafe/pwsafe.tcl:150-190`;
    kind: `source`.
- Bonobo note: Fault injection and process or system interruption evidence are missing for the replacement boundary.
