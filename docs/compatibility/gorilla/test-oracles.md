# Password Bonobo Black-Box Test Oracles

## Authority and scope

These scenarios specify observable inputs and outcomes, not internal design:

- `PasswordSafe` means the official format is authoritative for file structure, fields, and preservation.
- `Gorilla` means the pinned dossier observation is the compatibility authority.
- `Bonobo` means an approved Bonobo specification is the product authority.

An Authority line may join these exact tokens with ` + ` when independent parts of one oracle have different
authorities. The Evidence and Required clients lines delimit each authority's scope; one authority is never inferred
from another.

A Gorilla oracle marked as an evidence-gap closure test records the pinned client's result before any parity claim is
approved. A Bonobo-native feature is not a Gorilla feature. Its cross-client step proves only that ordinary
PasswordSafe data remains usable; it never claims that Gorilla or Password Safe understands native state.

A preservable unknown field is valid PasswordSafe content. It is tested separately from malformed or unsupported
mandatory content and never triggers fail-closed behavior merely because Bonobo does not interpret it.

## Synthetic-data rules

Every value below is fabricated, non-secret, and confined to a disposable test directory. Reserved `.invalid` hosts
prevent accidental contact with a real service. Network scenarios map those hosts to a controlled local endpoint.
No personal vault, real credential, provider account, device account, or upstream vault file is permitted.

`PB-SYN-BASE` is a synthetic PasswordSafe V3 vault named `pb-syn-main.psafe3` with:

- database UUID `11111111-1111-4111-8111-111111111111`;
- master input `fabricated-master-input-one`;
- record UUID `22222222-2222-4222-8222-222222222222` in group `Research.Sample`;
- title `Alpha Portal`, username `sample-user`, and password `fabricated-credential-value`;
- URL `https://alpha.example.invalid/login` and note `fabricated note A`;
- unknown record field type `0xE0` with bytes `66 61 62 72 69 63 61 74 65 64`;
- unknown header field type `0xE1` with the same fabricated bytes.

`PB-SYN-SECOND` adds UUID `33333333-3333-4333-8333-333333333333`, group `Research.Beta`, title `Beta Portal`,
username `sample-user-two`, password `fabricated-credential-two`, URL `https://beta.example.invalid/start`, and
note `fabricated note B`. A semantic manifest records database and record UUIDs, every standard field, every unknown
field type and byte sequence, and the declared format level. A separate SHA-256 value records each encrypted file.

## Gorilla and PasswordSafe compatibility oracles

### GOR-TEST-001 - Create, save, and reopen a vault

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-001` and `GOR-BEH-003`.
- Synthetic setup: Start with no active vault and the fabricated values from `PB-SYN-BASE`.
- Action: Create a vault, enter the master input twice, save as `pb-syn-main.psafe3`, close it, and reopen it.
- Expected observation: The empty vault precedes the first save; reopen accepts the input and shows the one record.
- Preservation requirement: No earlier file changes; the saved record shows every `PB-SYN-BASE` standard value.
- Cleanup: Close without pending changes and remove `pb-syn-main.psafe3` from the disposable directory.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-002 - Change the master input

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-007` and the approved program design section 6.
- Synthetic setup: Open `PB-SYN-BASE` with fabricated input `fabricated-master-input-one`.
- Action: Change it to `fabricated-master-input-two`, save, close, then try the old and new inputs in that order.
- Expected observation: The old input is rejected; the new input opens the same record and database identity.
- Preservation requirement: Record values, UUIDs, unknown field types, and unknown field bytes remain unchanged.
- Cleanup: Close the vault and remove the changed synthetic file.
- Required clients: Bonobo and Password Safe; Gorilla confirms only the observed prompt behavior.

### GOR-TEST-003 - Save with no semantic edit

- Authority: `PasswordSafe`.
- Evidence: Program design sections 4 and 11; `GOR-BEH-008`.
- Synthetic setup: Copy `PB-SYN-BASE`; record its encrypted hash and complete fabricated semantic manifest.
- Action: Open the copy in Bonobo, make no semantic edit, invoke Save once, close, and reopen it in each client.
- Expected observation: All clients authenticate and show the same manifest; changed ciphertext alone is acceptable.
- Preservation requirement: UUIDs, fields, field order where required, unknown types, and unknown bytes are identical.
- Cleanup: Remove the saved copy and every client-created backup from the disposable directory.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe.
- Coverage: open-save-no-semantic-edit.

### GOR-TEST-004 - Guard a switch and close with unsaved work

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-012` through `GOR-BEH-014`.
- Synthetic setup: Open a copy of `PB-SYN-BASE` and change its fabricated note to `fabricated pending note`.
- Action: Request another file and choose Cancel; request close and choose Cancel; request close again and discard.
- Expected observation: Both cancellations retain the active edit; discard closes without changing encrypted bytes.
- Preservation requirement: The source hash and its saved `fabricated note A` remain unchanged after discard.
- Cleanup: Close any open prompt and remove the untouched copy.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-005 - Edit one known field and preserve the rest

- Authority: `PasswordSafe`.
- Evidence: Program design section 4; `GOR-BEH-023`, `GOR-BEH-025`, and `GOR-BEH-057`.
- Synthetic setup: Copy `PB-SYN-BASE`; retain its fabricated manifest and both unknown field byte sequences.
- Action: Change only the title to `Alpha Portal Renamed`, save, reopen, then delete the record and discard on close.
- Expected observation: Reopen shows only the title change; discarded deletion leaves the saved renamed record intact.
- Preservation requirement: All unrelated standard values, UUIDs, unknown types, and unknown bytes remain identical.
- Cleanup: Remove the renamed synthetic copy.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe.
- Coverage: known-field-unknown-field-preservation.

### GOR-TEST-006 - Move and rename a group safely

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-030` through `GOR-BEH-032`.
- Synthetic setup: Open `PB-SYN-BASE` plus `PB-SYN-SECOND`; add empty fabricated group `Research.Empty`.
- Action: Move Beta under `Research.Sample`, rename that group to `Research.Renamed`, and save and reopen.
- Expected observation: Both records use the renamed path; the empty group is absent after reopen.
- Preservation requirement: Record UUIDs and every non-group field remain unchanged; root deletion stays unavailable.
- Cleanup: Remove the modified synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-007 - Search without mutating records

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-036`.
- Synthetic setup: Open `PB-SYN-BASE` plus `PB-SYN-SECOND` with no pending changes.
- Action: Search titles for `Beta`, advance once, then search case-sensitively for `beta`.
- Expected observation: The first search selects Beta; the second reports no match; the vault remains clean.
- Preservation requirement: The encrypted hash and complete fabricated semantic manifest remain unchanged.
- Cleanup: Clear the search state, close, and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-008 - Characterize the filtering evidence gap

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-037`; `GAP-037` in the feature matrix.
- Synthetic setup: Open `PB-SYN-BASE` plus `PB-SYN-SECOND` and record the two fabricated visible titles.
- Action: Inspect available record-view actions, apply any visible filter for `Alpha`, then clear it if offered.
- Expected observation: Record whether no filter exists or the exact visible set before, during, and after filtering.
- Preservation requirement: The evidence is not a parity pass; encrypted bytes and record values remain unchanged.
- Cleanup: Close without saving and remove the synthetic file and non-sensitive observation note.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-009 - Generate from a visible policy

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-041`.
- Synthetic setup: Edit the `PB-SYN-BASE` record with fabricated policy length 12 and letters and digits enabled.
- Action: Generate once, record only length and character classes, cancel, reopen the edit, and inspect the password.
- Expected observation: A 12-character value uses only enabled classes; cancel restores the fabricated original value.
- Preservation requirement: Generated credential text is never logged; the vault file and original value are unchanged.
- Cleanup: Clear the generated value from the test clipboard if present and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-010 - Characterize password-history behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-027`; matrix `GAP-027`; official PasswordSafe `formatV3.txt` section 3.3 note 12.
- Synthetic setup: In Password Safe, create `PB-SYN-BASE`, enable password history with limit 2, and save with
  password `fabricated-history-one`; change and save `fabricated-history-two`, then `fabricated-history-current`.
- Action: View history if available, change the password to `fabricated-new-value`, save, close, and reopen.
- Expected observation: Record visible history and the exact field `0x0F` value before and after the Gorilla change.
- Preservation requirement: No retention or restoration parity claim passes until the observation updates the dossier.
- Cleanup: Remove the copy and the fabricated history manifest.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-011 - Characterize alias behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-028`; matrix `GAP-028`; official PasswordSafe `formatV3.txt` section 3.3 note 3.
- Synthetic setup: A fabricated official-format fixture authority gives target UUID
  `22222222-2222-4222-8222-222222222222` mandatory Title `Alpha Portal`. Alias UUID
  `33333333-3333-4333-8333-333333333333` has mandatory Title `Alpha Alias` and password field type `0x06` value
  `[[22222222222242228222222222222222]]`.
- Action: Select `Alpha Alias` with UUID `33333333-3333-4333-8333-333333333333` for activate, copy, edit, export, and
  delete attempts; in a separate copy select target `Alpha Portal` by its exact UUID and attempt deletion.
- Expected observation: Record the visible target, copied value, mutations, export result, and deletion effects exactly.
- Preservation requirement: Keep the original encrypted fixture; no alias parity claim passes before dossier review.
- Cleanup: Close without saving and remove all synthetic alias/target copies and captured non-secret results.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-012 - Characterize record-shortcut behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-029`; matrix `GAP-029`; official PasswordSafe `formatV3.txt` section 3.3 note 4.
- Synthetic setup: A fabricated official-format fixture authority gives target UUID
  `22222222-2222-4222-8222-222222222222` mandatory Title `Alpha Portal`. Shortcut UUID
  `33333333-3333-4333-8333-333333333333` has mandatory Title `Alpha Shortcut` and password field type `0x06` value
  `[~22222222222242228222222222222222~]`.
- Action: Select `Alpha Shortcut` with UUID `33333333-3333-4333-8333-333333333333` for activate, edit, export, and
  delete attempts; in a separate copy select target `Alpha Portal` by its exact UUID and attempt deletion.
- Expected observation: Record navigation, mutation, export, and target-deletion effects for each copy exactly.
- Preservation requirement: Keep both original encrypted copies; no shortcut parity claim passes before dossier review.
- Cleanup: Close without saving and remove the shortcut copies and captured non-secret results.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-013 - Characterize protected-entry behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-026`; matrix `GAP-026`; official PasswordSafe `formatV3.txt` section 3.3 note 17.
- Synthetic setup: A fabricated official-format fixture authority sets record field type `0x15` to byte `01` on
  `PB-SYN-BASE`; Password Safe opens it and confirms the record is protected before Gorilla receives a copy.
- Action: Attempt edit, deletion, export, merge, username copy, and password copy in separate disposable copies.
- Expected observation: Record which actions are blocked, confirmed, or allowed and every resulting file manifest.
- Preservation requirement: Keep the original encrypted fixture; no protection parity claim passes before review.
- Cleanup: Close without saving and remove all protected-entry copies and non-secret result notes.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-014 - Copy and clear fabricated values

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-044`.
- Synthetic setup: Open `PB-SYN-BASE` copies `pb-syn-clipboard-timer.psafe3`,
  `pb-syn-clipboard-manual.psafe3`, and `pb-syn-clipboard-lock.psafe3`; set a one-second clear interval.
- Action: In the named timer, manual, and lock copies respectively, copy username and wait, copy password and clear,
  and copy username and lock without manual clearing.
- Expected observation: The requested value disappears after the timer, explicit clear, or lock in its respective run.
- Preservation requirement: Vault bytes and fields remain unchanged; copied text never enters logs or result files.
- Cleanup: Clear the clipboard, close all views, and remove `pb-syn-clipboard-timer.psafe3`,
  `pb-syn-clipboard-manual.psafe3`, and `pb-syn-clipboard-lock.psafe3`.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-015 - Resolve the URL-copy key conflict

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-043`; `GAP-043` in the feature matrix.
- Synthetic setup: Open `PB-SYN-BASE` on each desktop target with a cleared clipboard.
- Action: Press the documented URL-copy key and the active alternate key once each, clearing between presses.
- Expected observation: Record the exact clipboard field and visible status for each key and platform.
- Preservation requirement: No key parity claim passes before review; vault bytes remain unchanged.
- Cleanup: Clear the clipboard, close without saving, and remove the synthetic file and observation note.
- Required clients: Gorilla at the pinned revision on Windows, macOS, and X11.

### GOR-TEST-016 - Launch the original fabricated URL

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-046`.
- Synthetic setup: Open `PB-SYN-BASE` with a test browser that records only its fabricated launch argument.
- Action: Invoke Open Website once with username auto-copy disabled and once with it enabled.
- Expected observation: Both launches receive the exact stored URL; only the enabled run copies `sample-user`.
- Preservation requirement: Vault bytes and record fields remain unchanged; no real network destination is contacted.
- Cleanup: Clear the clipboard and browser record, close, and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-017 - Characterize browser error presentation

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-047`; `GAP-047` in the feature matrix.
- Synthetic setup: Use fabricated copies with an empty URL, invalid substitution, and unavailable test browser.
- Action: Request browser launch from each copy and acknowledge any visible result.
- Expected observation: Record exact status or error presentation and whether any clipboard change occurs.
- Preservation requirement: No failure-presentation parity claim passes before review; all vault hashes stay unchanged.
- Cleanup: Clear the clipboard, close without saving, and remove the three synthetic copies.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-018 - Characterize AutoType behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-048`; `GAP-048` in the feature matrix.
- Synthetic setup: Open `PB-SYN-BASE` with fabricated AutoType pattern `username-tab-password-enter`.
- Action: Focus a disposable local text capture surface and invoke every visible AutoType action once.
- Expected observation: Record the exact fabricated text and key order, or record that no action is available.
- Preservation requirement: No AutoType parity claim passes before review; vault bytes remain unchanged.
- Cleanup: Clear the capture surface and clipboard, close without saving, and remove the synthetic file.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-019 - Import valid and invalid CSV rows

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-050` and `GOR-BEH-051`.
- Synthetic setup: Write `pb-syn-import.csv` as UTF-8 without BOM, using LF and this header and row order:
  - `Group,Title,Username,Password,URL,Notes`
  - `Research.Sample,Alpha Import,sample-user,fabricated-one,https://alpha.example.invalid/,fabricated A`
  - `Research.Bad,Bad Import,bad-user,fabricated-bad,https://bad.example.invalid/,fabricated bad,EXTRA`
  - `Research.Beta,Beta Import,sample-user-two,fabricated-two,https://beta.example.invalid/,fabricated B`
- Action: Import once, inspect results, save, close, and reopen the vault.
- Expected observation: The first and third data rows are imported; the middle row with an extra seventh column is
  reported and skipped; reopen shows exactly Alpha Import and Beta Import as the two additions.
- Preservation requirement: Existing `PB-SYN-BASE` data and UUID remain unchanged; no row contains a real credential.
- Cleanup: Remove the CSV and imported synthetic vault.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-020 - Export only selected fields

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-049`.
- Synthetic setup: Open `PB-SYN-BASE`; choose fabricated output `pb-syn-export.csv` in the disposable directory.
- Action: Accept the plaintext warning and export title and username while excluding password and notes.
- Expected observation: UTF-8 output contains `Alpha Portal` and `sample-user` but neither excluded field.
- Preservation requirement: The vault hash remains unchanged; the plaintext file is treated as sensitive test output.
- Cleanup: Securely remove the export and synthetic vault copy from the disposable directory.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-021 - Merge and preserve unresolved conflict records

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-052` through `GOR-BEH-054` and `GOR-BEH-063`.
- Synthetic setup: Merge `PB-SYN-BASE` with a copy whose same UUID has title `Alpha Portal Other`.
- Action: In one conflict session, save while the unresolved pair remains; combine after that save by choosing
  `Alpha Portal`; close without another save; reopen the saved file.
- Expected observation: Close shows no unsaved-change prompt; after reopen the combination is lost and the unresolved
  pair remains exactly as it was at the preceding save.
- Preservation requirement: Record the saved hash and both complete conflict-record manifests before combination;
  close changes neither, and reopen yields both saved records with their saved identities and field values.
- Cleanup: Close the reopened vault without changes and remove the merged synthetic file and both source copies.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-022 - Characterize interrupted import and merge

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-060`; `GAP-060` in the feature matrix.
- Synthetic setup: Prepare 100 fabricated CSV rows and a 100-record fabricated merge vault in separate copies.
- Action: End the client after 25 visible additions with autosave off, repeat with autosave on, then reopen each copy.
- Expected observation: Record retained records, dirty state, output bytes, and recovery prompts for all four runs.
- Preservation requirement: Original inputs stay read-only; no interruption parity claim passes before dossier review.
- Cleanup: Remove all interrupted-run copies, CSV files, and non-sensitive count manifests.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-023 - Recover from a validated backup

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-020` and `GOR-BEH-021`.
- Synthetic setup: Save `PB-SYN-BASE` with `fabricated note A`; make and reopen an earlier backup to verify that note.
  Then change the primary note to `fabricated note recovered`, save the primary successfully, and retain its copy.
- Action: Remove only the active primary path; open the earlier backup and save it as `pb-syn-recovered.psafe3`;
  separately open the retained saved-primary copy.
- Expected observation: The earlier backup and recovered copy show `fabricated note A`; the saved primary shows
  `fabricated note recovered`; no client offers recovery without the fabricated master input.
- Preservation requirement: Recovery never overwrites the earlier backup or saved-primary control; each reopen keeps
  the database UUID, record UUID, unknown bytes, and the exact note state named above.
- Cleanup: Close all copies and remove the recovered copy, earlier backup, saved-primary control, and source vault.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-024 - Resolve backup enablement semantics

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-018`; `GAP-018` in the feature matrix.
- Synthetic setup: Open two `PB-SYN-BASE` copies in empty directories with backup preference off and on.
- Action: Change each note to a distinct fabricated value, save once, and list resulting files after close.
- Expected observation: Record exact backup count, names, locations, hashes, and visible errors for both settings.
- Preservation requirement: No backup-preference parity claim passes before review; retain both primary saved files.
- Cleanup: Remove all synthetic primary and backup files after recording the non-sensitive manifest.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-025 - Apply preferences without hidden record changes

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-039`, `GOR-BEH-040`, and `GOR-BEH-061`.
- Synthetic setup: Open `PB-SYN-BASE`; use fabricated preference copies for autosave on and off.
- Action: Change a global display preference, cancel; enable autosave, edit the note, and close and reopen.
- Expected observation: Canceled display change is absent; the accepted fabricated note is already durable.
- Preservation requirement: Non-note fields and unknown bytes remain unchanged; file permissions follow the platform.
- Cleanup: Remove the synthetic vault and restore the disposable preference profile.
- Required clients: Bonobo and Gorilla at the pinned revision on each desktop platform.

### GOR-TEST-026 - Bound and clear recent-file history

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-038` and `GOR-BEH-039`.
- Synthetic setup: Create fabricated files `pb-syn-one.psafe3` and `pb-syn-two.psafe3` with capacity one.
- Action: Open one then two, inspect history, clear it, cancel preferences, and inspect history again.
- Expected observation: Only file two precedes clearing; cleared history stays empty despite preference cancellation.
- Preservation requirement: Both vault hashes and manifests remain unchanged; history contains no real path.
- Cleanup: Remove both synthetic files and the disposable preference profile.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-027 - Lock after idle time without data loss

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-015` through `GOR-BEH-017`.
- Synthetic setup: Open `PB-SYN-BASE`, set one-minute idle lock, and make fabricated note `pending before lock`.
- Action: Copy the username, wait without activity, unlock with the master input, then save and reopen.
- Expected observation: Lock clears copied text and conceals views; unlock restores the pending note, which then saves.
- Preservation requirement: Lock alone neither discards nor saves the pending edit; all other fields remain unchanged.
- Cleanup: Clear the clipboard, reset the disposable idle setting, and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-028 - Preserve format level and unknown fields

- Authority: `PasswordSafe`.
- Evidence: Program design section 4; `GOR-BEH-055` through `GOR-BEH-057`; official PasswordSafe
  `formatV3.txt` sections 2.9.1, 3.2 note 1, and 4.1.
- Synthetic setup: An official-format fixture authority creates two `PB-SYN-BASE` copies. Their mandatory header
  Version field type `0x00` has length 2 and bytes `00 03` for V3 level `0x0300`, and `02 03` for V3 level `0x0302`.
- Action: In Bonobo, open and save each without migration consent; then round-trip separate copies through Gorilla and
  Password Safe and compare their manifests.
- Expected observation: Bonobo leaves each exact Version value unchanged and every client reads the standard manifest;
  Gorilla and Password Safe unknown-field results are recorded, not presumed.
- Preservation requirement: Bonobo retains unknown types and bytes exactly. Any other-client loss blocks a
  cross-client preservation claim; no client result silently authorizes a Bonobo metadata field.
- Cleanup: Remove all saved synthetic version copies.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe.

### GOR-TEST-029 - Fail closed on a malformed mandatory Version field

- Authority: `Bonobo`.
- Evidence: Program design section 10; `GOR-BEH-058`; official PasswordSafe `formatV3.txt` sections 2.9.1,
  3 `Field Structure`, and 3.2 note 1.
- Synthetic setup: An independent official-format fixture authority creates the fabricated file
  `pb-syn-version-length-one.psafe3`. Its header Version field type `0x00` uses little-endian declared length bytes
  `01 00 00 00` and the exact data byte `00`, although the official Version definition requires two bytes. Header END,
  mandatory record fields, record END, outer envelope, and EOF are otherwise valid; a recomputed stored HMAC
  authenticates the exact plaintext fields.
- Action: Record the complete encrypted input and SHA-256, attempt ordinary Open in Bonobo once, and dismiss the error.
- Expected observation: Bonobo classifies the field as malformed mandatory content, fails closed before an editable
  session exists, and offers no Save or conversion action.
- Preservation requirement: The original encrypted file's bytes and SHA-256 remain exactly unchanged; no output
  replacement, fallback rewrite, converted copy, or recovery file occurs.
- Cleanup: Retain only the non-sensitive hash and error classification, then remove the malformed synthetic input.
- Required clients: Bonobo; the official PasswordSafe format supplies the field authority, not a client run.
- Coverage: malformed-mandatory-fail-closed.

### GOR-TEST-030 - Characterize concurrent Gorilla access

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-059`; `GAP-059` in the feature matrix.
- Synthetic setup: Give two Gorilla processes separate disposable copies and then one shared `PB-SYN-BASE` path.
- Action: Open the shared path in both, edit distinct fabricated notes, save process one, then save process two.
- Expected observation: Record prompts, saved hashes, overwrite behavior, and stale-file artifacts for each process.
- Preservation requirement: Retain pre-run and process-one copies; no locking parity claim passes before review.
- Cleanup: Close both processes and remove shared, retained, and stale synthetic files.
- Required clients: Two Gorilla processes at the pinned revision.

### GOR-TEST-031 - Report a correctable error without mutation

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-024` and `GOR-BEH-062`.
- Synthetic setup: Open `PB-SYN-BASE` and start a fabricated new entry with empty title, URL, and username.
- Action: Accept the invalid entry, acknowledge the error, cancel the edit, and close without saving.
- Expected observation: A visible error blocks acceptance; no new tree item appears and the vault stays clean.
- Preservation requirement: The original encrypted hash and complete manifest remain unchanged.
- Cleanup: Remove the synthetic file and no-longer-visible edit state.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-032 - Characterize localization behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-062`; `GAP-900` in the feature matrix.
- Synthetic setup: Open `PB-SYN-BASE` in fresh profiles using default `en`, available `fr` from
  `sources/msgs/fr.msg`, and unavailable fabricated locale `zz-ZZ`.
- Action: In each run edit Alpha, clear title, URL, and username, attempt to save the edit, acknowledge the error,
  close without saving, restart with the same profile, and repeat; title fallback cannot apply.
- Expected observation: Record selected locale, fallback, error language, missing-key display, and restart requirement.
- Preservation requirement: No localization parity claim passes before review; vault bytes remain unchanged.
- Cleanup: Restore the disposable locale profile and remove the synthetic vault and observation note.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-033 - Close the Help-workflow evidence gap

- Authority: `Bonobo`.
- Evidence: Matrix `GAP-901`; approved program design parity-closure requirement.
- Synthetic setup: Open `PB-SYN-BASE` in a disposable future Bonobo acceptance build with fields concealed.
- Action: Attempt to reach user guidance for open, forgotten master input, edit, export, merge, and lock tasks.
- Expected observation: A passing future acceptance candidate reaches every named topic and reveals no fabricated value.
- Preservation requirement: This future Bonobo acceptance test makes no Gorilla Help claim; vault bytes, clipboard,
  recent files, and the encrypted hash remain unchanged.
- Cleanup: Close guidance and the vault, clear any visible fabricated value, and remove the synthetic file.
- Required clients: A future Bonobo acceptance candidate after the Help contract and `GAP-901` are approved.

### GOR-TEST-034 - Complete core workflows by keyboard

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-035` and `GOR-BEH-042`.
- Synthetic setup: Open `PB-SYN-BASE` on each desktop target with pointer input unavailable.
- Action: Select Alpha, open its edit, cancel, search for Alpha, copy username, clear it, and invoke lock by keyboard.
- Expected observation: Focus stays visible; each action is reachable; platform command modifiers behave as documented.
- Preservation requirement: Cancel leaves vault bytes unchanged; copied fabricated text is cleared before completion.
- Cleanup: Clear clipboard, close without saving, and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision on Windows, macOS, and X11.

### GOR-TEST-035 - Characterize replacement interruption

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-065`; `GAP-065` in the feature matrix.
- Synthetic setup: Copy `PB-SYN-BASE` to a test filesystem that denies replacement after staged output exists.
- Action: Change note to `fabricated interrupted note`, save once, end the client during a second controlled run,
  then reopen every surviving file after each run.
- Expected observation: Record the visible error, active dirty state, filenames, hashes, and readable surviving vaults.
- Preservation requirement: Keep the pre-run original; no interruption parity claim passes before dossier review.
- Cleanup: Remove staged and recovery copies only after their non-sensitive manifest is recorded.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

## Bonobo-extension oracles

### GOR-TEST-036 - Archive a complete selection before staging deletion

- Authority: `Bonobo`.
- Evidence: URL-audit design sections 5 through 14 and program design sections 6.3 and 8.
- Synthetic setup: In `PB-SYN-SECOND`, set Alpha URL to
  `https://audit.example.invalid/path?mode=fabricated#review`, save note `fabricated ordinary edit`, audit Alpha through
  a controlled endpoint, and select exactly two UUIDs: `22222222-2222-4222-8222-222222222222` and
  `33333333-3333-4333-8333-333333333333`; choose `pb-syn-archive.psafe3` as the archive destination.
- Action: Invoke `Archive & Delete Selected` once.
- Expected observation: The request is only `https://audit.example.invalid/path`; the archive exists and a
  read-only open reports record count 2 and complete UUID set `{22222222-2222-4222-8222-222222222222,
  33333333-3333-4333-8333-333333333333}`; only after that validation are both deletions staged and both rows labeled
  `Archived & deleted (unsaved)`. Discarding the staged cleanup leaves the saved ordinary note in the source.
- Preservation requirement: Query, fragment, title, group, username, UUID, and vault identity never enter an audit
  request. Until complete archive validation succeeds, the source manifest and dirty state remain unchanged. Both
  archive-record manifests match their source snapshots, including UUIDs, fields, and preservable unknown bytes.
- Cleanup: Discard staged cleanup, clear result rows, close read-only and source views, and remove both synthetic files.
- Required clients: Bonobo performs the action; Gorilla at the pinned revision and Password Safe read both final files.
- Coverage: archive-reopen-identity-deletion-staging.
- Coverage: ordinary-edit-url-cleanup-isolation.
- Coverage: url-audit-request-isolation.
- Coverage: cross-client-extension-gate.

### GOR-TEST-037 - Refuse overwrite after external mutation

- Authority: `Bonobo`.
- Evidence: Program design sections 6.2, 7, 10, and 11.
- Synthetic setup: Open provider copy A of `PB-SYN-BASE`; prepare B with note `fabricated external edit`.
- Action: In Bonobo change A's title to `Alpha Local Edit`; externally replace the provider file with B; invoke Save.
- Expected observation: Bonobo reports Conflict and preserves A, B, and an offered save-as-copy; B is not overwritten.
- Preservation requirement: Every version retains its UUID and unknown bytes; no custom sync counter enters the vault.
- Cleanup: Save A only as `pb-syn-conflict-copy.psafe3`, verify all copies, then remove them.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe open B and the conflict copy.
- Coverage: external-mutation-conflict; cross-client-extension-gate; deferred-native-no-vault-metadata.

### GOR-TEST-038 - Autofill only the requested fabricated credential

- Authority: `Bonobo`.
- Evidence: Program design sections 9.2, 11, and 12.6.
- Synthetic setup: Open `PB-SYN-BASE` on Android and ChromeOS with a local `alpha.example.invalid` login form.
- Action: Focus username, choose Alpha from Autofill, fill once, then attempt extension-only listing, URL-audit,
  publication, and export actions before locking Bonobo and requesting Autofill again.
- Expected observation: The first request fills only `sample-user` and the fabricated password. The Autofill surface
  cannot independently enumerate decrypted vault records, initiate a URL audit, publish, or export the vault;
  locked access fails, and no Bonobo cloud account or cloud copy exists.
- Preservation requirement: Local-file-first access remains app-authorized; the vault hash and manifest remain
  unchanged, and no Autofill or cloud state is written to the vault.
- Cleanup: Clear form fields and clipboard, close the vault, and remove the synthetic file and app-private copy.
- Required clients: Bonobo on Android and ChromeOS; Gorilla and Password Safe open the unchanged file afterward.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

### GOR-TEST-039 - Unlock with device authentication without vault metadata

- Authority: `Bonobo`.
- Evidence: Program design sections 9.1, 11, and 12.6.
- Synthetic setup: Open `PB-SYN-BASE` with its fabricated input on enrolled Android and ChromeOS test devices.
- Action: Enable biometric unlock, close and restart, cancel once, authenticate once, then change the master input.
- Expected observation: Cancel remains locked; authentication unlocks; the master-input change invalidates enrollment.
- Preservation requirement: Wrapped material stays device-bound; vault bytes and fields gain no biometric metadata.
- Cleanup: Revoke enrollment, remove device-bound test material, and delete the synthetic device copies.
- Required clients: Bonobo on Android and ChromeOS; Gorilla and Password Safe open the unchanged vault afterward.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

### GOR-TEST-040 - Restrict the iOS credential provider

- Authority: `Bonobo`.
- Evidence: Program design sections 9.2, 11, and 12.7.
- Synthetic setup: Open `PB-SYN-BASE` on iOS with a local relying party for `alpha.example.invalid`.
- Action: Request while locked, unlock, fill Alpha once, then attempt provider-only listing, URL-audit, publication,
  and export actions before relocking and requesting again.
- Expected observation: Locked access fails; the chosen fabricated credential fills once. The provider cannot
  independently enumerate decrypted vault records, initiate a URL audit, publish, or export the vault; relock blocks
  reuse, and no Bonobo cloud account or cloud copy exists.
- Preservation requirement: Vault bytes, UUIDs, unknown fields, and standard fields remain unchanged; no provider cache
  or cloud-matching metadata is stored in the PasswordSafe file.
- Cleanup: Clear relying-party fields, revoke extension access, and remove all synthetic copies and cached test state.
- Required clients: Bonobo on iOS; Gorilla at the pinned revision and Password Safe open the unchanged vault.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

### GOR-TEST-041 - Unlock with iOS device authentication without vault metadata

- Authority: `Bonobo`.
- Evidence: Program design sections 9.1, 11, and 12.7.
- Synthetic setup: Open `PB-SYN-BASE` with its fabricated input on an enrolled iOS test device.
- Action: Enable biometric unlock, close and restart, cancel once, authenticate once, then change the master input.
- Expected observation: Cancel remains locked; iOS biometric authentication unlocks; the input change invalidates it.
- Preservation requirement: Wrapped material stays device-bound; vault bytes and fields gain no biometric metadata.
- Cleanup: Revoke enrollment, remove device-bound test material, and delete the synthetic device copy.
- Required clients: Bonobo on iOS; Gorilla and Password Safe open the unchanged vault afterward.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

## Supplemental review-closure oracles

### GOR-TEST-042 - Preserve the active vault across lifecycle failures

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-002`, `GOR-BEH-004`, and `GOR-BEH-005`.
- Synthetic setup: Copy `PB-SYN-BASE` to `pb-syn-lifecycle-source.psafe3` and
  `pb-syn-lifecycle-readable.psafe3`; open the source, change its note to `fabricated pending note`, and retain its
  hash.
- Action: Resolve unsaved work before a new vault by choosing Cancel; attempt to open inaccessible
  `pb-syn-missing.psafe3`; then open `pb-syn-lifecycle-readable.psafe3` with wrong master input
  `fabricated-master-input-wrong`.
- Expected observation: The canceled new-vault request preserves the pending edit. The inaccessible path keeps its open
  prompt available. The wrong master input is cleared and retry remains possible. Neither failure replaces Alpha.
- Preservation requirement: The source bytes and hash remain unchanged; the pending in-memory note remains active.
- Cleanup: Cancel the prompt, discard the edit, close, and remove `pb-syn-lifecycle-source.psafe3` and
  `pb-syn-lifecycle-readable.psafe3`.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-043 - Save As and preserve data on writable-path failures

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-009` through `GOR-BEH-011`.
- Synthetic setup: Open three `PB-SYN-BASE` copies and give each a distinct fabricated note edit. Make copy two's
  destination read-only. Put copy three on a controlled filesystem that returns disk-full after 64 output bytes while
  leaving its existing destination readable; record each original destination hash and directory listing.
- Action: On copy one, cancel Save As, then save to `pb-syn-renamed.psafe3`. Save copy two and cancel at the read-only
  warning. Save copy three to exercise the caught write-stage failure.
- Expected observation: Save As cancel changes no path; success adopts the new path and clears dirty state. Read-only
  cancel leaves the edit dirty. The caught write-stage failure reports an error and leaves no temporary output.
- Preservation requirement: Failed and canceled runs leave original hashes unchanged; only successful Save As creates
  a file, whose full manifest equals its in-memory source plus the named note edit.
- Cleanup: Restore disposable permissions and fault controls, then remove all synthetic files and temporary outputs.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-044 - Create, validate, and delete fabricated entries

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-022` through `GOR-BEH-025`.
- Synthetic setup: Open five independent `PB-SYN-BASE` copies for create, fallback, two validation, and deletion runs.
  In validation copy A, prepare a new record with blank title, URL, and username, valid group `Research.Valid`, and
  password `fabricated-validation-a`. In separately reset validation copy B, prepare valid title `Valid Identity`,
  username `sample-valid`, password `fabricated-validation-b`, and malformed dot-prefixed group `.Bad`.
- Action: Create and accept Beta with a title; create Gamma with empty title to exercise title fallback from URL
  `https://gamma.example.invalid/`; attempt acceptance in validation copy A, then independently in validation copy B;
  delete Alpha in the fifth copy without confirmation.
- Expected observation: Beta appears and Gamma uses its URL as title. Validation copy A is rejected for missing
  identity; validation copy B is rejected for its group. Alpha disappears immediately without a confirmation.
- Preservation requirement: Each validation source hash and manifest remains unchanged; accepted creation and deletion
  are confined to their independent copies.
- Cleanup: Discard all dirty copies, close each vault, and remove every synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-045 - Delete groups safely and activate an entry

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-030` through `GOR-BEH-035`.
- Synthetic setup: Open three `PB-SYN-SECOND` copies; add fabricated empty group `Research.Empty` to two copies.
- Action: Delete the empty group in copy one. In copy two, delete the nonempty group `Research`, cancel, then confirm.
  In copy three, select Alpha and activate it twice with the configured action set to Edit.
- Expected observation: Empty deletion has no confirmation or dirty change. Nonempty cancel preserves all descendants;
  confirmation removes their complete UUID set and makes the copy dirty. Double activation opens Alpha's edit.
- Preservation requirement: Selection and activation change no vault bytes; canceled deletion preserves every record;
  confirmed deletion remains confined to its disposable copy.
- Cleanup: Cancel the edit, discard dirty changes, close all copies, and remove their synthetic files.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-046 - Observe X11 selection transfer and lock clearing

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-044` and `GOR-BEH-045`.
- Synthetic setup: On X11, open `PB-SYN-BASE`, enable auto-copy, and clear the test clipboard and selection.
- Action: Copy Alpha username; have a controlled second application make an actual X11 selection request; observe the
  resulting clipboard; lock without manual clearing, then request both clipboard and selection again.
- Expected observation: The selection request receives `sample-user` and schedules the fabricated password for the
  clipboard. Lock clears both owned values, so neither post-lock request returns fabricated credential text.
- Preservation requirement: Vault bytes and fields remain unchanged; captured fabricated text is held only in memory.
- Cleanup: Clear clipboard and selection, close both applications, and remove the synthetic file.
- Required clients: Gorilla at the pinned revision on X11; Bonobo validates only its lock-clear requirement.

### GOR-TEST-047 - Refuse deletion when archive validation fails

- Authority: `Bonobo`.
- Evidence: URL-audit design sections 8, 9, and 13; program design sections 6.3 and 8.
- Synthetic setup: Open `PB-SYN-SECOND` and select both fabricated records. A controlled fault filesystem acknowledges
  each new archive write but returns a valid one-record fabricated archive containing only Alpha on every later read.
- Action: Invoke `Archive & Delete Selected` once and acknowledge the archive validation failure.
- Expected observation: Archive validation fails visibly; no source deletion is staged, no row receives a deleted
  state, and the source manifest, dirty state, record count, complete UUID set, and encrypted hash remain unchanged.
- Preservation requirement: The fault archive cannot authorize deletion; retain source and pre-action hash exactly.
- Cleanup: Close the source unchanged and remove the fault archive, source copy, and disposable fault control.
- Required clients: Bonobo performs the fault case; no other client is required to accept the invalid archive.

### GOR-TEST-048 - Contrast stored-HMAC integrity-mismatch handling

- Authority: `PasswordSafe` + `Gorilla` + `Bonobo`.
- Evidence: `GOR-BEH-006` and `GOR-BEH-058`; program design section 10; official PasswordSafe `formatV3.txt`
  sections 2.8, 2.9, and 3.
- Synthetic setup: An official-format fixture authority copies `PB-SYN-BASE`, flips exactly one bit in its stored HMAC
  after the unencrypted end marker, and duplicates the result as two byte-identical stored-HMAC mismatch copies:
  `pb-syn-hmac-bonobo.psafe3` for Bonobo and `pb-syn-hmac-gorilla.psafe3` for Gorilla. Retain the unmodified baseline,
  byte offset, XOR mask, and both pre-open SHA-256 values; `pb-syn-hmac-bonobo-output.psafe3` begins absent.
- Action: Open the Bonobo copy with the correct fabricated master input and record the result. Separately open the
  Gorilla copy with that input, record and dismiss its warning, inspect Alpha, close without saving, and compare both
  source files with their pre-open controls.
- Expected observation: Gorilla opens with an integrity warning, shows Alpha's complete manifest, and leaves its source
  unchanged. Bonobo fails closed before an editable session exists, offers no Save, leaves its source unchanged, and
  creates no replacement, fallback rewrite, recovery file, or converted output.
- Preservation requirement: Both mismatch sources remain byte-for-byte equal to their pre-open controls, including the
  one-bit stored-HMAC change; their encrypted field bytes remain identical to the unmodified baseline.
- Cleanup: Close Gorilla without saving, dismiss Bonobo's error, assert that no output exists, and remove both mismatch
  sources, their controls, the unmodified baseline, and the absent-output sentinel path.
- Required clients: Bonobo and Gorilla at the pinned revision; PasswordSafe supplies the stored-HMAC integrity rule.

### GOR-TEST-049 - Distinguish initial and later backup failures

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-019`.
- Synthetic setup: Open two `PB-SYN-BASE` copies and give each a fabricated note edit. For copy one, keep the primary
  writable but deny creation at the initial-backup path. For copy two, permit primary and initial backup writes but deny
  creation in the configured later-backup directory.
- Action: Request close and Save on each copy; after the reported error, request close again without another edit.
- Expected observation: Both primary files contain their edited note. Initial-backup failure leaves dirty state and
  prompts to save again. Later-backup failure leaves clean state and the second close has no unsaved-work prompt.
- Preservation requirement: Each pre-run file is retained; primary output and backup results have separate hashes.
- Cleanup: Close or discard each run as needed, restore destination access, and remove all synthetic outputs.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-050 - Lock an untitled vault with backup behavior enabled

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-064`.
- Synthetic setup: Create two untitled vaults with fabricated Alpha content, enable backup-on-save behavior, and make
  the configured later-backup directory deny creation while the primary destination remains writable.
- Action: Lock copy one, choose No at the save prompt, and inspect its directory. Lock copy two, choose Yes, select
  `pb-syn-lock.psafe3`, allow a later backup failure, acknowledge the result, and unlock it.
- Expected observation: No creates no file and locking continues. Yes creates the primary file before the backup error;
  locking continues after the error, and unlock shows the saved fabricated Alpha content.
- Preservation requirement: No-path dismissal writes nothing; the Yes path retains its complete saved manifest.
- Cleanup: Close both vaults, restore backup access, and remove the synthetic primary and backup artifacts.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-051 - Fail closed on a synthetic unsupported major format

- Authority: `Bonobo`.
- Evidence: Program design section 10; official PasswordSafe `formatV3.txt` sections 1.2, 2.9.1, and 3.2 note 1.
- Synthetic setup: An independent official-format fixture authority creates the fabricated file
  `pb-syn-unsupported-major.psafe3` as a structurally valid authenticated envelope. Header Version field type `0x00`
  declares length 2 and holds bytes `00 04`, the little-endian value `0x0400`. Header END, every mandatory record
  field, record END, EOF, and stored HMAC are valid. This is a synthetic later-major 4.0 probe, not an actual V4
  format or product claim, and the mandatory Version value is not an unknown preservable field.
- Action: Record the complete encrypted input and SHA-256, attempt ordinary Open in Bonobo once, and dismiss the error.
- Expected observation: Bonobo classifies the input as unsupported major content, fails closed before an editable
  session exists, and offers no Save or conversion action; it does not classify the structurally valid field as
  malformed mandatory content.
- Preservation requirement: The original encrypted file's bytes and SHA-256 remain exactly unchanged; no output
  replacement, fallback rewrite, converted copy, or recovery file occurs.
- Cleanup: Retain only the non-sensitive hash and error classification, then remove the unsupported synthetic input.
- Required clients: Bonobo; the official PasswordSafe format supplies byte order and major-version authority.
- Coverage: unsupported-major-fail-closed; unsupported-fail-closed-original-bytes.

### GOR-TEST-052 - Contrast a missing mandatory Version field

- Authority: `PasswordSafe` + `Gorilla` + `Bonobo`.
- Evidence: `GOR-BEH-058`; program design section 10; official PasswordSafe `formatV3.txt` sections 2.9.1, 2.11,
  and 3.2 note 1; pinned locations `sources/pwsafe/pwsafe-v3.tcl:176-183`, `sources/gorilla.tcl:4494-4520`, and
  `sources/gorilla.tcl:4584-4636`.
- Synthetic setup: An official-format authority creates a fabricated authenticated missing-Version input and makes
  two byte-identical copies, `pb-syn-missing-version-bonobo.psafe3` for Bonobo and
  `pb-syn-missing-version-gorilla.psafe3` for Gorilla. It omits Version type `0x00`; database UUID type `0x01` is
  `11111111-1111-4111-8111-111111111111`, Preferences type `0x02` has an empty UTF-8 value, and header END is valid.
  Its Alpha record has UUID `22222222-2222-4222-8222-222222222222`, mandatory Title `Alpha`, mandatory Password
  `fabricated password 1`, record END, EOF, and a stored HMAC over every plaintext field present. Record both hashes;
  `pb-syn-bonobo-rejected.psafe3` begins absent as the Bonobo output sentinel.
- Action: Attempt Open on the Bonobo source with the fabricated master input and inspect the error and directory.
  Separately open the Gorilla source, use Save As to create `pb-syn-defaulted-version.psafe3`, wait for success, close,
  and inspect both sources, the named output, and mandatory initial `pb-syn-defaulted-version.bak` read-only.
- Expected observation: Bonobo fails closed, keeps its source bytes and hash unchanged, creates no output, and offers no
  editable session or Save. Gorilla opens through its evidenced in-memory V3.0 fallback. Its named output contains a
  Version field type `0x00`, length 2, and bytes `00 03`; database UUID, record UUID, and user-authored record values
  match the input manifest. The named output and initial `.bak` are byte-identical.
- Preservation requirement: Both missing-Version source files remain byte-identical to their controls. Source-to-output
  comparison covers Version, database UUID, record UUID, and user-authored record semantics, not ciphertext, field
  order, padding, or writer-owned Preferences serialization and header normalization. The output-to-backup comparison
  covers every byte.
- Cleanup: Dismiss Bonobo's error, close Gorilla, and remove the Bonobo source, Gorilla source, named output, initial
  `.bak`, absent-output sentinel, controls, hashes, and non-sensitive manifests.
- Required clients: Bonobo and Gorilla at the pinned revision; PasswordSafe supplies mandatory-field authority.

### GOR-TEST-053 - Compare observable ordinary semantic-save transactions

- Authority: `Gorilla` + `Bonobo`.
- Evidence: `GOR-BEH-008`; program design sections 6.2, 10, and 11; pinned locations
  `sources/gorilla.tcl:4382-4407` and `sources/gorilla.tcl:4584-4636`.
- Synthetic setup: Prepare four independent `PB-SYN-BASE` copies whose Alpha note is `fabricated note A`: Gorilla
  success, Gorilla failure, Bonobo success, and Bonobo failure. Retain a read-only control for each. Disable Gorilla's
  later backup; its initial `.bak` paths begin absent. External disposable filesystem gates can pause or deny only the
  named backup or publication destination without changing any source or control.
- Action: For Gorilla success, change the note to `fabricated Gorilla saved`, invoke Save once, pause initial `.bak`
  creation, snapshot the completed primary and dirty indicator, then release the gate and close. For Gorilla failure,
  change it to `fabricated Gorilla failed`, deny initial `.bak`, invoke Save, record the error, and request close.
  For Bonobo success, change the note to `fabricated Bonobo saved`, invoke Save, wait until Save returns success, then
  request close. For Bonobo failure, change it to `fabricated Bonobo pending`, allow a validated encrypted recovery copy
  but deny primary publication, invoke Save, record the error, and request close. Reopen completed artifacts read-only.
- Expected observation: Gorilla success publishes its edited primary before initial backup starts; dirty remains set at
  the pause, its initial `.bak` then contains `fabricated Gorilla saved`, and dirty clears only after both succeed, so
  close does not prompt. Gorilla failure leaves an edited primary containing `fabricated Gorilla failed`, no initial
  `.bak`, dirty set, and a close prompt. Bonobo success returns only after its primary authenticates with
  `fabricated Bonobo saved`; dirty is clear and close does not prompt. This contract prescribes no Bonobo write order.
  Bonobo failure leaves the last validated primary unchanged with `fabricated note A`, retains an authenticating
  encrypted recovery copy containing `fabricated Bonobo pending`, keeps dirty set, and presents a close prompt.
- Preservation requirement: Every completed primary, Gorilla initial backup, and Bonobo recovery copy retains Alpha's
  UUID, unrelated standard fields, field order where required, and unknown bytes. Bonobo and Gorilla each open the
  other's successful primary and observe only its exact note edit; no client publishes plaintext recovery data.
- Cleanup: Resolve each close prompt by discarding only the pending in-memory edit, restore destination access, and
  remove all four sources, controls, snapshots, initial backups, encrypted recovery copies, and manifests.
- Required clients: Bonobo and Gorilla at the pinned revision perform their named operations and cross-open successes.

## Extension metadata gate

No oracle above approves a persistent Bonobo field. For any future candidate, duplicate the exact synthetic vault,
name the field type and fabricated bytes, round-trip it independently through the claimed Gorilla and Password Safe
versions, and compare type, bytes, UUIDs, format level, and all unrelated fields. Any loss, rewrite, warning, or
unavailable client keeps that field disabled or moves the state to a separately encrypted Bonobo document.
