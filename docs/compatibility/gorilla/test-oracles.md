# Password Bonobo Black-Box Test Oracles

## Authority and scope

These scenarios specify observable inputs and outcomes, not internal design:

- `PasswordSafe` means the official format is authoritative for file structure, fields, and preservation.
- `Gorilla` means the pinned dossier observation is the compatibility authority.
- `Bonobo` means an approved Bonobo specification is the product authority.

A Gorilla oracle marked as an evidence-gap closure test records the pinned client's result before any parity claim is
approved. A Bonobo-native feature is not a Gorilla feature. Its cross-client step proves only that ordinary
PasswordSafe data remains usable; it never claims that Gorilla or Password Safe understands native state.

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
- Evidence: `GOR-BEH-001` through `GOR-BEH-006`.
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
- Evidence: Program design sections 4 and 11; `GOR-BEH-008` through `GOR-BEH-011`.
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
- Evidence: Program design section 4; `GOR-BEH-022` through `GOR-BEH-025` and `GOR-BEH-057`.
- Synthetic setup: Copy `PB-SYN-BASE`; retain its fabricated manifest and both unknown field byte sequences.
- Action: Change only the title to `Alpha Portal Renamed`, save, reopen, then delete the record and discard on close.
- Expected observation: Reopen shows only the title change; discarded deletion leaves the saved renamed record intact.
- Preservation requirement: All unrelated standard values, UUIDs, unknown types, and unknown bytes remain identical.
- Cleanup: Remove the renamed synthetic copy.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe.
- Coverage: known-field-unknown-field-preservation.

### GOR-TEST-006 - Move and rename a group safely

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-030` through `GOR-BEH-035`.
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
- Evidence: `GOR-BEH-027`; `GAP-027` in the feature matrix.
- Synthetic setup: Open a format-valid `PB-SYN-BASE` copy with fabricated history values `old-one` and `old-two`.
- Action: View history if available, change the password to `fabricated-new-value`, save, close, and reopen.
- Expected observation: Record visible history and the exact saved history field before and after the change.
- Preservation requirement: No retention or restoration parity claim passes until the observation updates the dossier.
- Cleanup: Remove the copy and the fabricated history manifest.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-011 - Characterize alias behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-028`; `GAP-028` in the feature matrix.
- Synthetic setup: Use `PB-SYN-SECOND` as a fabricated alias to `PB-SYN-BASE` by their defined UUIDs.
- Action: Activate, copy from, edit, export, and attempt to delete the fabricated alias and then its target.
- Expected observation: Record the visible target, copied value, mutations, export result, and deletion effects exactly.
- Preservation requirement: Keep the original encrypted fixture; no alias parity claim passes before dossier review.
- Cleanup: Close without saving and remove the synthetic alias copy and captured non-secret results.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-012 - Characterize record-shortcut behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-029`; `GAP-029` in the feature matrix.
- Synthetic setup: Use `PB-SYN-SECOND` as a fabricated shortcut to `PB-SYN-BASE` by their defined UUIDs.
- Action: Activate, edit, export, and attempt to delete the shortcut and then the target in separate disposable copies.
- Expected observation: Record navigation, mutation, export, and target-deletion effects for each copy exactly.
- Preservation requirement: Keep both original encrypted copies; no shortcut parity claim passes before dossier review.
- Cleanup: Close without saving and remove the shortcut copies and captured non-secret results.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-013 - Characterize protected-entry behavior

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-026`; `GAP-026` in the feature matrix.
- Synthetic setup: Open a format-valid protected `PB-SYN-BASE` record with only fabricated values.
- Action: Attempt edit, deletion, export, merge, username copy, and password copy in separate disposable copies.
- Expected observation: Record which actions are blocked, confirmed, or allowed and every resulting file manifest.
- Preservation requirement: Keep the original encrypted fixture; no protection parity claim passes before review.
- Cleanup: Close without saving and remove all protected-entry copies and non-secret result notes.
- Required clients: Gorilla at the pinned revision; Password Safe supplies the format-valid fixture.

### GOR-TEST-014 - Copy and clear fabricated values

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-044` and `GOR-BEH-045`.
- Synthetic setup: Open `PB-SYN-BASE`; set the clear interval to one second using only fabricated values.
- Action: Copy username, wait for clearing, copy password, clear manually, then lock the vault.
- Expected observation: Each requested value appears only until the timer, manual clear, or lock removes it.
- Preservation requirement: Vault bytes and fields remain unchanged; copied text never enters logs or result files.
- Cleanup: Clear the clipboard, close the vault, and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision; X11 auto-copy is checked only on X11.

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
- Synthetic setup: Create fabricated UTF-8 CSV rows for Alpha, a malformed row, and Beta in that order.
- Action: Import once, inspect results, save, close, and reopen the vault.
- Expected observation: Alpha and Beta exist, the malformed row is reported and absent, and partial success is visible.
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
- Action: Save the unresolved pair; reopen, combine to the original title, close, and reopen again.
- Expected observation: The saved pair survives; a post-save combine is not silently treated as durable.
- Preservation requirement: Both pre-combine records remain recoverable until an explicit successful save.
- Cleanup: Remove the merged synthetic file and both source copies.
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
- Evidence: `GOR-BEH-019` through `GOR-BEH-021` and `GOR-BEH-064`.
- Synthetic setup: Save `PB-SYN-BASE`, change note to `fabricated note recovered`, and retain its backup copy.
- Action: Remove only the active disposable copy, reopen the backup, verify identity, and save it under a new name.
- Expected observation: The backup opens with the expected UUID and note; no forgotten-input recovery is offered.
- Preservation requirement: Recovery never overwrites the retained backup and never invents unsaved content.
- Cleanup: Remove the recovered copy, backup, and original synthetic file.
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
- Evidence: `GOR-BEH-015` through `GOR-BEH-017` and `GOR-BEH-064`.
- Synthetic setup: Open `PB-SYN-BASE`, set one-minute idle lock, and make fabricated note `pending before lock`.
- Action: Copy the username, wait without activity, unlock with the master input, then save and reopen.
- Expected observation: Lock clears copied text and conceals views; unlock restores the pending note, which then saves.
- Preservation requirement: Lock alone neither discards nor saves the pending edit; all other fields remain unchanged.
- Cleanup: Clear the clipboard, reset the disposable idle setting, and remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-028 - Preserve format level and unknown fields

- Authority: `PasswordSafe`.
- Evidence: Program design section 4; `GOR-BEH-055` through `GOR-BEH-057`.
- Synthetic setup: Use fabricated supported older V3 and current V3 files with the `PB-SYN-BASE` unknown fields.
- Action: Open and save each without migration consent, then reopen in all required clients.
- Expected observation: Each declared level stays unchanged; every standard field and UUID is readable.
- Preservation requirement: Unknown field types and bytes survive exactly; no silent format-level increase occurs.
- Cleanup: Remove all saved synthetic version copies.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe.

### GOR-TEST-029 - Fail closed on unsupported or malformed content

- Authority: `PasswordSafe`.
- Evidence: Program design section 10; `GOR-BEH-058` and `GOR-BEH-065`.
- Synthetic setup: Copy `PB-SYN-BASE`; make one unsupported critical-field copy and one truncated-field copy.
- Action: Record each encrypted hash, attempt to open and save each copy, dismiss the error, and hash again.
- Expected observation: Neither copy opens as an editable vault and no save or replacement occurs.
- Preservation requirement: Both original encrypted byte sequences and hashes remain exactly unchanged.
- Cleanup: Remove the two malformed synthetic copies after retaining only non-sensitive error categories.
- Required clients: Bonobo; Password Safe supplies the format authority for the fabricated invalid cases.
- Coverage: unsupported-fail-closed-original-bytes.

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
- Synthetic setup: Open `PB-SYN-BASE` under default, one available non-default, and unavailable fabricated locales.
- Action: Trigger the same empty-title error in each run and restart after each locale choice.
- Expected observation: Record selected locale, fallback, error language, missing-key display, and restart requirement.
- Preservation requirement: No localization parity claim passes before review; vault bytes remain unchanged.
- Cleanup: Restore the disposable locale profile and remove the synthetic vault and observation note.
- Required clients: Gorilla at the pinned revision; Bonobo only after the gap result is approved.

### GOR-TEST-033 - Reach task help without exposing secrets

- Authority: `Gorilla`.
- Evidence: `GOR-BEH-001`, `GOR-BEH-020`, and the dossier help evidence cited throughout.
- Synthetic setup: Open `PB-SYN-BASE` and keep all fabricated credential fields concealed.
- Action: Request help for opening, forgotten master input, entry editing, export, merge, and locking.
- Expected observation: Each topic is reachable and describes the user task without revealing record values.
- Preservation requirement: Help access does not change the vault, clipboard, recent files, or encrypted hash.
- Cleanup: Close help and the vault, then remove the synthetic file.
- Required clients: Bonobo and Gorilla at the pinned revision.

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

### GOR-TEST-036 - Audit, archive, stage deletion, and discard cleanup

- Authority: `Bonobo`.
- Evidence: URL-audit design sections 5 through 14 and program design sections 6.3 and 8.
- Synthetic setup: Add URL `https://audit.example.invalid/path?mode=fabricated#review` to `PB-SYN-BASE`.
- Action: Save note `fabricated ordinary edit`; audit through a controlled endpoint; select Alpha; archive to
  `pb-syn-archive.psafe3`; reopen the archive; stage deletion; discard only the staged cleanup; reopen the main file.
- Expected observation: The request contains only `https://audit.example.invalid/path`; archive UUID matches Alpha;
  the row reads `Archived & deleted (unsaved)` before discard; the saved ordinary note remains after discard.
- Preservation requirement: Query, fragment, title, group, username, UUID, and vault identity never enter the request;
  no deletion precedes archive reopen and identity verification; no custom audit field enters either vault.
- Cleanup: Cancel requests, clear result rows, close both vaults, and remove archive and main synthetic files.
- Required clients: Bonobo, Gorilla at the pinned revision, and Password Safe open the final main and archive files.
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
- Action: Focus username, choose Alpha from Autofill, accept fill, lock Bonobo, and request Autofill again.
- Expected observation: The first request fills only `sample-user` and the fabricated password; locked access fails.
- Preservation requirement: The vault hash and manifest remain unchanged; no Autofill state is written to the vault.
- Cleanup: Clear form fields and clipboard, close the vault, and remove the synthetic file and app-private copy.
- Required clients: Bonobo on Android and ChromeOS; Gorilla and Password Safe open the unchanged file afterward.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

### GOR-TEST-039 - Unlock with device authentication without vault metadata

- Authority: `Bonobo`.
- Evidence: Program design sections 9.1, 11, 12.6, and 12.7.
- Synthetic setup: Open `PB-SYN-BASE` with its fabricated input on enrolled Android and iOS test devices.
- Action: Enable biometric unlock, close and restart, cancel once, authenticate once, then change the master input.
- Expected observation: Cancel remains locked; authentication unlocks; the master-input change invalidates enrollment.
- Preservation requirement: Wrapped material stays device-bound; vault bytes and fields gain no biometric metadata.
- Cleanup: Revoke enrollment, remove device-bound test material, and delete the synthetic device copies.
- Required clients: Bonobo on Android and iOS; Gorilla and Password Safe open the unchanged vault afterward.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

### GOR-TEST-040 - Restrict the iOS credential provider

- Authority: `Bonobo`.
- Evidence: Program design sections 9.2, 11, and 12.7.
- Synthetic setup: Open `PB-SYN-BASE` on iOS with a local relying party for `alpha.example.invalid`.
- Action: Request credentials while locked, unlock, choose Alpha, fill once, relock, and reopen the vault externally.
- Expected observation: Locked enumeration fails; the chosen fabricated credential fills once; relock blocks reuse.
- Preservation requirement: Vault bytes, UUIDs, unknown fields, and standard fields remain unchanged; no provider cache
  or matching metadata is stored in the PasswordSafe file.
- Cleanup: Clear relying-party fields, revoke extension access, and remove all synthetic copies and cached test state.
- Required clients: Bonobo on iOS; Gorilla at the pinned revision and Password Safe open the unchanged vault.
- Coverage: cross-client-extension-gate; deferred-native-no-vault-metadata.

## Extension metadata gate

No oracle above approves a persistent Bonobo field. For any future candidate, duplicate the exact synthetic vault,
name the field type and fabricated bytes, round-trip it independently through the claimed Gorilla and Password Safe
versions, and compare type, bytes, UUIDs, format level, and all unrelated fields. Any loss, rewrite, warning, or
unavailable client keeps that field disabled or moves the state to a separately encrypted Bonobo document.
