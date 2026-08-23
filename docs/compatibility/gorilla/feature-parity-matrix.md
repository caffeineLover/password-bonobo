# Password Bonobo Feature-Parity Matrix

## Contract boundaries

- PasswordSafe format authority governs file syntax, standard fields, identifiers, and lossless preservation.
- A Gorilla-compatible requirement is claimed only from `Confirmed` or `Supported` dossier evidence.
- A Bonobo product decision comes only from an approved Bonobo specification, not from Gorilla evidence.
- An Unresolved evidence gap remains a research item and never establishes parity by inference.
- No Bonobo metadata extension is approved for storage in a PasswordSafe file by this contract.
- Deferred native capability boundary: native features are scheduled to their named owner and are not current parity.

The complete disposition vocabulary is `Required`, `Modernized`, `Deferred`, `Excluded`, `Bonobo extension`, and
`Unverified`. The `Bonobo extension` rows identify origin, not implementation status. Their native delivery is
deferred to the owner shown below. Biometric unlock has separate Android/ChromeOS and iOS delivery rows so each row
has one owner. Gorilla and Password Safe are asked only to preserve ordinary PasswordSafe data; this matrix does not
assert that either client understands Bonobo-native behavior or Bonobo metadata.

An `Excluded` row records an intentional Bonobo divergence and is not a Gorilla compatibility requirement. It remains
in the matrix so that the rejected upstream behavior and the governing Bonobo product rule are both testable.

## Keys

Owners are the eight exact subproject names from the approved program design:

- O1: Repository foundation and compatibility dossier.
- O2: Lossless PasswordSafe core.
- O3: Vault application core and desktop foundation.
- O4: URL audit and cleanup.
- O5: Provider-safe files and conflict resolution.
- O6: Android and ChromeOS.
- O7: iOS.
- O8: Parity closure and stable release.

Platform keys are normative:

- D: Desktop (Windows, macOS, Linux).
- A: Android.
- C: ChromeOS.
- I: iOS.
- B: BSD.
- ALL: D/A/C/I/B.

Evidence keys use the accepted behavior IDs in
[the neutral dossier](./behavior-dossier.md). A range includes both endpoints. `GAP` keys resolve in the register
below. Approved specification keys are `S4` for URL-audit design sections 5–14, `S5` for program design sections 6–7,
`S6` for program design section 9.1, `S7` for program design section 9.2, and `S8` for program design section 10. A `+`
joins approved keys when both independently govern the row.
Test IDs resolve in
[the black-box oracle catalog](./test-oracles.md).

## Matrix

| ID | Feature family | Disposition | Evidence | Owner | Platforms | Data-loss | Security | Tests |
|---|---|---|---|---|---|---|---|---|
|GOR-FEAT-001|Vault lifecycle|Required|GOR-BEH-001–005|O3|ALL|Critical|Critical|GOR-TEST-001,GOR-TEST-003,GOR-TEST-042|
| GOR-FEAT-002 | Master-password change | Required | GOR-BEH-007 | O2 | ALL | Critical | Critical | GOR-TEST-002 |
|GOR-FEAT-003|Save path/write guards|Required|GOR-BEH-009–011|O2|ALL|Critical|Critical|GOR-TEST-043|
| GOR-FEAT-004 | Close guards | Modernized | GOR-BEH-012–014 | O3 | ALL | Critical | Material | GOR-TEST-004 |
|GOR-FEAT-005|Entry lifecycle|Modernized|GOR-BEH-022–025|O3|ALL|Critical|Critical|GOR-TEST-005, GOR-TEST-044|
|GOR-FEAT-006|Groups|Modernized|GOR-BEH-030–035|O3|ALL|Critical|Material|GOR-TEST-006, GOR-TEST-045|
| GOR-FEAT-007 | Search | Modernized | GOR-BEH-036 | O3 | ALL | Routine | Material | GOR-TEST-007 |
| GOR-FEAT-008 | Filter gap | Unverified | GOR-BEH-037; GAP-037 | O8 | D/B | Routine | Material | GOR-TEST-008 |
| GOR-FEAT-009 | Generator and policies | Modernized | GOR-BEH-041 | O3 | ALL | Material | Critical | GOR-TEST-009 |
| GOR-FEAT-010 | History gap | Unverified | GOR-BEH-027; GAP-027 | O8 | ALL | Critical | Critical | GOR-TEST-010 |
| GOR-FEAT-011 | Aliases gap | Unverified | GOR-BEH-028; GAP-028 | O8 | ALL | Critical | Critical | GOR-TEST-011 |
|GOR-FEAT-012|Record shortcuts|Unverified|GOR-BEH-029; GAP-029|O8|ALL|Critical|Material|GOR-TEST-012|
| GOR-FEAT-013 | Protected entries | Unverified | GOR-BEH-026; GAP-026 | O8 | ALL | Critical | Critical | GOR-TEST-013 |
|GOR-FEAT-014|Clipboard|Modernized|GOR-BEH-044–045|O3|ALL|Routine|Critical|GOR-TEST-014, GOR-TEST-046|
| GOR-FEAT-015 | URL-copy key gap | Unverified | GOR-BEH-043; GAP-043 | O8 | D/B | Routine | Critical | GOR-TEST-015 |
| GOR-FEAT-016 | Browser launch | Modernized | GOR-BEH-046 | O3 | ALL | Routine | Material | GOR-TEST-016 |
| GOR-FEAT-017 | Browser error gap | Unverified | GOR-BEH-047; GAP-047 | O8 | D/B | Routine | Material | GOR-TEST-017 |
| GOR-FEAT-018 | AutoType gap | Unverified | GOR-BEH-048; GAP-048 | O8 | D/B | Critical | Critical | GOR-TEST-018 |
| GOR-FEAT-019 | CSV import | Required | GOR-BEH-050–051 | O3 | ALL | Critical | Material | GOR-TEST-019 |
| GOR-FEAT-020 | CSV export | Required | GOR-BEH-049 | O3 | ALL | Critical | Critical | GOR-TEST-020 |
|GOR-FEAT-021|Merge|Modernized|GOR-BEH-052–054|O3|ALL|Critical|Critical|GOR-TEST-021,GOR-TEST-055|
| GOR-FEAT-022 | Interruption gap | Unverified | GOR-BEH-060; GAP-060 | O8 | ALL | Critical | Material | GOR-TEST-022 |
|GOR-FEAT-023|Backup/recovery|Modernized|GOR-BEH-019–021|O3|ALL|Critical|Critical|GOR-TEST-023,GOR-TEST-049|
| GOR-FEAT-024 | Backup gap | Unverified | GOR-BEH-018; GAP-018 | O8 | D/B | Critical | Material | GOR-TEST-024 |
|GOR-FEAT-025|Preferences|Modernized|GOR-BEH-039–040, GOR-BEH-061|O3|D/B|Material|Material|GOR-TEST-025|
| GOR-FEAT-026 | Recent files | Modernized | GOR-BEH-038 | O3 | ALL | Routine | Material | GOR-TEST-026 |
| GOR-FEAT-027 | Locking/idle | Modernized | GOR-BEH-015–017 | O3 | ALL | Critical | Critical | GOR-TEST-027 |
| GOR-FEAT-028 | PasswordSafe versions | Required | GOR-BEH-055–057 | O2 | ALL | Critical | Critical | GOR-TEST-028 |
|GOR-FEAT-029|Mandatory validation|Required|GOR-BEH-058; Approved:S8|O2|ALL|Critical|Critical|GOR-TEST-029,GOR-TEST-051|
| GOR-FEAT-030 | Lock-file gap | Unverified | GOR-BEH-059; GAP-059 | O8 | D/B | Critical | Critical | GOR-TEST-030 |
| GOR-FEAT-031 | Errors | Modernized | GOR-BEH-062 | O3 | ALL | Critical | Material | GOR-TEST-031 |
| GOR-FEAT-032 | Localization gap | Unverified | GOR-BEH-062; GAP-900 | O8 | ALL | Routine | Material | GOR-TEST-032 |
|GOR-FEAT-033|Help|Unverified|GAP-901|O8|ALL|Routine|Material|GOR-TEST-033|
|GOR-FEAT-034|Accessibility-relevant keyboard|Modernized|GOR-BEH-042|O3|D/B|Routine|Routine|GOR-TEST-034|
| GOR-FEAT-035 | Replacement gap | Unverified | GOR-BEH-065; GAP-065 | O8 | ALL | Critical | Critical | GOR-TEST-035 |
|GOR-FEAT-036|URL audit and cleanup|Bonobo extension|Approved:S4|O4|ALL|Critical|Critical|GOR-TEST-036, GOR-TEST-047|
|GOR-FEAT-037|Provider conflict safety|Bonobo extension|Approved:S5|O5|ALL|Critical|Critical|GOR-TEST-037|
| GOR-FEAT-038 | Android Autofill | Bonobo extension | Approved:S7 | O6 | A/C | Critical | Critical | GOR-TEST-038 |
|GOR-FEAT-039|Biometric unlock - Android/ChromeOS|Bonobo extension|Approved:S6|O6|A/C|Critical|Critical|GOR-TEST-039|
|GOR-FEAT-040|iOS credential provider|Bonobo extension|Approved:S7|O7|I|Critical|Critical|GOR-TEST-040|
|GOR-FEAT-041|Biometric unlock - iOS|Bonobo extension|Approved:S6|O7|I|Critical|Critical|GOR-TEST-041|
|GOR-FEAT-042|Untitled-vault lock save|Modernized|GOR-BEH-064|O3|ALL|Critical|Critical|GOR-TEST-050|
|GOR-FEAT-043|Fail-open|Excluded|GOR-BEH-006,GOR-BEH-066;Approved:S8|O2|ALL|Critical|Critical|GOR-TEST-048,GOR-TEST-052|
|GOR-FEAT-044|Ordinary-edit persistence|Required|GOR-BEH-008; Approved:S5+S8|O2|ALL|Critical|Critical|GOR-TEST-053|
|GOR-FEAT-045|Gorilla post-save resolution loss|Excluded|GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-054|

`GOR-FEAT-043` deliberately excludes two atomic Gorilla outcomes: `GOR-BEH-006` warning-open for a stored-HMAC mismatch
and `GOR-BEH-066` in-memory V3.0 defaulting when Version is absent. The official V3 Version header is mandatory and has
two data bytes. Bonobo program design section 10 instead requires unsupported or malformed content to fail closed,
retain the original encrypted bytes, and create no replacement. The row does not include `GOR-BEH-058` rejection.

`GOR-FEAT-044` requires observable ordinary-edit persistence and no loss, not a shared Save gesture. Gorilla uses its
explicit Save and backup path. Bonobo commits an ordinary edit when its complete form is confirmed; provider
unavailability retains the encrypted local edit as `Sync pending`. Save/discard close prompts belong only to staged
URL-audit cleanup.

`GOR-FEAT-021` preserves normal merge classification, field-by-field resolution, and unresolved-record preservation
without inheriting the destructive close outcome in `GOR-BEH-063`.  Bonobo's no-loss authority requires a confirmed
resolution or deletion to become transactional durable work before close.  If provider publication cannot complete,
the work remains explicitly staged or conflicted and silent discard is blocked.

`GOR-FEAT-045` isolates `GOR-BEH-063` as an Excluded Gorilla-only characterization.  It is neither a modernized Bonobo
merge behavior nor a cross-implementation passing oracle.

## Evidence-gap register

- GAP-018: backup enablement is contradictory; a disabled-preference black-box observation is missing.
- GAP-026: protected-entry preservation and enforcement lack direct format evidence and a visible test.
- GAP-027: password-history creation, retention, restoration, and deletion have no visible workflow evidence.
- GAP-028: alias identity, target preservation, and target-deletion effects lack a format example and visible test.
- GAP-029: record-shortcut identity and target behavior lack a format example and visible test.
- GAP-037: Gorilla evidence establishes search but no distinct filter workflow or visible result.
- GAP-043: help and active key binding conflict; per-platform observation is missing.
- GAP-047: the browser failure distinctions lack an executable observation for the missing-URL result.
- GAP-048: AutoType storage is recognized, but its user action, output, and platform behavior are not evidenced.
- GAP-059: concurrent open/save, overwrite prevention, read-only fallback, and stale locks lack a two-process test.
- GAP-060: interrupted import and merge outcomes with autosave enabled and disabled are not evidenced.
- GAP-065: replacement failure and process or system interruption lack controlled fault observations.
- GAP-900: message evidence exists, but locale selection, fallback, and live retranslation are not evidenced.
- GAP-901: dossier citations use help for other behaviors, but establish no Help workflow or topic reachability.

## Closure rules

`Unverified` rows are explicit gaps, not parity commitments. Their oracles collect missing black-box evidence; they do
not prescribe a Bonobo result until the dossier and matrix are reviewed. All other Gorilla rows preserve only the
neutral observable contract and allow a modern interaction design.

PasswordSafe rows require semantic and unknown-field preservation independent of Gorilla's current behavior. The
Bonobo-extension rows persist no custom PasswordSafe metadata under this contract. Native state such as provider
revisions, wrapped unlock material, and extension caches stays outside the vault. A future metadata field requires a
new, field-specific Gorilla and Password Safe round trip before its matrix disposition can change.
