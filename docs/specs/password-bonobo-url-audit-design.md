# Password Bonobo URL Audit and Cleanup — Design Specification

Date: 2026-08-22
Status: Approved design, pending implementation plan
Target: Password Bonobo (native Tcl/Tk implementation based on Password Gorilla)

## 1. Purpose

Add a native Password Bonobo feature, based on Password Gorilla, that audits login entries with populated URL fields,
identifies websites that are likely obsolete or require human review, and supports safe bulk cleanup of obsolete
credentials.

The primary user goal is to reduce the size of a large Password Gorilla database by finding credentials for websites
that are no longer useful and deleting them deliberately. The feature must prioritize reviewability and data safety
over aggressive automatic classification.

## 2. Core Principles

1. The scanner never automatically deletes or modifies password entries.
2. Network classification is advisory. The user makes the final decision.
3. Ambiguous results are classified as `Needs Review`, not `Dead`.
4. Deletion changes only the in-memory database until the user invokes Gorilla's normal Save command.
5. Archiving is an explicit export to a separate encrypted PasswordSafe/Gorilla database file, not an “archived” flag
   on an entry.
6. `Archive & Delete Selected` is the primary cleanup action; `Delete Selected` is secondary.
7. Archive creation must succeed completely before any selected entry is deleted from memory.
8. The scanner must not transmit usernames, passwords, notes, query strings, fragments, or other credential contents.

## 3. Scope

### 3.1 In scope

- Scan every login entry with a nonempty URL field.
- Normalize web URLs for testing without modifying stored values.
- Strip query strings and fragments from the network request.
- Check URLs asynchronously while keeping the Tk UI responsive.
- Follow a bounded number of redirects.
- Classify results as `Working`, `Needs Review`, `Dead`, or `Not Checked`.
- Detect common parked/domain-for-sale pages conservatively.
- Show URL hygiene warnings independently from website-health status.
- Present results in a modeless review window.
- Allow browser opening, jumping to the corresponding Gorilla entry, and rechecking individual rows.
- Support bulk selection and deletion.
- Support exporting selected records to a new encrypted `.psafe3` archive before deletion.
- Use the current database master password by default for the archive, with an option to choose a different password.
- Preserve the original on-disk database until the user explicitly saves it.

### 3.2 Out of scope for version 1

- Automatically deleting entries.
- Automatically saving the cleaned main database.
- Clearing only the URL field.
- Adding an archive flag to the PasswordSafe record format.
- Appending to an existing archive database.
- Overwriting an existing archive database.
- Automatically rewriting stored URLs after redirects.
- Logging in to websites or submitting credentials.
- Executing JavaScript or behaving as a full browser.
- Following non-web schemes such as `ftp:`, `ssh:`, or custom application schemes.

## 4. Entry Point

Add a command under the existing Login menu:

`Login -> Audit Website URLs...`

The command is available only when a database is open.

A new top-level Tools menu is not introduced for version 1.

## 5. URL Collection and Normalization

For each login entry:

1. Read the URL field.
2. Skip entries whose URL is empty or whitespace only.
3. Preserve the original URL exactly as stored for display and later browser opening.
4. Construct a separate audit URL used only for network testing.
5. Remove the fragment (`#...`) from the audit URL.
6. Remove the query string (`?...`) from the audit URL.
7. If the URL has an explicit `https://` scheme, test it as written after sanitization.
8. If the URL has an explicit `http://` scheme, test it as written after sanitization and permit a normal redirect to
   HTTPS.
9. If no scheme is present, try `https://` first. Only if that fails in a way consistent with there being no usable
   HTTPS endpoint may the checker attempt `http://`.
10. If an explicit non-HTTP(S) scheme is present, classify the entry `Not Checked`.
11. Malformed values that cannot be safely normalized are `Not Checked`, never `Dead`.

Normalization never changes the URL stored in the database.

## 6. URL Hygiene Warnings

Website health and URL hygiene are separate dimensions.

Possible hygiene notes include:

- `Query parameters`
- `Fragment`
- `Potentially sensitive parameters`

A URL remains `Working` if the website works even when a hygiene warning is present.

Potentially sensitive query parameter names should be detected case-insensitively using a conservative list such as:

- `token`
- `auth`
- `key`
- `session`
- `code`
- `password`
- `passwd`
- `reset`
- `email`
- `user`
- `username`
- `account`

Only parameter names are inspected for warning purposes. Parameter values must not be logged, transmitted, or copied
into diagnostic output.

## 7. Network Checking Model

### 7.1 Native Tcl implementation

Implement the checker inside Gorilla using Tcl's asynchronous HTTP facilities rather than invoking an external
executable such as `curl`.

The implementation should use a small bounded pool of concurrent requests. A default concurrency of 4 is recommended;
the internal design may permit a small maximum such as 6 if testing shows that this remains responsive and polite.

### 7.2 HTTPS requirement

HTTPS checking requires a TLS-capable Tcl socket provider. Password Gorilla's source bundle includes Tcllib, but TclTLS
is a separate extension. The implementation must therefore:

- require and configure TclTLS (or an equivalent native Tcl TLS provider);
- preserve certificate validation;
- support SNI;
- ship or otherwise reliably provide the appropriate CA trust material on supported platforms;
- fail closed if HTTPS cannot be validated rather than silently disabling certificate verification.

If TLS support is unavailable, the audit should display a clear prerequisite/error message rather than misclassifying
HTTPS sites as dead.

### 7.3 Request behavior

- Use ordinary unauthenticated HTTP(S) GET requests.
- Do not send cookies, usernames, passwords, notes, or database metadata.
- Use a neutral, non-identifying User-Agent that does not reveal the database name, entry title, username, or
  master-password-manager context.
- Do not rely solely on HEAD because many servers handle HEAD differently from GET and parked-page detection requires
  examining a small response body.
- Stop reading response bodies once enough data has been obtained for classification; do not download large pages
  unnecessarily.
- Apply a bounded per-request timeout. The initial implementation should use a value around 10 seconds and make the
  constant easy to tune.
- Follow at most 5 redirects.
- Detect and terminate redirect loops.

## 8. Classification Rules

The scanner exposes four health classifications.

### 8.1 Working

Classify as `Working` when there is strong evidence that the saved site is still usable, including:

- successful 2xx response;
- ordinary redirect that resolves successfully;
- HTTP-to-HTTPS upgrade;
- redirect within the same hostname;
- conservative canonical-host normalization such as adding or removing only a leading `www.`.

A redirect to a meaningfully different hostname is not automatically considered working even if the final response is
successful.

### 8.2 Needs Review

Use `Needs Review` whenever the evidence is ambiguous. Examples include:

- `401 Unauthorized`;
- `403 Forbidden`;
- `429 Too Many Requests`;
- CAPTCHA, bot protection, or Cloudflare-style challenge;
- TLS/certificate errors;
- timeout;
- connection refusal;
- `5xx` server error;
- redirect to a substantially different hostname;
- saved path returns `404` or `410` while the site root remains alive;
- page content suggests possible parking/retirement but does not meet the confidence threshold for `Dead`;
- any result where the checker cannot distinguish a dead service from a temporary or automation-specific failure.

A saved login page returning `404` or `410` does not by itself make the entry `Dead`. The checker must test the site
root before deciding whether the site as a whole appears gone.

### 8.3 Dead

`Dead` is intentionally high-confidence. It may be assigned when, for example:

- DNS resolution definitively reports that the hostname does not exist;
- the target or redirect destination matches a confidently recognized domain-parking/domain-for-sale pattern;
- both the saved target and the site root return evidence that the site has intentionally been retired, such as a
  conclusive `410 Gone`, with no contrary evidence.

Temporary network failures must not be promoted to `Dead` merely because retries failed.

### 8.4 Not Checked

Use `Not Checked` for:

- non-HTTP(S) schemes;
- malformed URLs that cannot be safely normalized;
- unsupported URL forms;
- other entries intentionally excluded from web checking.

## 9. Parked / Domain-for-Sale Detection

Parking detection should be conservative and heuristic-driven.

The detector may inspect a bounded amount of returned HTML/text for recognizable patterns associated with registrar
parking, domain-for-sale pages, or known parking providers.

Requirements:

- Keep parking rules isolated from general HTTP classification so they can be expanded or corrected without changing
  the scanner core.
- Prefer false negatives over false positives.
- If confidence is not high, classify `Needs Review` rather than `Dead`.
- Never make deletion automatic based on parking detection.

## 10. Review Window

Open a modeless `URL Audit Results` window so the user can continue interacting with the main Gorilla window.

### 10.1 Progress area

Show:

- `Scanning: N / Total`
- progress bar
- `Cancel Scan` button while scanning

Results appear incrementally as checks complete.

The user may begin reviewing completed results before the full scan finishes.

Cancellation stops launching new checks and cancels outstanding checks where possible. Completed results remain
available.

### 10.2 Result table

Use a Tk/ttk multi-column list/tree control with columns equivalent to:

- selected checkbox/state
- Group / Entry
- Stored URL
- Status
- Reason
- Redirect / URL warning

The model should retain, per row:

- record UUID or stable record identifier;
- group;
- title;
- original stored URL;
- sanitized audit URL;
- status;
- detailed reason;
- final redirect destination, if any;
- hygiene warning(s);
- deletion/archive state.

### 10.3 Default filtering

Show by default:

- `Dead`
- `Needs Review`

Hide by default:

- `Working`
- `Not Checked`

Provide filter controls for all four categories.

### 10.4 Selection behavior

- Nothing is selected for deletion automatically.
- Provide `Select All Dead`.
- Provide `Select Visible` if straightforward in the chosen widget implementation.
- Provide `Clear Selection`.
- Selection is independent from classification; the user may choose any visible result.

### 10.5 Row actions

Provide row-level actions:

- `Open Website` — opens the original stored URL in the user's configured/default browser using Gorilla's existing
  browser-launch behavior;
- `Go to Login` — selects/reveals the corresponding entry in Gorilla's main tree;
- `Recheck` — repeats the network classification for that record.

Double-clicking a row should open the stored website in the browser unless platform/UI conventions strongly favor
another existing Gorilla behavior.

### 10.6 Bottom actions

Primary action:

`Archive & Delete Selected`

Secondary action:

`Delete Selected`

Other action:

`Close`

After deletion, keep affected rows in the audit window and mark them `Deleted (unsaved)` rather than removing them
immediately. This preserves a visible audit trail for the current session.

## 11. Deleting Selected Entries

`Delete Selected` performs the following:

1. Validate the selected records still exist in the current in-memory database.
2. Detect protected entries and exclude them from deletion.
3. Ask for explicit confirmation, including the count of entries to be deleted.
4. Delete confirmed, unprotected entries from the in-memory database only.
5. Mark the current database modified using Gorilla's normal modified-state mechanism.
6. Update the audit rows to `Deleted (unsaved)`.
7. Do not invoke Save.

The existing on-disk database remains unchanged until the user uses Gorilla's normal Save command.

If the user closes Gorilla without saving and chooses not to save changes, the original database on disk remains intact.

## 12. Archive & Delete Selected

Archiving is implemented as creation of a separate encrypted PasswordSafe/Gorilla database file containing the
selected records.

### 12.1 Archive file behavior

- Create a brand-new `.psafe3` file.
- Do not append to an existing archive in version 1.
- Do not silently overwrite an existing file.
- Default filename pattern:

  `<current-database-base>-dead-YYYY-MM-DD.psafe3`

- Allow the user to choose another filename/location.

### 12.2 Archive password

Default option:

`Use current database master password`

Alternative:

`Use a different archive password`

If a different password is selected, require it to be entered twice and validate that the two values match before
writing.

The URL-audit feature must not cause Gorilla to retain the current master password longer than it already does. If
Gorilla does not retain the current master password in retrievable form after unlock, choosing `Use current database
master password` should prompt the user to re-enter that password rather than introducing new long-lived password
storage.

### 12.3 Transactional sequence

`Archive & Delete Selected` must perform these steps in order:

1. Snapshot/copy the complete selected records required for archive creation.
2. Re-resolve the selected records by stable identifier and validate protected-entry behavior before destructive
   changes. If protected or stale records are present, present an explicit summary of which records will be skipped
   before proceeding. Protected records are neither archived nor deleted unless the user first unprotects them through
   Gorilla's normal UI.
3. Create a new PasswordSafe database object for the archive.
4. Copy the complete selected records into it, preserving record fields and stable record identity where the existing
   PasswordSafe implementation permits this safely.
5. Write the archive to a temporary file in the destination directory.
6. Close the archive successfully.
7. Reopen/validate the archive using the selected archive password and verify that the expected record count and
   record identities are present.
8. Atomically rename the temporary file to the requested archive filename.
9. Only after steps 1–8 succeed, delete the selected unprotected entries from the current in-memory database.
10. Mark the current database modified.
11. Mark result rows `Archived & deleted (unsaved)`.
12. Do not save the current main database automatically.

If any archive step fails, no selected entry is deleted.

### 12.4 Protected entries

Entries protected by PasswordSafe/Gorilla protections may appear in audit results but must not be silently unprotected
or deleted by the audit tool.

If selected, the operation should identify them and tell the user they must first be unprotected through Gorilla's
normal entry-editing mechanism. A mixed selection may proceed only after Gorilla clearly reports the count of
protected/stale records being skipped and the count that will actually be archived/deleted.

## 13. Data Safety and Failure Handling

### 13.1 Scan failures

A network failure never changes the database.

### 13.2 Archive failures

Examples include:

- invalid destination;
- permission denied;
- write failure;
- disk-full condition;
- encryption/database-write error;
- archive validation failure;
- rename failure.

Any such failure leaves the current database entries untouched.

Temporary archive files should be removed when safe to do so after a failed operation. A failure to remove a temporary
file should be reported without deleting original records.

### 13.3 Stale results

Because the review window is modeless, a record may be edited or deleted in the main Gorilla window after scanning.
Before any destructive action, re-resolve each selected record by stable identifier and validate that it still exists.

If a record no longer exists, mark it stale/skipped rather than treating that as a fatal error for unrelated selected
records.

## 14. Security and Privacy

The audit window is security-sensitive because it exposes entry titles, groups, and URLs. It is bound to the database
session that created it. If the database is locked, closed, or replaced with another database, Gorilla must cancel
outstanding audit requests and close the audit window (or equivalently remove all sensitive row data and disable
actions). The preferred version-1 behavior is to close the audit window. Background scanning must not defeat
Gorilla's normal idle-lock policy.


- Never transmit passwords, usernames, notes, or other credential fields.
- Strip query strings and fragments before network requests.
- Do not log sensitive URL parameter values.
- Avoid logging full URLs or URL paths in routine diagnostics. If diagnostic logging is needed, prefer hostname plus
  non-sensitive status/error metadata.
- Do not include the database filename, entry title, group, username, or UUID in HTTP headers.
- Keep TLS certificate validation enabled.
- Treat TLS validation failures as `Needs Review`.
- Do not silently downgrade an explicitly `https://` stored URL to HTTP.
- For a URL without a scheme, HTTPS is attempted first; HTTP fallback is only a discovery mechanism for scheme-less
  input.
- Archive files are always encrypted PasswordSafe/Gorilla databases, never plaintext CSV/JSON/text exports.
- Archive passwords must be handled with the same sensitivity as the current master password and cleared from
  temporary UI variables where Gorilla's conventions permit.

## 15. Proposed Internal Components

Keep the implementation separated into small Tcl namespaces/modules rather than adding all logic directly to
`gorilla.tcl`.

Suggested responsibilities:

### `gorilla::URLAudit`

Owns scan orchestration and audit state:

- collect eligible records;
- schedule requests;
- maintain bounded concurrency;
- cancellation;
- aggregate progress;
- connect checker results to UI rows.

### `gorilla::URLAudit::URL`

Pure URL-handling functions:

- sanitize query/fragment;
- detect/normalize scheme;
- classify non-web schemes;
- derive root URL;
- compare redirect hosts conservatively;
- detect hygiene warnings.

### `gorilla::URLAudit::HTTP`

Network boundary:

- asynchronous GET;
- timeout;
- redirect handling;
- response-size cap;
- TLS setup;
- response normalization;
- cleanup/cancellation.

### `gorilla::URLAudit::Classifier`

Pure classification logic:

- map network observations to `Working`, `Needs Review`, `Dead`, `Not Checked`;
- root fallback checks;
- parking detection;
- human-readable reason strings.

### `gorilla::URLAudit::Dialog`

Review UI:

- modeless window;
- progress controls;
- result list;
- filters;
- selection controls;
- row actions;
- delete/archive buttons;
- status updates.

### `gorilla::URLAudit::Archive`

Archive transaction:

- create archive DB;
- copy records;
- temporary-file write;
- validation reopen;
- atomic rename;
- only then request in-memory deletion.

Where practical, the modules should reuse existing Gorilla record-selection, browser-launch, database-modified,
PasswordSafe-write, and delete-entry functions rather than duplicating them.

## 16. Testing Strategy

### 16.1 URL parsing / hygiene unit tests

Cover:

- `https://example.com/login`
- `http://example.com/login`
- `example.com/login`
- query strings;
- fragments;
- query plus fragment;
- potentially sensitive parameter names;
- malformed strings;
- explicit non-web schemes;
- Unicode/escaped URL edge cases where supported by the existing URL parser.

Verify the original stored URL is never modified.

### 16.2 HTTP/classification tests

Use a controlled local HTTP test server where possible. Cover:

- 200;
- 204;
- same-host redirect;
- HTTP-to-HTTPS redirect where test infrastructure supports it;
- `www` canonical redirect;
- cross-host redirect;
- 401;
- 403;
- 404 with live root;
- 410 with live root;
- conclusive retired root;
- 429;
- 500/502/503;
- timeout;
- connection refusal;
- DNS failure through an injectable resolver/network boundary where deterministic testing is required;
- redirect loop;
- redirect limit exceeded;
- TLS certificate failure;
- parked-domain signatures;
- uncertain parking-like page.

### 16.3 UI tests

Verify:

- scan does not freeze the main Tk event loop;
- progress count is correct;
- results appear incrementally;
- cancellation works;
- completed results survive cancellation;
- default filters show only `Dead` and `Needs Review`;
- nothing is selected automatically;
- `Select All Dead`, `Select Visible`, and `Clear Selection` behave correctly;
- browser opening uses the original stored URL;
- `Go to Login` selects the correct main-tree entry;
- recheck updates one row safely;
- deleted rows remain visible as `Deleted (unsaved)`.

### 16.4 Database safety tests

Verify:

- `Delete Selected` changes only the in-memory database;
- the database is marked modified after deletion;
- the original file bytes do not change before Save;
- choosing not to save on exit leaves the original file unchanged;
- protected entries are not deleted;
- stale/deleted records are skipped safely.

### 16.5 Archive transaction tests

Verify:

- archive contains exactly the selected records;
- expected fields survive intact, including group, title, username, password, URL, notes, and supported metadata;
- archive opens successfully with the chosen password;
- archive can be opened by Gorilla and, where practical, Password Safe;
- same-current-password path works;
- different-password path works;
- password confirmation mismatch prevents writing;
- destination collision is handled safely;
- permission failure deletes nothing;
- simulated write failure deletes nothing;
- simulated validation failure deletes nothing;
- simulated rename failure deletes nothing;
- successful archive is finalized before main-memory deletion occurs.

### 16.6 Large-database test

Test against a synthetic database with enough URL-bearing records to expose UI freezes, runaway memory usage, or poor
scheduling behavior.

Success criteria:

- UI remains responsive throughout the scan;
- concurrency never exceeds the configured bound;
- cancellation is prompt;
- memory growth remains proportional to result count rather than response-body size;
- review and bulk selection remain usable with hundreds or thousands of rows.

## 17. Acceptance Criteria

The feature is complete when all of the following are true:

1. A user can invoke `Login -> Audit Website URLs...` on an open database.
2. Every nonempty URL field is either checked or explicitly classified `Not Checked`.
3. Query strings and fragments are never sent in audit HTTP requests.
4. The main UI remains responsive while scanning.
5. Results appear incrementally and the scan can be cancelled.
6. Dead-site classification remains conservative; ambiguous cases become `Needs Review`.
7. Working entries are hidden by default but can be shown.
8. No entry is preselected for deletion.
9. The user can open the stored URL, jump to the login entry, and recheck a result.
10. `Delete Selected` affects memory only and never saves automatically.
11. `Archive & Delete Selected` creates and validates a new encrypted archive before deleting from memory.
12. Archive failure leaves all selected entries untouched.
13. Protected entries are respected.
14. The original on-disk database changes only when the user explicitly saves it through Gorilla's normal Save workflow.
15. Generated archives open successfully as PasswordSafe/Gorilla databases.

## 18. Repository / Format Context

The design is aligned with the current public Password Gorilla source structure:

- Gorilla is a Tcl/Tk application whose main UI and menus are in `sources/gorilla.tcl`.
- The source bundle includes Tcllib and a PasswordSafe implementation under `sources/pwsafe`.
- Gorilla's existing UI already uses `ttk::treeview` and has normal Login-menu delete behavior, browser-launch
  behavior, and File Save/Save As/Export commands that the feature should reuse rather than duplicate.
- PasswordSafe V3 is an encrypted, extensible, platform-independent format with per-record fields including UUID and
  URL-related record data.
- TclTLS supports Tcl 8.5+ but requires explicit TLS/certificate configuration; HTTPS support must therefore be
  treated as a packaging/security requirement rather than assumed. Because current Gorilla source includes Tcl 9
  compatibility work, packaged TclTLS builds must also match the Tcl major version used by each distribution.

References:

- https://github.com/zdia/gorilla
- https://github.com/zdia/gorilla/blob/master/sources/gorilla.tcl
- https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
- https://core.tcl-lang.org/tcltls/doc/trunk/doc/tls.html

## 19. Explicitly Deferred Enhancements

Potential later enhancements, not required for version 1:

- append selected entries to an existing archive;
- persistent audit history;
- user-configurable timeout/concurrency settings;
- richer domain-parking provider database;
- optional URL-update suggestions after redirects;
- re-run only previously ambiguous/dead results;
- export an audit report that contains no secrets;
- scheduled/automatic audits;
- more sophisticated registrable-domain comparison using a Public Suffix List;
- user-maintained allow/ignore rules for known sites.
