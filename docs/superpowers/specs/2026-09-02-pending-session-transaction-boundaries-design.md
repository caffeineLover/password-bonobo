# Pending-Session Transaction-Boundary Revision Design

Date: 2026-09-02

Status: Approved in conversation; written review pending

## 1. Purpose and scope

This design is a narrow addendum to the approved vault-application desktop foundation design. It closes two Task 4
security and lifecycle gaps without changing the public suspension API, encrypted artifact format, selector schema, or
the planned Task 5 desktop-package work.

The revision has two goals:

1. A retained pending-directory anchor must still identify the directory at the current pending-directory pathname
   before any completed scan is trusted for slot absence or selection.
2. An explicit pending discard that has irreversibly removed the selected state must remain a committed success even
   if releasing its destination lock later fails.

The existing requirements remain in force: enumeration is retained-handle based and strictly bounded, pending errors
are path-free, selectors remain private, pre-commit failures retain retryable state, and Task 5 cannot begin until Task
4 passes independent review.

## 2. Retained-directory authority

The pending store will continue to open one validated private `_PublicationAnchor` and enumerate child names directly
from its retained POSIX descriptor or Windows handle. Each operation that uses a complete directory scan will separate
collection from authorization:

1. Stream and validate every directory entry under the existing strict entry-count ceiling.
2. Retain only the minimal match state required by the caller; do not create an unbounded name collection.
3. After the stream is exhausted, call `anchor.stable()` immediately before interpreting the scan as authoritative.
4. Treat `False`, an exception, or any other uncertainty as `StorageError(StorageReason.VERIFICATION_FAILED)` through
   the existing closed-error boundary.

`_source_has_pending_locked` will no longer return early after finding a match. It will finish the bounded scan, make
the final identity check, and only then return its accumulated result. `_publication_previous_locked` and
`_find_locked` will make the same final check before accepting absence, rejecting ambiguity, or returning a selected
slot. Open, publish, verify, and discard continue using their existing exact child identities after selection.

This closes the retained-directory ABA case in which a valid empty decoy is opened, the real directory is restored,
and absence from the decoy would otherwise be trusted. A current-path mismatch can deny the operation, but it can
never authorize alias open, duplicate suspension, selector removal, or fallback to source state.

## 3. Discard commit reconciliation

`PendingSessionStore.discard` will distinguish the mutation result from destination-lock teardown. A committed flag
outside the destination-lock context will be set only after `_discard_locked` reports that the selected pending state
has crossed its existing irreversible deletion boundary.

The outcomes are:

- Before commit, lookup, validation, rename, deletion, synchronization, or lock errors remain failures. The facade
  stays locked, retains the selector, and permits an exact retry when the state may still exist.
- After commit, destination-lock unlock or close failure cannot restore the deleted pending state and therefore must
  not be surfaced as retryable failure. The store returns committed success, and the facade clears its selector and
  publishes locked state without pending work.
- Every surfaced error continues through the path-free pending boundary. No raw lock path may appear in the exception,
  its cause or context, a snapshot, or a representation.

The change is deliberately confined to discard. Publish, open, and verify retain their current teardown semantics
because their success and recovery contracts differ.

## 4. Verification design

Red-first regressions will cover both boundaries before implementation:

- A deterministic decoy-before-open and real-directory-before-final-check race must fail closed for alias lookup and
  initial suspension while the authoritative slot remains intact.
- Each complete-scan consumer must reject a failed final `anchor.stable()` check, including positive-match and absence
  paths, without leaking private paths.
- Existing entry-count, malformed native-record, retained-child identity, and enumeration-error tests must remain
  green.
- Fault injection after committed discard, during destination-lock unlock and close, must return success and allow the
  facade to clear its selector.
- Equivalent failures before discard commit must remain failures and retain retryable selector state.

After the focused tests pass, verification will repeat the Task 4 selected suite, all three strict mypy platform
profiles, Ruff, formatting-diff, structure, compatibility, provenance, Bandit, dependency audit, REUSE, tracked-file,
whitespace, source/wheel build, and exact-Botan full-suite gates already used by Task 4.

## 5. Execution and review boundary

This addendum will be translated into a small Task 4 repair plan. Under the selected subagent-driven workflow, repair
round 4 uses a fresh implementation agent and retains independent review. Task 4 is complete only after the reviewer
reports no Critical or Important findings and the required verification is green. If review still rejects the task,
the workflow's remaining repair and adjudication rules apply. Tasks 5 through 8 remain pending until that approval.
