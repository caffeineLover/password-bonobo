"""Serialize safe application lifecycle commands over the PasswordSafe service.

This facade owns active sessions, deferred replacement passphrases, and
handle-to-key mappings.  Immutable snapshots disclose only Task 1's approved
presentation data; all PasswordSafe resources remain private to this module.
"""

import secrets
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Literal, Protocol, TypeVar
from uuid import uuid4

from bonobo_core.passwordsafe import (
    NewRecord,
    RecordFieldType,
    RecordHandle,
    RecordView,
    RevisionToken,
    SecretBuffer,
    SecretLease,
    SetSecretField,
    SetTextField,
)
from bonobo_core.passwordsafe.crypto import RandomSource, SystemRandomSource

from .errors import ApplicationFailure, ApplicationFailureReason, to_application_failure
from .ports import BrowserPort, ClipboardPort
from .projection import project_records, search_records
from .records import RecordDraft
from .types import ApplicationPhase, ApplicationSnapshot, DecisionToken, RecordKey, RecordSummary



#### Describe the narrow public session surface needed by lifecycle commands.
####
#### The facade deliberately depends only on public, non-mutating projection
#### access and explicit terminal lifecycle operations.  It never receives a
#### session path, revision, record secret, or document implementation detail.
####
class VaultSessionLike(Protocol):



    #### Report whether accepted mutations have not yet been published.
    ####
    @property
    def dirty(self) -> bool:
        raise NotImplementedError



    #### Return the current opaque revision without exposing it from the facade.
    ####
    @property
    def revision(self) -> RevisionToken:
        raise NotImplementedError



    #### Return immutable public views for the current authenticated document.
    ####
    def records(self) -> tuple[RecordView, ...]:
        raise NotImplementedError



    #### Apply one revision-bound patch and return its revised public view.
    ####
    def apply(
        self,
        handle: RecordHandle,
        expected_revision: RevisionToken,
        edits: tuple[SetTextField | SetSecretField, ...],
    ) -> RecordView:
        raise NotImplementedError



    #### Add one new record while consuming its supplied password owner.
    ####
    def add(self, new_record: NewRecord, expected_revision: RevisionToken) -> RecordView:
        raise NotImplementedError



    #### Lease one explicitly requested secret field without exposing it in a view.
    ####
    def reveal(self, handle: RecordHandle, field_type: RecordFieldType) -> SecretLease:
        raise NotImplementedError



    #### Close a session that has no unsaved changes.
    ####
    def lock(self) -> None:
        raise NotImplementedError



    #### Discard unsaved changes before closing the active session.
    ####
    def discard_and_lock(self) -> None:
        raise NotImplementedError



SessionT = TypeVar("SessionT", bound=VaultSessionLike)



#### Describe the public PasswordSafe operations coordinated by the facade.
####
#### The session type stays coupled through this protocol so the concrete
#### `VaultService.save(VaultSession)` signature remains valid while headless
#### tests can supply a lightweight structural fake session.
####
class VaultServiceLike(Protocol[SessionT]):



    #### Create and return one authenticated vault session.
    ####
    def create(self, path: Path, passphrase: SecretBuffer) -> SessionT:
        raise NotImplementedError



    #### Open and return one authenticated vault session.
    ####
    def open(self, path: Path, passphrase: SecretBuffer) -> SessionT:
        raise NotImplementedError



    #### Publish the supplied authenticated session.
    ####
    def save(self, session: SessionT) -> object:
        raise NotImplementedError



#### Identify the explicit response to a close or replacement confirmation.
####
class CloseChoice(StrEnum):
    SAVE = "save"
    DISCARD = "discard"
    CANCEL = "cancel"



#### Report a rejected application command without exposing domain error detail.
####
class ApplicationCommandError(RuntimeError):
    """Raise a stable message for stale, busy, or invalid lifecycle commands."""



#### Retain one deferred create or open operation while user confirmation is pending.
####
#### This private owner transfers the passphrase supplied to a replacement
#### command.  Resolution closes it exactly once after cancellation or after
#### the deferred service operation, including BaseException failure paths.
####
@dataclass(slots=True, repr=False)
class _Replacement:
    action: Literal["create", "open"]
    path: Path
    passphrase: SecretBuffer
    display_label: str



#### Bind an opaque single-use token to one prior snapshot and optional replacement.
####
#### A close decision has no replacement.  A dirty create/open decision keeps
#### the existing session live until the candidate has authenticated and been
#### projected, so failed authentication cannot discard unsaved work.
####
@dataclass(slots=True, repr=False)
class _PendingDecision:
    token: DecisionToken
    prior: ApplicationSnapshot
    replacement: _Replacement | None



#### Serialize lifecycle state and expose only immutable presentation snapshots.
####
#### One re-entrant lock protects each command and its private session maps.
#### Service calls occur while the facade is `BUSY`, which prevents nested calls
#### from observing or mutating an incomplete transition.
####
class VaultApplication[ApplicationSessionT: VaultSessionLike]:
    _browser: BrowserPort | None
    _clipboard: ClipboardPort | None
    _decision: _PendingDecision | None
    _draft_revisions: dict[tuple[int, RecordKey | None], RevisionToken]
    _generation: int
    _lock: RLock
    _next_record_key: int
    _random: RandomSource
    _record_keys: dict[RecordHandle, RecordKey]
    _search: str
    _service: VaultServiceLike[ApplicationSessionT]
    _session: ApplicationSessionT | None
    _snapshot: ApplicationSnapshot



    #### Initialize an empty facade with caller-supplied service and optional randomness.
    ####
    #### The service retains its core resource configuration.  Injected randomness
    #### exists only to make 128-bit decision tokens deterministic in headless
    #### tests; production defaults to the established system random source.
    ####
    def __init__(
        self,
        service: VaultServiceLike[ApplicationSessionT],
        *,
        clipboard: ClipboardPort | None = None,
        browser: BrowserPort | None = None,
        random_source: RandomSource | None = None,
    ) -> None:
        selected_random = SystemRandomSource() if random_source is None else random_source
        if not isinstance(selected_random, RandomSource):
            raise TypeError("random source must implement the application randomness protocol")
        self._lock = RLock()
        self._service = service
        self._random = selected_random
        self._clipboard = clipboard
        self._browser = browser
        self._session = None
        self._generation = 0
        self._next_record_key = 1
        self._draft_revisions = {}
        self._record_keys = {}
        self._search = ""
        self._snapshot = ApplicationSnapshot(0, ApplicationPhase.EMPTY, "", False, (), None, None, None)
        self._decision = None



    #### Return the last committed immutable presentation snapshot.
    ####
    @property
    def snapshot(self) -> ApplicationSnapshot:
        with self._lock:
            return self._snapshot



    #### Expose a non-secret mutation count only when a headless test session supplies it.
    ####
    #### Production PasswordSafe sessions do not provide this test observation,
    #### so the facade reports zero rather than exposing any domain state.
    ####
    @property
    def test_session_change_count(self) -> int:
        with self._lock:
            session = self._session
            count = 0 if session is None else getattr(session, "change_count", 0)
            return count if isinstance(count, int) else 0



    #### Filter the current safe record projection without touching the session.
    ####
    #### Search operates only on title, group, and username through Task 1's
    #### deterministic projection helper.  It consumes a presentation generation
    #### so a subsequently submitted draft cannot race an accepted query change.
    ####
    def set_search(self, query: str, expected_generation: int) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            if not isinstance(query, str):
                raise ApplicationCommandError("search query is invalid")
            prior_search = self._search
            self._search = query
            session = self._require_session()
            try:
                records = self._refresh_active_projection(session)
            except BaseException as error:
                self._search = prior_search
                return self._restore_failure(previous, error)
            return self._publish(
                ApplicationPhase.UNLOCKED_DIRTY if session.dirty else ApplicationPhase.UNLOCKED_CLEAN,
                previous.display_label,
                session.dirty,
                records,
                previous.selected if self._contains_key(records, previous.selected) else None,
                None,
                None,
            )



    #### Create a generation-bound metadata-only draft for one current record.
    ####
    #### The facade resolves the opaque handle and retains its revision privately.
    #### Callers receive no URL, PasswordSafe identity, note, or secret-bearing
    #### field, even though the underlying public view contains additional data.
    ####
    def begin_edit(self, key: RecordKey | None, expected_generation: int) -> RecordDraft:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            if key is None:
                session = self._require_session()
                self._capture_draft_revision(previous.generation, None, self._current_revision(session))
                return RecordDraft(None, previous.generation, "", "", "", False)
            handle = self._resolve_handle(key)
            session = self._require_session()
            view = self._view_for_handle(session, handle)
            self._capture_draft_revision(previous.generation, key, self._current_revision(session))
            return RecordDraft(key, previous.generation, view.title, view.group, view.username, view.protected)



    #### Apply one confirmed draft and optional transient secrets as one revision.
    ####
    #### Every supplied secret owner closes on success, rejection, adapter error,
    #### or interruption.  No-op drafts model editor cancellation and therefore
    #### avoid the session entirely.
    ####
    def commit_edit(
        self,
        draft: RecordDraft,
        password: SecretBuffer | None,
        *,
        url: SecretBuffer | None = None,
    ) -> ApplicationSnapshot:
        try:
            with self._lock:
                if not isinstance(draft, RecordDraft):
                    raise ApplicationCommandError("record draft is invalid")
                self._validate_optional_secret(password, "password")
                self._validate_optional_secret(url, "website")
                previous = self._validate_active_generation(draft.generation)
                if draft.key is None:
                    return self._add_draft(previous, draft, password, url)
                return self._apply_draft(previous, draft, password, url)
        finally:
            self._close_secret_without_masking(password)
            self._close_secret_without_masking(url)



    #### Copy a public username through the same short-lived clipboard lease boundary.
    ####
    def copy_username(self, key: RecordKey, expected_generation: int) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            handle = self._resolve_handle(key)
            session = self._require_session()
            try:
                view = self._view_for_handle(session, handle)
                with SecretLease.from_bytes(view.username.encode("utf-8")) as lease:
                    self._copy_lease(lease)
                return self._restore_snapshot(previous)
            except BaseException as error:
                return self._restore_port_failure(previous, ApplicationFailureReason.CLIPBOARD_UNAVAILABLE, error)



    #### Copy a password only through an explicit in-context session secret lease.
    ####
    def copy_password(self, key: RecordKey, expected_generation: int) -> ApplicationSnapshot:
        return self._copy_secret_field(key, expected_generation, RecordFieldType.PASSWORD)



    #### Open a stored URL only through an explicit in-context application secret lease.
    ####
    def open_website(self, key: RecordKey, expected_generation: int) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            handle = self._resolve_handle(key)
            session = self._require_session()
            try:
                view = self._view_for_handle(session, handle)
                with SecretLease.from_bytes(view.url.encode("utf-8")) as lease:
                    browser = self._browser
                    if browser is None or not browser.open(lease):
                        raise RuntimeError("browser is unavailable")
                return self._restore_snapshot(previous)
            except BaseException as error:
                return self._restore_port_failure(previous, ApplicationFailureReason.BROWSER_UNAVAILABLE, error)



    #### Create a vault unless dirty work first requires explicit replacement approval.
    ####
    #### Callers transfer the passphrase owner to this boundary.  It is closed
    #### immediately after the service call or retained privately until a
    #### replacement decision is resolved.
    ####
    def create(self, path: Path, passphrase: SecretBuffer, display_label: str) -> ApplicationSnapshot:
        with self._lock:
            replacement = self._validated_replacement("create", path, passphrase, display_label)
            if self._is_dirty_unlocked():
                return self._await_replacement(replacement)
            return self._run_replacement(replacement)



    #### Open a vault unless dirty work first requires explicit replacement approval.
    ####
    #### Candidate authentication and projection complete before the active
    #### session is closed.  A failed deferred open therefore restores the prior
    #### dirty session instead of losing unsaved work.
    ####
    def open(self, path: Path, passphrase: SecretBuffer, display_label: str) -> ApplicationSnapshot:
        with self._lock:
            replacement = self._validated_replacement("open", path, passphrase, display_label)
            if self._is_dirty_unlocked():
                return self._await_replacement(replacement)
            return self._run_replacement(replacement)



    #### Publish the current session after verifying the caller's snapshot generation.
    ####
    #### Publication failure preserves the dirty session and all existing safe
    #### projections.  Save results and revisions remain within PasswordSafe and
    #### are never copied into the application snapshot.
    ####
    def save(self, expected_generation: int) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            session = self._require_session()
            self._invalidate_decision()
            self._enter_busy(previous)
            saved = False
            try:
                self._service.save(session)
                saved = True
                return self._commit_session(session, previous.display_label)
            except BaseException as error:
                if saved:
                    return self._fail_closed(session, previous.display_label, error)
                return self._restore_failure(previous, error)



    #### Request a close, immediately locking clean state or issuing a dirty decision.
    ####
    #### The decision token is created from exactly 128 bits of injected
    #### randomness and is compared in constant time when resolved.
    ####
    def request_close(self, expected_generation: int) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            session = self._require_session()
            self._invalidate_decision()
            if previous.phase is ApplicationPhase.UNLOCKED_DIRTY:
                return self._await_close(previous)
            self._enter_busy(previous)
            try:
                session.lock()
                return self._commit_locked(previous.display_label)
            except BaseException as error:
                return self._fail_closed(session, previous.display_label, error)



    #### Resolve one exact close or replacement decision token and invalidate it.
    ####
    #### Cancellation restores the prior unlocked snapshot without a service call.
    #### A deferred replacement authenticates before the old session is discarded,
    #### while a normal close saves or discards only after the user has approved it.
    ####
    def resolve_close(self, decision: DecisionToken | None, choice: CloseChoice) -> ApplicationSnapshot:
        with self._lock:
            pending = self._validate_decision(decision)
            if not isinstance(choice, CloseChoice):
                raise ApplicationCommandError("close choice is invalid")
            self._decision = None
            if choice is CloseChoice.CANCEL:
                self._close_replacement_without_masking(pending.replacement)
                return self._restore_snapshot(pending.prior)
            if pending.replacement is not None:
                if choice is CloseChoice.SAVE:
                    return self._save_then_replace(pending)
                return self._run_replacement(pending.replacement, prior=pending.prior)
            return self._resolve_close_only(pending.prior, choice)



    #### Lock an unlocked clean session after verifying the caller's snapshot generation.
    ####
    #### Dirty lock suspension is deliberately excluded from this early lifecycle
    #### task and is added only with the authenticated pending-session facility.
    ####
    def lock_clean(self, expected_generation: int) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            if previous.phase is not ApplicationPhase.UNLOCKED_CLEAN:
                raise ApplicationCommandError("clean lock requires an unlocked clean session")
            session = self._require_session()
            self._invalidate_decision()
            self._enter_busy(previous)
            try:
                session.lock()
                return self._commit_locked(previous.display_label)
            except BaseException as error:
                return self._fail_closed(session, previous.display_label, error)



    #### Add a new unprotected record after consuming one transient password owner.
    ####
    #### New-record URLs exist only as a short string required by PasswordSafe's
    #### existing public constructor.  The conversion occurs within this command
    #### and is neither stored in a draft nor projected to application state.
    ####
    def _add_draft(
        self,
        previous: ApplicationSnapshot,
        draft: RecordDraft,
        password: SecretBuffer | None,
        url: SecretBuffer | None,
    ) -> ApplicationSnapshot:
        if draft.protected:
            raise ApplicationCommandError("new record protection is unavailable")
        if password is None:
            raise ApplicationCommandError("new record password is required")
        session = self._require_session()
        revision = self._consume_draft_revision(draft.generation, None)
        if self._current_revision(session) is not revision:
            raise ApplicationCommandError("record draft is stale")
        self._enter_busy(previous)
        mutated = False
        try:
            url_text = self._secret_text(url)
            new_record = NewRecord(uuid4(), draft.title, password, draft.username, draft.group, url_text)
            session.add(new_record, revision)
            mutated = True
            records = self._refresh_active_projection(session)
            return self._publish(
                ApplicationPhase.UNLOCKED_DIRTY,
                previous.display_label,
                True,
                records,
                None,
                None,
                None,
            )
        except BaseException as error:
            if mutated:
                return self._fail_closed(session, previous.display_label, error)
            return self._restore_failure(previous, error)



    #### Apply one existing-record patch with the revision captured for its draft.
    ####
    #### Text edits and separate secret edits form one ordered session patch, so a
    #### successful confirmation creates exactly one revision.  Protection state
    #### remains metadata-only in this early vertical slice.
    ####
    def _apply_draft(
        self,
        previous: ApplicationSnapshot,
        draft: RecordDraft,
        password: SecretBuffer | None,
        url: SecretBuffer | None,
    ) -> ApplicationSnapshot:
        key = draft.key
        if key is None:
            raise ApplicationCommandError("record draft is invalid")
        handle = self._resolve_handle(key)
        session = self._require_session()
        revision = self._consume_draft_revision(draft.generation, key)
        if self._current_revision(session) is not revision:
            raise ApplicationCommandError("record draft is stale")
        view = self._view_for_handle(session, handle)
        if draft.protected != view.protected:
            raise ApplicationCommandError("record protection edit is unavailable")
        edits: list[SetTextField | SetSecretField] = []
        for field_type, value, current in (
            (RecordFieldType.TITLE, draft.title, view.title),
            (RecordFieldType.GROUP, draft.group, view.group),
            (RecordFieldType.USERNAME, draft.username, view.username),
        ):
            if value != current:
                edits.append(SetTextField(field_type, value))
        if password is not None:
            edits.append(SetSecretField(RecordFieldType.PASSWORD, password))
        if url is not None:
            edits.append(SetTextField(RecordFieldType.URL, self._secret_text(url)))
        if not edits:
            return previous
        self._enter_busy(previous)
        mutated = False
        try:
            session.apply(handle, revision, tuple(edits))
            mutated = True
            records = self._refresh_active_projection(session)
            return self._publish(
                ApplicationPhase.UNLOCKED_DIRTY,
                previous.display_label,
                True,
                records,
                previous.selected if self._contains_key(records, previous.selected) else None,
                None,
                None,
            )
        except BaseException as error:
            if mutated:
                return self._fail_closed(session, previous.display_label, error)
            return self._restore_failure(previous, error)



    #### Copy one revealed field through the clipboard while retaining no lease.
    ####
    def _copy_secret_field(
        self,
        key: RecordKey,
        expected_generation: int,
        field_type: RecordFieldType,
    ) -> ApplicationSnapshot:
        with self._lock:
            previous = self._validate_active_generation(expected_generation)
            handle = self._resolve_handle(key)
            session = self._require_session()
            try:
                with session.reveal(handle, field_type) as lease:
                    self._copy_lease(lease)
                return self._restore_snapshot(previous)
            except BaseException as error:
                return self._restore_port_failure(previous, ApplicationFailureReason.CLIPBOARD_UNAVAILABLE, error)



    #### Pass an open lease to the configured clipboard with only a safe lifetime.
    ####
    def _copy_lease(self, lease: SecretLease) -> None:
        clipboard = self._clipboard
        if clipboard is None:
            raise RuntimeError("clipboard is unavailable")
        clipboard.copy(lease, lifetime_seconds=30)



    #### Project a port failure without retaining its exception or leased value.
    ####
    def _restore_port_failure(
        self,
        previous: ApplicationSnapshot,
        reason: ApplicationFailureReason,
        _error: BaseException,
    ) -> ApplicationSnapshot:
        return self._publish(
            previous.phase,
            previous.display_label,
            previous.dirty,
            previous.records,
            previous.selected,
            ApplicationFailure(reason, f"application.failure.{reason.value}"),
            None,
        )



    #### Resolve a public key through the facade-owned private handle mapping.
    ####
    def _resolve_handle(self, key: RecordKey) -> RecordHandle:
        if not isinstance(key, RecordKey):
            raise ApplicationCommandError("record key is invalid")
        for handle, mapped_key in self._record_keys.items():
            if mapped_key == key:
                return handle
        raise ApplicationCommandError("record key is unavailable")



    #### Retrieve one current private view without exposing it beyond this module.
    ####
    def _view_for_handle(self, session: ApplicationSessionT, handle: RecordHandle) -> RecordView:
        for view in session.records():
            if view.handle is handle:
                return view
        raise ApplicationCommandError("record key is unavailable")



    #### Read the session's current private revision for a generation-checked command.
    ####
    def _current_revision(self, session: ApplicationSessionT) -> RevisionToken:
        revision = session.revision
        if not isinstance(revision, RevisionToken):
            raise ApplicationCommandError("record revision is unavailable")
        return revision



    #### Retain one opaque revision only for an edit begun at this snapshot generation.
    ####
    def _capture_draft_revision(self, generation: int, key: RecordKey | None, revision: RevisionToken) -> None:
        self._draft_revisions[(generation, key)] = revision



    #### Consume one private revision before a draft can cancel or mutate session state.
    ####
    def _consume_draft_revision(self, generation: int, key: RecordKey | None) -> RevisionToken:
        revision = self._draft_revisions.pop((generation, key), None)
        if revision is None:
            raise ApplicationCommandError("record draft is stale")
        return revision



    #### Convert one supplied URL owner only during the immediate add command.
    ####
    def _secret_text(self, value: SecretBuffer | None) -> str:
        if value is None:
            return ""
        return bytes(value.borrow()).decode("utf-8")



    #### Reject malformed optional secret owners before session state changes.
    ####
    def _validate_optional_secret(self, value: SecretBuffer | None, label: str) -> None:
        if value is not None and (not isinstance(value, SecretBuffer) or value.closed):
            raise ApplicationCommandError(f"{label} is invalid")



    #### Close one caller-owned secret without masking the command outcome.
    ####
    def _close_secret_without_masking(self, value: SecretBuffer | None) -> None:
        if value is not None:
            with suppress(BaseException):
                value.close()



    #### Validate one replacement command and take ownership of its caller secret.
    ####
    def _validated_replacement(
        self,
        action: Literal["create", "open"],
        path: Path,
        passphrase: SecretBuffer,
        display_label: str,
    ) -> _Replacement:
        if self._snapshot.phase is ApplicationPhase.BUSY:
            raise ApplicationCommandError("application command is busy")
        if self._snapshot.phase is ApplicationPhase.AWAITING_DECISION:
            raise ApplicationCommandError("a close decision is required")
        if not isinstance(path, Path):
            raise ApplicationCommandError("vault locator is invalid")
        if not isinstance(passphrase, SecretBuffer) or passphrase.closed:
            raise ApplicationCommandError("passphrase is invalid")
        if not isinstance(display_label, str):
            raise ApplicationCommandError("display label is invalid")
        self._invalidate_decision()
        return _Replacement(action, path, passphrase, display_label)



    #### Report whether the committed snapshot owns unsaved active session state.
    ####
    def _is_dirty_unlocked(self) -> bool:
        return self._snapshot.phase is ApplicationPhase.UNLOCKED_DIRTY and self._session is not None



    #### Issue a single-use replacement token without invoking the core service.
    ####
    def _await_replacement(self, replacement: _Replacement) -> ApplicationSnapshot:
        previous = self._snapshot
        try:
            token = self._new_decision_token()
        except BaseException as error:
            self._close_replacement_without_masking(replacement)
            return self._restore_failure(previous, error)
        self._decision = _PendingDecision(token, previous, replacement)
        return self._publish(
            ApplicationPhase.AWAITING_DECISION,
            previous.display_label,
            True,
            previous.records,
            previous.selected,
            None,
            token,
        )



    #### Issue a single-use close token while preserving the exact dirty snapshot.
    ####
    def _await_close(self, previous: ApplicationSnapshot) -> ApplicationSnapshot:
        try:
            token = self._new_decision_token()
        except BaseException as error:
            return self._restore_failure(previous, error)
        self._decision = _PendingDecision(token, previous, None)
        return self._publish(
            ApplicationPhase.AWAITING_DECISION,
            previous.display_label,
            True,
            previous.records,
            previous.selected,
            None,
            token,
        )



    #### Generate exactly one opaque 128-bit token and reject malformed randomness.
    ####
    def _new_decision_token(self) -> DecisionToken:
        entropy = self._random.bytes(16)
        if not isinstance(entropy, bytes) or len(entropy) != 16:
            raise RuntimeError("decision randomness is unavailable")
        return DecisionToken(entropy)



    #### Authenticate and project a replacement before committing it over prior state.
    ####
    def _run_replacement(
        self,
        replacement: _Replacement,
        *,
        prior: ApplicationSnapshot | None = None,
    ) -> ApplicationSnapshot:
        previous = self._snapshot if prior is None else prior
        old_session = self._session
        candidate: ApplicationSessionT | None = None
        old_terminal_started = False
        self._enter_busy(previous)
        try:
            if replacement.action == "create":
                candidate = self._service.create(replacement.path, replacement.passphrase)
            else:
                candidate = self._service.open(replacement.path, replacement.passphrase)
            records, record_keys = self._project_session(candidate)
            if old_session is not None:
                old_terminal_started = True
                old_session.lock() if not old_session.dirty else old_session.discard_and_lock()
                self._clear_clipboard_without_masking()
            self._session = candidate
            self._record_keys = record_keys
            return self._commit_projected_session(candidate, replacement.display_label, records)
        except BaseException as error:
            if candidate is not None and candidate is not old_session:
                self._discard_without_masking(candidate)
            if old_terminal_started and old_session is not None:
                return self._fail_closed(old_session, previous.display_label, error)
            return self._restore_failure(previous, error)
        finally:
            self._close_replacement_without_masking(replacement)



    #### Save the prior dirty session before carrying out an approved replacement.
    ####
    def _save_then_replace(self, pending: _PendingDecision) -> ApplicationSnapshot:
        replacement = pending.replacement
        if replacement is None:
            raise ApplicationCommandError("decision is stale")
        session = self._require_session()
        self._enter_busy(pending.prior)
        save_succeeded = False
        try:
            self._service.save(session)
            save_succeeded = True
            saved = ApplicationSnapshot(
                pending.prior.generation,
                ApplicationPhase.UNLOCKED_DIRTY if session.dirty else ApplicationPhase.UNLOCKED_CLEAN,
                pending.prior.display_label,
                session.dirty,
                self._refresh_active_projection(session),
                pending.prior.selected,
                None,
                None,
            )
            return self._run_replacement(replacement, prior=saved)
        except BaseException as error:
            self._close_replacement_without_masking(replacement)
            if save_succeeded:
                return self._fail_closed(session, pending.prior.display_label, error)
            return self._restore_failure(pending.prior, error)



    #### Resolve a normal close after its token has been verified and consumed.
    ####
    def _resolve_close_only(self, previous: ApplicationSnapshot, choice: CloseChoice) -> ApplicationSnapshot:
        session = self._require_session()
        self._enter_busy(previous)
        terminal_started = False
        try:
            if choice is CloseChoice.SAVE:
                self._service.save(session)
                terminal_started = True
                session.lock()
            else:
                terminal_started = True
                session.discard_and_lock()
            return self._commit_locked(previous.display_label)
        except BaseException as error:
            if terminal_started:
                return self._fail_closed(session, previous.display_label, error)
            return self._restore_failure(previous, error)



    #### Build safe record projections and private handle mappings for one candidate session.
    ####
    def _project_session(
        self,
        session: ApplicationSessionT,
    ) -> tuple[tuple[RecordSummary, ...], dict[RecordHandle, RecordKey]]:
        views = session.records()
        record_keys = {
            view.handle: RecordKey(self._next_record_key + index)
            for index, view in enumerate(views)
        }
        return project_records(views, record_keys), record_keys



    #### Commit one projected session and advance the facade record-key sequence.
    ####
    def _commit_projected_session(
        self,
        session: ApplicationSessionT,
        display_label: str,
        records: tuple[RecordSummary, ...],
    ) -> ApplicationSnapshot:
        self._next_record_key += len(records)
        phase = ApplicationPhase.UNLOCKED_DIRTY if session.dirty else ApplicationPhase.UNLOCKED_CLEAN
        return self._publish(phase, display_label, session.dirty, self._filter_records(records), None, None, None)



    #### Project the active session after successful save without assigning new keys.
    ####
    def _commit_session(self, session: ApplicationSessionT, display_label: str) -> ApplicationSnapshot:
        records = self._refresh_active_projection(session)
        phase = ApplicationPhase.UNLOCKED_DIRTY if session.dirty else ApplicationPhase.UNLOCKED_CLEAN
        return self._publish(phase, display_label, session.dirty, records, None, None, None)



    #### Refresh private handle mappings after a successful mutation.
    ####
    #### Existing handles retain their facade-owned keys.  A newly added handle
    #### receives a fresh key only after the session mutation has succeeded, and
    #### removed handles disappear from every private mapping.
    ####
    def _refresh_active_projection(self, session: ApplicationSessionT) -> tuple[RecordSummary, ...]:
        views = session.records()
        keys: dict[RecordHandle, RecordKey] = {}
        for view in views:
            key = self._record_keys.get(view.handle)
            if key is None:
                key = RecordKey(self._next_record_key)
                self._next_record_key += 1
            keys[view.handle] = key
        self._record_keys = keys
        return self._filter_records(project_records(views, keys))



    #### Apply the current safe search query without considering any domain field.
    ####
    def _filter_records(self, records: tuple[RecordSummary, ...]) -> tuple[RecordSummary, ...]:
        return search_records(records, self._search)



    #### Determine whether a retained presentation selection remains visible.
    ####
    def _contains_key(self, records: tuple[RecordSummary, ...], key: RecordKey | None) -> bool:
        return key is not None and any(summary.key == key for summary in records)



    #### Commit a terminal locked snapshot without retaining any record projection.
    ####
    def _commit_locked(self, display_label: str) -> ApplicationSnapshot:
        self._session = None
        self._record_keys = {}
        self._clear_clipboard_without_masking()
        return self._publish(ApplicationPhase.LOCKED, display_label, False, (), None, None, None)



    #### Ask the configured adapter to clear only clipboard content it still owns.
    ####
    #### Clipboard cleanup cannot reverse a completed session close, so adapter
    #### errors are intentionally suppressed after the terminal transition.
    ####
    def _clear_clipboard_without_masking(self) -> None:
        clipboard = self._clipboard
        if clipboard is not None:
            with suppress(BaseException):
                clipboard.clear_owned()



    #### Discard private state and publish a locked safe failure after an irreversible step.
    ####
    #### A successful save or terminal session operation may mutate the source before
    #### raising from a later projection or cleanup step.  Republishing its prior
    #### unlocked view would misrepresent private state, so dispose of it and fail
    #### closed instead.
    ####
    def _fail_closed(
        self,
        session: ApplicationSessionT,
        display_label: str,
        error: BaseException,
    ) -> ApplicationSnapshot:
        self._discard_without_masking(session)
        self._session = None
        self._record_keys = {}
        self._clear_clipboard_without_masking()
        return self._publish(
            ApplicationPhase.LOCKED,
            display_label,
            False,
            (),
            None,
            to_application_failure(error),
            None,
        )



    #### Enter the private busy state while a synchronous service transition is running.
    ####
    def _enter_busy(self, previous: ApplicationSnapshot) -> None:
        self._snapshot = ApplicationSnapshot(
            previous.generation,
            ApplicationPhase.BUSY,
            previous.display_label,
            previous.dirty,
            previous.records,
            previous.selected,
            None,
            None,
        )



    #### Restore prior presentation data with only an application-safe failure projection.
    ####
    def _restore_failure(self, previous: ApplicationSnapshot, error: BaseException) -> ApplicationSnapshot:
        return self._publish(
            previous.phase,
            previous.display_label,
            previous.dirty,
            previous.records,
            previous.selected,
            to_application_failure(error),
            None,
        )



    #### Restore an unchanged prior snapshot after a user cancellation.
    ####
    def _restore_snapshot(self, previous: ApplicationSnapshot) -> ApplicationSnapshot:
        return self._publish(
            previous.phase,
            previous.display_label,
            previous.dirty,
            previous.records,
            previous.selected,
            None,
            None,
        )



    #### Publish one immutable snapshot and consume the next generation number.
    ####
    def _publish(
        self,
        phase: ApplicationPhase,
        display_label: str,
        dirty: bool,
        records: tuple[RecordSummary, ...],
        selected: RecordKey | None,
        failure: ApplicationFailure | None,
        decision: DecisionToken | None,
    ) -> ApplicationSnapshot:
        self._draft_revisions.clear()
        self._generation += 1
        self._snapshot = ApplicationSnapshot(
            self._generation,
            phase,
            display_label,
            dirty,
            records,
            selected,
            failure,
            decision,
        )
        return self._snapshot



    #### Verify one command generation against the current unlocked presentation state.
    ####
    def _validate_active_generation(self, expected_generation: int) -> ApplicationSnapshot:
        if self._snapshot.phase is ApplicationPhase.BUSY:
            raise ApplicationCommandError("application command is busy")
        if self._snapshot.phase is ApplicationPhase.AWAITING_DECISION:
            raise ApplicationCommandError("a close decision is required")
        if expected_generation != self._snapshot.generation:
            raise ApplicationCommandError("application view is stale")
        if self._snapshot.phase not in (ApplicationPhase.UNLOCKED_CLEAN, ApplicationPhase.UNLOCKED_DIRTY):
            raise ApplicationCommandError("no unlocked vault is available")
        return self._snapshot



    #### Return the private active session after an unlocked-state validation.
    ####
    def _require_session(self) -> ApplicationSessionT:
        if self._session is None:
            raise ApplicationCommandError("no unlocked vault is available")
        return self._session



    #### Verify an opaque token with constant-time bytes comparison and current state.
    ####
    def _validate_decision(self, decision: DecisionToken | None) -> _PendingDecision:
        pending = self._decision
        if (
            self._snapshot.phase is not ApplicationPhase.AWAITING_DECISION
            or pending is None
            or not isinstance(decision, DecisionToken)
            or not secrets.compare_digest(pending.token.value, decision.value)
        ):
            raise ApplicationCommandError("decision is stale")
        return pending



    #### Invalidate any current token and dispose of its deferred secret if necessary.
    ####
    def _invalidate_decision(self) -> None:
        pending = self._decision
        self._decision = None
        if pending is not None:
            self._close_replacement_without_masking(pending.replacement)



    #### Close a deferred secret without masking the state transition outcome.
    ####
    def _close_replacement_without_masking(self, replacement: _Replacement | None) -> None:
        if replacement is None:
            return
        with suppress(BaseException):
            replacement.passphrase.close()



    #### Dispose of a newly authenticated candidate after projection or replacement failure.
    ####
    def _discard_without_masking(self, session: ApplicationSessionT) -> None:
        with suppress(BaseException):
            session.discard_and_lock()
