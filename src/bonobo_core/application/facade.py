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

from bonobo_core.passwordsafe import RecordHandle, RecordView, SecretBuffer
from bonobo_core.passwordsafe.crypto import RandomSource, SystemRandomSource

from .errors import ApplicationFailure, to_application_failure
from .projection import project_records
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



    #### Return immutable public views for the current authenticated document.
    ####
    def records(self) -> tuple[RecordView, ...]:
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
    _decision: _PendingDecision | None
    _generation: int
    _lock: RLock
    _next_record_key: int
    _random: RandomSource
    _record_keys: dict[RecordHandle, RecordKey]
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
        random_source: RandomSource | None = None,
    ) -> None:
        selected_random = SystemRandomSource() if random_source is None else random_source
        if not isinstance(selected_random, RandomSource):
            raise TypeError("random source must implement the application randomness protocol")
        self._lock = RLock()
        self._service = service
        self._random = selected_random
        self._session = None
        self._generation = 0
        self._next_record_key = 1
        self._record_keys = {}
        self._snapshot = ApplicationSnapshot(0, ApplicationPhase.EMPTY, "", False, (), None, None, None)
        self._decision = None



    #### Return the last committed immutable presentation snapshot.
    ####
    @property
    def snapshot(self) -> ApplicationSnapshot:
        with self._lock:
            return self._snapshot



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
                project_records(session.records(), self._record_keys),
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
        return self._publish(phase, display_label, session.dirty, records, None, None, None)



    #### Project the active session after successful save without assigning new keys.
    ####
    def _commit_session(self, session: ApplicationSessionT, display_label: str) -> ApplicationSnapshot:
        records = project_records(session.records(), self._record_keys)
        phase = ApplicationPhase.UNLOCKED_DIRTY if session.dirty else ApplicationPhase.UNLOCKED_CLEAN
        return self._publish(phase, display_label, session.dirty, records, None, None, None)



    #### Commit a terminal locked snapshot without retaining any record projection.
    ####
    def _commit_locked(self, display_label: str) -> ApplicationSnapshot:
        self._session = None
        self._record_keys = {}
        return self._publish(ApplicationPhase.LOCKED, display_label, False, (), None, None, None)



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
