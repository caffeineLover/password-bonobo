"""Provide focused fake PasswordSafe service and session objects for facade tests.

The fakes preserve the public service/session effects the facade owns while
remaining independent from encryption, storage, and fabricated file contents.
"""

from collections.abc import Callable

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
    SuspendedSession,
)



#### Construct one stable view whose secret-bearing URL must not reach application DTOs.
####
#### Application projection and lifecycle tests use this independent fabricated
#### view to bind facade-owned record keys.  The full object resembles the
#### public session return while ensuring no PasswordSafe test helper imports
#### into the separate application test package.
####
def fabricated_record_view() -> RecordView:
    return RecordView(
        RecordHandle(),
        RevisionToken(),
        "Alpha Portal",
        "Research",
        "sample-user",
        "https://example.invalid/private",
        False,
    )



#### Represent one mutable authenticated session with observable close behavior.
####
#### Lifecycle tests use this fake to model only public state and resource
#### ownership.  It intentionally exposes no path, secret, or domain mutation
#### operation because the facade must not depend on those details here.
####
class FakeVaultSession:
    _revision: RevisionToken
    apply_calls: int
    change_count: int
    discard_error: BaseException | None
    records_error: BaseException | None
    records_value: tuple[RecordView, ...]
    dirty: bool
    discard_calls: int
    lock_error: BaseException | None
    lock_calls: int
    locked: bool



    #### Initialize an active session with caller-supplied non-secret record views.
    ####
    def __init__(self, records: tuple[RecordView, ...], *, dirty: bool = False) -> None:
        self._revision = records[0].revision if records else RevisionToken()
        self.apply_calls = 0
        self.change_count = 0
        self.records_value = records
        self.dirty = dirty
        self.discard_calls = 0
        self.discard_error = None
        self.records_error = None
        self.lock_calls = 0
        self.lock_error = None
        self.locked = False



    #### Return the current fake document revision for facade command validation.
    ####
    @property
    def revision(self) -> RevisionToken:
        return self._revision



    #### Simulate an external revision change without any application notification.
    ####
    def advance_revision_out_of_band(self) -> None:
        self._revision = RevisionToken()



    #### Return current immutable record views as the real session's public API does.
    ####
    def records(self) -> tuple[RecordView, ...]:
        if self.records_error is not None:
            raise self.records_error
        return self.records_value



    #### Apply fabricated public-field updates and produce one fresh fake revision.
    ####
    def apply(
        self,
        handle: RecordHandle,
        _expected_revision: RevisionToken,
        edits: tuple[SetTextField | SetSecretField, ...],
    ) -> RecordView:
        if _expected_revision is not self._revision:
            raise ValueError("fabricated revision is stale")
        for view in self.records_value:
            if view.handle is not handle:
                continue
            title = view.title
            group = view.group
            username = view.username
            url = view.url
            for edit in edits:
                if isinstance(edit, SetTextField):
                    if edit.field_type is RecordFieldType.TITLE:
                        title = edit.value
                    elif edit.field_type is RecordFieldType.GROUP:
                        group = edit.value
                    elif edit.field_type is RecordFieldType.USERNAME:
                        username = edit.value
                    elif edit.field_type is RecordFieldType.URL:
                        url = edit.value
                else:
                    edit.value.close()
            self._revision = RevisionToken()
            updated = RecordView(handle, self._revision, title, group, username, url, view.protected)
            self.records_value = tuple(
                updated
                if existing.handle is handle
                else RecordView(
                    existing.handle,
                    self._revision,
                    existing.title,
                    existing.group,
                    existing.username,
                    existing.url,
                    existing.protected,
                )
                for existing in self.records_value
            )
            self.apply_calls += 1
            self.change_count += 1
            self.dirty = True
            return updated
        raise ValueError("fabricated record is unavailable")



    #### Add a fabricated record while closing the supplied password owner.
    ####
    def add(self, new_record: NewRecord, _expected_revision: RevisionToken) -> RecordView:
        try:
            if _expected_revision is not self._revision:
                raise ValueError("fabricated revision is stale")
            self._revision = RevisionToken()
            view = RecordView(
                RecordHandle(),
                self._revision,
                new_record.title,
                new_record.group,
                new_record.username,
                new_record.url,
                False,
            )
            self.records_value = (
                *(
                    RecordView(
                        existing.handle,
                        self._revision,
                        existing.title,
                        existing.group,
                        existing.username,
                        existing.url,
                        existing.protected,
                    )
                    for existing in self.records_value
                ),
                view,
            )
            self.change_count += 1
            self.dirty = True
            return view
        finally:
            new_record.password.close()



    #### Lease only fabricated password or URL material for explicit port actions.
    ####
    def reveal(self, handle: RecordHandle, field_type: RecordFieldType) -> SecretLease:
        if not any(view.handle is handle for view in self.records_value):
            raise ValueError("fabricated record is unavailable")
        if field_type is RecordFieldType.PASSWORD:
            return SecretLease.from_bytes(b"fabricated-password")
        if field_type is RecordFieldType.URL:
            return SecretLease.from_bytes(b"https://fabricated.example.invalid/private")
        raise ValueError("fabricated secret field is unavailable")



    #### Mark this clean fake session closed through the public lock operation.
    ####
    def lock(self) -> None:
        if self.dirty:
            raise AssertionError("dirty fake session must not be clean-locked")
        self.lock_calls += 1
        self.locked = True
        if self.lock_error is not None:
            raise self.lock_error



    #### Explicitly discard fake changes and close the session.
    ####
    def discard_and_lock(self) -> None:
        self.discard_calls += 1
        self.dirty = False
        self.locked = True
        if self.discard_error is not None:
            raise self.discard_error



#### Supply predetermined public service outcomes without real vault I/O.
####
#### Each operation closes no passphrase itself so facade tests verify that the
#### application command boundary owns the temporary secret lifetime.
####
class FakeVaultService:
    create_calls: int
    create_error: BaseException | None
    create_session: FakeVaultSession
    open_calls: int
    open_error: BaseException | None
    open_session: FakeVaultSession
    on_open: Callable[[], None] | None
    save_calls: int
    save_error: BaseException | None
    suspend_calls: int
    suspend_error: BaseException | None
    suspended_result: SuspendedSession
    resume_calls: int
    resume_error: BaseException | None
    resume_session: FakeVaultSession
    discard_suspended_calls: int
    discard_suspended_error: BaseException | None



    #### Initialize successful default outcomes over fabricated session objects.
    ####
    def __init__(self, session: FakeVaultSession) -> None:
        self.create_calls = 0
        self.create_error = None
        self.create_session = session
        self.open_calls = 0
        self.open_error = None
        self.open_session = session
        self.on_open = None
        self.save_calls = 0
        self.save_error = None
        self.suspend_calls = 0
        self.suspend_error = None
        self.suspended_result = SuspendedSession("a" * 64, "b" * 64, "c" * 64, 512)
        self.resume_calls = 0
        self.resume_error = None
        self.resume_session = session
        self.discard_suspended_calls = 0
        self.discard_suspended_error = None



    #### Return the configured new-vault session or raise its configured failure.
    ####
    def create(self, _path: object, _passphrase: SecretBuffer) -> FakeVaultSession:
        self.create_calls += 1
        if self.create_error is not None:
            raise self.create_error
        return self.create_session



    #### Return the configured opened session or raise its configured failure.
    ####
    def open(self, _path: object, _passphrase: SecretBuffer) -> FakeVaultSession:
        self.open_calls += 1
        if self.on_open is not None:
            self.on_open()
        if self.open_error is not None:
            raise self.open_error
        return self.open_session



    #### Mark the supplied fake session clean after its configured save succeeds.
    ####
    def save(self, session: FakeVaultSession) -> object:
        self.save_calls += 1
        if self.save_error is not None:
            raise self.save_error
        session.dirty = False
        return object()



    #### Mark one dirty fake session terminal after configured suspension success.
    ####
    def suspend(self, session: FakeVaultSession) -> SuspendedSession:
        self.suspend_calls += 1
        if self.suspend_error is not None:
            raise self.suspend_error
        session.dirty = False
        session.locked = True
        return self.suspended_result



    #### Return the configured resumed session or raise its selected failure.
    ####
    def resume(
        self,
        _path: object,
        _passphrase: SecretBuffer,
        _suspended: SuspendedSession,
    ) -> FakeVaultSession:
        self.resume_calls += 1
        if self.resume_error is not None:
            raise self.resume_error
        return self.resume_session



    #### Record explicit removal of the selected fake pending state.
    ####
    def discard_suspended(self, _suspended: SuspendedSession) -> None:
        self.discard_suspended_calls += 1
        if self.discard_suspended_error is not None:
            raise self.discard_suspended_error



#### Record clipboard interactions while consuming each lease only during the call.
####
class RecordingClipboard:
    clear_calls: int
    copied: bytes | None
    copy_error: BaseException | None
    _last_lease: SecretLease | None



    #### Initialize an empty recording port with optional fabricated failure injection.
    ####
    def __init__(self) -> None:
        self.clear_calls = 0
        self.copied = None
        self.copy_error = None
        self._last_lease = None



    #### Copy a lease only while it remains open and optionally raise a fake error.
    ####
    def copy(self, value: SecretLease, *, lifetime_seconds: int) -> None:
        if lifetime_seconds <= 0:
            raise AssertionError("clipboard lifetime must be positive")
        self.copied = bytes(value.borrow())
        self._last_lease = value
        if self.copy_error is not None:
            raise self.copy_error



    #### Record adapter-owned clipboard clearing after terminal facade transitions.
    ####
    def clear_owned(self) -> None:
        self.clear_calls += 1



    #### Report whether the most recently observed lease was wiped on facade exit.
    ####
    @property
    def last_lease_closed(self) -> bool:
        return self._last_lease is not None and self._last_lease.closed



#### Record browser interactions while keeping every leased URL within the call.
####
class RecordingBrowser:
    _last_lease: SecretLease | None
    open_error: BaseException | None
    opened: bool



    #### Initialize a successful browser port with optional fabricated failure injection.
    ####
    def __init__(self) -> None:
        self._last_lease = None
        self.open_error = None
        self.opened = False



    #### Accept one leased URL without retaining or rendering its contents.
    ####
    def open(self, value: SecretLease) -> bool:
        value.borrow()
        self._last_lease = value
        if self.open_error is not None:
            raise self.open_error
        self.opened = True
        return True



    #### Report whether the most recently observed lease was wiped on facade exit.
    ####
    @property
    def last_lease_closed(self) -> bool:
        return self._last_lease is not None and self._last_lease.closed
