"""Provide focused fake PasswordSafe service and session objects for facade tests.

The fakes preserve the public service/session effects the facade owns while
remaining independent from encryption, storage, and fabricated file contents.
"""

from collections.abc import Callable

from bonobo_core.passwordsafe import RecordHandle, RecordView, RevisionToken, SecretBuffer



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
    records_value: tuple[RecordView, ...]
    dirty: bool
    discard_calls: int
    lock_calls: int



    #### Initialize an active session with caller-supplied non-secret record views.
    ####
    def __init__(self, records: tuple[RecordView, ...], *, dirty: bool = False) -> None:
        self.records_value = records
        self.dirty = dirty
        self.discard_calls = 0
        self.lock_calls = 0



    #### Return current immutable record views as the real session's public API does.
    ####
    def records(self) -> tuple[RecordView, ...]:
        return self.records_value



    #### Mark this clean fake session closed through the public lock operation.
    ####
    def lock(self) -> None:
        if self.dirty:
            raise AssertionError("dirty fake session must not be clean-locked")
        self.lock_calls += 1



    #### Explicitly discard fake changes and close the session.
    ####
    def discard_and_lock(self) -> None:
        self.discard_calls += 1
        self.dirty = False



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
