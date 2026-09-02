"""Verify dirty sessions suspend only into authenticated private ciphertext.

All vaults, passphrases, and record values are fabricated.  Tests retain the
source pathname before suspension so no locked session property is accessed.
"""

import os
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import asdict
from multiprocessing import get_context
from multiprocessing.connection import Connection
from pathlib import Path
from threading import Event, Thread
from typing import Literal
from uuid import UUID

import pytest

import bonobo_core.passwordsafe.pending as pending_module
import bonobo_core.passwordsafe.storage as storage_module
from bonobo_core.passwordsafe import (
    AuthenticationError,
    ExternalModificationError,
    NewRecord,
    SecretBuffer,
    SuspendedSession,
    VaultService,
    VaultSession,
)
from bonobo_core.passwordsafe.errors import StorageError, StorageReason
from bonobo_core.passwordsafe.model import VaultDocument
from bonobo_core.passwordsafe.pending import (
    PendingSessionStore,
    PendingStage,
    _LocatedPending,
    _open_private_anchor,
)
from bonobo_core.passwordsafe.reader import PasswordSafeReader
from bonobo_core.passwordsafe.storage import (
    FileBaseline,
    LocalVaultStore,
    StorageStage,
    _PublicationAnchor,
)
from bonobo_core.passwordsafe.storage import (
    _capture_regular_file as _storage_capture_regular_file,
)
from tests.passwordsafe.helpers import DeterministicRandomSource
from tests.passwordsafe.test_writer import _private_directory, _XorBackend



#### Represent an injected process-control failure without aborting the pytest run.
####
class _InjectedControlFlow(BaseException):
    pass



#### Raise one raw path-bearing failure while entering a fabricated lock scope.
####
class _FailingLockScope:
    __slots__ = ("_private_path",)



    #### Retain only one fabricated private path for the injected failure.
    ####
    def __init__(self, private_path: Path) -> None:
        self._private_path = private_path



    #### Interrupt lock-scope entry with the deliberately path-bearing failure.
    ####
    def __enter__(self) -> None:
        raise OSError(f"fabricated lock failure at {self._private_path}")



    #### Never suppress a failure if exit is unexpectedly reached.
    ####
    def __exit__(self, *_args: object) -> Literal[False]:
        return False



#### Delegate retained-directory operations while controlling the final identity check.
####
class _FinalIdentityAnchor:
    __slots__ = ("_anchor", "_stable", "stable_calls")



    #### Retain the production anchor and one deterministic final-check outcome.
    ####
    def __init__(self, anchor: _PublicationAnchor, stable: Callable[[], bool]) -> None:
        self._anchor = anchor
        self._stable = stable
        self.stable_calls = 0



    #### Stream names from the retained production directory identity.
    ####
    def iter_child_names(self) -> Iterator[str]:
        return self._anchor.iter_child_names()



    #### Delegate persistent child creation to the retained production anchor.
    ####
    def create_persistent(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        return self._anchor.create_persistent(name)



    #### Delegate read-only child opening to the retained production anchor.
    ####
    def open_child(self, name: str) -> tuple[int, tuple[int, int]] | None:
        return self._anchor.open_child(name)



    #### Delegate replace-capable child opening to the retained production anchor.
    ####
    def open_child_for_replace(self, name: str) -> tuple[int, tuple[int, int]] | None:
        return self._anchor.open_child_for_replace(name)



    #### Delegate retained child privacy validation without reopening its pathname.
    ####
    def private_child_is_safe(self, descriptor: int, identity: tuple[int, int]) -> bool:
        return self._anchor.private_child_is_safe(descriptor, identity)



    #### Delegate exact retained-child replacement to the production anchor.
    ####
    def replace_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        return self._anchor.replace_child(descriptor, identity, source_name, destination_name)



    #### Delegate absent-only retained-child publication to the production anchor.
    ####
    def publish_new_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        return self._anchor.publish_new_child(descriptor, identity, source_name, destination_name)



    #### Delegate exact retained-child removal to the production anchor.
    ####
    def remove_if_same(self, descriptor: int, name: str, identity: tuple[int, int]) -> bool:
        return self._anchor.remove_if_same(descriptor, name, identity)



    #### Return only the injected outcome and count each final authorization attempt.
    ####
    def stable(self) -> bool:
        self.stable_calls += 1
        return self._stable()



    #### Delegate directory synchronization to the retained production anchor.
    ####
    def synchronize(self) -> None:
        self._anchor.synchronize()



    #### Release the retained production directory identity.
    ####
    def close(self) -> None:
        self._anchor.close()



#### Inject one concrete process-lock lifecycle failure through production locking.
####
def _install_process_lock_fault(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    private_path: Path,
) -> None:
    lock_name = "_lock_windows_descriptor" if os.name == "nt" else "_lock_posix_descriptor"
    unlock_name = "_unlock_windows_descriptor" if os.name == "nt" else "_unlock_posix_descriptor"



    #### Raise a raw private-path failure from the selected native seam.
    ####
    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"fabricated {stage} failure at {private_path}")

    if stage == "acquire":
        monkeypatch.setattr(storage_module, lock_name, fail)
        return
    if stage == "chmod":
        monkeypatch.setattr(os, "chmod", fail)
        return
    if stage == "unlock":
        monkeypatch.setattr(storage_module, unlock_name, fail)
        return
    if stage != "close":
        raise AssertionError("unsupported fabricated lock stage")
    production_lock = getattr(storage_module, lock_name)
    production_close = os.close
    selected_descriptor = -1



    #### Remember only the descriptor which successfully obtained the process lock.
    ####
    def remember_lock(descriptor: int) -> None:
        nonlocal selected_descriptor
        production_lock(descriptor)
        selected_descriptor = descriptor



    #### Close the real descriptor, then surface the fabricated close failure.
    ####
    def fail_selected_close(descriptor: int) -> None:
        production_close(descriptor)
        if descriptor == selected_descriptor:
            raise OSError(f"fabricated close failure at {private_path}")

    monkeypatch.setattr(storage_module, lock_name, remember_lock)
    monkeypatch.setattr(os, "close", fail_selected_close)



#### Assemble one deterministic service with persistent private pending storage.
####
def _service(tmp_path: Path) -> VaultService:
    return VaultService(
        _XorBackend(),
        _private_directory(tmp_path, "pending-working"),
        _private_directory(tmp_path, "pending-private"),
        random_source=DeterministicRandomSource(bytes((index + 73) % 251 for index in range(131072))),
    )



#### Exercise absent-only publication through the retained native directory identity.
####
def test_native_anchor_publishes_staged_child_by_retained_identity(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path, "anchor-private")
    anchor = _open_private_anchor(directory)
    descriptor = -1
    staged_name = ".fabricated-staged"
    published_name = ".fabricated-published"
    payload = b"fabricated-anchor-payload"
    try:
        created = anchor.create_persistent(staged_name)
        assert created is not None
        descriptor, identity, cleanup_name = created
        assert cleanup_name == staged_name
        assert os.write(descriptor, payload) == len(payload)
        os.fsync(descriptor)

        assert anchor.publish_new_child(descriptor, identity, staged_name, published_name)
        assert not (directory / staged_name).exists()
        assert (directory / published_name).exists()
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(payload)) == payload
    finally:
        if descriptor >= 0:
            with suppress(BaseException):
                os.close(descriptor)
        with suppress(BaseException):
            anchor.close()



#### Hold one pending open guard in a spawned process until its parent releases it.
####
def _hold_pending_identity_guard(
    pending: str,
    working: str,
    source: str,
    connection: Connection,
) -> None:
    store = PendingSessionStore(Path(pending), Path(working))
    with store.guard_open(Path(source)):
        connection.send("locked")
        connection.recv()



#### Attempt an alias guard and report only after entering the protected region.
####
def _acquire_pending_alias_guard(
    pending: Path,
    working: Path,
    source: Path,
    acquired: Event,
) -> None:
    store = PendingSessionStore(pending, working)
    with store.guard_open(source):
        acquired.set()



#### Replace the pending pathname only while a pathname enumeration is active.
####
def _aba_scandir(
    directory: Path,
    substitute: Path,
    retained: Path,
) -> Callable[[str | os.PathLike[str]], Iterator[os.DirEntry[str]]]:
    production_scandir = os.scandir
    armed = True



    #### Expose an empty pathname, then restore the retained directory before return.
    ####
    def enumerate_substitute(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
        nonlocal armed
        if Path(path) != directory or not armed:
            with production_scandir(path) as entries:
                yield from entries
            return
        armed = False
        directory.replace(retained)
        substitute.replace(directory)
        try:
            with production_scandir(directory) as entries:
                yield from entries
        finally:
            directory.replace(substitute)
            retained.replace(directory)

    return enumerate_substitute



#### Create one dirty session whose unsaved title exists only in memory.
####
def _dirty_session(service: VaultService, path: Path) -> VaultSession:
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-pending-master"))
    session.add(
        NewRecord(
            UUID("77777777-7777-4777-8777-777777777777"),
            "Unsaved pending title",
            SecretBuffer.from_bytes(b"fabricated-pending-credential"),
            username="sample-user",
            url="https://pending.example.invalid",
        ),
        session.revision,
    )
    return session



#### Commit authenticated private ciphertext before wiping the dirty live session.
####
def test_dirty_suspend_is_authenticated_private_and_leaves_source_unchanged(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    before = source.read_bytes()

    suspended = service.suspend(session)

    assert session.locked
    assert source.read_bytes() == before
    assert isinstance(suspended, SuspendedSession)
    assert set(asdict(suspended)) == {"identifier", "sha256", "source_sha256", "size"}
    assert len(suspended.identifier) == 64
    assert suspended.size > 0
    assert not hasattr(suspended, "path")
    assert str(source) not in repr(suspended)



#### Block a fresh open through a hard link when the file identity has pending work.
####
def test_fresh_open_rejects_pending_source_hard_link_alias(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    alias = tmp_path / "fabricated-open-alias.psafe3"
    os.link(source, alias)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")
    unexpectedly_opened: VaultSession | None = None

    try:
        with pytest.raises(StorageError):
            unexpectedly_opened = service.open(alias, passphrase)
    finally:
        if unexpectedly_opened is not None:
            unexpectedly_opened.lock()

    assert passphrase.closed
    service.discard_suspended(source, suspended)



#### Refuse a second initial suspension reached through the same hard-link identity.
####
def test_alias_initial_suspend_cannot_publish_a_second_visible_slot(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    source_session = _dirty_session(service, source)
    alias = tmp_path / "fabricated-suspend-alias.psafe3"
    os.link(source, alias)
    alias_session = service.open(alias, SecretBuffer.from_bytes(b"fabricated-pending-master"))
    alias_session.add(
        NewRecord(
            UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            "Alias-only pending edit",
            SecretBuffer.from_bytes(b"fabricated-alias-secret"),
        ),
        alias_session.revision,
    )
    suspended = service.suspend(source_session)

    with pytest.raises(StorageError):
        service.suspend(alias_session)

    slots = tuple((tmp_path / "pending-private").glob(".bonobo-pending-slot-*.slot"))
    assert len(slots) == 1
    assert alias_session.dirty
    assert not alias_session.locked
    service._pending.verify(source, suspended)
    alias_session.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Serialize cross-process alias guards by source identity rather than pathname.
####
def test_pending_identity_guard_blocks_hard_link_alias_across_processes(tmp_path: Path) -> None:
    pending = _private_directory(tmp_path, "identity-pending")
    working = _private_directory(tmp_path, "identity-working")
    source = tmp_path / "fabricated-identity-source.psafe3"
    alias = tmp_path / "fabricated-identity-alias.psafe3"
    source.write_bytes(b"fabricated encrypted identity bytes")
    os.link(source, alias)
    context = get_context("spawn")
    parent_connection, child_connection = context.Pipe()
    process = context.Process(
        target=_hold_pending_identity_guard,
        args=(str(pending), str(working), str(source), child_connection),
    )
    process.start()
    contender: Thread | None = None
    acquired = Event()
    try:
        assert parent_connection.poll(5.0)
        assert parent_connection.recv() == "locked"
        contender = Thread(
            target=_acquire_pending_alias_guard,
            args=(pending, working, alias, acquired),
        )
        contender.start()
        assert not acquired.wait(0.25)
    finally:
        if process.is_alive():
            parent_connection.send("release")
        if contender is not None:
            contender.join(timeout=5.0)
        process.join(timeout=5.0)
        parent_connection.close()
        child_connection.close()

    assert acquired.is_set()
    assert process.exitcode == 0
    assert contender is not None and not contender.is_alive()



#### Project path-bearing acquisition failures at every pending-store boundary.
####
@pytest.mark.parametrize("operation", ["publish", "open", "discard", "verify"])
def test_pending_public_boundaries_close_process_lock_acquisition_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    suspended: SuspendedSession | None = None
    if operation != "publish":
        suspended = service.suspend(session)
    private_path = tmp_path / "pending-working" / ".fabricated-private.lock"



    #### Fail the destination process lock before its body can execute.
    ####
    def failing_destination_lock(*_args: object, **_kwargs: object) -> _FailingLockScope:
        return _FailingLockScope(private_path)

    monkeypatch.setattr(pending_module, "_destination_lock", failing_destination_lock)

    with pytest.raises(StorageError) as captured:
        if operation == "publish":
            service.suspend(session)
        elif operation == "open":
            assert suspended is not None
            service._pending.open(source, suspended)
        elif operation == "discard":
            assert suspended is not None
            service._pending.discard(source, suspended)
        else:
            assert suspended is not None
            service._pending.verify(source, suspended)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(private_path) not in str(captured.value)
    assert str(private_path) not in repr(captured.value)
    monkeypatch.undo()
    if suspended is None:
        assert session.dirty
        assert not session.locked
        session.discard_and_lock()
    else:
        service._pending.verify(source, suspended)
        service.discard_suspended(source, suspended)



#### Project acquisition, chmod, unlock, and close failures from real lock scopes.
####
@pytest.mark.parametrize("stage", ["acquire", "chmod", "unlock", "close"])
def test_pending_guard_closes_process_lock_lifecycle_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    private_path = tmp_path / "pending-working" / ".fabricated-private.lock"
    _install_process_lock_fault(monkeypatch, stage, private_path)

    with pytest.raises(StorageError) as captured, service._pending.guard_open(source):
        pass

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(private_path) not in str(captured.value)
    assert str(private_path) not in repr(captured.value)
    monkeypatch.undo()
    session.discard_and_lock()



#### Reconcile process-lock cleanup failure after pending publication as committed.
####
@pytest.mark.parametrize("stage", ["unlock", "close"])
def test_suspend_process_lock_cleanup_failure_locks_with_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    private_path = tmp_path / "pending-working" / ".fabricated-private.lock"
    _install_process_lock_fault(monkeypatch, stage, private_path)

    with pytest.raises(StorageError) as captured:
        service.suspend(session)

    suspended = getattr(captured.value, "suspended", None)
    assert isinstance(suspended, SuspendedSession)
    assert session.locked
    assert captured.value.__cause__ is None
    committed_context = captured.value.__context__
    assert str(private_path) not in str(captured.value)
    assert str(private_path) not in repr(captured.value)
    while committed_context is not None:
        assert isinstance(committed_context, StorageError)
        assert committed_context.__cause__ is None
        assert str(private_path) not in repr(committed_context)
        committed_context = committed_context.__context__
    monkeypatch.undo()
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)



#### Treat destination-lock teardown after exact discard as committed success.
####
@pytest.mark.parametrize("stage", ["unlock", "close"])
def test_committed_discard_ignores_destination_lock_teardown_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    private_path = tmp_path / "pending-working" / ".fabricated-private.lock"
    _install_process_lock_fault(monkeypatch, stage, private_path)

    try:
        service.discard_suspended(source, suspended)
    finally:
        monkeypatch.undo()

    with pytest.raises(StorageError):
        service._pending.verify(source, suspended)



#### Retain the exact selector after every explicit-discard precommit failure.
####
@pytest.mark.parametrize("stage", ["acquire", "chmod", "lookup", "removal"])
def test_failed_explicit_discard_before_commit_retains_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    private_path = tmp_path / "pending-working" / ".fabricated-private.lock"



    #### Raise one raw lookup failure before any pending state can be hidden.
    ####
    def fail_lookup(
        _store: PendingSessionStore,
        _source: Path,
        _suspended: SuspendedSession,
    ) -> _LocatedPending:
        raise OSError(f"fabricated lookup failure at {private_path}")

    if stage in ("acquire", "chmod"):
        _install_process_lock_fault(monkeypatch, stage, private_path)
    elif stage == "lookup":
        monkeypatch.setattr(PendingSessionStore, "_find_locked", fail_lookup)
    else:
        service._pending.faults.raise_at(PendingStage.CLEANUP)

    with pytest.raises(StorageError) as captured:
        service.discard_suspended(source, suspended)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(private_path) not in str(captured.value)
    assert str(private_path) not in repr(captured.value)
    assert suspended.identifier not in repr(captured.value)
    monkeypatch.undo()
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)
    with pytest.raises(StorageError):
        service._pending.verify(source, suspended)



#### Authorize every completed retained-directory scan against its current path.
####
@pytest.mark.parametrize("final_outcome", ["false", "error"])
@pytest.mark.parametrize(
    ("operation", "scan_outcome"),
    [
        ("guard-open-alias", "positive-match"),
        ("publish-alias", "positive-match"),
        ("publish-new", "absence"),
        ("open", "selected-match"),
        ("verify", "selected-match"),
        ("discard", "selected-match"),
    ],
)
def test_complete_pending_scans_require_final_current_anchor_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    scan_outcome: str,
    final_outcome: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    source_session = _dirty_session(service, source)
    alias = tmp_path / "fabricated-source-alias.psafe3"
    alias_session: VaultSession | None = None
    new_source = tmp_path / "fabricated-new-source.psafe3"
    new_session: VaultSession | None = None
    if operation in ("guard-open-alias", "publish-alias"):
        os.link(source, alias)
    if operation == "publish-alias":
        alias_session = service.open(alias, SecretBuffer.from_bytes(b"fabricated-pending-master"))
        alias_session.add(
            NewRecord(
                UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
                "Alias final-anchor edit",
                SecretBuffer.from_bytes(b"fabricated-alias-final-anchor-secret"),
            ),
            alias_session.revision,
        )
    if operation == "publish-new":
        new_session = _dirty_session(service, new_source)
    suspended = service.suspend(source_session)
    private_path = tmp_path / "pending-private"
    production_open = pending_module._open_private_anchor
    wrapped: list[_FinalIdentityAnchor] = []
    unexpected_suspended: SuspendedSession | None = None
    entered_guard = False



    #### Return the selected false or raw path-bearing final-check outcome.
    ####
    def fail_final_identity() -> bool:
        if final_outcome == "error":
            raise OSError(f"fabricated final identity failure at {private_path}")
        return False



    #### Wrap each production anchor without altering any operation except stable.
    ####
    def open_failing_anchor(path: Path) -> _PublicationAnchor:
        wrapper = _FinalIdentityAnchor(production_open(path), fail_final_identity)
        wrapped.append(wrapper)
        return wrapper

    monkeypatch.setattr(pending_module, "_open_private_anchor", open_failing_anchor)
    try:
        with pytest.raises(StorageError) as captured:
            if operation == "guard-open-alias":
                with service._pending.guard_open(alias):
                    entered_guard = True
            elif operation == "publish-alias":
                assert alias_session is not None
                unexpected_suspended = service.suspend(alias_session)
            elif operation == "publish-new":
                assert new_session is not None
                unexpected_suspended = service.suspend(new_session)
            elif operation == "open":
                service._pending.open(source, suspended).snapshot.close()
            elif operation == "verify":
                service._pending.verify(source, suspended)
            else:
                service._pending.discard(source, suspended)
    finally:
        monkeypatch.undo()
        if unexpected_suspended is not None:
            cleanup_source = alias if operation == "publish-alias" else new_source
            with suppress(StorageError):
                service.discard_suspended(cleanup_source, unexpected_suspended)
        if alias_session is not None and not alias_session.locked:
            alias_session.discard_and_lock()
        if new_session is not None and not new_session.locked:
            new_session.discard_and_lock()

    assert not entered_guard
    assert sum(anchor.stable_calls for anchor in wrapped) == 1, (
        f"{operation}:{scan_outcome} did not perform exactly one final authorization"
    )
    assert captured.value.reason == StorageReason.VERIFICATION_FAILED.value
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(private_path) not in str(captured.value)
    assert str(private_path) not in repr(captured.value)
    assert suspended.identifier not in str(captured.value)
    assert suspended.identifier not in repr(captured.value)
    assert len(tuple(private_path.glob(".bonobo-pending-slot-*.slot"))) == 1
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)



#### Reject a decoy opened before the authoritative directory returns to its path.
####
@pytest.mark.parametrize("operation", ["alias-open", "alias-suspend"])
def test_decoy_before_anchor_open_requires_final_current_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    source_session = _dirty_session(service, source)
    alias = tmp_path / "fabricated-decoy-alias.psafe3"
    os.link(source, alias)
    alias_session: VaultSession | None = None
    if operation == "alias-suspend":
        alias_session = service.open(alias, SecretBuffer.from_bytes(b"fabricated-pending-master"))
        alias_session.add(
            NewRecord(
                UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
                "Alias decoy edit",
                SecretBuffer.from_bytes(b"fabricated-alias-decoy-secret"),
            ),
            alias_session.revision,
        )
    suspended = service.suspend(source_session)
    pending = tmp_path / "pending-private"
    substitute = _private_directory(tmp_path, "fabricated-decoy-pending")
    retained = tmp_path / "fabricated-retained-pending"
    production_open = pending_module._open_private_anchor
    armed = True
    restored = False
    wrapped: list[_FinalIdentityAnchor] = []
    unexpected_session: VaultSession | None = None
    unexpected_suspended: SuspendedSession | None = None
    passphrase = (
        SecretBuffer.from_bytes(b"fabricated-pending-master")
        if operation == "alias-open"
        else None
    )



    #### Restore the real directory to its pathname exactly once.
    ####
    def restore_real_directory() -> None:
        nonlocal restored
        if restored:
            return
        pending.replace(substitute)
        retained.replace(pending)
        restored = True



    #### Restore the current pathname immediately before checking the decoy anchor.
    ####
    def restore_then_check(anchor: _PublicationAnchor) -> bool:
        restore_real_directory()
        return anchor.stable()



    #### Open the empty decoy first and expose restoration only at final authorization.
    ####
    def open_decoy_anchor(path: Path) -> _PublicationAnchor:
        nonlocal armed
        if path != pending or not armed:
            return production_open(path)
        armed = False
        pending.replace(retained)
        substitute.replace(pending)
        try:
            anchor = production_open(path)
        except BaseException:
            restore_real_directory()
            raise



        #### Bind restoration to this retained decoy's final stable check.
        ####
        def final_identity() -> bool:
            return restore_then_check(anchor)

        wrapper = _FinalIdentityAnchor(anchor, final_identity)
        wrapped.append(wrapper)
        return wrapper

    monkeypatch.setattr(pending_module, "_open_private_anchor", open_decoy_anchor)
    try:
        with pytest.raises(StorageError) as captured:
            if operation == "alias-open":
                assert passphrase is not None
                unexpected_session = service.open(alias, passphrase)
            else:
                assert alias_session is not None
                unexpected_suspended = service.suspend(alias_session)
    finally:
        if not restored:
            restore_real_directory()
        monkeypatch.undo()
        if unexpected_session is not None:
            unexpected_session.lock()
        if unexpected_suspended is not None:
            with suppress(StorageError):
                service.discard_suspended(alias, unexpected_suspended)
        if alias_session is not None and not alias_session.locked:
            alias_session.discard_and_lock()

    if passphrase is not None:
        assert passphrase.closed
    assert sum(anchor.stable_calls for anchor in wrapped) == 1
    assert captured.value.reason == StorageReason.VERIFICATION_FAILED.value
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(pending) not in repr(captured.value)
    assert suspended.identifier not in repr(captured.value)
    assert len(tuple(pending.glob(".bonobo-pending-slot-*.slot"))) == 1
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)



#### Enumerate the retained pending directory even during pathname ABA replacement.
####
def test_alias_open_rejects_pending_during_directory_enumeration_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    alias = tmp_path / "fabricated-aba-open-alias.psafe3"
    os.link(source, alias)
    pending = tmp_path / "pending-private"
    substitute = _private_directory(tmp_path, "fabricated-empty-pending")
    retained = tmp_path / "fabricated-retained-pending"
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")
    unexpectedly_opened: VaultSession | None = None
    monkeypatch.setattr(os, "scandir", _aba_scandir(pending, substitute, retained))

    try:
        with pytest.raises(StorageError):
            unexpectedly_opened = service.open(alias, passphrase)
    finally:
        monkeypatch.undo()
        if unexpectedly_opened is not None:
            unexpectedly_opened.lock()

    assert passphrase.closed
    service.discard_suspended(source, suspended)



#### Refuse alias suspension while the pending pathname undergoes a complete ABA.
####
def test_alias_suspend_rejects_pending_during_directory_enumeration_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    source_session = _dirty_session(service, source)
    alias = tmp_path / "fabricated-aba-suspend-alias.psafe3"
    os.link(source, alias)
    alias_session = service.open(alias, SecretBuffer.from_bytes(b"fabricated-pending-master"))
    alias_session.add(
        NewRecord(
            UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            "Alias ABA edit",
            SecretBuffer.from_bytes(b"fabricated-alias-aba-secret"),
        ),
        alias_session.revision,
    )
    suspended = service.suspend(source_session)
    pending = tmp_path / "pending-private"
    substitute = _private_directory(tmp_path, "fabricated-empty-pending")
    retained = tmp_path / "fabricated-retained-pending"
    unexpected: SuspendedSession | None = None
    monkeypatch.setattr(os, "scandir", _aba_scandir(pending, substitute, retained))

    try:
        with pytest.raises(StorageError):
            unexpected = service.suspend(alias_session)
    finally:
        monkeypatch.undo()
        if unexpected is not None:
            service.discard_suspended(alias, unexpected)
        if not alias_session.locked:
            alias_session.discard_and_lock()
        service.discard_suspended(source, suspended)



#### Reject a hostile pending directory before unbounded enumeration can continue.
####
def test_pending_directory_entry_count_is_strictly_bounded(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-count-source.psafe3"
    session = service.create(source, SecretBuffer.from_bytes(b"fabricated-pending-master"))
    session.lock()
    pending = tmp_path / "pending-private"
    for index in range(257):
        entry = pending / f".fabricated-hostile-entry-{index:03d}"
        entry.write_bytes(b"fabricated encrypted noise")
        entry.chmod(0o600)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")
    unexpectedly_opened: VaultSession | None = None

    try:
        with pytest.raises(StorageError) as captured:
            unexpectedly_opened = service.open(source, passphrase)
    finally:
        if unexpectedly_opened is not None:
            unexpectedly_opened.lock()

    assert passphrase.closed
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(pending) not in repr(captured.value)



#### Reject resume when the original source identity or encrypted baseline changed.
####
def test_resume_rejects_source_changed_after_suspend(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    suspended = service.suspend(session)
    replacement = tmp_path / "fabricated-replacement.psafe3"
    replacement_session = service.create(
        replacement,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
    )
    replacement_session.lock()
    replacement.replace(source)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(ExternalModificationError):
        service.resume(source, passphrase, suspended)

    assert passphrase.closed



#### Resume exact unsaved content and remove pending state only after save succeeds.
####
def test_resume_preserves_dirty_revision_until_successful_save(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    source_before = source.read_bytes()
    suspended = service.suspend(session)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    resumed = service.resume(source, passphrase, suspended)

    assert passphrase.closed
    assert resumed.records()[0].title == "Unsaved pending title"
    assert source.read_bytes() == source_before
    service.save(resumed)
    assert not resumed.dirty
    with pytest.raises(StorageError):
        service.discard_suspended(source, suspended)
    resumed.lock()



#### Retain a valid pending artifact after wrong-passphrase authentication failure.
####
def test_wrong_passphrase_does_not_consume_pending_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    wrong = SecretBuffer.from_bytes(b"fabricated-wrong-master")

    with pytest.raises(AuthenticationError):
        service.resume(source, wrong, suspended)

    assert wrong.closed
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    assert resumed.records()[0].title == "Unsaved pending title"
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Remove one selected pending slot while leaving the unchanged source untouched.
####
def test_discard_suspended_removes_only_pending_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    source_before = source.read_bytes()
    suspended = service.suspend(session)

    service.discard_suspended(source, suspended)

    assert source.read_bytes() == source_before
    with pytest.raises(StorageError):
        service.resume(
            source,
            SecretBuffer.from_bytes(b"fabricated-pending-master"),
            suspended,
        )



#### Keep the dirty live session and source unchanged at every precommit fault.
####
@pytest.mark.parametrize(
    "stage",
    [
        PendingStage.PREPARATION,
        PendingStage.WRITE,
        PendingStage.FILE_SYNC,
        PendingStage.AUTHENTICATION,
        PendingStage.COMPARE,
        PendingStage.SLOT_PUBLICATION,
        PendingStage.DIRECTORY_SYNC,
        PendingStage.POST_PUBLICATION_VALIDATION,
    ],
)
def test_suspend_precommit_fault_retains_dirty_session_and_no_visible_slot(
    tmp_path: Path,
    stage: PendingStage,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    source_before = source.read_bytes()
    service._pending.faults.raise_at(stage)

    with pytest.raises(StorageError):
        service.suspend(session)

    assert not session.locked
    assert session.dirty
    assert source.read_bytes() == source_before
    assert not tuple((tmp_path / "pending-private").glob(".bonobo-pending-slot-*.slot"))



#### Treat obsolete-artifact cleanup faults as success after the new slot commits.
####
def test_suspend_cleanup_fault_returns_committed_resumable_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    source_before = source.read_bytes()
    service._pending.faults.raise_at(PendingStage.CLEANUP)

    suspended = service.suspend(session)

    assert session.locked
    assert source.read_bytes() == source_before
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    assert resumed.records()[0].title == "Unsaved pending title"
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Reject ciphertext tampering without consuming or replacing the selected artifact.
####
def test_resume_rejects_tampered_pending_artifact(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    artifact = (
        tmp_path
        / "pending-private"
        / f".bonobo-pending-artifact-{suspended.identifier}.psafe3"
    )
    artifact.write_bytes(b"fabricated-tampered-ciphertext")
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError):
        service.resume(source, passphrase, suspended)

    assert passphrase.closed
    assert artifact.read_bytes() == b"fabricated-tampered-ciphertext"



#### Reject two valid visible slots that both claim the same stable identifier.
####
def test_resume_rejects_ambiguous_pending_slots(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    pending_directory = tmp_path / "pending-private"
    slot = next(pending_directory.glob(".bonobo-pending-slot-*.slot"))
    duplicate = pending_directory / f".bonobo-pending-slot-{'d' * 64}.slot"
    duplicate.write_bytes(slot.read_bytes())
    duplicate.chmod(0o600)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError):
        service.resume(source, passphrase, suspended)

    assert passphrase.closed



#### Never delete a replacement file substituted after exact artifact selection.
####
def test_discard_identity_replacement_preserves_replacement_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    pending_directory = tmp_path / "pending-private"
    replacement_bytes = b"fabricated-attacker-replacement"
    production_find = PendingSessionStore._find_locked



    #### Substitute a new identity only after cleanup retained the selected descriptor.
    ####
    def replace_after_find(
        store: PendingSessionStore,
        source_path: Path,
        selector: SuspendedSession,
    ) -> _LocatedPending:
        located = production_find(store, source_path, selector)
        os.close(located.artifact_descriptor)
        located.artifact_descriptor = -1
        replacement_name = ".fabricated-replacement"
        created = located.anchor.create_persistent(replacement_name)
        assert created is not None
        descriptor, identity, cleanup_name = created
        assert cleanup_name == replacement_name
        try:
            assert os.write(descriptor, replacement_bytes) == len(replacement_bytes)
            os.fsync(descriptor)
            assert located.anchor.replace_child(
                descriptor,
                identity,
                replacement_name,
                located.artifact_name,
            )
        finally:
            os.close(descriptor)
        return located

    monkeypatch.setattr(PendingSessionStore, "_find_locked", replace_after_find)

    with pytest.raises(StorageError):
        service.discard_suspended(source, suspended)

    artifact = pending_directory / f".bonobo-pending-artifact-{suspended.identifier}.psafe3"
    assert artifact.read_bytes() == replacement_bytes



#### Roll the visible slot back when cleanup is interrupted by a BaseException.
####
def test_discard_cleanup_baseexception_retains_resumable_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    located = service._pending._find_locked(source, suspended)
    anchor_type = type(located.anchor)
    artifact_name = located.artifact_name
    production_remove = anchor_type.remove_if_same
    located.close()



    #### Interrupt only the selected artifact removal after the slot is hidden.
    ####
    def interrupt_artifact_cleanup(
        anchor: _PublicationAnchor,
        descriptor: int,
        name: str,
        identity: tuple[int, int],
    ) -> bool:
        if name == artifact_name:
            raise KeyboardInterrupt("fabricated cleanup interruption")
        return production_remove(anchor, descriptor, name, identity)

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(anchor_type, "remove_if_same", interrupt_artifact_cleanup)
        with pytest.raises(KeyboardInterrupt, match="fabricated cleanup interruption"):
            service.discard_suspended(source, suspended)

    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    assert resumed.records()[0].title == "Unsaved pending title"
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Keep the valid pending slot when publication of a resumed save fails.
####
def test_failed_resumed_save_retains_valid_pending_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    service._store.faults.raise_at(StorageStage.CREATE)

    with pytest.raises(StorageError):
        service.save(resumed)

    assert resumed.dirty
    resumed.discard_and_lock()
    retried = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    assert retried.records()[0].title == "Unsaved pending title"
    retried.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Preserve the old valid slot when replacement publication cannot commit.
####
@pytest.mark.parametrize(
    "stage",
    [
        PendingStage.SLOT_PUBLICATION,
        PendingStage.DIRECTORY_SYNC,
        PendingStage.POST_PUBLICATION_VALIDATION,
    ],
)
def test_pending_replacement_fault_restores_old_valid_slot(
    tmp_path: Path,
    stage: PendingStage,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    first = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    resumed.add(
        NewRecord(
            UUID("88888888-8888-4888-8888-888888888888"),
            "Second unsaved title",
            SecretBuffer.from_bytes(b"fabricated-second-credential"),
        ),
        resumed.revision,
    )
    service._pending.faults.raise_at(stage)

    with pytest.raises(StorageError):
        service.suspend(resumed)

    assert resumed.dirty
    assert not resumed.locked
    resumed.discard_and_lock()
    restored = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    assert tuple(record.title for record in restored.records()) == ("Unsaved pending title",)
    restored.discard_and_lock()
    service.discard_suspended(source, first)



#### Replace one old slot atomically and make only the new selector resumable.
####
def test_successful_pending_replacement_exposes_only_new_slot(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    first = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    resumed.add(
        NewRecord(
            UUID("88888888-8888-4888-8888-888888888888"),
            "Second unsaved title",
            SecretBuffer.from_bytes(b"fabricated-second-credential"),
        ),
        resumed.revision,
    )

    second = service.suspend(resumed)

    old_passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")
    with pytest.raises(StorageError):
        service.resume(source, old_passphrase, first)
    assert old_passphrase.closed
    current = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        second,
    )
    assert tuple(record.title for record in current.records()) == (
        "Unsaved pending title",
        "Second unsaved title",
    )
    current.discard_and_lock()
    service.discard_suspended(source, second)



#### Reject a source mutation between initial capture and authenticated reopen.
####
def test_resume_rechecks_source_after_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    replacement = tmp_path / "fabricated-other-source.psafe3"
    replacement_session = service.create(
        replacement,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
    )
    replacement_session.lock()
    production_capture = LocalVaultStore.capture
    swapped = False



    #### Retarget the source immediately after the first exact baseline capture.
    ####
    def replace_after_first_capture(store: LocalVaultStore, path: Path) -> FileBaseline:
        nonlocal swapped
        baseline = production_capture(store, path)
        if store is service._store and path == source and not swapped:
            swapped = True
            replacement.replace(source)
        return baseline

    monkeypatch.setattr(LocalVaultStore, "capture", replace_after_first_capture)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(ExternalModificationError):
        service.resume(source, passphrase, suspended)

    assert swapped
    assert passphrase.closed
    service._pending.verify(source, suspended)



#### Reject a missing stable slot without exposing a private locator in the error.
####
def test_resume_rejects_missing_pending_slot_with_closed_reason(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    slot = next((tmp_path / "pending-private").glob(".bonobo-pending-slot-*.slot"))
    slot.unlink()
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError) as captured:
        service.resume(source, passphrase, suspended)

    assert passphrase.closed
    assert captured.value.__cause__ is None
    assert str(tmp_path) not in str(captured.value)



#### Reject selector metadata that disagrees with the private stable slot record.
####
def test_resume_rejects_mismatched_pending_selector(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    mismatched = SuspendedSession(
        suspended.identifier,
        "e" * 64,
        suspended.source_sha256,
        suspended.size,
    )
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError):
        service.resume(source, passphrase, mismatched)

    assert passphrase.closed



#### Preserve a candidate-path replacement swapped after the preliminary baseline read.
####
def test_candidate_cleanup_identity_swap_never_deletes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    working_directory = tmp_path / "pending-working"
    replacement_bytes = b"fabricated-candidate-replacement"
    production_capture = _storage_capture_regular_file
    candidate_captures: dict[Path, int] = {}
    replaced_candidate: Path | None = None



    #### Swap the candidate name after cleanup receives its earlier exact baseline.
    ####
    def replace_after_preliminary_capture(path: Path) -> FileBaseline:
        nonlocal replaced_candidate
        baseline = production_capture(path)
        if path.parent == working_directory:
            candidate_captures[path] = candidate_captures.get(path, 0) + 1
            if candidate_captures[path] == 2:
                replacement = working_directory / ".fabricated-candidate-replacement"
                replacement.write_bytes(replacement_bytes)
                replacement.chmod(0o600)
                replacement.replace(path)
                replaced_candidate = path
        return baseline

    monkeypatch.setattr(
        "bonobo_core.passwordsafe.pending._capture_regular_file",
        replace_after_preliminary_capture,
    )

    suspended = service.suspend(_dirty_session(service, source))

    assert replaced_candidate is not None
    assert replaced_candidate.read_bytes() == replacement_bytes
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Reject a pending directory reached through a symbolic-link component.
####
def test_pending_store_rejects_symbolic_link_directory(tmp_path: Path) -> None:
    real_pending = _private_directory(tmp_path, "real-pending")
    linked_pending = tmp_path / "linked-pending"
    try:
        linked_pending.symlink_to(real_pending, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(StorageError):
        PendingSessionStore(
            linked_pending,
            _private_directory(tmp_path, "linked-working"),
        )

    assert not any(os.scandir(real_pending))



#### Reject a symbolic-link artifact instead of authenticating its encrypted target.
####
def test_resume_rejects_symbolic_link_pending_artifact(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    pending_directory = tmp_path / "pending-private"
    artifact = pending_directory / f".bonobo-pending-artifact-{suspended.identifier}.psafe3"
    target = pending_directory / ".fabricated-encrypted-target"
    artifact.replace(target)
    try:
        artifact.symlink_to(target)
    except OSError:
        target.replace(artifact)
        pytest.skip("symbolic links are unavailable")
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError):
        service.resume(source, passphrase, suspended)

    assert passphrase.closed
    assert target.exists()



#### Reconcile a still-authoritative selector after retarget cleanup fails.
####
def test_suspend_source_change_with_pending_cleanup_failure_locks_with_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    replacement = tmp_path / "fabricated-external-source.psafe3"
    replacement_session = service.create(
        replacement,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
    )
    replacement_session.lock()
    production_capture = LocalVaultStore.capture
    captures = 0



    #### Retarget the source before the service's post-publication capture.
    ####
    def replace_before_second_capture(store: LocalVaultStore, path: Path) -> FileBaseline:
        nonlocal captures
        if store is service._store and path == source:
            captures += 1
            if captures == 2:
                replacement.replace(source)
        return production_capture(store, path)



    #### Fail exact pending cleanup after the service observes the retarget.
    ####
    def reject_pending_cleanup(
        _store: PendingSessionStore,
        _source: Path,
        _suspended: SuspendedSession,
    ) -> None:
        raise StorageError(StorageReason.PUBLICATION_FAILED)

    monkeypatch.setattr(LocalVaultStore, "capture", replace_before_second_capture)
    monkeypatch.setattr(PendingSessionStore, "discard", reject_pending_cleanup)

    with pytest.raises(StorageError) as captured:
        service.suspend(session)

    monkeypatch.undo()
    assert captures == 2
    suspended = getattr(captured.value, "suspended", None)
    assert isinstance(suspended, SuspendedSession)
    assert session.locked
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)



#### Reconcile a source-capture BaseException after pending publication commits.
####
def test_suspend_postpublication_capture_failure_locks_with_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    production_capture = LocalVaultStore.capture
    captures = 0



    #### Interrupt only the service capture performed after pending publication.
    ####
    def fail_second_capture(store: LocalVaultStore, path: Path) -> FileBaseline:
        nonlocal captures
        if store is service._store and path == source:
            captures += 1
            if captures == 2:
                raise _InjectedControlFlow()
        return production_capture(store, path)

    monkeypatch.setattr(LocalVaultStore, "capture", fail_second_capture)

    with pytest.raises(StorageError) as captured:
        service.suspend(session)

    suspended = getattr(captured.value, "suspended", None)
    assert captures == 2
    assert isinstance(suspended, SuspendedSession)
    assert session.locked
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)



#### Treat every typed pending verification failure as uncertain authority.
####
@pytest.mark.parametrize("reason", tuple(StorageReason))
def test_suspend_authority_storage_uncertainty_keeps_selector_locked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: StorageReason,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    production_capture = LocalVaultStore.capture
    production_verify = PendingSessionStore.verify
    captures = 0



    #### Interrupt only after the new selector has become visible.
    ####
    def fail_second_capture(store: LocalVaultStore, path: Path) -> FileBaseline:
        nonlocal captures
        if store is service._store and path == source:
            captures += 1
            if captures == 2:
                raise _InjectedControlFlow()
        return production_capture(store, path)



    #### Model a typed but nonauthoritative verification outcome.
    ####
    def fail_verification(
        store: PendingSessionStore,
        selected_source: Path,
        suspended: SuspendedSession,
    ) -> None:
        if captures < 2:
            production_verify(store, selected_source, suspended)
            return
        raise StorageError(reason)

    monkeypatch.setattr(LocalVaultStore, "capture", fail_second_capture)
    monkeypatch.setattr(PendingSessionStore, "verify", fail_verification)

    with pytest.raises(StorageError) as captured:
        service.suspend(session)

    monkeypatch.undo()
    suspended = getattr(captured.value, "suspended", None)
    assert captures == 2
    assert isinstance(suspended, SuspendedSession)
    assert session.locked
    service._pending.verify(source, suspended)
    service.discard_suspended(source, suspended)



#### Restore the true dirty session when failed cleanup already removed the selector.
####
def test_suspend_removed_selector_aborts_frozen_snapshot_and_remains_mutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    replacement = tmp_path / "fabricated-external-source.psafe3"
    replacement_session = service.create(
        replacement,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
    )
    replacement_session.lock()
    production_capture = LocalVaultStore.capture
    production_discard = PendingSessionStore.discard
    captures = 0



    #### Retarget the source before the service's post-publication capture.
    ####
    def replace_before_second_capture(store: LocalVaultStore, path: Path) -> FileBaseline:
        nonlocal captures
        if store is service._store and path == source:
            captures += 1
            if captures == 2:
                replacement.replace(source)
        return production_capture(store, path)



    #### Raise after exact discard has already removed the new selector.
    ####
    def discard_then_interrupt(
        store: PendingSessionStore,
        selected_source: Path,
        suspended: SuspendedSession,
    ) -> None:
        production_discard(store, selected_source, suspended)
        raise _InjectedControlFlow()

    monkeypatch.setattr(LocalVaultStore, "capture", replace_before_second_capture)
    monkeypatch.setattr(PendingSessionStore, "discard", discard_then_interrupt)

    with pytest.raises(_InjectedControlFlow):
        service.suspend(session)

    assert captures == 2
    assert not session.locked
    assert session.dirty
    assert session._save_snapshot is None
    session.add(
        NewRecord(
            UUID("99999999-9999-4999-8999-999999999999"),
            "Mutable after removed pending selector",
            SecretBuffer.from_bytes(b"fabricated-after-failure"),
        ),
        session.revision,
    )
    session.discard_and_lock()



#### Keep resumed state dirty and retryable when save cannot clean pending identity.
####
def test_resumed_save_cleanup_failure_retains_pending_until_retry(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    service._pending.faults.raise_at(PendingStage.CLEANUP)

    with pytest.raises(StorageError):
        service.save(resumed)

    dirty_after_failure = resumed.dirty
    assert dirty_after_failure
    service.save(resumed)
    dirty_after_retry = resumed.dirty
    assert not dirty_after_retry
    with pytest.raises(StorageError):
        service.discard_suspended(source, suspended)
    resumed.lock()



#### Reject a stale independent resume instead of replacing a newer suspension.
####
def test_independent_resumes_compare_and_swap_the_expected_pending_selector(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    first = service.suspend(_dirty_session(service, source))
    earlier = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    stale = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    earlier.add(
        NewRecord(
            UUID("11111111-1111-4111-8111-111111111111"),
            "Earlier resumed edit",
            SecretBuffer.from_bytes(b"fabricated-earlier-secret"),
        ),
        earlier.revision,
    )
    second = service.suspend(earlier)
    stale.add(
        NewRecord(
            UUID("22222222-2222-4222-8222-222222222222"),
            "Stale resumed edit",
            SecretBuffer.from_bytes(b"fabricated-stale-secret"),
        ),
        stale.revision,
    )

    with pytest.raises(StorageError):
        service.suspend(stale)

    assert stale.dirty
    assert not stale.locked
    current = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        second,
    )
    assert tuple(record.title for record in current.records()) == (
        "Unsaved pending title",
        "Earlier resumed edit",
    )
    stale.discard_and_lock()
    current.discard_and_lock()
    service.discard_suspended(source, second)



#### Compare-and-swap the retained expected slot without replacing an attacker.
####
def test_expected_selector_cas_does_not_clobber_replaced_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    first = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    resumed.add(
        NewRecord(
            UUID("55555555-5555-4555-8555-555555555555"),
            "Expected selector CAS edit",
            SecretBuffer.from_bytes(b"fabricated-selector-cas-secret"),
        ),
        resumed.revision,
    )
    anchor = _open_private_anchor(tmp_path / "pending-private")
    anchor_type = type(anchor)
    production_publish = anchor_type.publish_new_child
    anchor.close()
    attacker_payload = b"fabricated-attacker-cas-slot"
    replaced = False



    #### Substitute the stable slot exactly when publication consumes its expected identity.
    ####
    def replace_expected_slot(
        selected_anchor: _PublicationAnchor,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        nonlocal replaced
        if (
            not replaced
            and source_name.startswith(".bonobo-pending-slot-")
            and source_name.endswith(".slot")
            and destination_name.startswith(".bonobo-pending-previous-slot-")
        ):
            replaced = True
            displaced_name = ".fabricated-expected-slot"
            assert production_publish(
                selected_anchor,
                descriptor,
                identity,
                source_name,
                displaced_name,
            )
            attacker_name = ".fabricated-attacker-cas-slot"
            created = selected_anchor.create_persistent(attacker_name)
            assert created is not None
            attacker_descriptor, attacker_identity, _cleanup = created
            try:
                assert os.write(attacker_descriptor, attacker_payload) == len(attacker_payload)
                os.fsync(attacker_descriptor)
                assert production_publish(
                    selected_anchor,
                    attacker_descriptor,
                    attacker_identity,
                    attacker_name,
                    source_name,
                )
            finally:
                os.close(attacker_descriptor)
        return production_publish(
            selected_anchor,
            descriptor,
            identity,
            source_name,
            destination_name,
        )

    monkeypatch.setattr(anchor_type, "publish_new_child", replace_expected_slot)

    with pytest.raises(StorageError):
        service.suspend(resumed)

    assert replaced
    stable_slot = next((tmp_path / "pending-private").glob(".bonobo-pending-slot-*.slot"))
    assert stable_slot.read_bytes() == attacker_payload
    assert resumed.dirty
    assert not resumed.locked
    resumed.discard_and_lock()



#### Refuse an ordinary open while the source has an explicit pending revision.
####
def test_fresh_open_cannot_bypass_visible_pending_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError):
        service.open(source, passphrase)

    assert passphrase.closed
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Recheck the source after pending authentication and before session publication.
####
def test_resume_rechecks_source_after_pending_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    replacement = tmp_path / "fabricated-post-auth-source.psafe3"
    replacement_session = service.create(
        replacement,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
    )
    replacement_session.lock()
    production_open_snapshot = PasswordSafeReader.open_snapshot
    replaced = False



    #### Retarget only after the pending artifact has authenticated successfully.
    ####
    def replace_after_pending_authentication(
        reader: PasswordSafeReader,
        snapshot: object,
        passphrase: SecretBuffer,
    ) -> object:
        nonlocal replaced
        opened = production_open_snapshot(reader, snapshot, passphrase)  # type: ignore[arg-type]
        replacement.replace(source)
        replaced = True
        return opened

    monkeypatch.setattr(PasswordSafeReader, "open_snapshot", replace_after_pending_authentication)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(ExternalModificationError):
        service.resume(source, passphrase, suspended)

    assert replaced
    assert passphrase.closed
    service._pending.verify(source, suspended)



#### Bind resume and discard to the exact source locator, not a hard-link alias.
####
def test_pending_selector_rejects_hard_link_source_alias(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    alias = tmp_path / "fabricated-alias.psafe3"
    os.link(source, alias)
    resume_passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError):
        service.resume(alias, resume_passphrase, suspended)
    with pytest.raises(StorageError):
        service.discard_suspended(alias, suspended)

    assert resume_passphrase.closed
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Reconcile faults after artifact deletion as a completed explicit discard.
####
@pytest.mark.parametrize("boundary", ["tombstone", "final-sync", "descriptor-close"])
def test_discard_postcommit_fault_does_not_wedge_dead_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    located = service._pending._find_locked(source, suspended)
    anchor_type = type(located.anchor)
    production_remove = anchor_type.remove_if_same
    production_synchronize = anchor_type.synchronize
    production_close = _LocatedPending.close
    located.close()
    sync_calls = 0



    #### Fail only cleanup that occurs after the selected artifact is gone.
    ####
    def remove_with_tombstone_fault(
        anchor: object,
        descriptor: int,
        name: str,
        identity: tuple[int, int],
    ) -> bool:
        if boundary == "tombstone" and name.startswith(".bonobo-pending-discard-"):
            raise OSError("fabricated private tombstone path")
        return production_remove(anchor, descriptor, name, identity)  # type: ignore[arg-type]



    #### Fail the final directory sync but not the pre-deletion visibility sync.
    ####
    def synchronize_with_final_fault(anchor: object) -> None:
        nonlocal sync_calls
        sync_calls += 1
        if boundary == "final-sync" and sync_calls == 2:
            raise OSError("fabricated private directory path")
        production_synchronize(anchor)  # type: ignore[arg-type]



    #### Raise only after all selected descriptors have actually closed.
    ####
    def close_with_postcommit_fault(pending: _LocatedPending, *, close_anchor: bool = True) -> None:
        production_close(pending, close_anchor=close_anchor)
        if boundary == "descriptor-close":
            raise OSError("fabricated private descriptor path")

    monkeypatch.setattr(anchor_type, "remove_if_same", remove_with_tombstone_fault)
    monkeypatch.setattr(anchor_type, "synchronize", synchronize_with_final_fault)
    monkeypatch.setattr(_LocatedPending, "close", close_with_postcommit_fault)

    service.discard_suspended(source, suspended)

    retry_passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")
    with pytest.raises(StorageError) as captured:
        service.resume(source, retry_passphrase, suspended)
    assert retry_passphrase.closed
    assert str(tmp_path) not in str(captured.value)



#### Close a transferred passphrase when selector validation rejects resume early.
####
def test_resume_invalid_selector_closes_transferred_passphrase(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(TypeError):
        service.resume(source, passphrase, object())  # type: ignore[arg-type]

    assert passphrase.closed



#### Keep one authenticated descriptor continuously through pending publication.
####
def test_suspend_never_reopens_authenticated_artifact_for_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    anchor = _open_private_anchor(tmp_path / "pending-private")
    anchor_type = type(anchor)
    production_open = anchor_type.open_child_for_replace
    anchor.close()



    #### Reject only the insecure second open of a freshly authenticated artifact.
    ####
    def reject_artifact_reopen(anchor: object, name: str) -> object:
        if name.startswith(".bonobo-pending-write-"):
            raise OSError("fabricated artifact ABA")
        return production_open(anchor, name)  # type: ignore[arg-type]

    monkeypatch.setattr(anchor_type, "open_child_for_replace", reject_artifact_reopen)

    suspended = service.suspend(_dirty_session(service, source))

    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Refuse rollback when an attacker replaced the current stable slot identity.
####
def test_rollback_does_not_clobber_replacement_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    first = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    resumed.add(
        NewRecord(
            UUID("33333333-3333-4333-8333-333333333333"),
            "Rollback slot edit",
            SecretBuffer.from_bytes(b"fabricated-rollback-slot-secret"),
        ),
        resumed.revision,
    )
    production_restore = PendingSessionStore._restore_previous_slot
    replacement_bytes = b"fabricated-attacker-slot"



    #### Replace the stable slot after publication but before rollback begins.
    ####
    def replace_slot_before_rollback(
        store: PendingSessionStore,
        anchor: object,
        slot_name: str,
        slot_descriptor: int,
        slot_identity: tuple[int, int],
        previous: _LocatedPending | None,
    ) -> bool:
        replacement_name = ".fabricated-attacker-slot"
        displaced_name = ".fabricated-displaced-slot"
        assert anchor.publish_new_child(  # type: ignore[attr-defined]
            slot_descriptor,
            slot_identity,
            slot_name,
            displaced_name,
        )
        created = anchor.create_persistent(replacement_name)  # type: ignore[attr-defined]
        assert created is not None
        descriptor, identity, _cleanup = created
        try:
            assert os.write(descriptor, replacement_bytes) == len(replacement_bytes)
            os.fsync(descriptor)
            assert anchor.publish_new_child(  # type: ignore[attr-defined]
                descriptor,
                identity,
                replacement_name,
                slot_name,
            )
        finally:
            os.close(descriptor)
        return production_restore(
            store,
            anchor,  # type: ignore[arg-type]
            slot_name,
            slot_descriptor,
            slot_identity,
            previous,
        )

    monkeypatch.setattr(PendingSessionStore, "_restore_previous_slot", replace_slot_before_rollback)
    service._pending.faults.raise_at(PendingStage.POST_PUBLICATION_VALIDATION)

    with pytest.raises(StorageError):
        service.suspend(resumed)

    slot = next((tmp_path / "pending-private").glob(".bonobo-pending-slot-*.slot"))
    assert slot.read_bytes() == replacement_bytes
    assert resumed.dirty
    assert not resumed.locked
    resumed.discard_and_lock()



#### Keep the new valid slot when the old artifact cannot support safe rollback.
####
def test_rollback_refuses_replaced_old_artifact_and_commits_new_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    first = service.suspend(_dirty_session(service, source))
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        first,
    )
    resumed.add(
        NewRecord(
            UUID("44444444-4444-4444-8444-444444444444"),
            "Rollback artifact edit",
            SecretBuffer.from_bytes(b"fabricated-rollback-artifact-secret"),
        ),
        resumed.revision,
    )
    production_restore = PendingSessionStore._restore_previous_slot
    replaced_old = tmp_path / "pending-private" / f".bonobo-pending-artifact-{first.identifier}.psafe3"



    #### Replace the old artifact identity before rollback decides authority.
    ####
    def replace_artifact_before_rollback(
        store: PendingSessionStore,
        anchor: object,
        slot_name: str,
        slot_descriptor: int,
        slot_identity: tuple[int, int],
        previous: _LocatedPending | None,
    ) -> bool:
        assert previous is not None
        displaced_name = ".fabricated-displaced-old-artifact"
        attacker_name = ".fabricated-old-artifact"
        assert anchor.publish_new_child(  # type: ignore[attr-defined]
            previous.artifact_descriptor,
            previous.artifact_identity,
            previous.artifact_name,
            displaced_name,
        )
        created = anchor.create_persistent(attacker_name)  # type: ignore[attr-defined]
        assert created is not None
        descriptor, identity, _cleanup = created
        try:
            payload = b"fabricated-attacker-artifact"
            assert os.write(descriptor, payload) == len(payload)
            os.fsync(descriptor)
            assert anchor.publish_new_child(  # type: ignore[attr-defined]
                descriptor,
                identity,
                attacker_name,
                previous.artifact_name,
            )
        finally:
            os.close(descriptor)
        return production_restore(
            store,
            anchor,  # type: ignore[arg-type]
            slot_name,
            slot_descriptor,
            slot_identity,
            previous,
        )

    monkeypatch.setattr(PendingSessionStore, "_restore_previous_slot", replace_artifact_before_rollback)
    service._pending.faults.raise_at(PendingStage.POST_PUBLICATION_VALIDATION)

    second = service.suspend(resumed)

    assert replaced_old.read_bytes() == b"fabricated-attacker-artifact"
    current = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        second,
    )
    assert current.records()[-1].title == "Rollback artifact edit"
    current.discard_and_lock()
    service.discard_suspended(source, second)



#### Convert a path-bearing directory enumeration failure into a closed error.
####
def test_pending_enumeration_oserror_is_closed_and_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    suspended = service.suspend(_dirty_session(service, source))
    anchor = _open_private_anchor(tmp_path / "pending-private")
    anchor_type = type(anchor)
    anchor.close()



    #### Fail only private pending enumeration with a path-bearing diagnostic.
    ####
    def fail_private_enumeration(_anchor: _PublicationAnchor) -> Iterator[str]:
        raise OSError(f"fabricated enumeration failure: {tmp_path}")

    monkeypatch.setattr(anchor_type, "iter_child_names", fail_private_enumeration)
    passphrase = SecretBuffer.from_bytes(b"fabricated-pending-master")

    with pytest.raises(StorageError) as captured:
        service.resume(source, passphrase, suspended)

    assert passphrase.closed
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert str(tmp_path) not in str(captured.value)
    monkeypatch.undo()
    service.discard_suspended(source, suspended)



#### Reconcile a committed pending artifact when live snapshot cleanup is interrupted.
####
def test_suspend_cleanup_baseexception_locks_session_and_returns_committed_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    production_close = VaultDocument.close



    #### Interrupt only the frozen live save snapshot after pending commit.
    ####
    def interrupt_frozen_snapshot(document: VaultDocument) -> None:
        if session._save_snapshot is document:
            raise KeyboardInterrupt("fabricated live snapshot cleanup interruption")
        production_close(document)

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(VaultDocument, "close", interrupt_frozen_snapshot)
        with pytest.raises(StorageError) as captured:
            service.suspend(session)

    suspended = getattr(captured.value, "suspended", None)
    assert isinstance(suspended, SuspendedSession)
    assert session.locked
    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    assert resumed.records()[0].title == "Unsaved pending title"
    resumed.discard_and_lock()
    service.discard_suspended(source, suspended)



#### Validate Windows privacy on the retained child handle, not a pathname decoy.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows retained-handle DACL verification")
def test_pending_publication_rejects_weak_retained_windows_child_dacl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe._windows_security import WindowsDirectoryAnchor

    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    checks = 0



    #### Reject every retained child even though its current pathname is private.
    ####
    def reject_retained_child(
        _anchor: WindowsDirectoryAnchor,
        _descriptor: int,
        _identity: tuple[int, int],
    ) -> bool:
        nonlocal checks
        checks += 1
        return False

    monkeypatch.setattr(
        WindowsDirectoryAnchor,
        "private_child_is_safe",
        reject_retained_child,
        raising=False,
    )

    with pytest.raises(StorageError):
        service.suspend(_dirty_session(service, source))

    assert checks > 0
