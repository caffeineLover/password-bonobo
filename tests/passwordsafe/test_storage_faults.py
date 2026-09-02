"""Verify transactional local publication across every injected failure stage."""

import os
from multiprocessing import get_context
from multiprocessing.connection import Connection
from pathlib import Path
from threading import Event, Thread

import pytest
from helpers import DeterministicRandomSource
from test_storage import _publication_case
from test_writer import _private_directory, _XorBackend

from bonobo_core.passwordsafe.constants import FILE_TAG
from bonobo_core.passwordsafe.errors import StorageError
from bonobo_core.passwordsafe.storage import (
    LocalVaultStore,
    StorageStage,
    _copy_descriptor_to_descriptor,
    _destination_lock,
    _RecoverySlot,
    _vault_locator,
)
from bonobo_core.passwordsafe.writer import PasswordSafeWriter



_BEFORE_REPLACE = (
    StorageStage.CREATE,
    StorageStage.PERMISSION,
    StorageStage.WRITE,
    StorageStage.FILE_SYNC,
    StorageStage.REOPEN,
    StorageStage.COMPARE,
    StorageStage.LOCK,
    StorageStage.BASELINE_RECHECK,
    StorageStage.RECOVERY_WRITE,
    StorageStage.RECOVERY_SYNC,
    StorageStage.REPLACE,
)
_AFTER_REPLACE = (
    StorageStage.DIRECTORY_SYNC,
    StorageStage.PUBLISHED_VERIFICATION,
    StorageStage.CLEANUP,
)



#### Hold one destination lock in a spawned process until its parent releases it.
####
def _hold_process_lock(working: str, destination: str, connection: Connection) -> None:
    with _destination_lock(Path(working), Path(destination)):
        connection.send("locked")
        connection.recv()



#### Acquire one destination lock in a thread and report entry to its caller.
####
def _acquire_thread_lock(working: Path, destination: Path, acquired: Event) -> None:
    with _destination_lock(working, destination):
        acquired.set()



#### Return every transaction stage with the complete file expected afterward.
####
def _stage_cases() -> tuple[tuple[StorageStage, bool], ...]:
    return tuple((stage, False) for stage in _BEFORE_REPLACE) + tuple(
        (stage, True) for stage in _AFTER_REPLACE
    )



#### Keep either the complete old or complete new ciphertext at every fault.
####
@pytest.mark.parametrize(("stage", "new_is_authoritative"), _stage_cases())
def test_fault_never_leaves_partial_authoritative_file(
    tmp_path: Path,
    stage: StorageStage,
    new_is_authoritative: bool,
) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    candidate_bytes = case.candidate.path.read_bytes()
    recovery_directory = _private_directory(tmp_path, "store-recovery")
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        recovery_directory,
        validator=case.validator,
        random_source=DeterministicRandomSource(bytes(index % 179 for index in range(512))),
    )
    baseline = store.capture(case.source)
    store.faults.raise_at(stage)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, baseline)

    expected = candidate_bytes if new_is_authoritative else original
    assert case.source.read_bytes() == expected
    assert case.source.read_bytes().startswith(FILE_TAG)
    assert b"fabricated-credential" not in case.source.read_bytes()
    if stage is StorageStage.CLEANUP:
        assert case.candidate.path.exists()
    else:
        assert not case.candidate.path.exists()
    assert not store.pending_candidates()
    for recovery in store.available_recovery(case.source):
        encrypted = (recovery_directory / recovery.identifier).read_bytes()
        assert encrypted.startswith(FILE_TAG)
        assert b"fabricated-credential" not in encrypted
    if new_is_authoritative:
        recoveries = store.available_recovery(case.source)
        assert len(recoveries) == 1
        store.restore(
            case.source,
            recoveries[0],
            store.capture(case.source),
            validator=case.recovery_validator,
        )
        assert case.source.read_bytes() == original
    case.close()



#### Keep the original and remove staged output when replacement itself fails.
####
def test_replace_failure_keeps_original_and_cleans_pending(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    baseline = store.capture(case.source)
    store.faults.raise_at(StorageStage.REPLACE)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, baseline)

    assert case.source.read_bytes() == original
    assert not store.pending_candidates()
    case.close()



#### Reject a candidate changed after writer authentication and keep the source.
####
def test_changed_writer_candidate_is_rejected_before_publication(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    case.candidate.path.write_bytes(case.candidate.path.read_bytes() + b"changed")
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    baseline = store.capture(case.source)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, baseline)

    assert case.source.read_bytes() == original
    assert not case.candidate.path.exists()
    assert not store.pending_candidates()
    case.close()



#### Replace a post-rename recovery slot on the next successful publication.
####
def test_retry_after_post_replace_fault_keeps_one_prior_revision(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    working_directory = _private_directory(tmp_path, "store-working")
    recovery_directory = _private_directory(tmp_path, "store-recovery")
    store = LocalVaultStore(
        working_directory,
        recovery_directory,
        validator=case.validator,
        random_source=DeterministicRandomSource(bytes(index % 173 for index in range(1024))),
    )
    writer = PasswordSafeWriter(
        _XorBackend(),
        case.validator.reader,
        _private_directory(tmp_path, "retry-candidates"),
        random_source=DeterministicRandomSource(bytes(index % 167 for index in range(8192))),
    )
    retry_candidate = writer.write(
        case.validator.opened.document,
        case.validator.opened.crypto_state,
    )
    baseline = store.capture(case.source)
    store.faults.raise_at(StorageStage.DIRECTORY_SYNC)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, baseline)
    first_published_sha256 = store.capture(case.source).sha256

    resumed = LocalVaultStore(
        working_directory,
        recovery_directory,
        validator=case.validator,
        random_source=DeterministicRandomSource(bytes(index % 163 for index in range(1024))),
    )
    resumed.publish(case.source, retry_candidate, resumed.capture(case.source))
    recoveries = resumed.available_recovery(case.source)

    assert len(recoveries) == 1
    assert recoveries[0].sha256 == first_published_sha256
    case.close()



#### Ignore a crash-leftover artifact until a durable recovery slot names it.
####
def test_uncommitted_recovery_artifact_is_not_advertised(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    recovery_directory = _private_directory(tmp_path, "store-recovery")
    (recovery_directory / ("a" * 64)).write_bytes(b"incomplete encrypted recovery")
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        recovery_directory,
        validator=case.validator,
    )

    assert not store.available_recovery(case.source)
    case.candidate.path.unlink()
    case.close()



#### Serialize competing processes before either may enter a vault transaction.
####
def test_destination_lock_blocks_a_competing_process(tmp_path: Path) -> None:
    working = _private_directory(tmp_path, "store-working")
    destination = tmp_path / "vault.psafe3"
    destination.write_bytes(b"encrypted placeholder")
    context = get_context("spawn")
    parent_connection, child_connection = context.Pipe()
    process = context.Process(
        target=_hold_process_lock,
        args=(str(working), str(destination), child_connection),
    )
    process.start()
    assert parent_connection.poll(5.0)
    assert parent_connection.recv() == "locked"
    acquired = Event()
    contender = Thread(target=_acquire_thread_lock, args=(working, destination, acquired))
    contender.start()

    assert not acquired.wait(0.25)
    parent_connection.send("release")
    assert acquired.wait(5.0)

    contender.join(timeout=5.0)
    process.join(timeout=5.0)
    parent_connection.close()
    child_connection.close()
    assert process.exitcode == 0
    assert not contender.is_alive()



#### Complete publication despite repeated short writes from the operating system.
####
def test_partial_os_writes_are_completed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _publication_case(tmp_path)
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    expected = case.candidate.path.read_bytes()
    real_write = os.write



    #### Limit each nonempty native write while preserving its real result.
    ####
    def short_write(descriptor: int, payload: bytes) -> int:
        limit = max(1, len(payload) // 3)
        return real_write(descriptor, payload[:limit])

    monkeypatch.setattr(os, "write", short_write)

    store.publish(case.source, case.candidate, store.capture(case.source))

    assert case.source.read_bytes() == expected
    case.close()



#### Preserve the original when the real file synchronization call fails.
####
def test_file_sync_os_error_keeps_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )



    #### Fail the first actual file synchronization instead of the stage seam.
    ####
    def reject_sync(_descriptor: int) -> None:
        raise OSError

    monkeypatch.setattr(os, "fsync", reject_sync)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, store.capture(case.source))

    assert case.source.read_bytes() == original
    case.close()



#### Treat an already missing obsolete recovery as completed crash cleanup.
####
def test_missing_obsolete_recovery_does_not_poison_restart(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    working_directory = _private_directory(tmp_path, "store-working")
    recovery_directory = _private_directory(tmp_path, "store-recovery")
    store = LocalVaultStore(
        working_directory,
        recovery_directory,
        validator=case.validator,
    )
    store.publish(case.source, case.candidate, store.capture(case.source))
    locator = _vault_locator(case.source)
    slot = store._read_recovery_slot(locator)
    assert slot is not None
    store._write_recovery_slot(locator, _RecoverySlot(slot.current, ("b" * 64,)))
    writer = PasswordSafeWriter(
        _XorBackend(),
        case.validator.reader,
        _private_directory(tmp_path, "restart-candidates"),
        random_source=DeterministicRandomSource(bytes(index % 157 for index in range(8192))),
    )
    candidate = writer.write(case.validator.opened.document, case.validator.opened.crypto_state)
    resumed = LocalVaultStore(
        working_directory,
        recovery_directory,
        validator=case.validator,
    )

    resumed.publish(case.source, candidate, resumed.capture(case.source))

    assert len(resumed.available_recovery(case.source)) == 1
    case.close()



#### Stop a growing encrypted source before any byte beyond the cumulative bound is written.
####
def test_descriptor_copy_enforces_cumulative_bound_before_each_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import storage

    chunks = iter((b"abcd", b"efgh", b"i", b""))
    written = bytearray()

    monkeypatch.setattr(storage, "MAX_ENCRYPTED_FILE_BYTES", 8)
    monkeypatch.setattr(storage, "MAX_IO_CHUNK_BYTES", 4)
    monkeypatch.setattr(os, "fstat", lambda _descriptor: type("Metadata", (), {"st_mode": 0o100600, "st_size": 4})())
    monkeypatch.setattr(os, "lseek", lambda *_arguments: 0)
    monkeypatch.setattr(os, "read", lambda *_arguments: next(chunks))
    monkeypatch.setattr(storage, "_write_descriptor_bytes", lambda _descriptor, payload: written.extend(payload))

    with pytest.raises(OSError):
        _copy_descriptor_to_descriptor(11, 12)

    assert bytes(written) == b"abcdefgh"
