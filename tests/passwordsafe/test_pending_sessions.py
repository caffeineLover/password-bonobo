"""Verify dirty sessions suspend only into authenticated private ciphertext.

All vaults, passphrases, and record values are fabricated.  Tests retain the
source pathname before suspension so no locked session property is accessed.
"""

import os
from dataclasses import asdict
from pathlib import Path
from uuid import UUID

import pytest
from helpers import DeterministicRandomSource
from test_writer import _private_directory, _XorBackend

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
from bonobo_core.passwordsafe.pending import (
    PendingSessionStore,
    PendingStage,
    _LocatedPending,
)
from bonobo_core.passwordsafe.storage import (
    FileBaseline,
    LocalVaultStore,
    StorageStage,
    _PublicationAnchor,
)
from bonobo_core.passwordsafe.storage import (
    _capture_regular_file as _storage_capture_regular_file,
)



#### Assemble one deterministic service with persistent private pending storage.
####
def _service(tmp_path: Path) -> VaultService:
    return VaultService(
        _XorBackend(),
        _private_directory(tmp_path, "pending-working"),
        _private_directory(tmp_path, "pending-private"),
        random_source=DeterministicRandomSource(bytes((index + 73) % 251 for index in range(131072))),
    )



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
        service.discard_suspended(suspended)
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
    service.discard_suspended(suspended)



#### Remove one selected pending slot while leaving the unchanged source untouched.
####
def test_discard_suspended_removes_only_pending_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "fabricated-source.psafe3"
    session = _dirty_session(service, source)
    source_before = source.read_bytes()
    suspended = service.suspend(session)

    service.discard_suspended(suspended)

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
    service.discard_suspended(suspended)



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
        selector: SuspendedSession,
    ) -> _LocatedPending:
        located = production_find(store, selector)
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
        service.discard_suspended(suspended)

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
    located = service._pending._find_locked(suspended)
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
            service.discard_suspended(suspended)

    resumed = service.resume(
        source,
        SecretBuffer.from_bytes(b"fabricated-pending-master"),
        suspended,
    )
    assert resumed.records()[0].title == "Unsaved pending title"
    resumed.discard_and_lock()
    service.discard_suspended(suspended)



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
    service.discard_suspended(suspended)



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
    service.discard_suspended(first)



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
    service.discard_suspended(second)



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
    service._pending.verify(suspended)



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
    service.discard_suspended(suspended)



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



#### Abort the live save snapshot even when post-commit source cleanup also fails.
####
def test_suspend_source_change_with_pending_cleanup_failure_keeps_session_mutable(
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
        _suspended: SuspendedSession,
    ) -> None:
        raise StorageError(StorageReason.PUBLICATION_FAILED)

    monkeypatch.setattr(LocalVaultStore, "capture", replace_before_second_capture)
    monkeypatch.setattr(PendingSessionStore, "discard", reject_pending_cleanup)

    with pytest.raises(StorageError):
        service.suspend(session)

    assert captures == 2
    assert not session.locked
    assert session.dirty
    session.add(
        NewRecord(
            UUID("99999999-9999-4999-8999-999999999999"),
            "Mutable after failed suspend",
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
        service.discard_suspended(suspended)
    resumed.lock()
