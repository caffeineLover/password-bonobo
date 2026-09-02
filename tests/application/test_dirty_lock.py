"""Verify dirty application lock and unlock retain only private suspension state."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

import bonobo_core.passwordsafe.storage as storage_module
from bonobo_core.application.facade import ApplicationCommandError, VaultApplication
from bonobo_core.application.types import ApplicationPhase
from bonobo_core.passwordsafe import (
    AuthenticationError,
    AuthenticationReason,
    SecretBuffer,
    SuspendedSession,
    VaultService,
)
from bonobo_core.passwordsafe.crypto import TwofishKey
from bonobo_core.passwordsafe.errors import StorageError, StorageReason
from tests.application.fakes import (
    FakeVaultService,
    FakeVaultSession,
    RecordingClipboard,
    fabricated_record_view,
)



#### Implement one deterministic reversible block transform for the real-service facade regression.
####
class _XorKey:
    __slots__ = ("_closed", "_mask")



    #### Retain one fabricated mask for the lifetime of this test key.
    ####
    def __init__(self, key_material: SecretBuffer) -> None:
        self._mask = bytes(key_material.borrow()[:16])
        self._closed = False



    #### Apply the reversible fabricated transform to one exact block.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("test key is closed")
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Reverse the same fabricated block transform.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)



    #### Make this test key terminal at backend context exit.
    ####
    def close(self) -> None:
        self._closed = True



#### Supply the deterministic test cipher through the production protocol.
####
class _XorBackend:



    #### Yield one scoped key and close it after the codec operation.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key = _XorKey(key_material)
        try:
            yield key
        finally:
            key.close()



    #### Complete the fake backend gate without claiming production suitability.
    ####
    def self_test(self) -> None:
        return None



#### Inject one post-commit process-lock teardown failure through production locking.
####
def _install_process_lock_teardown_fault(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    private_path: Path,
) -> None:
    lock_name = "_lock_windows_descriptor" if os.name == "nt" else "_lock_posix_descriptor"
    unlock_name = "_unlock_windows_descriptor" if os.name == "nt" else "_unlock_posix_descriptor"



    #### Raise one raw private-path failure from the selected native seam.
    ####
    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"fabricated {stage} failure at {private_path}")

    if stage == "unlock":
        monkeypatch.setattr(storage_module, unlock_name, fail)
        return
    if stage != "close":
        raise AssertionError("unsupported fabricated lock teardown stage")
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



#### Suspend dirty state before publishing the terminal locked snapshot.
####
def test_dirty_lock_uses_service_suspension_and_clears_public_records() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    service.suspended_result = SuspendedSession("a" * 64, "b" * 64, "c" * 64, 512)
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )

    locked = app.lock(opened.generation)

    assert service.suspend_calls == 1
    assert locked.phase is ApplicationPhase.LOCKED
    assert locked.records == ()
    assert "aaaaaaaa" not in repr(locked)



#### Reauthenticate and resume pending state using a caller-owned passphrase.
####
def test_unlock_resumes_pending_state_and_closes_passphrase() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    resumed = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service.resume_session = resumed
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    app.lock(opened.generation)
    passphrase = SecretBuffer.from_bytes(b"fabricated")

    unlocked = app.unlock(passphrase)

    assert service.resume_calls == 1
    assert passphrase.closed
    assert unlocked.phase is ApplicationPhase.UNLOCKED_DIRTY



#### Keep a safe locked snapshot and pending state after failed authentication.
####
def test_failed_unlock_remains_locked_and_can_retry() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    resumed = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service.resume_session = resumed
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    app.lock(opened.generation)
    failed_passphrase = SecretBuffer.from_bytes(b"fabricated-wrong")
    service.resume_error = AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED)

    failed = app.unlock(failed_passphrase)

    assert failed.phase is ApplicationPhase.LOCKED
    assert failed.failure is not None
    assert failed_passphrase.closed
    service.resume_error = None
    retried = app.unlock(SecretBuffer.from_bytes(b"fabricated"))
    assert retried.phase is ApplicationPhase.UNLOCKED_DIRTY



#### Require explicit pending discard before replacing a locked dirty source.
####
def test_locked_pending_state_requires_explicit_discard_before_replacement() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    locked = app.lock(opened.generation)
    replacement_passphrase = SecretBuffer.from_bytes(b"fabricated-replacement")

    with pytest.raises(ApplicationCommandError):
        app.open(Path("fabricated-other.psafe3"), replacement_passphrase, "Other")

    assert replacement_passphrase.closed
    discarded = app.discard_suspended(locked.generation)
    assert service.discard_suspended_calls == 1
    assert discarded.phase is ApplicationPhase.LOCKED



#### Keep the dirty unlocked projection when suspension fails before commit.
####
def test_dirty_lock_precommit_failure_remains_unlocked_and_does_not_clear_clipboard() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    service.suspend_error = StorageError(StorageReason.PUBLICATION_FAILED)
    clipboard = RecordingClipboard()
    app = VaultApplication(service, clipboard=clipboard)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )

    failed = app.lock(opened.generation)

    assert failed.phase is ApplicationPhase.UNLOCKED_DIRTY
    assert failed.failure is not None
    assert session.dirty
    assert not session.locked
    assert clipboard.clear_calls == 0



#### Clear adapter-owned clipboard content when dirty lock becomes terminal.
####
def test_dirty_lock_clears_clipboard_only_after_successful_terminal_transition() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    clipboard = RecordingClipboard()
    app = VaultApplication(service, clipboard=clipboard)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )

    locked = app.lock(opened.generation)

    assert locked.phase is ApplicationPhase.LOCKED
    assert clipboard.clear_calls == 1



#### Retain private pending metadata after failed explicit discard so retry is possible.
####
def test_failed_explicit_discard_stays_locked_and_can_retry() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    locked = app.lock(opened.generation)
    service.discard_suspended_error = StorageError(StorageReason.PUBLICATION_FAILED)

    failed = app.discard_suspended(locked.generation)

    assert failed.phase is ApplicationPhase.LOCKED
    assert failed.failure is not None
    service.discard_suspended_error = None
    retried = app.discard_suspended(failed.generation)
    assert retried.phase is ApplicationPhase.LOCKED
    assert retried.failure is None
    assert service.discard_suspended_calls == 2



#### Clear committed pending state after destination-lock teardown fails.
####
@pytest.mark.parametrize("stage", ["unlock", "close"])
def test_committed_discard_teardown_failure_clears_facade_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    working = tmp_path / "pending-working"
    working.mkdir(mode=0o700)
    working.chmod(0o700)
    pending = tmp_path / "pending-private"
    pending.mkdir(mode=0o700)
    pending.chmod(0o700)
    service = VaultService(
        _XorBackend(),
        working,
        pending,
    )
    app = VaultApplication(service)
    source = tmp_path / "fabricated-vault.psafe3"
    opened = app.create(source, SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    draft = replace(app.begin_edit(None, opened.generation), title="Unsaved pending title")
    changed = app.commit_edit(draft, SecretBuffer.from_bytes(b"fabricated-pending-credential"))
    locked = app.lock(changed.generation)
    private_path = working / ".fabricated-private.lock"
    _install_process_lock_teardown_fault(monkeypatch, stage, private_path)

    discarded = app.discard_suspended(locked.generation)
    monkeypatch.undo()

    assert discarded.phase is ApplicationPhase.LOCKED
    assert not discarded.dirty
    assert discarded.records == ()
    assert discarded.failure is None
    replacement_passphrase = SecretBuffer.from_bytes(b"fabricated-replacement")
    replaced = app.create(tmp_path / "fabricated-replacement.psafe3", replacement_passphrase, "Replacement")
    assert replacement_passphrase.closed
    assert replaced.phase is ApplicationPhase.UNLOCKED_CLEAN



#### Reauthenticate a clean locked source without fabricating a pending revision.
####
def test_clean_unlock_reopens_source_and_closes_passphrase() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=False)
    service = FakeVaultService(session)
    reopened = FakeVaultSession((fabricated_record_view(),), dirty=False)
    service.open_session = reopened
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    app.lock(opened.generation)
    passphrase = SecretBuffer.from_bytes(b"fabricated")

    unlocked = app.unlock(passphrase)

    assert unlocked.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert service.open_calls == 2
    assert service.resume_calls == 0
    assert passphrase.closed



#### Close transferred unlock input even when the facade rejects the current phase.
####
def test_unlock_rejection_closes_transferred_passphrase() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=False)
    app = VaultApplication(FakeVaultService(session))
    app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    passphrase = SecretBuffer.from_bytes(b"fabricated-unlock-rejection")

    with pytest.raises(ApplicationCommandError):
        app.unlock(passphrase)

    assert passphrase.closed



#### Keep a committed dirty suspension privately available after terminal cleanup fails.
####
def test_committed_suspend_failure_finishes_locked_with_private_selector() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    service.suspend_committed_error = StorageError(StorageReason.PUBLICATION_FAILED)
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )

    failed = app.lock(opened.generation)

    assert failed.phase is ApplicationPhase.LOCKED
    assert failed.failure is not None
    service.suspend_committed_error = None
    resumed = app.unlock(SecretBuffer.from_bytes(b"fabricated"))
    assert resumed.phase is ApplicationPhase.UNLOCKED_DIRTY



#### Reconcile a committed save failure as locked and reopen the clean source.
####
def test_committed_save_failure_clears_dead_pending_selector() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    app = VaultApplication(service)
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated"),
        "Fabricated",
    )
    locked = app.lock(opened.generation)
    resumed = app.unlock(SecretBuffer.from_bytes(b"fabricated"))
    service.save_committed_error = StorageError(StorageReason.PUBLICATION_FAILED)

    failed = app.save(resumed.generation)

    assert locked.phase is ApplicationPhase.LOCKED
    assert failed.phase is ApplicationPhase.LOCKED
    assert failed.failure is not None
    service.save_committed_error = None
    reopened = app.unlock(SecretBuffer.from_bytes(b"fabricated"))
    assert reopened.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert service.resume_calls == 1
