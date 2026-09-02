"""Exercise the serialized, non-secret application lifecycle facade.

These tests pin the user-visible transitions, stale-view rejection, deferred
replacement safety, and owned passphrase lifetime without touching real files.
"""

from pathlib import Path

import pytest
from fakes import FakeVaultService, FakeVaultSession, fabricated_record_view

from bonobo_core.application.facade import ApplicationCommandError, CloseChoice, VaultApplication
from bonobo_core.application.types import ApplicationPhase
from bonobo_core.passwordsafe import (
    AuthenticationError,
    AuthenticationReason,
    SecretBuffer,
    StorageError,
    StorageReason,
)



#### Provide a fake service whose first successful open supplies one clean session.
####
@pytest.fixture
def fake_service() -> FakeVaultService:
    return FakeVaultService(FakeVaultSession((fabricated_record_view(),)))



#### Open a fabricated vault and optionally retain unsaved fake changes.
####
def opened_application(fake_service: FakeVaultService, *, dirty: bool) -> VaultApplication[FakeVaultSession]:
    fake_service.open_session.dirty = dirty
    app = VaultApplication(fake_service)
    opened = app.open(Path("fabricated-vault.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    expected_phase = ApplicationPhase.UNLOCKED_DIRTY if dirty else ApplicationPhase.UNLOCKED_CLEAN
    assert opened.phase is expected_phase
    return app



#### Keep a failed deferred replacement from discarding the authenticated dirty session.
####
def test_failed_replacement_retains_dirty_active_session(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    before = app.snapshot
    passphrase = SecretBuffer.from_bytes(b"fabricated")
    pending = app.open(Path("fabricated-other.psafe3"), passphrase, "Other")
    assert fake_service.open_calls == 1
    fake_service.open_error = AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED)

    result = app.resolve_close(pending.decision, CloseChoice.DISCARD)

    assert pending.phase is ApplicationPhase.AWAITING_DECISION
    assert fake_service.open_calls == 2
    assert result.phase is ApplicationPhase.UNLOCKED_DIRTY
    assert result.records == before.records
    assert result.failure is not None
    assert fake_service.open_session.discard_calls == 0
    assert passphrase.closed



#### Close transferred passphrase ownership after a successful initial open.
####
def test_open_closes_passphrase_after_success(fake_service: FakeVaultService) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated")

    result = app.open(Path("fabricated-vault.psafe3"), passphrase, "Fabricated")

    assert result.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert passphrase.closed



#### Create an initial vault through the service while retaining no passphrase owner.
####
def test_create_commits_a_clean_session_and_closes_passphrase(fake_service: FakeVaultService) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated")

    result = app.create(Path("fabricated-vault.psafe3"), passphrase, "Fabricated")

    assert fake_service.create_calls == 1
    assert result.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert passphrase.closed



#### Restore the newly clean active session if a saved replacement cannot authenticate.
####
def test_failed_saved_replacement_retains_clean_active_session(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    passphrase = SecretBuffer.from_bytes(b"fabricated")
    pending = app.open(Path("fabricated-other.psafe3"), passphrase, "Other")
    fake_service.open_error = AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED)

    result = app.resolve_close(pending.decision, CloseChoice.SAVE)

    assert fake_service.save_calls == 1
    assert result.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert result.failure is not None
    assert passphrase.closed



#### Require one exact decision token and invalidate it after an accepted cancellation.
####
def test_dirty_close_requires_single_use_decision(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)

    pending = app.request_close(app.snapshot.generation)
    canceled = app.resolve_close(pending.decision, CloseChoice.CANCEL)

    assert pending.phase is ApplicationPhase.AWAITING_DECISION
    assert pending.decision is not None
    assert len(pending.decision.value) == 16
    assert canceled.phase is ApplicationPhase.UNLOCKED_DIRTY
    with pytest.raises(ApplicationCommandError, match="decision is stale"):
        app.resolve_close(pending.decision, CloseChoice.DISCARD)



#### Save only the current dirty session and leave it clean after publication.
####
def test_save_commits_a_dirty_session(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)

    result = app.save(app.snapshot.generation)

    assert fake_service.save_calls == 1
    assert result.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert not result.dirty



#### Retain dirty session state and publish only safe failure data when save fails.
####
def test_failed_save_retains_dirty_session_with_safe_failure(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    before = app.snapshot
    fake_service.save_error = StorageError(StorageReason.PUBLICATION_FAILED)

    result = app.save(before.generation)

    assert result.phase is ApplicationPhase.UNLOCKED_DIRTY
    assert result.records == before.records
    assert result.failure is not None
    assert "fabricated-vault" not in repr(result)



#### Lock a clean session through its public close method and remove all record projections.
####
def test_lock_clean_closes_session(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=False)

    result = app.lock_clean(app.snapshot.generation)

    assert fake_service.open_session.lock_calls == 1
    assert result.phase is ApplicationPhase.LOCKED
    assert result.records == ()
    assert result.selected is None



#### Discard only after the dirty-close decision authorizes the irreversible transition.
####
def test_discarded_close_calls_discard_and_lock(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    pending = app.request_close(app.snapshot.generation)

    result = app.resolve_close(pending.decision, CloseChoice.DISCARD)

    assert fake_service.open_session.discard_calls == 1
    assert result.phase is ApplicationPhase.LOCKED



#### Reject a stale state mutation before it can call the underlying service.
####
def test_save_rejects_stale_generation(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    stale_generation = app.snapshot.generation - 1

    with pytest.raises(ApplicationCommandError, match="view is stale"):
        app.save(stale_generation)

    assert fake_service.save_calls == 0



#### Close passphrase ownership after a nonstandard failure without leaking its text.
####
def test_open_closes_passphrase_after_base_exception(fake_service: FakeVaultService) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated")
    fake_service.open_error = KeyboardInterrupt("fabricated-private-path")

    result = app.open(Path("fabricated-vault.psafe3"), passphrase, "Fabricated")

    assert passphrase.closed
    assert result.phase is ApplicationPhase.EMPTY
    assert result.failure is not None
    assert "fabricated-private-path" not in repr(result)
