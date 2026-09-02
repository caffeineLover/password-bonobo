"""Exercise the serialized, non-secret application lifecycle facade.

These tests pin the user-visible transitions, stale-view rejection, deferred
replacement safety, and owned passphrase lifetime without touching real files.
"""

from pathlib import Path
from typing import Literal, cast

import pytest

from bonobo_core.application.facade import ApplicationCommandError, CloseChoice, VaultApplication
from bonobo_core.application.types import ApplicationPhase, ApplicationSnapshot
from bonobo_core.passwordsafe import (
    AuthenticationError,
    AuthenticationReason,
    SecretBuffer,
    StorageError,
    StorageReason,
)
from tests.application.fakes import FakeVaultService, FakeVaultSession, fabricated_record_view



#### Represent an injected validation BaseException without stopping pytest.
####
class _InjectedReplacementControlFlow(BaseException):
    pass



#### Invoke one public replacement boundary with deliberately runtime-typed inputs.
####
def _replacement_command(
    app: VaultApplication[FakeVaultSession],
    action: Literal["create", "open"],
    path: object,
    passphrase: SecretBuffer,
    display_label: object,
) -> object:
    if action == "create":
        return app.create(path, passphrase, display_label)  # type: ignore[arg-type]
    return app.open(path, passphrase, display_label)  # type: ignore[arg-type]



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



#### Fail closed when old-session discard mutates and then raises during replacement.
####
def test_replacement_cleanup_failure_does_not_republish_old_dirty_state(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    candidate = FakeVaultSession((fabricated_record_view(),))
    fake_service.open_session.discard_error = RuntimeError("fabricated-old-session-failure")
    fake_service.open_session = candidate
    pending = app.open(Path("fabricated-other.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Other")

    result = app.resolve_close(pending.decision, CloseChoice.DISCARD)

    assert result.phase is ApplicationPhase.LOCKED
    assert result.records == ()
    assert result.failure is not None
    assert candidate.discard_calls == 1



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



#### Close a valid replacement input rejected by an invalid path.
####
@pytest.mark.parametrize("action", ["create", "open"])
def test_replacement_invalid_path_closes_passphrase(
    fake_service: FakeVaultService,
    action: Literal["create", "open"],
) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated-invalid-path")

    with pytest.raises(ApplicationCommandError):
        _replacement_command(app, action, object(), passphrase, "Fabricated")

    assert passphrase.closed



#### Close a valid replacement input rejected by an invalid display label.
####
@pytest.mark.parametrize("action", ["create", "open"])
def test_replacement_invalid_display_label_closes_passphrase(
    fake_service: FakeVaultService,
    action: Literal["create", "open"],
) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated-invalid-label")

    with pytest.raises(ApplicationCommandError):
        _replacement_command(
            app,
            action,
            Path("fabricated-vault.psafe3"),
            passphrase,
            object(),
        )

    assert passphrase.closed



#### Close a valid replacement input rejected during a reentrant BUSY phase.
####
@pytest.mark.parametrize("action", ["create", "open"])
def test_replacement_busy_rejection_closes_passphrase(
    fake_service: FakeVaultService,
    action: Literal["create", "open"],
) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated-busy-rejection")
    rejected = False



    #### Reenter only while the outer open has published BUSY internally.
    ####
    def reject_during_open() -> None:
        nonlocal rejected
        with pytest.raises(ApplicationCommandError):
            _replacement_command(
                app,
                action,
                Path("fabricated-nested.psafe3"),
                passphrase,
                "Nested",
            )
        rejected = True

    fake_service.on_open = reject_during_open
    opened = app.open(
        Path("fabricated-vault.psafe3"),
        SecretBuffer.from_bytes(b"fabricated-outer"),
        "Fabricated",
    )

    assert opened.phase is ApplicationPhase.UNLOCKED_CLEAN
    assert rejected
    assert passphrase.closed



#### Close only the newly rejected input while a deferred decision retains its owner.
####
@pytest.mark.parametrize("action", ["create", "open"])
def test_replacement_awaiting_decision_rejection_closes_only_new_passphrase(
    fake_service: FakeVaultService,
    action: Literal["create", "open"],
) -> None:
    app = opened_application(fake_service, dirty=True)
    deferred = SecretBuffer.from_bytes(b"fabricated-deferred-owner")
    pending = app.open(Path("fabricated-other.psafe3"), deferred, "Other")
    rejected = SecretBuffer.from_bytes(b"fabricated-awaiting-rejection")

    with pytest.raises(ApplicationCommandError):
        _replacement_command(
            app,
            action,
            Path("fabricated-third.psafe3"),
            rejected,
            "Third",
        )

    assert rejected.closed
    assert not deferred.closed
    canceled = app.resolve_close(pending.decision, CloseChoice.CANCEL)
    assert canceled.phase is ApplicationPhase.UNLOCKED_DIRTY
    assert deferred.closed



#### Close a valid replacement input when validation itself raises BaseException.
####
@pytest.mark.parametrize("action", ["create", "open"])
def test_replacement_validation_baseexception_closes_passphrase(
    fake_service: FakeVaultService,
    monkeypatch: pytest.MonkeyPatch,
    action: Literal["create", "open"],
) -> None:
    app = VaultApplication(fake_service)
    passphrase = SecretBuffer.from_bytes(b"fabricated-validation-interrupt")



    #### Interrupt before ownership can be transferred into a replacement object.
    ####
    def interrupt_validation(*_args: object, **_kwargs: object) -> object:
        raise _InjectedReplacementControlFlow()

    monkeypatch.setattr(VaultApplication, "_validated_replacement", interrupt_validation)

    with pytest.raises(_InjectedReplacementControlFlow):
        _replacement_command(
            app,
            action,
            Path("fabricated-interrupted.psafe3"),
            passphrase,
            "Interrupted",
        )

    assert passphrase.closed



#### Own and close every valid replacement before normalization or BUSY publication.
####
@pytest.mark.parametrize("action", ["create", "open"])
@pytest.mark.parametrize("boundary", ["normalization", "busy-publication"])
def test_replacement_pre_service_baseexception_closes_owner_and_restores_session(
    fake_service: FakeVaultService,
    monkeypatch: pytest.MonkeyPatch,
    action: Literal["create", "open"],
    boundary: Literal["normalization", "busy-publication"],
) -> None:
    app = opened_application(fake_service, dirty=False)
    before = app.snapshot
    passphrase = SecretBuffer.from_bytes(b"fabricated-pre-service-interrupt")



    #### Interrupt one post-transfer operation before any replacement service call.
    ####
    def interrupt(*_args: object, **_kwargs: object) -> object:
        raise _InjectedReplacementControlFlow()

    if boundary == "normalization":
        monkeypatch.setattr(Path, "absolute", interrupt)
    else:
        monkeypatch.setattr(VaultApplication, "_enter_busy", interrupt)

    result = cast(
        ApplicationSnapshot,
        _replacement_command(
            app,
            action,
            Path("fabricated-interrupted.psafe3"),
            passphrase,
            "Interrupted",
        ),
    )

    assert result.phase is before.phase
    assert result.dirty is before.dirty
    assert result.display_label == before.display_label
    assert result.records == before.records
    assert result.failure is not None
    assert passphrase.closed
    assert fake_service.create_calls == 0
    assert fake_service.open_calls == 1



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



#### Fail closed if a successful save is followed by a partially completed terminal lock.
####
def test_saved_close_lock_failure_does_not_republish_dirty_state(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    pending = app.request_close(app.snapshot.generation)
    fake_service.open_session.lock_error = RuntimeError("fabricated-lock-failure")

    result = app.resolve_close(pending.decision, CloseChoice.SAVE)

    assert fake_service.save_calls == 1
    assert result.phase is ApplicationPhase.LOCKED
    assert not result.dirty
    assert result.records == ()
    assert result.failure is not None



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



#### Fail closed when save completes but rebuilding the safe projection fails.
####
def test_post_save_projection_failure_does_not_republish_dirty_state(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=True)
    fake_service.open_session.records_error = RuntimeError("fabricated-projection-failure")

    result = app.save(app.snapshot.generation)

    assert fake_service.save_calls == 1
    assert result.phase is ApplicationPhase.LOCKED
    assert not result.dirty
    assert result.records == ()
    assert result.failure is not None



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



#### Fail closed if an immediate clean close raises after taking terminal action.
####
def test_clean_request_close_failure_does_not_republish_unlocked_state(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=False)
    fake_service.open_session.lock_error = RuntimeError("fabricated-lock-failure")

    result = app.request_close(app.snapshot.generation)

    assert result.phase is ApplicationPhase.LOCKED
    assert result.records == ()
    assert result.failure is not None



#### Fail closed if an explicit clean lock raises after taking terminal action.
####
def test_clean_lock_failure_does_not_republish_unlocked_state(fake_service: FakeVaultService) -> None:
    app = opened_application(fake_service, dirty=False)
    fake_service.open_session.lock_error = RuntimeError("fabricated-lock-failure")

    result = app.lock_clean(app.snapshot.generation)

    assert result.phase is ApplicationPhase.LOCKED
    assert result.records == ()
    assert result.failure is not None



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
