"""Specify explicit leased secret actions and their failure boundaries.

All values in these tests are fabricated.  Assertions inspect only controlled
fake-port effects and safe snapshots, never application-internal identities.
"""

from pathlib import Path

import pytest

from bonobo_core.application import (
    ApplicationFailureReason,
    RecordKey,
    VaultApplication,
)
from bonobo_core.passwordsafe import SecretBuffer
from tests.application.fakes import (
    FakeVaultService,
    FakeVaultSession,
    RecordingBrowser,
    RecordingClipboard,
    fabricated_record_view,
)



#### Provide one application configured with observable fabricated platform ports.
####
@pytest.fixture
def configured_application() -> tuple[VaultApplication[FakeVaultSession], RecordingClipboard, RecordingBrowser]:
    clipboard = RecordingClipboard()
    browser = RecordingBrowser()
    session = FakeVaultSession((fabricated_record_view(),))
    app = VaultApplication(FakeVaultService(session), clipboard=clipboard, browser=browser)
    app.open(Path("fabricated-vault.psafe3"), SecretBuffer.from_bytes(b"fabricated-unlock"), "Fabricated")
    return app, clipboard, browser



#### Copy a password through an in-context lease and retain no value in the snapshot.
####
def test_copy_password_closes_lease_and_snapshot_never_contains_secret(
    configured_application: tuple[VaultApplication[FakeVaultSession], RecordingClipboard, RecordingBrowser],
) -> None:
    application, clipboard, _browser = configured_application

    result = application.copy_password(RecordKey(1), application.snapshot.generation)

    assert clipboard.copied == b"fabricated-password"
    assert clipboard.last_lease_closed
    assert "fabricated-password" not in repr(result)



#### Map clipboard port errors to a closed failure reason without leaking its error text.
####
def test_clipboard_failure_is_safe_and_keeps_committed_snapshot(
    configured_application: tuple[VaultApplication[FakeVaultSession], RecordingClipboard, RecordingBrowser],
) -> None:
    application, clipboard, _browser = configured_application
    before = application.snapshot
    clipboard.copy_error = RuntimeError("fabricated-password must never escape")

    result = application.copy_username(RecordKey(1), before.generation)

    assert result.records == before.records
    assert result.failure is not None
    assert result.failure.reason is ApplicationFailureReason.CLIPBOARD_UNAVAILABLE
    assert clipboard.last_lease_closed
    assert "fabricated-password" not in repr(result)



#### Route browser errors through a closed failure without exposing the leased URL.
####
def test_browser_failure_is_safe_and_closes_the_lease(
    configured_application: tuple[VaultApplication[FakeVaultSession], RecordingClipboard, RecordingBrowser],
) -> None:
    application, _clipboard, browser = configured_application
    browser.open_error = RuntimeError("https://fabricated.example.invalid/private")

    result = application.open_website(RecordKey(1), application.snapshot.generation)

    assert browser.last_lease_closed
    assert result.failure is not None
    assert result.failure.reason is ApplicationFailureReason.BROWSER_UNAVAILABLE
    assert "example.invalid" not in repr(result)



#### Clear application-owned clipboard content when a clean vault session locks.
####
def test_lock_clears_application_owned_clipboard_content(
    configured_application: tuple[VaultApplication[FakeVaultSession], RecordingClipboard, RecordingBrowser],
) -> None:
    application, clipboard, _browser = configured_application
    application.copy_password(RecordKey(1), application.snapshot.generation)

    result = application.lock_clean(application.snapshot.generation)

    assert result.records == ()
    assert clipboard.clear_calls == 1
