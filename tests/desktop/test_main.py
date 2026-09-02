"""Verify fail-closed desktop composition-root startup behavior."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from PySide6.QtCore import QUrl
from tests.application.fakes import FakeVaultService, FakeVaultSession, fabricated_record_view

from bonobo_core.application import ApplicationPhase, VaultApplication
from bonobo_core.passwordsafe import SecretBuffer, VaultSession
from bonobo_desktop import resources
from bonobo_desktop.main import _request_shutdown_lock, main



#### Return a safe nonzero status when the packaged QML root cannot load.
####
#### The missing root is an observable startup failure.  The desktop adapter
#### must not continue into Qt's event loop without a root object.
####
def test_desktop_main_fails_safely_when_qml_root_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resources, "main_qml_url", lambda: QUrl())
    assert main(["password-bonobo"]) == 1



#### Suspend an active dirty vault before desktop engine teardown can finish.
####
#### The terminal facade command preserves dirty state as encrypted suspension;
#### an interactive close request would leave an awaiting decision and an
#### unlocked authenticated session after the event loop exits.
####
def test_desktop_shutdown_suspends_a_dirty_vault() -> None:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    service = FakeVaultService(session)
    application = VaultApplication(service)
    with SecretBuffer.from_bytes(b"fabricated-passphrase") as passphrase:
        opened = application.open(Path("fabricated.psafe3"), passphrase, "Fabricated")
    assert opened.phase is ApplicationPhase.UNLOCKED_DIRTY

    _request_shutdown_lock(cast(VaultApplication[VaultSession], application))

    assert service.suspend_calls == 1
    assert application.snapshot.phase is ApplicationPhase.LOCKED
