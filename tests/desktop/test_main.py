"""Verify fail-closed desktop composition-root startup behavior."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from PySide6.QtCore import QObject, QUrl
from tests.application.fakes import FakeVaultService, FakeVaultSession, fabricated_record_view

from bonobo_core.application import ApplicationPhase, VaultApplication
from bonobo_core.passwordsafe import SecretBuffer, VaultSession
from bonobo_desktop import resources
from bonobo_desktop.controller import DesktopController
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



#### Compose the controller and closed record model before loading the packaged root.
####
def test_desktop_main_injects_only_controller_before_qml_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import PySide6.QtGui
    import PySide6.QtQml

    events: list[str] = []
    context_values: dict[str, object] = {}
    idle_instances: list[object] = []



    #### Record the sole QML context object and load order without parsing a real file.
    ####
    class FakeEngine:



        #### Return this recording object as the declarative root context.
        ####
        def rootContext(self) -> FakeEngine:  # noqa: N802 - mirrors Qt API.
            return self



        #### Capture exactly one named QML boundary object.
        ####
        def setContextProperty(self, name: str, value: object) -> None:  # noqa: N802 - mirrors Qt API.
            events.append("context")
            context_values[name] = value



        #### Record that loading occurs only after context injection.
        ####
        def load(self, _url: QUrl) -> None:
            events.append("load")



        #### Present one inert root object so startup can enter and leave the loop.
        ####
        def rootObjects(self) -> list[QObject]:  # noqa: N802 - mirrors Qt API.
            return [QObject()]



        #### Mirror deferred QObject cleanup used by the real engine.
        ####
        def deleteLater(self) -> None:  # noqa: N802 - mirrors Qt API.
            events.append("delete")



    #### Record the retained idle adapter and its deterministic shutdown cleanup.
    ####
    class FakeIdleController:
        closed: bool
        is_unlocked: object
        lock_request: object



        #### Capture phase and lock callbacks supplied by the composition root.
        ####
        def __init__(
            self,
            _application: object,
            lock_request: object,
            *,
            timeout_ms: int,
            is_unlocked: object,
        ) -> None:
            assert timeout_ms > 0
            self.closed = False
            self.is_unlocked = is_unlocked
            self.lock_request = lock_request
            idle_instances.append(self)



        #### Accept snapshot notifications while the fake remains retained.
        ####
        def synchronize_phase(self) -> None:
            assert not self.closed



        #### Record application-shutdown release of the event-filter owner.
        ####
        def close(self) -> None:
            self.closed = True
            events.append("idle-close")

    session = FakeVaultSession(())
    monkeypatch.setattr(resources, "main_qml_url", lambda: QUrl("qrc:/fabricated/Main.qml"))
    monkeypatch.setattr("bonobo_desktop.main._botan_library_path", lambda: Path("fabricated-botan"))
    monkeypatch.setattr(
        "bonobo_desktop.main._private_directories",
        lambda _root: (tmp_path / "work", tmp_path / "recovery"),
    )
    monkeypatch.setattr("bonobo_desktop.main.VaultService.with_botan", lambda *_args: FakeVaultService(session))
    monkeypatch.setattr(PySide6.QtQml, "QQmlApplicationEngine", FakeEngine)
    monkeypatch.setattr("bonobo_desktop.lifecycle.IdleLockController", FakeIdleController)
    qt_application = PySide6.QtGui.QGuiApplication.instance()
    assert qt_application is not None
    monkeypatch.setattr(type(qt_application), "exec", lambda _self: 0)

    assert main(["password-bonobo"]) == 0

    assert events[:2] == ["context", "load"]
    assert set(context_values) == {"desktopController"}
    assert isinstance(context_values["desktopController"], DesktopController)
    assert context_values["desktopController"].property("records") is not None
    assert len(idle_instances) == 1
    idle = cast(FakeIdleController, idle_instances[0])
    controller = context_values["desktopController"]
    assert getattr(idle.lock_request, "__self__", None) is controller
    assert callable(idle.is_unlocked)
    assert idle.closed
    assert events[-2:] == ["idle-close", "delete"]
