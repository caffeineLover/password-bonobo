"""Exercise the Qt Quick shell through real offscreen keyboard interaction."""

from collections.abc import Generator
from pathlib import Path
from typing import cast

import pytest
from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QAccessible, QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickItem, QQuickWindow
from PySide6.QtTest import QTest
from pytestqt.qtbot import QtBot
from tests.application.fakes import FakeVaultService, FakeVaultSession, fabricated_record_view

from bonobo_core.application import ApplicationPhase, VaultApplication
from bonobo_core.passwordsafe import SecretBuffer, VaultSession
from bonobo_desktop.controller import DesktopController
from bonobo_desktop.resources import main_qml_url
from bonobo_desktop.tasks import FacadeExecutor



Shell = tuple[QQuickWindow, DesktopController, FacadeExecutor[VaultApplication[VaultSession]], FakeVaultSession]



#### Load one real unlocked shell backed only by fabricated in-memory service data.
####
@pytest.fixture
def unlocked_shell(qtbot: QtBot) -> Generator[Shell]:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    application = VaultApplication(FakeVaultService(session))
    with SecretBuffer.from_bytes(b"fabricated-passphrase") as passphrase:
        application.open(Path("fabricated.psafe3"), passphrase, "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty("desktopController", controller)
    engine.load(main_qml_url())
    roots = engine.rootObjects()
    assert roots
    window = cast(QQuickWindow, roots[0])
    window.show()
    QTest.qWaitForWindowExposed(window)
    yield window, controller, executor, session
    window.close()
    executor.shutdown()
    assert executor._pool.waitForDone(5000)



#### Find one named real QML object and fail with its missing contract name.
####
def _item(window: QQuickWindow, name: str) -> QQuickItem:
    found = window.findChild(QQuickItem, name)
    assert found is not None, name
    return found



#### Find one named popup or item through the real QML object tree.
####
def _object(window: QQuickWindow, name: str) -> QObject:
    found = window.findChild(QObject, name)
    assert found is not None, name
    return found



#### Focus search through Ctrl+F and save dirty state through Ctrl+S.
####
def test_global_search_and_save_shortcuts(unlocked_shell: Shell, qtbot: QtBot) -> None:
    window, controller, _executor, _session = unlocked_shell
    search = _item(window, "searchField")

    QTest.keyClick(window, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
    assert search.hasActiveFocus()
    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        QTest.keyClick(window, Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier)

    assert controller.property("phase") == ApplicationPhase.UNLOCKED_CLEAN.value
    assert search.hasActiveFocus()



#### Lock through the global Ctrl+L shortcut.
####
def test_lock_shortcut(
    unlocked_shell: Shell,
    qtbot: QtBot,
) -> None:
    window, controller, _executor, _session = unlocked_shell

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        QTest.keyClick(window, Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
    assert controller.property("phase") == ApplicationPhase.LOCKED.value



#### Open the selected record with Enter and cancel locally with Escape without mutation.
####
def test_enter_opens_editor_and_escape_cancels_without_mutation(unlocked_shell: Shell) -> None:
    window, _controller, _executor, session = unlocked_shell
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()

    QTest.keyClick(window, Qt.Key.Key_Return)
    editor = _object(window, "recordEditor")
    assert editor.property("visible") is True
    title_field = editor.findChild(QQuickItem, "editorTitle")
    password_field = editor.findChild(QQuickItem, "editorPassword")
    assert title_field is not None
    assert password_field is not None
    assert title_field.property("text") == "Alpha Portal"
    password_field.setProperty("text", "fabricated-local-secret")

    QTest.keyClick(window, Qt.Key.Key_Escape)

    assert editor.property("visible") is False
    assert password_field.property("text") == ""
    assert session.change_count == 0



#### Restore record-list focus after a reset retains the selected record.
####
def test_model_reset_restores_focus_to_retained_record(unlocked_shell: Shell, qtbot: QtBot) -> None:
    window, controller, _executor, _session = unlocked_shell
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.set_search("Alpha")

    qtbot.waitUntil(record_list.hasActiveFocus, timeout=1000)
    assert record_list.property("currentIndex") == 0



#### Return focus to search when a model reset removes the selected record.
####
def test_model_reset_restores_search_when_selection_is_filtered_out(
    unlocked_shell: Shell,
    qtbot: QtBot,
) -> None:
    window, controller, _executor, _session = unlocked_shell
    search = _item(window, "searchField")
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.set_search("No fabricated match")

    assert search.hasActiveFocus()
    assert record_list.property("currentIndex") == -1



#### Give every scoped action a nonempty accessibility name and keyboard focus.
####
def test_every_action_has_access_name_and_tab_focus(unlocked_shell: Shell) -> None:
    window, _controller, _executor, _session = unlocked_shell
    for name in (
        "saveButton",
        "lockButton",
        "addButton",
        "editButton",
        "copyUsernameButton",
        "copyPasswordButton",
        "openWebsiteButton",
    ):
        action = _item(window, name)
        interface = QAccessible.queryAccessibleInterface(action)
        assert interface is not None
        assert interface.text(QAccessible.Text.Name)
        assert action.property("activeFocusOnTab") is True

    application = QGuiApplication.instance()
    assert application is not None
