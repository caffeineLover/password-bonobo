"""Exercise the Qt Quick shell through real offscreen keyboard interaction."""

from collections.abc import Generator
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QAccessible, QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickItem, QQuickWindow
from PySide6.QtTest import QTest
from pytestqt.qtbot import QtBot
from tests.application.fakes import FakeVaultService, FakeVaultSession, fabricated_record_view

from bonobo_core.application import (
    ApplicationFailure,
    ApplicationFailureReason,
    ApplicationPhase,
    ApplicationSnapshot,
    VaultApplication,
)
from bonobo_core.passwordsafe import (
    RecordHandle,
    RecordView,
    SecretBuffer,
    VaultSession,
)
from bonobo_desktop.controller import DesktopController
from bonobo_desktop.resources import main_qml_url
from bonobo_desktop.tasks import FacadeExecutor



Shell = tuple[QQuickWindow, DesktopController, FacadeExecutor[VaultApplication[VaultSession]], FakeVaultSession]

_FAILURE_STATUS_COPY: dict[ApplicationFailureReason, str] = {
    ApplicationFailureReason.AUTHENTICATION_FAILED: "The passphrase was not accepted.",
    ApplicationFailureReason.INTEGRITY_FAILED: "Vault integrity verification failed.",
    ApplicationFailureReason.MALFORMED_VAULT: "The vault data is malformed.",
    ApplicationFailureReason.UNSUPPORTED_FORMAT: "This vault format is not supported.",
    ApplicationFailureReason.INCOMPATIBLE_EXPORT: "The vault uses incompatible export settings.",
    ApplicationFailureReason.RESOURCE_LIMIT: "The vault exceeds supported resource limits.",
    ApplicationFailureReason.CRYPTO_BACKEND: "Secure vault processing is unavailable.",
    ApplicationFailureReason.PROTECTED_RECORD: "That protected record cannot be changed.",
    ApplicationFailureReason.STALE_REVISION: "The vault changed. Review the latest data and try again.",
    ApplicationFailureReason.UNSAVED_CHANGES: "Save or discard the pending changes first.",
    ApplicationFailureReason.EXTERNAL_MODIFICATION: "The vault changed outside Password Bonobo.",
    ApplicationFailureReason.STORAGE: "The vault could not be read or written.",
    ApplicationFailureReason.RECOVERY_AVAILABLE: "Recovery data is available for this vault.",
    ApplicationFailureReason.CLIPBOARD_UNAVAILABLE: "The clipboard is unavailable.",
    ApplicationFailureReason.BROWSER_UNAVAILABLE: "The website could not be opened.",
    ApplicationFailureReason.UNEXPECTED: "The action could not be completed.",
}



#### Load one real shell backed only by fabricated in-memory service data.
####
def _load_shell(
    qtbot: QtBot,
    application: VaultApplication[FakeVaultSession],
    session: FakeVaultSession,
) -> Generator[Shell]:
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



#### Load the initial welcome view with no selected source.
####
@pytest.fixture
def welcome_shell(qtbot: QtBot) -> Generator[Shell]:
    session = FakeVaultSession(())
    application = VaultApplication(FakeVaultService(session))
    yield from _load_shell(qtbot, application, session)



#### Load one real unlocked shell backed by two fabricated in-memory records.
####
@pytest.fixture
def unlocked_shell(qtbot: QtBot) -> Generator[Shell]:
    first = fabricated_record_view()
    second = RecordView(
        RecordHandle(),
        first.revision,
        "Beta Console",
        "Zeta Examples",
        "second-user",
        "https://second.example.invalid/private",
        False,
    )
    session = FakeVaultSession((first, second), dirty=True)
    application = VaultApplication(FakeVaultService(session))
    with SecretBuffer.from_bytes(b"fabricated-passphrase") as passphrase:
        application.open(Path("fabricated.psafe3"), passphrase, "Fabricated")
    yield from _load_shell(qtbot, application, session)



#### Load the locked view after one clean fabricated vault was closed.
####
@pytest.fixture
def locked_shell(qtbot: QtBot) -> Generator[Shell]:
    session = FakeVaultSession(())
    application = VaultApplication(FakeVaultService(session))
    with SecretBuffer.from_bytes(b"fabricated-passphrase") as passphrase:
        opened = application.open(Path("fabricated.psafe3"), passphrase, "Fabricated")
    application.lock(opened.generation)
    yield from _load_shell(qtbot, application, session)



#### Load the decision modal over one fabricated dirty vault.
####
@pytest.fixture
def decision_shell(qtbot: QtBot) -> Generator[Shell]:
    session = FakeVaultSession((fabricated_record_view(),), dirty=True)
    application = VaultApplication(FakeVaultService(session))
    with SecretBuffer.from_bytes(b"fabricated-passphrase") as passphrase:
        opened = application.open(Path("fabricated.psafe3"), passphrase, "Fabricated")
    application.request_close(opened.generation)
    yield from _load_shell(qtbot, application, session)



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



#### Prove one complete declared tab cycle with a visible focused item at every stop.
####
def _assert_tab_cycle(window: QQuickWindow, names: tuple[str, ...], qtbot: QtBot) -> None:
    first = _item(window, names[0])
    qtbot.waitUntil(first.hasActiveFocus, timeout=1000)
    assert first.property("visible") is True
    for name in (*names[1:], names[0]):
        QTest.keyClick(window, Qt.Key.Key_Tab)
        target = _item(window, name)
        qtbot.waitUntil(target.hasActiveFocus, timeout=1000)
        assert target.property("visible") is True



#### Prove every named keyboard stop has an access name and opts into tab focus.
####
def _assert_accessible_tab_stops(window: QQuickWindow, names: tuple[str, ...]) -> None:
    for name in names:
        action = _item(window, name)
        interface = QAccessible.queryAccessibleInterface(action)
        assert interface is not None, name
        assert interface.text(QAccessible.Text.Name), name
        assert action.property("activeFocusOnTab") is True, name



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



#### Keep the complete local editor draft until a delayed command acknowledges success.
####
def test_record_editor_closes_and_clears_only_after_success_acknowledgement(
    unlocked_shell: Shell,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window, controller, _executor, session = unlocked_shell
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()
    QTest.keyClick(window, Qt.Key.Key_Return)
    editor = _object(window, "recordEditor")
    title_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorTitle"))
    group_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorGroup"))
    username_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorUsername"))
    password_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorPassword"))
    entered = Event()
    release = Event()
    records = session.records



    #### Hold the first record refresh until local draft retention is observed.
    ####
    def delayed_records() -> tuple[RecordView, ...]:
        entered.set()
        assert release.wait(5)
        return records()

    monkeypatch.setattr(session, "records", delayed_records)
    title_field.setProperty("text", "Acknowledged Portal")
    group_field.setProperty("text", "Acknowledged Group")
    username_field.setProperty("text", "acknowledged-user")
    password_field.setProperty("text", "fabricated-local-secret")
    assert editor.setProperty("awaitingConfirmation", True)
    assert controller.confirm_record(
        1,
        "Acknowledged Portal",
        "Acknowledged Group",
        "acknowledged-user",
        False,
        "fabricated-local-secret",
    )
    assert entered.wait(5)
    draft_before_acknowledgement = (
        editor.property("visible"),
        title_field.property("text"),
        group_field.property("text"),
        username_field.property("text"),
        password_field.property("text"),
    )
    release.set()
    qtbot.waitUntil(lambda: editor.property("visible") is False, timeout=5000)

    assert draft_before_acknowledgement == (
        True,
        "Acknowledged Portal",
        "Acknowledged Group",
        "acknowledged-user",
        "fabricated-local-secret",
    )
    assert password_field.property("text") == ""
    assert session.change_count == 1



#### Prevent user dismissal from erasing a draft while its command is pending.
####
def test_record_editor_cannot_be_dismissed_before_acknowledgement(
    unlocked_shell: Shell,
) -> None:
    window, _controller, _executor, _session = unlocked_shell
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()
    QTest.keyClick(window, Qt.Key.Key_Return)
    editor = _object(window, "recordEditor")
    title_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorTitle"))
    password_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorPassword"))
    cancel_button = _item(window, "editorCancelButton")
    title_field.setProperty("text", "Pending Portal")
    password_field.setProperty("text", "fabricated-local-secret")

    assert editor.setProperty("awaitingConfirmation", True)
    QTest.keyClick(window, Qt.Key.Key_Escape)

    assert editor.property("visible") is True
    assert cancel_button.property("enabled") is False
    assert title_field.property("text") == "Pending Portal"
    assert password_field.property("text") == "fabricated-local-secret"



#### Keep a rejected editor draft available and report only fixed generic status copy.
####
def test_record_editor_retains_draft_after_worker_rejection(
    unlocked_shell: Shell,
    qtbot: QtBot,
) -> None:
    window, controller, _executor, session = unlocked_shell
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()
    QTest.keyClick(window, Qt.Key.Key_Return)
    editor = _object(window, "recordEditor")
    title_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorTitle"))
    group_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorGroup"))
    username_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorUsername"))
    password_field = cast(QQuickItem, editor.findChild(QQuickItem, "editorPassword"))
    sensitive_text = r"fabricated-secret at C:\private\vault.psafe3"
    session.records_error = RuntimeError(sensitive_text)
    title_field.setProperty("text", "Retained Portal")
    group_field.setProperty("text", "Retained Group")
    username_field.setProperty("text", "retained-user")
    password_field.setProperty("text", "fabricated-local-secret")

    assert editor.setProperty("awaitingConfirmation", True)
    with qtbot.waitSignal(controller.commandRejected, timeout=5000):
        assert controller.confirm_record(
            1,
            "Retained Portal",
            "Retained Group",
            "retained-user",
            False,
            "fabricated-local-secret",
        )
    qtbot.waitUntil(
        lambda: _item(window, "applicationStatus").property("text") == "The action could not be completed.",
        timeout=1000,
    )

    status = _item(window, "applicationStatus")
    assert editor.property("visible") is True
    assert title_field.property("text") == "Retained Portal"
    assert group_field.property("text") == "Retained Group"
    assert username_field.property("text") == "retained-user"
    assert password_field.property("text") == "fabricated-local-secret"
    assert status.property("text") == "The action could not be completed."
    assert sensitive_text not in repr((status.property("text"), status.property("Accessible.name")))



#### Present every closed failure key as fixed localized-safe accessible status copy.
####
def test_application_status_consumes_every_closed_failure_key(
    unlocked_shell: Shell,
) -> None:
    window, controller, _executor, _session = unlocked_shell
    status = _item(window, "applicationStatus")
    interface = QAccessible.queryAccessibleInterface(status)
    assert interface is not None

    for generation, (reason, expected_copy) in enumerate(_FAILURE_STATUS_COPY.items(), start=100):
        failure = ApplicationFailure(reason, f"application.failure.{reason.value}")
        snapshot = ApplicationSnapshot(
            generation,
            ApplicationPhase.UNLOCKED_CLEAN,
            "Fabricated",
            False,
            (),
            None,
            failure,
            None,
        )
        controller._accept_result(snapshot)
        assert status.property("text") == expected_copy
        assert status.property("visible") is True
        assert interface.role() is QAccessible.Role.AlertMessage
        assert interface.text(QAccessible.Text.Name) == expected_copy
        assert failure.presentation_key not in expected_copy



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

    qtbot.waitUntil(search.hasActiveFocus, timeout=1000)
    assert record_list.property("currentIndex") == -1



#### Do not silently select a different remaining row when the retained key disappears.
####
def test_model_reset_clears_selection_when_another_filtered_record_remains(
    unlocked_shell: Shell,
    qtbot: QtBot,
) -> None:
    window, controller, _executor, _session = unlocked_shell
    search = _item(window, "searchField")
    record_list = _item(window, "recordList")
    record_list.setProperty("currentIndex", 0)
    record_list.forceActiveFocus()
    QTest.keyClick(window, Qt.Key.Key_Down)
    assert record_list.property("currentIndex") == 1

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.set_search("Alpha Portal")

    qtbot.waitUntil(search.hasActiveFocus, timeout=1000)
    assert record_list.property("count") == 1
    assert record_list.property("currentIndex") == -1



#### Give every scoped action a nonempty accessibility name and keyboard focus.
####
def test_vault_has_accessible_complete_tab_cycle(unlocked_shell: Shell, qtbot: QtBot) -> None:
    window, _controller, _executor, _session = unlocked_shell
    names = (
        "searchField",
        "recordList",
        "addButton",
        "editButton",
        "copyUsernameButton",
        "copyPasswordButton",
        "openWebsiteButton",
        "saveButton",
        "lockButton",
    )
    _assert_accessible_tab_stops(window, names)
    _assert_tab_cycle(window, names, qtbot)



#### Welcome view starts visibly focused and exposes one complete accessible tab cycle.
####
def test_welcome_has_accessible_complete_tab_cycle(welcome_shell: Shell, qtbot: QtBot) -> None:
    window, _controller, _executor, _session = welcome_shell
    names = ("welcomeLabel", "welcomePassword", "createButton", "openButton")
    assert window.findChild(QQuickItem, "welcomeFile") is None
    _assert_accessible_tab_stops(window, names)
    _assert_tab_cycle(window, names, qtbot)



#### Unlock view starts visibly focused and exposes one complete accessible tab cycle.
####
def test_unlock_has_accessible_complete_tab_cycle(locked_shell: Shell, qtbot: QtBot) -> None:
    window, _controller, _executor, _session = locked_shell
    names = ("unlockPassword", "unlockButton")
    _assert_accessible_tab_stops(window, names)
    _assert_tab_cycle(window, names, qtbot)



#### Record editor starts on title and exposes every action in one deterministic cycle.
####
def test_record_editor_has_accessible_complete_tab_cycle(unlocked_shell: Shell, qtbot: QtBot) -> None:
    window, _controller, _executor, _session = unlocked_shell
    add_button = _item(window, "addButton")
    add_button.forceActiveFocus()
    QTest.keyClick(window, Qt.Key.Key_Space)
    names = (
        "editorTitle",
        "editorGroup",
        "editorUsername",
        "editorPassword",
        "editorConfirmButton",
        "editorCancelButton",
    )
    _assert_accessible_tab_stops(window, names)
    _assert_tab_cycle(window, names, qtbot)



#### Decision modal starts on Save and traps one complete accessible action cycle.
####
def test_decision_dialog_has_accessible_complete_tab_cycle(
    decision_shell: Shell,
    qtbot: QtBot,
) -> None:
    window, _controller, _executor, _session = decision_shell
    names = ("decisionSaveButton", "decisionDiscardButton", "decisionCancelButton")
    _assert_accessible_tab_stops(window, names)
    _assert_tab_cycle(window, names, qtbot)

    application = QGuiApplication.instance()
    assert application is not None
