"""Verify serialized facade execution and safe Qt controller projection."""

from __future__ import annotations

from pathlib import Path
from threading import Event, Lock, Thread
from typing import cast

import pytest
from PySide6.QtCore import QCoreApplication, QRunnable, QThread, QThreadPool
from pytestqt.qtbot import QtBot
from tests.application.fakes import (
    FakeVaultService,
    FakeVaultSession,
    RecordingClipboard,
    fabricated_record_view,
)

from bonobo_core.application import (
    ApplicationPhase,
    ApplicationSnapshot,
    VaultApplication,
)
from bonobo_core.passwordsafe import RecordHandle, RecordView, SecretBuffer, VaultSession
from bonobo_desktop.controller import DesktopController
from bonobo_desktop.file_dialog import VaultFileSelection
from bonobo_desktop.models import RecordListModel
from bonobo_desktop.tasks import FacadeExecutor



#### Build one inert safe snapshot for executor scheduling tests.
####
def _snapshot(generation: int) -> ApplicationSnapshot:
    return ApplicationSnapshot(generation, ApplicationPhase.EMPTY, "", False, (), None, None, None)



#### Return the model's current title projection through its public Qt roles.
####
def _record_titles(model: RecordListModel) -> tuple[str, ...]:
    title_role = next(role for role, name in model.roleNames().items() if name == b"title")
    return tuple(cast(str, model.data(model.index(row, 0), title_role)) for row in range(model.rowCount()))



#### Supply deterministic private locators for controller secret-lifetime tests.
####
class _SelectedDialog:



    #### Return one test-owned open selection.
    ####
    def select_open(self, display_label: str) -> VaultFileSelection:
        return VaultFileSelection(Path("fabricated-open.psafe3"), display_label)



    #### Return one test-owned create selection.
    ####
    def select_create(self, display_label: str) -> VaultFileSelection:
        return VaultFileSelection(Path("fabricated-create.psafe3"), display_label)



#### Submit one passphrase-bearing controller intent by its closed test name.
####
def _submit_secret_intent(controller: DesktopController, intent: str) -> bool:
    if intent == "create":
        return controller.create_vault("Fabricated")
    if intent == "open":
        return controller.open_vault("Fabricated")
    if intent == "unlock":
        return controller.unlock_vault()
    raise AssertionError("unknown test intent")



#### Record concurrent command entry while test-owned events hold the first worker operation.
####
class _RecordingFacade:
    active: int
    completed: list[int]
    first_completed: Event
    first_entered: Event
    maximum_concurrency: int
    release_first: Event
    _lock: Lock



    #### Initialize deterministic concurrency observations and coordination events.
    ####
    def __init__(self) -> None:
        self.active = 0
        self.completed = []
        self.first_completed = Event()
        self.first_entered = Event()
        self.maximum_concurrency = 0
        self.release_first = Event()
        self._lock = Lock()



    #### Execute one numbered command while tracking overlapping entries.
    ####
    def run(self, number: int) -> ApplicationSnapshot:
        with self._lock:
            self.active += 1
            self.maximum_concurrency = max(self.maximum_concurrency, self.active)
        if number == 1:
            self.first_entered.set()
            assert self.release_first.wait(5)
        with self._lock:
            self.active -= 1
            self.completed.append(number)
        if number == 1:
            self.first_completed.set()
        return _snapshot(number)



#### Run two accepted commands in submission order without overlapping facade access.
####
def test_executor_never_runs_two_facade_commands_concurrently(qtbot: QtBot) -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    results: list[ApplicationSnapshot] = []
    executor.resultReady.connect(results.append)

    assert executor.submit(lambda target: target.run(1))
    assert facade.first_entered.wait(5)
    assert executor.submit(lambda target: target.run(2))
    facade.release_first.set()
    qtbot.waitUntil(lambda: len(results) == 2, timeout=5000)

    assert facade.maximum_concurrency == 1
    assert facade.completed == [1, 2]
    assert [snapshot.generation for snapshot in results] == [1, 2]
    executor.shutdown()



#### Deliver worker results to QObject receivers on the Qt GUI thread.
####
def test_executor_queues_results_to_the_gui_thread(qtbot: QtBot) -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    delivery_threads: list[QThread] = []

    executor.resultReady.connect(lambda _snapshot: delivery_threads.append(QThread.currentThread()))
    with qtbot.waitSignal(executor.resultReady, timeout=5000):
        assert executor.submit(lambda _target: _snapshot(1))

    application = QCoreApplication.instance()
    assert application is not None
    assert delivery_threads == [application.thread()]
    executor.shutdown()



#### Reject queued work after admission closes and drain a classified durability operation.
####
def test_executor_shutdown_drains_active_work_and_rejects_new_commands(qtbot: QtBot) -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    assert executor.submit(lambda target: target.run(1), drain_on_shutdown=True)
    assert facade.first_entered.wait(5)
    shutdown_returned = Event()



    #### Request shutdown outside the test thread so its active wait is observable.
    ####
    def request_shutdown() -> None:
        executor.shutdown()
        shutdown_returned.set()

    shutdown_thread = Thread(target=request_shutdown)
    with qtbot.waitSignal(executor.shutdownStarted, timeout=5000):
        shutdown_thread.start()
    assert not executor.submit(lambda target: target.run(2))
    assert not shutdown_returned.is_set()
    facade.release_first.set()
    assert shutdown_returned.wait(5)
    shutdown_thread.join()
    assert facade.completed == [1]



#### Return from shutdown without waiting for an active non-durability operation.
####
def test_executor_shutdown_does_not_drain_active_non_durability_work(qtbot: QtBot) -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    shutdown_returned = Event()
    assert executor.submit(lambda target: target.run(1))
    assert facade.first_entered.wait(5)



    #### Observe shutdown independently while the facade command remains blocked.
    ####
    def request_shutdown() -> None:
        executor.shutdown()
        shutdown_returned.set()

    shutdown_thread = Thread(target=request_shutdown)
    with qtbot.waitSignal(executor.shutdownStarted, timeout=5000):
        shutdown_thread.start()
    assert shutdown_returned.wait(5)
    assert not executor.submit(lambda target: target.run(2))
    assert facade.completed == []
    facade.release_first.set()
    assert facade.first_completed.wait(5)
    shutdown_thread.join()
    assert executor._pool.waitForDone(5000)



#### Run one terminal callback exactly once when shutdown finds the executor idle.
####
def test_executor_shutdown_runs_idle_terminal_callback_once() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    terminal_calls: list[_RecordingFacade] = []

    executor.shutdown(terminal_calls.append)
    executor.shutdown(terminal_calls.append)

    assert terminal_calls == [facade]
    assert not executor.submit(lambda target: target.run(2))



#### Keep terminal callback failures closed while preserving one-way shutdown.
####
def test_executor_shutdown_closes_terminal_callback_failure() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    terminal_calls = 0



    #### Fail with fabricated diagnostics that must remain inside the executor.
    ####
    def terminal(_target: _RecordingFacade) -> None:
        nonlocal terminal_calls
        terminal_calls += 1
        raise RuntimeError("fabricated terminal failure")

    executor.shutdown(terminal)
    executor.shutdown(terminal)

    assert terminal_calls == 1
    assert not executor.submit(lambda target: target.run(2))



#### Drain active durability work before running the terminal callback exactly once.
####
def test_executor_shutdown_runs_terminal_after_active_drain(qtbot: QtBot) -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    terminal_finished = Event()
    shutdown_returned = Event()
    order: list[str] = []



    #### Mark the active durability command complete before terminal handling.
    ####
    def command(target: _RecordingFacade) -> ApplicationSnapshot:
        result = target.run(1)
        order.append("command")
        return result

    assert executor.submit(command, drain_on_shutdown=True)
    assert facade.first_entered.wait(5)



    #### Record exclusive terminal entry after the active command has returned.
    ####
    def terminal(_target: _RecordingFacade) -> None:
        order.append("terminal")
        terminal_finished.set()



    #### Observe that durability shutdown includes terminal completion.
    ####
    def request_shutdown() -> None:
        executor.shutdown(terminal)
        shutdown_returned.set()

    shutdown_thread = Thread(target=request_shutdown)
    with qtbot.waitSignal(executor.shutdownStarted, timeout=5000):
        shutdown_thread.start()
    assert not terminal_finished.is_set()
    assert not shutdown_returned.is_set()
    facade.release_first.set()
    assert terminal_finished.wait(5)
    assert shutdown_returned.wait(5)
    shutdown_thread.join()
    assert executor._pool.waitForDone(5000)

    assert order == ["command", "terminal"]
    executor.shutdown(terminal)
    assert order == ["command", "terminal"]



#### Return promptly for active ordinary work but serialize terminal finalization behind it.
####
def test_executor_shutdown_defers_terminal_after_active_non_durability(qtbot: QtBot) -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    terminal_finished = Event()
    queued_canceled = Event()
    order: list[str] = []



    #### Mark the active ordinary command complete before terminal handling.
    ####
    def command(target: _RecordingFacade) -> ApplicationSnapshot:
        result = target.run(1)
        order.append("command")
        return result

    assert executor.submit(command)
    assert facade.first_entered.wait(5)



    #### Prove transferred ownership is canceled before terminal handling begins.
    ####
    def cancel_queued() -> None:
        order.append("canceled")
        queued_canceled.set()

    assert executor.submit(lambda target: target.run(2), canceled=cancel_queued)



    #### Record the terminal boundary only after the ordinary command releases the facade.
    ####
    def terminal(_target: _RecordingFacade) -> None:
        order.append("terminal")
        terminal_finished.set()

    with qtbot.waitSignal(executor.shutdownStarted, timeout=5000):
        executor.shutdown(terminal)
    assert queued_canceled.is_set()
    assert not terminal_finished.is_set()
    facade.release_first.set()
    assert terminal_finished.wait(5)
    qtbot.waitUntil(lambda: facade.completed == [1], timeout=5000)
    assert executor._pool.waitForDone(5000)

    assert order == ["canceled", "command", "terminal"]
    executor.shutdown(terminal)
    assert order == ["canceled", "command", "terminal"]



#### Release queued command ownership when shutdown clears work that never starts.
####
def test_executor_shutdown_cancels_queued_command_ownership() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    canceled = Event()
    shutdown_returned = Event()
    assert executor.submit(lambda target: target.run(1), drain_on_shutdown=True)
    assert facade.first_entered.wait(5)
    assert executor.submit(lambda target: target.run(2), canceled=canceled.set)



    #### Request shutdown outside the test thread so queued cancellation is observable.
    ####
    def request_shutdown() -> None:
        executor.shutdown()
        shutdown_returned.set()

    shutdown_thread = Thread(target=request_shutdown)
    shutdown_thread.start()
    assert canceled.wait(5)
    facade.release_first.set()
    assert shutdown_returned.wait(5)
    shutdown_thread.join()
    assert facade.completed == [1]



#### Roll back task admission and release real secret ownership when pool start raises.
####
def test_executor_submission_is_transactional_when_pool_start_raises() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    original_pool = executor._pool
    failure = KeyboardInterrupt("fabricated pool-start interruption")
    owner = SecretBuffer.from_bytes(b"fabricated-queued-secret")



    #### Raise before the task can become reachable by the worker pool.
    ####
    class _FailingPool:



        #### Preserve the original submission interruption for the caller.
        ####
        def start(self, _task: QRunnable) -> None:
            raise failure

    executor._pool = cast(QThreadPool, _FailingPool())
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            executor.submit(lambda _target: _snapshot(1), canceled=owner.close)
    finally:
        executor._pool = original_pool

    assert caught.value is failure
    assert owner.closed
    assert executor._tasks == set()
    executor.shutdown()



#### Cancel a queued command by closing its transferred real secret owner.
####
def test_executor_shutdown_closes_real_secret_for_queued_cancellation() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    owner = SecretBuffer.from_bytes(b"fabricated-queued-secret")
    canceled = Event()
    shutdown_returned = Event()
    assert executor.submit(lambda target: target.run(1), drain_on_shutdown=True)
    assert facade.first_entered.wait(5)



    #### Close the real owner and expose only completion of that cleanup.
    ####
    def cancel_secret() -> None:
        owner.close()
        canceled.set()

    assert executor.submit(lambda target: target.run(2), canceled=cancel_secret)



    #### Request shutdown independently while active durability work is held.
    ####
    def request_shutdown() -> None:
        executor.shutdown()
        shutdown_returned.set()

    shutdown_thread = Thread(target=request_shutdown)
    shutdown_thread.start()
    try:
        assert canceled.wait(5)
        assert owner.closed
        assert not shutdown_returned.is_set()
    finally:
        facade.release_first.set()
        assert shutdown_returned.wait(5)
        shutdown_thread.join()

    assert facade.completed == [1]



#### Notify exactly once after replacing transient passphrase input.
####
def test_controller_emits_passphrase_notification_after_replacement() -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    notifications = 0



    #### Count the closed property notification without observing its value.
    ####
    def count_notification() -> None:
        nonlocal notifications
        notifications += 1

    controller.passphraseChanged.connect(count_notification)
    assert controller.setProperty("passphrase", "fabricated-passphrase")

    assert notifications == 1
    assert controller.property("passphrasePresent") is True
    executor.shutdown()



#### Wipe and notify transient passphrase state before a manual lock is submitted.
####
def test_controller_clears_passphrase_before_lock(qtbot: QtBot) -> None:
    session = FakeVaultSession(())
    application = VaultApplication(FakeVaultService(session))
    application.open(Path("fabricated.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    notifications = 0



    #### Count both the setter and terminal clear transitions.
    ####
    def count_notification() -> None:
        nonlocal notifications
        notifications += 1

    controller.passphraseChanged.connect(count_notification)
    assert controller.setProperty("passphrase", "residual-input")
    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.lock()
        assert controller.property("passphrasePresent") is False

    assert notifications == 2
    assert controller.property("phase") == ApplicationPhase.LOCKED.value
    executor.shutdown()



#### Wipe transient passphrase state when the controller begins shutdown.
####
def test_controller_shutdown_clears_passphrase() -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    notifications = 0



    #### Count the setter and shutdown clear transitions.
    ####
    def count_notification() -> None:
        nonlocal notifications
        notifications += 1

    controller.passphraseChanged.connect(count_notification)
    assert controller.setProperty("passphrase", "residual-input")
    controller.shutdown()

    assert notifications == 2
    assert controller.property("passphrasePresent") is False



#### Clear passphrase input before worker submission and publish one primitive snapshot update.
####
def test_controller_clears_passphrase_before_open_and_projects_snapshot(qtbot: QtBot) -> None:
    entered = Event()
    release = Event()
    session = FakeVaultSession((fabricated_record_view(),))
    service = FakeVaultService(session)



    #### Hold fake authentication until the test observes cleared GUI input.
    ####
    def block_open() -> None:
        entered.set()
        assert release.wait(5)

    service.on_open = block_open
    application = VaultApplication(service)
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    selected_locator = Path("fabricated.psafe3")



    #### Return one Python-owned native selection without exposing it through Qt.
    ####
    class _OpenDialog:
        calls: list[str]



        #### Initialize safe display-label observations.
        ####
        def __init__(self) -> None:
            self.calls = []



        #### Return the test-owned private locator for one open intent.
        ####
        def select_open(self, display_label: str) -> VaultFileSelection:
            self.calls.append(display_label)
            return VaultFileSelection(selected_locator, display_label)



        #### Reject an unexpected create intent in this open-only regression.
        ####
        def select_create(self, _display_label: str) -> VaultFileSelection | None:
            raise AssertionError("create selection was not requested")

    dialog = _OpenDialog()
    controller = DesktopController(typed_application, executor, file_dialog=dialog)
    signals = 0



    #### Count only the controller's accepted snapshot publications.
    ####
    def count_signal() -> None:
        nonlocal signals
        signals += 1

    controller.snapshotChanged.connect(count_signal)
    assert controller.setProperty("passphrase", "fabricated-passphrase")
    assert controller.property("passphrasePresent") is True
    assert controller.open_vault("Fabricated")
    assert controller.property("passphrase") == ""
    assert controller.property("passphrasePresent") is False
    assert entered.wait(5)
    release.set()
    qtbot.waitUntil(
        lambda: controller.property("phase") == ApplicationPhase.UNLOCKED_CLEAN.value,
        timeout=5000,
    )

    assert signals == 1
    assert controller.property("displayLabel") == "Fabricated"
    assert controller.property("dirty") is False
    assert controller.property("failureKey") == ""
    assert controller.property("selectedKey") == 0
    assert controller.property("decisionRequired") is False
    assert dialog.calls == ["Fabricated"]
    records = cast(RecordListModel, controller.property("records"))
    assert records.rowCount() == 1
    executor.shutdown()



#### Keep create selection private and expose only one safe label argument to Qt.
####
def test_controller_create_intent_has_no_qml_locator_argument(qtbot: QtBot) -> None:
    session = FakeVaultSession(())
    service = FakeVaultService(session)
    application = VaultApplication(service)
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)



    #### Supply one private create selection from the injected native adapter.
    ####
    class _CreateDialog:



        #### Return the test-owned locator and the unchanged safe label.
        ####
        def select_create(self, display_label: str) -> VaultFileSelection:
            return VaultFileSelection(Path("fabricated-created.psafe3"), display_label)



        #### Reject an unexpected open intent in this create-only regression.
        ####
        def select_open(self, _display_label: str) -> VaultFileSelection | None:
            raise AssertionError("open selection was not requested")

    controller = DesktopController(typed_application, executor, file_dialog=_CreateDialog())
    assert controller.setProperty("passphrase", "fabricated-passphrase")

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.create_vault("Created")

    assert service.create_calls == 1
    assert controller.property("displayLabel") == "Created"
    metaobject = controller.metaObject()
    assert metaobject.indexOfMethod("createVault(QString)") >= 0
    assert metaobject.indexOfMethod("createVault(QString,QString)") == -1
    assert metaobject.indexOfMethod("openVault(QString,QString)") == -1
    executor.shutdown()



#### Transfer raw controller input to one owner before either native dialog opens.
####
@pytest.mark.parametrize("intent", ("create", "open"))
def test_controller_takes_passphrase_ownership_before_native_selection(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> None:
    service = FakeVaultService(FakeVaultSession(()))
    application = VaultApplication(service)
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    owners: list[SecretBuffer] = []
    take_ownership = SecretBuffer.take_ownership
    during_dialog: list[tuple[bool, bytes, int, bool]] = []



    #### Capture the real owner created at synchronous slot entry.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owner = take_ownership(value)
        owners.append(owner)
        return owner



    #### Observe controller and owner state while returning one accepted selection.
    ####
    class _ObservingDialog:



        #### Record ownership state while selecting the fabricated open vault.
        ####
        def select_open(self, display_label: str) -> VaultFileSelection:
            during_dialog.append(
                (
                    cast(bool, controller.property("passphrasePresent")),
                    bytes(controller._passphrase),
                    len(owners),
                    owners[0].closed if owners else True,
                )
            )
            return VaultFileSelection(Path("fabricated-open.psafe3"), display_label)



        #### Record ownership state while selecting the fabricated create destination.
        ####
        def select_create(self, display_label: str) -> VaultFileSelection:
            during_dialog.append(
                (
                    cast(bool, controller.property("passphrasePresent")),
                    bytes(controller._passphrase),
                    len(owners),
                    owners[0].closed if owners else True,
                )
            )
            return VaultFileSelection(Path("fabricated-create.psafe3"), display_label)

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    controller = DesktopController(typed_application, executor, file_dialog=_ObservingDialog())
    assert controller.setProperty("passphrase", "fabricated-passphrase")

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert _submit_secret_intent(controller, intent)

    assert during_dialog == [(False, b"", 1, False)]
    assert len(owners) == 1
    assert owners[0].closed
    assert (service.create_calls, service.open_calls) == ((1, 0) if intent == "create" else (0, 1))
    executor.shutdown()



#### Close the transferred real owner when either native dialog is canceled.
####
@pytest.mark.parametrize("intent", ("create", "open"))
def test_controller_closes_owned_passphrase_when_native_selection_is_canceled(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    owners: list[SecretBuffer] = []
    owned_storage: list[bytearray] = []
    take_ownership = SecretBuffer.take_ownership
    during_dialog: list[tuple[bool, bytes, int]] = []



    #### Capture the real owner and its adopted mutable storage.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owned_storage.append(value)
        owner = take_ownership(value)
        owners.append(owner)
        return owner



    #### Observe ownership state before returning native cancellation.
    ####
    class _CanceledDialog:



        #### Cancel open selection after recording controller state.
        ####
        def select_open(self, _display_label: str) -> None:
            during_dialog.append(
                (
                    cast(bool, controller.property("passphrasePresent")),
                    bytes(controller._passphrase),
                    len(owners),
                )
            )



        #### Cancel create selection after recording controller state.
        ####
        def select_create(self, _display_label: str) -> None:
            during_dialog.append(
                (
                    cast(bool, controller.property("passphrasePresent")),
                    bytes(controller._passphrase),
                    len(owners),
                )
            )

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    controller = DesktopController(typed_application, executor, file_dialog=_CanceledDialog())
    rejections: list[tuple[object, ...]] = []
    controller.commandRejected.connect(lambda *values: rejections.append(values))
    assert controller.setProperty("passphrase", "fabricated-passphrase")

    assert not _submit_secret_intent(controller, intent)

    assert during_dialog == [(False, b"", 1)]
    assert rejections == []
    assert len(owners) == 1
    assert owners[0].closed
    assert bytes(owned_storage[0]) == b"\x00" * len(owned_storage[0])
    executor.shutdown()



#### Contain adversarial native-dialog failures behind argument-free rejection.
####
@pytest.mark.parametrize("intent", ("create", "open"))
def test_controller_contains_native_selection_failure_without_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    sensitive_text = rf"fabricated-passphrase at C:\private\{intent}.psafe3"
    failure = KeyboardInterrupt(sensitive_text)
    owners: list[SecretBuffer] = []
    owned_storage: list[bytearray] = []
    take_ownership = SecretBuffer.take_ownership



    #### Capture the real owner and its adopted mutable storage.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owned_storage.append(value)
        owner = take_ownership(value)
        owners.append(owner)
        return owner



    #### Raise one adversarial diagnostic from either native selection boundary.
    ####
    class _InterruptedDialog:



        #### Raise the closed test interruption during open selection.
        ####
        def select_open(self, _display_label: str) -> VaultFileSelection | None:
            raise failure



        #### Raise the closed test interruption during create selection.
        ####
        def select_create(self, _display_label: str) -> VaultFileSelection | None:
            raise failure

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    controller = DesktopController(typed_application, executor, file_dialog=_InterruptedDialog())
    rejections: list[tuple[object, ...]] = []
    controller.commandRejected.connect(lambda *values: rejections.append(values))
    assert controller.setProperty("passphrase", "fabricated-passphrase")
    before = (
        controller.property("phase"),
        controller.property("displayLabel"),
        controller.property("failureKey"),
        controller.property("selectedKey"),
    )

    try:
        accepted = _submit_secret_intent(controller, intent)
    except BaseException:
        pytest.fail("native dialog exception escaped the QML-facing slot")

    after = (
        controller.property("phase"),
        controller.property("displayLabel"),
        controller.property("failureKey"),
        controller.property("selectedKey"),
    )
    signal = controller.metaObject().method(controller.metaObject().indexOfSignal("commandRejected()"))
    assert not accepted
    assert rejections == [()]
    assert signal.parameterCount() == 0
    assert before == after
    assert len(owners) == 1
    assert owners[0].closed
    assert bytes(owned_storage[0]) == b"\x00" * len(owned_storage[0])
    assert sensitive_text not in repr((after, controller.__dict__))
    executor.shutdown()



#### Close real passphrase owners when create, open, or unlock admission returns false.
####
@pytest.mark.parametrize("intent", ("create", "open", "unlock"))
def test_controller_closes_passphrase_when_executor_rejects(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor, file_dialog=_SelectedDialog())
    owners: list[SecretBuffer] = []
    take_ownership = SecretBuffer.take_ownership



    #### Capture the real mutable passphrase owner at the controller boundary.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owner = take_ownership(value)
        owners.append(owner)
        return owner

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    assert controller.setProperty("passphrase", "fabricated-passphrase")
    executor.shutdown()

    assert not _submit_secret_intent(controller, intent)
    assert len(owners) == 1
    assert owners[0].closed



#### Close real passphrase owners and preserve create, open, or unlock submission errors.
####
@pytest.mark.parametrize("intent", ("create", "open", "unlock"))
def test_controller_closes_passphrase_when_executor_submission_raises(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor, file_dialog=_SelectedDialog())
    owners: list[SecretBuffer] = []
    take_ownership = SecretBuffer.take_ownership
    failure = KeyboardInterrupt(f"fabricated {intent} submission interruption")



    #### Capture the real mutable passphrase owner at the controller boundary.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owner = take_ownership(value)
        owners.append(owner)
        return owner



    #### Raise the exact interruption before executor ownership can settle.
    ####
    def interrupt_submission(*_args: object, **_kwargs: object) -> bool:
        raise failure

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    monkeypatch.setattr(executor, "submit", interrupt_submission)
    assert controller.setProperty("passphrase", "fabricated-passphrase")

    with pytest.raises(KeyboardInterrupt) as caught:
        _submit_secret_intent(controller, intent)

    assert caught.value is failure
    assert len(owners) == 1
    assert owners[0].closed
    executor.shutdown()



#### Clear every passphrase owner through successful create, open, and unlock terminals.
####
@pytest.mark.parametrize("intent", ("create", "open", "unlock"))
def test_controller_closes_passphrase_after_terminal_result(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> None:
    session = FakeVaultSession(())
    application = VaultApplication(FakeVaultService(session))
    if intent == "unlock":
        with SecretBuffer.from_bytes(b"fabricated-initial-passphrase") as initial:
            opened = application.open(Path("fabricated.psafe3"), initial, "Fabricated")
        application.lock(opened.generation)
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor, file_dialog=_SelectedDialog())
    owners: list[SecretBuffer] = []
    take_ownership = SecretBuffer.take_ownership



    #### Capture the real mutable passphrase owner at the controller boundary.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owner = take_ownership(value)
        owners.append(owner)
        return owner

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    assert controller.setProperty("passphrase", "fabricated-passphrase")

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert _submit_secret_intent(controller, intent)

    assert len(owners) == 1
    assert owners[0].closed
    executor.shutdown()



#### Convert primitive Qt record keys back to the closed RecordKey facade type.
####
def test_controller_maps_qml_record_key_to_application_key(qtbot: QtBot) -> None:
    session = FakeVaultSession((fabricated_record_view(),))
    clipboard = RecordingClipboard()
    application = VaultApplication(FakeVaultService(session), clipboard=clipboard)
    application.open(Path("fabricated.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.copy_password(1)

    assert clipboard.copied == b"fabricated-password"
    executor.shutdown()



#### Coalesce two edits before the first result and render only the latest query.
####
def test_controller_serializes_two_search_edits_before_first_result(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = fabricated_record_view()
    second = RecordView(
        RecordHandle(),
        first.revision,
        "Beta Console",
        "Examples",
        "second-user",
        "https://second.example.invalid/private",
        False,
    )
    session = FakeVaultSession((first, second))
    application = VaultApplication(FakeVaultService(session))
    application.open(Path("fabricated.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    entered = Event()
    release = Event()
    records = session.records
    calls = 0
    rejections: list[tuple[object, ...]] = []



    #### Hold only the first search projection until both edits are submitted.
    ####
    def delayed_records() -> tuple[RecordView, ...]:
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(5)
        return records()

    monkeypatch.setattr(session, "records", delayed_records)
    controller.commandRejected.connect(lambda *values: rejections.append(values))
    model = cast(RecordListModel, controller.property("records"))

    assert controller.set_search("Alpha")
    assert entered.wait(5)
    assert controller.set_search("Beta")
    release.set()
    qtbot.waitUntil(lambda: bool(rejections) or _record_titles(model) == ("Beta Console",), timeout=5000)

    assert rejections == []
    assert _record_titles(model) == ("Beta Console",)
    assert calls == 2
    executor.shutdown()



#### Retry the latest pending search after a safe first-result failure snapshot.
####
def test_controller_retries_latest_search_after_first_result_failure(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = fabricated_record_view()
    second = RecordView(
        RecordHandle(),
        first.revision,
        "Beta Console",
        "Examples",
        "second-user",
        "https://second.example.invalid/private",
        False,
    )
    session = FakeVaultSession((first, second))
    application = VaultApplication(FakeVaultService(session))
    application.open(Path("fabricated.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    entered = Event()
    release = Event()
    records = session.records
    calls = 0
    rejections: list[tuple[object, ...]] = []



    #### Fail the held first refresh and let the pending latest refresh succeed.
    ####
    def initially_failing_records() -> tuple[RecordView, ...]:
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(5)
            raise RuntimeError("fabricated sensitive-looking first search failure")
        return records()

    monkeypatch.setattr(session, "records", initially_failing_records)
    controller.commandRejected.connect(lambda *values: rejections.append(values))
    model = cast(RecordListModel, controller.property("records"))

    assert controller.set_search("Alpha")
    assert entered.wait(5)
    assert controller.set_search("Beta")
    release.set()
    qtbot.waitUntil(lambda: bool(rejections) or _record_titles(model) == ("Beta Console",), timeout=5000)

    assert rejections == []
    assert _record_titles(model) == ("Beta Console",)
    assert calls == 2
    executor.shutdown()



#### Publish worker failures only through zero-argument signals and closed state.
####
def test_worker_failure_signals_never_retain_sensitive_exception_text(qtbot: QtBot) -> None:
    sensitive_text = r"fabricated-passphrase at C:\private\vault.psafe3"
    session = FakeVaultSession((fabricated_record_view(),))
    application = VaultApplication(FakeVaultService(session))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    failed: list[tuple[object, ...]] = []
    rejected: list[tuple[object, ...]] = []
    executor.commandFailed.connect(lambda *values: failed.append(values))
    controller.commandRejected.connect(lambda *values: rejected.append(values))



    #### Raise text resembling both a secret and a private source locator.
    ####
    def fail_worker(_target: VaultApplication[VaultSession]) -> ApplicationSnapshot:
        raise RuntimeError(sensitive_text)

    with qtbot.waitSignal(controller.commandRejected, timeout=5000):
        assert executor.submit(fail_worker)

    model = cast(RecordListModel, controller.property("records"))
    public_state = (
        controller.property("phase"),
        controller.property("displayLabel"),
        controller.property("failureKey"),
        controller.property("passphrase"),
        _record_titles(model),
    )
    assert failed == [()]
    assert rejected == [()]
    assert executor.metaObject().method(executor.metaObject().indexOfSignal("commandFailed()")).parameterCount() == 0
    controller_signal = controller.metaObject().method(controller.metaObject().indexOfSignal("commandRejected()"))
    assert controller_signal.parameterCount() == 0
    assert sensitive_text not in repr(public_state)
    assert sensitive_text not in repr(controller.__dict__)
    executor.shutdown()



#### Confirm primitive editor fields through one private generation-bound facade draft.
####
def test_controller_confirms_existing_record_without_exposing_draft(qtbot: QtBot) -> None:
    session = FakeVaultSession((fabricated_record_view(),))
    application = VaultApplication(FakeVaultService(session))
    application.open(Path("fabricated.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.confirm_record(
            1,
            "Updated Portal",
            "Research",
            "updated-user",
            False,
            "fabricated-new-password",
        )

    assert session.apply_calls == 1
    assert session.records_value[0].title == "Updated Portal"
    assert controller.property("dirty") is True
    assert not hasattr(controller, "recordDraft")
    executor.shutdown()



#### Add a record from primitive fields while keeping the generated key and secret private.
####
def test_controller_confirms_new_record_from_zero_key(qtbot: QtBot) -> None:
    session = FakeVaultSession(())
    application = VaultApplication(FakeVaultService(session))
    application.open(Path("fabricated.psafe3"), SecretBuffer.from_bytes(b"fabricated"), "Fabricated")
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)

    with qtbot.waitSignal(controller.snapshotChanged, timeout=5000):
        assert controller.confirm_record(
            0,
            "Added Portal",
            "Examples",
            "added-user",
            False,
            "fabricated-added-password",
        )

    assert session.change_count == 1
    assert session.records_value[0].title == "Added Portal"
    assert controller.property("records").rowCount() == 1
    executor.shutdown()



#### Close a newly owned editor secret when shutdown rejects worker admission.
####
def test_controller_closes_record_password_when_executor_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    owners: list[SecretBuffer] = []
    take_ownership = SecretBuffer.take_ownership



    #### Capture the real mutable owner created at the controller boundary.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owner = take_ownership(value)
        owners.append(owner)
        return owner

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    executor.shutdown()

    assert not controller.confirm_record(0, "Rejected", "Examples", "sample", False, "fabricated")
    assert len(owners) == 1
    assert owners[0].closed



#### Close a newly owned editor secret when executor submission itself raises.
####
def test_controller_closes_record_password_when_executor_submission_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    owners: list[SecretBuffer] = []
    take_ownership = SecretBuffer.take_ownership
    failure = KeyboardInterrupt("fabricated submission interruption")



    #### Capture the real mutable owner before submission is interrupted.
    ####
    def capture_owner(value: bytearray) -> SecretBuffer:
        owner = take_ownership(value)
        owners.append(owner)
        return owner



    #### Raise the exact fabricated interruption from the executor boundary.
    ####
    def interrupt_submission(*_args: object, **_kwargs: object) -> bool:
        raise failure

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(capture_owner))
    monkeypatch.setattr(executor, "submit", interrupt_submission)

    with pytest.raises(KeyboardInterrupt) as caught:
        controller.confirm_record(0, "Interrupted", "Examples", "sample", False, "fabricated")

    assert caught.value is failure
    assert len(owners) == 1
    assert owners[0].closed
    executor.shutdown()



#### Preserve the submission interruption even when emergency owner cleanup fails.
####
def test_controller_secret_cleanup_never_masks_submission_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = VaultApplication(FakeVaultService(FakeVaultSession(())))
    typed_application = cast(VaultApplication[VaultSession], application)
    executor = FacadeExecutor(typed_application)
    controller = DesktopController(typed_application, executor)
    failure = KeyboardInterrupt("fabricated submission interruption")
    cleanup_calls = 0



    #### Model cleanup failure after ownership has transferred to the controller.
    ####
    class _FailingSecretOwner:



        #### Record the attempted cleanup before raising a fabricated failure.
        ####
        def close(self) -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            raise RuntimeError("fabricated cleanup failure")

    owner = cast(SecretBuffer, _FailingSecretOwner())



    #### Raise the exact fabricated interruption from the executor boundary.
    ####
    def interrupt_submission(*_args: object, **_kwargs: object) -> bool:
        raise failure

    monkeypatch.setattr(SecretBuffer, "take_ownership", staticmethod(lambda _value: owner))
    monkeypatch.setattr(executor, "submit", interrupt_submission)

    with pytest.raises(KeyboardInterrupt) as caught:
        controller.confirm_record(0, "Interrupted", "Examples", "sample", False, "fabricated")

    assert caught.value is failure
    assert cleanup_calls == 1
    executor.shutdown()
