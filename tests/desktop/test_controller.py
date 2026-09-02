"""Verify serialized facade execution and safe Qt controller projection."""

from __future__ import annotations

from pathlib import Path
from threading import Event, Lock, Thread
from typing import cast

from PySide6.QtCore import QCoreApplication, QThread
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
from bonobo_core.passwordsafe import SecretBuffer, VaultSession
from bonobo_desktop.controller import DesktopController
from bonobo_desktop.models import RecordListModel
from bonobo_desktop.tasks import FacadeExecutor



#### Build one inert safe snapshot for executor scheduling tests.
####
def _snapshot(generation: int) -> ApplicationSnapshot:
    return ApplicationSnapshot(generation, ApplicationPhase.EMPTY, "", False, (), None, None, None)



#### Record concurrent command entry while test-owned events hold the first worker operation.
####
class _RecordingFacade:
    active: int
    completed: list[int]
    first_entered: Event
    maximum_concurrency: int
    release_first: Event
    _lock: Lock



    #### Initialize deterministic concurrency observations and coordination events.
    ####
    def __init__(self) -> None:
        self.active = 0
        self.completed = []
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



#### Reject queued work after shutdown starts and wait for the active operation to leave its boundary.
####
def test_executor_shutdown_drains_active_work_and_rejects_new_commands() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    assert executor.submit(lambda target: target.run(1))
    assert facade.first_entered.wait(5)
    shutdown_returned = Event()



    #### Request shutdown outside the test thread so its active wait is observable.
    ####
    def request_shutdown() -> None:
        executor.shutdown()
        shutdown_returned.set()

    shutdown_thread = Thread(target=request_shutdown)
    shutdown_thread.start()
    assert not executor.submit(lambda target: target.run(2))
    assert not shutdown_returned.is_set()
    facade.release_first.set()
    assert shutdown_returned.wait(5)
    shutdown_thread.join()
    assert facade.completed == [1]



#### Release queued command ownership when shutdown clears work that never starts.
####
def test_executor_shutdown_cancels_queued_command_ownership() -> None:
    facade = _RecordingFacade()
    executor = FacadeExecutor(facade)
    canceled = Event()
    shutdown_returned = Event()
    assert executor.submit(lambda target: target.run(1))
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
    controller = DesktopController(typed_application, executor)
    signals = 0



    #### Count only the controller's accepted snapshot publications.
    ####
    def count_signal() -> None:
        nonlocal signals
        signals += 1

    controller.snapshotChanged.connect(count_signal)
    assert controller.setProperty("passphrase", "fabricated-passphrase")
    assert controller.property("passphrasePresent") is True
    assert controller.open_vault("fabricated.psafe3", "Fabricated")
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
    records = cast(RecordListModel, controller.property("records"))
    assert records.rowCount() == 1
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
