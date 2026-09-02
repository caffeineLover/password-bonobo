"""Verify serialized facade execution and safe Qt controller projection."""

from __future__ import annotations

from pathlib import Path
from threading import Event, Lock, Thread
from typing import cast

import pytest
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
