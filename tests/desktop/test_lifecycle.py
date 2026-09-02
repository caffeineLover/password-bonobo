"""Verify monotonic idle lock submission and qualifying application activity."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QCoreApplication, QEvent, QObject
from pytestqt.qtbot import QtBot

from bonobo_desktop.lifecycle import IdleLockController



#### Provide a deterministic monotonic elapsed timer for event-driven idle tests.
####
class _ManualElapsedTimer:
    elapsed_value: int



    #### Initialize a stopped clock at the monotonic origin.
    ####
    def __init__(self) -> None:
        self.elapsed_value = 0



    #### Start or restart the fake monotonic interval.
    ####
    def start(self) -> None:
        self.elapsed_value = 0



    #### Restart the fake interval and return its prior elapsed value.
    ####
    def restart(self) -> int:
        prior = self.elapsed_value
        self.elapsed_value = 0
        return prior



    #### Return the deterministic elapsed interval in milliseconds.
    ####
    def elapsed(self) -> int:
        return self.elapsed_value



#### Emit a timer callback through Qt so tests coordinate on signals instead of sleeping.
####
def _await_timer_poll(qtbot: QtBot, controller: IdleLockController, predicate: Callable[[], bool]) -> None:
    with qtbot.waitSignal(controller.polled, timeout=1000):
        controller.poll()
    assert predicate()



#### Submit the lock callback exactly once after the monotonic idle deadline expires.
####
def test_idle_expiry_submits_lock_once(qtbot: QtBot) -> None:
    application = QCoreApplication.instance()
    assert application is not None
    timer = _ManualElapsedTimer()
    submissions = 0



    #### Count the closed lock callback without introducing another scheduler.
    ####
    def submit_lock() -> None:
        nonlocal submissions
        submissions += 1

    controller = IdleLockController(application, submit_lock, timeout_ms=100, elapsed_timer=timer)
    timer.elapsed_value = 100
    _await_timer_poll(qtbot, controller, lambda: submissions == 1)
    timer.elapsed_value = 500
    _await_timer_poll(qtbot, controller, lambda: submissions == 1)
    controller.close()



#### Restart the deadline only for qualifying application input events.
####
def test_idle_activity_filter_ignores_non_input_and_resets_for_input(qtbot: QtBot) -> None:
    application = QCoreApplication.instance()
    assert application is not None
    timer = _ManualElapsedTimer()
    submissions = 0



    #### Count the lock callback after the event-filter reset boundary.
    ####
    def submit_lock() -> None:
        nonlocal submissions
        submissions += 1

    controller = IdleLockController(application, submit_lock, timeout_ms=100, elapsed_timer=timer)
    target = QObject()
    timer.elapsed_value = 75
    QCoreApplication.sendEvent(target, QEvent(QEvent.Type.User))
    assert timer.elapsed_value == 75
    QCoreApplication.sendEvent(target, QEvent(QEvent.Type.KeyPress))
    assert timer.elapsed_value == 0
    timer.elapsed_value = 100
    _await_timer_poll(qtbot, controller, lambda: submissions == 1)
    controller.close()



#### Arm only while unlocked and rearm after every locked-to-unlocked transition.
####
#### An expiry remains one-shot within one unlocked phase.  Successful relock
#### followed by unlock starts a fresh monotonic interval and permits one new
#### submission without reconstructing the retained application event filter.
####
def test_idle_lock_is_phase_aware_and_rearms_after_unlock(qtbot: QtBot) -> None:
    application = QCoreApplication.instance()
    assert application is not None
    timer = _ManualElapsedTimer()
    unlocked = False
    submissions = 0



    #### Report the current test-owned application phase without exposing a DTO.
    ####
    def is_unlocked() -> bool:
        return unlocked



    #### Count one lock request for each distinct unlocked lifetime.
    ####
    def submit_lock() -> None:
        nonlocal submissions
        submissions += 1

    controller = IdleLockController(
        application,
        submit_lock,
        timeout_ms=100,
        is_unlocked=is_unlocked,
        elapsed_timer=timer,
    )
    timer.elapsed_value = 500
    _await_timer_poll(qtbot, controller, lambda: submissions == 0)

    unlocked = True
    controller.synchronize_phase()
    assert timer.elapsed_value == 0
    timer.elapsed_value = 100
    _await_timer_poll(qtbot, controller, lambda: submissions == 1)
    timer.elapsed_value = 500
    _await_timer_poll(qtbot, controller, lambda: submissions == 1)

    unlocked = False
    controller.synchronize_phase()
    unlocked = True
    controller.synchronize_phase()
    timer.elapsed_value = 100
    _await_timer_poll(qtbot, controller, lambda: submissions == 2)
    controller.close()
