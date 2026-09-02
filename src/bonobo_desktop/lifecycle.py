"""Request one facade lock after monotonic qualifying-input inactivity.

The controller installs one application-wide event filter and uses
``QElapsedTimer`` for its deadline.  A short Qt timer only prompts deadline
checks; it is never the time authority.
"""

from collections.abc import Callable
from typing import ClassVar, Protocol, override

from PySide6.QtCore import QCoreApplication, QElapsedTimer, QEvent, QObject, QTimer, Signal, Slot



#### Describe the monotonic elapsed operations used by the idle deadline.
####
class _ElapsedTimer(Protocol):



    #### Start the monotonic interval at zero.
    ####
    def start(self) -> None:
        raise NotImplementedError



    #### Restart the interval after qualifying user activity.
    ####
    def restart(self) -> int:
        raise NotImplementedError



    #### Return elapsed monotonic milliseconds since the last start or restart.
    ####
    def elapsed(self) -> int:
        raise NotImplementedError



_QUALIFYING_EVENTS: frozenset[QEvent.Type] = frozenset(
    {
        QEvent.Type.KeyPress,
        QEvent.Type.MouseButtonPress,
        QEvent.Type.MouseButtonRelease,
        QEvent.Type.MouseMove,
        QEvent.Type.Wheel,
        QEvent.Type.TouchBegin,
        QEvent.Type.TouchUpdate,
        QEvent.Type.TabletPress,
        QEvent.Type.TabletMove,
    }
)



#### Track application-wide activity and submit the configured lock callback once.
####
class IdleLockController(QObject):
    lockRequested: ClassVar[Signal] = Signal()  # noqa: N815 - Qt metaobject API.
    polled: ClassVar[Signal] = Signal()
    _application: QCoreApplication
    _active: bool
    _elapsed: _ElapsedTimer
    _is_unlocked: Callable[[], bool] | None
    _lock_request: Callable[[], object]
    _submitted: bool
    _timeout_ms: int
    _timer: QTimer



    #### Install the activity filter and arm one monotonic idle interval.
    ####
    def __init__(
        self,
        application: QCoreApplication,
        lock_request: Callable[[], object],
        *,
        timeout_ms: int,
        is_unlocked: Callable[[], bool] | None = None,
        elapsed_timer: _ElapsedTimer | None = None,
    ) -> None:
        super().__init__()
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise ValueError("idle timeout must be a positive integer")
        self._application = application
        self._lock_request = lock_request
        self._timeout_ms = timeout_ms
        self._is_unlocked = is_unlocked
        self._elapsed = QElapsedTimer() if elapsed_timer is None else elapsed_timer
        self._active = is_unlocked is None or is_unlocked()
        self._submitted = False
        self._timer = QTimer(self)
        self._timer.setInterval(min(max(timeout_ms // 4, 1), 1000))
        self._timer.timeout.connect(self.poll)
        application.installEventFilter(self)
        self._elapsed.start()
        if self._active:
            self._timer.start()



    #### Restart the monotonic deadline for qualifying application input events.
    ####
    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if self._active and not self._submitted and event.type() in _QUALIFYING_EVENTS:
            self._elapsed.restart()
        return super().eventFilter(watched, event)



    #### Synchronize timer ownership with the current unlocked application phase.
    ####
    #### A locked-to-unlocked transition resets one-shot submission and starts a
    #### fresh monotonic interval.  Remaining within one phase never rearms an
    #### expired request or extends an interval without qualifying user input.
    ####
    @Slot()
    def synchronize_phase(self) -> None:
        is_unlocked = self._is_unlocked
        if is_unlocked is None:
            return
        active = is_unlocked()
        if active == self._active:
            return
        self._active = active
        if active:
            self._submitted = False
            self._elapsed.restart()
            self._timer.start()
        else:
            self._timer.stop()



    #### Check the monotonic deadline and submit one lock request after expiry.
    ####
    @Slot()
    def poll(self) -> None:
        if self._active and not self._submitted and self._elapsed.elapsed() >= self._timeout_ms:
            self._submitted = True
            self._timer.stop()
            self.lockRequested.emit()
            self._lock_request()
        self.polled.emit()



    #### Remove the application filter and stop future deadline checks.
    ####
    def close(self) -> None:
        self._active = False
        self._timer.stop()
        self._application.removeEventFilter(self)
