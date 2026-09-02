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
    _elapsed: _ElapsedTimer
    _lock_request: Callable[[], None]
    _submitted: bool
    _timeout_ms: int
    _timer: QTimer



    #### Install the activity filter and arm one monotonic idle interval.
    ####
    def __init__(
        self,
        application: QCoreApplication,
        lock_request: Callable[[], None],
        *,
        timeout_ms: int,
        elapsed_timer: _ElapsedTimer | None = None,
    ) -> None:
        super().__init__()
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise ValueError("idle timeout must be a positive integer")
        self._application = application
        self._lock_request = lock_request
        self._timeout_ms = timeout_ms
        self._elapsed = QElapsedTimer() if elapsed_timer is None else elapsed_timer
        self._submitted = False
        self._timer = QTimer(self)
        self._timer.setInterval(min(max(timeout_ms // 4, 1), 1000))
        self._timer.timeout.connect(self.poll)
        application.installEventFilter(self)
        self._elapsed.start()
        self._timer.start()



    #### Restart the monotonic deadline for qualifying application input events.
    ####
    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if not self._submitted and event.type() in _QUALIFYING_EVENTS:
            self._elapsed.restart()
        return super().eventFilter(watched, event)



    #### Check the monotonic deadline and submit one lock request after expiry.
    ####
    @Slot()
    def poll(self) -> None:
        if not self._submitted and self._elapsed.elapsed() >= self._timeout_ms:
            self._submitted = True
            self._timer.stop()
            self.lockRequested.emit()
            self._lock_request()
        self.polled.emit()



    #### Remove the application filter and stop future deadline checks.
    ####
    def close(self) -> None:
        self._timer.stop()
        self._application.removeEventFilter(self)
