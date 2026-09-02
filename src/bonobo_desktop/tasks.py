"""Serialize facade commands and provide synchronous GUI-thread invocation.

One private thread pool executes immutable command envelopes in submission
order.  Worker outcomes cross back through queued Qt signals without carrying
raw exception objects or text.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import ClassVar, cast

from PySide6.QtCore import QObject, QRunnable, Qt, QThread, QThreadPool, Signal, Slot

from bonobo_core.application import ApplicationSnapshot



#### Retain one fixed facade operation and target after queue admission.
####
@dataclass(frozen=True, slots=True)
class _CommandEnvelope[FacadeT]:
    facade: FacadeT
    command: Callable[[FacadeT], ApplicationSnapshot]
    canceled: Callable[[], None] | None



#### Execute one immutable envelope without publishing exceptions across threads.
####
class _CommandTask[FacadeT](QRunnable):
    _envelope: _CommandEnvelope[FacadeT]
    _failed: Callable[[], None]
    _finished: Callable[[ApplicationSnapshot], None]
    _done: Callable[[object], None]
    _state_guard: Lock
    _started: bool
    _canceled: bool



    #### Initialize one pool-owned task and its safe outcome callbacks.
    ####
    def __init__(
        self,
        envelope: _CommandEnvelope[FacadeT],
        finished: Callable[[ApplicationSnapshot], None],
        failed: Callable[[], None],
        done: Callable[[object], None],
    ) -> None:
        super().__init__()
        self._envelope = envelope
        self._finished = finished
        self._failed = failed
        self._done = done
        self._state_guard = Lock()
        self._started = False
        self._canceled = False



    #### Cancel only a command that has not entered its facade boundary.
    ####
    #### The optional callback releases transferred ownership such as a queued
    #### passphrase.  Cleanup failures remain private and cannot mask shutdown.
    ####
    def cancel_if_pending(self) -> None:
        with self._state_guard:
            if self._started or self._canceled:
                return
            self._canceled = True
        try:
            canceled = self._envelope.canceled
            if canceled is not None:
                canceled()
        except BaseException:
            pass
        finally:
            self._done(self)



    #### Run on the sole worker and convert every escaped failure to a closed signal.
    ####
    @Slot()
    def run(self) -> None:
        with self._state_guard:
            if self._canceled:
                return
            self._started = True
        try:
            result = self._envelope.command(self._envelope.facade)
        except BaseException:
            self._failed()
        else:
            self._finished(result)
        finally:
            self._done(self)



#### Queue facade commands on exactly one worker and drain active work at shutdown.
####
class FacadeExecutor[FacadeT](QObject):
    resultReady: ClassVar[Signal] = Signal(object)  # noqa: N815 - Qt metaobject API.
    commandFailed: ClassVar[Signal] = Signal()  # noqa: N815 - Qt metaobject API.
    _facade: FacadeT
    _guard: Lock
    _pool: QThreadPool
    _shutdown: bool
    _tasks: set[object]



    #### Initialize a private one-thread pool for one facade instance.
    ####
    def __init__(self, facade: FacadeT) -> None:
        super().__init__()
        self._facade = facade
        self._guard = Lock()
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(1)
        self._shutdown = False
        self._tasks = set()



    #### Admit one immutable command envelope unless shutdown has begun.
    ####
    def submit(
        self,
        command: Callable[[FacadeT], ApplicationSnapshot],
        *,
        canceled: Callable[[], None] | None = None,
    ) -> bool:
        envelope = _CommandEnvelope(self._facade, command, canceled)
        task = _CommandTask(envelope, self.resultReady.emit, self.commandFailed.emit, self._task_done)
        with self._guard:
            if self._shutdown:
                return False
            self._tasks.add(task)
            self._pool.start(task)
        return True



    #### Release the executor's ownership of one completed or canceled task.
    ####
    def _task_done(self, task: object) -> None:
        with self._guard:
            self._tasks.discard(task)



    #### Reject new commands, discard queued work, and wait for the active boundary.
    ####
    #### Waiting is intentionally unbounded because process exit must not cut off
    #### an active save or encrypted suspension after it has begun publication.
    ####
    def shutdown(self) -> None:
        with self._guard:
            if self._shutdown:
                return
            self._shutdown = True
            tasks = tuple(self._tasks)
            self._pool.clear()
        for task in tasks:
            cast(_CommandTask[FacadeT], task).cancel_if_pending()
        self._pool.waitForDone(-1)



#### Carry one synchronous GUI invocation result without retaining it afterward.
####
@dataclass(slots=True)
class _Invocation[ResultT]:
    operation: Callable[[], ResultT]
    result: ResultT | None = None
    error: BaseException | None = None



#### Marshal minimal platform work synchronously to the owning Qt GUI thread.
####
class GuiThreadInvoker(QObject):
    _requested: ClassVar[Signal] = Signal(object)



    #### Initialize the bridge on the GUI thread and use blocking queued delivery.
    ####
    def __init__(self) -> None:
        super().__init__()
        self._requested.connect(self._invoke, Qt.ConnectionType.BlockingQueuedConnection)



    #### Execute an operation directly on GUI or block a worker until GUI completion.
    ####
    def call[ResultT](self, operation: Callable[[], ResultT]) -> ResultT:
        invocation = _Invocation(operation)
        if QThread.currentThread() == self.thread():
            self._invoke(invocation)
        else:
            self._requested.emit(invocation)
        if invocation.error is not None:
            raise invocation.error
        return cast(ResultT, invocation.result)



    #### Run one invocation on the bridge's GUI affinity and retain only its outcome.
    ####
    @Slot(object)
    def _invoke(self, value: object) -> None:
        invocation = cast(_Invocation[object], value)
        try:
            invocation.result = invocation.operation()
        except BaseException as error:
            invocation.error = error
