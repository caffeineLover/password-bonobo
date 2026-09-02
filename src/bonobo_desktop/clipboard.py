"""Implement nonce-owned, finite-lifetime Qt clipboard writes.

Leased bytes are copied and wiped only inside a synchronous GUI-thread
operation.  Clipboard clearing compares a fresh random MIME nonce so content
installed later by another owner is never erased.
"""

from secrets import token_bytes
from typing import Final

from PySide6.QtCore import QByteArray, QMimeData, QObject, QTimer
from PySide6.QtGui import QClipboard

from bonobo_core.passwordsafe import SecretLease

from .tasks import GuiThreadInvoker



BONOBO_CLIPBOARD_MIME: Final[str] = "application/x-password-bonobo-clipboard-nonce"
_NONCE_BYTES: Final[int] = 32



#### Own Bonobo clipboard content until replacement, explicit clear, or timer expiry.
####
class QtClipboardPort(QObject):
    _clipboard: QClipboard
    _invoker: GuiThreadInvoker
    _nonce: bytes | None
    _timer: QTimer



    #### Initialize GUI-affine clipboard ownership and its reusable expiry timer.
    ####
    def __init__(self, clipboard: QClipboard) -> None:
        super().__init__()
        self._clipboard = clipboard
        self._invoker = GuiThreadInvoker()
        self._nonce = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear_owned)



    #### Synchronously write a leased UTF-8 value and fresh nonce on the GUI thread.
    ####
    def copy(self, value: SecretLease, *, lifetime_seconds: int) -> None:
        if isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int) or lifetime_seconds <= 0:
            raise ValueError("clipboard lifetime must be a positive integer")



        #### Perform the complete leased copy and nonce publication on the GUI thread.
        ####
        def write() -> None:
            temporary = bytearray(value.borrow())
            try:
                nonce = token_bytes(_NONCE_BYTES)
                mime_data = QMimeData()
                mime_data.setData("text/plain;charset=utf-8", QByteArray(temporary))
                mime_data.setData(BONOBO_CLIPBOARD_MIME, QByteArray(nonce))
                self._clipboard.setMimeData(mime_data)
                self._nonce = nonce
                self._timer.start(lifetime_seconds * 1000)
            finally:
                temporary[:] = b"\x00" * len(temporary)

        self._invoker.call(write)



    #### Synchronously clear the clipboard only while the current nonce is owned.
    ####
    def clear_owned(self) -> None:
        self._invoker.call(self._clear_owned_on_gui)



    #### Compare and clear the current GUI clipboard without crossing thread affinity.
    ####
    def _clear_owned_on_gui(self) -> None:
        nonce = self._nonce
        self._timer.stop()
        self._nonce = None
        if nonce is None:
            return
        current = self._clipboard.mimeData().data(BONOBO_CLIPBOARD_MIME).data()
        if current == nonce:
            self._clipboard.clear()
