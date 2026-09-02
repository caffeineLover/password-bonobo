"""Verify leased Qt clipboard and browser operations remain GUI-thread bounded."""

from __future__ import annotations

from threading import Event, Thread

import pytest
from PySide6.QtCore import QByteArray, QMimeData, QThread, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from pytestqt.qtbot import QtBot

from bonobo_core.passwordsafe import SecretLease
from bonobo_desktop.browser import QtBrowserPort
from bonobo_desktop.clipboard import BONOBO_CLIPBOARD_MIME, QtClipboardPort



#### Marshal a leased clipboard write to the GUI thread before the worker closes its lease.
####
def test_clipboard_copy_from_worker_returns_after_gui_write(qtbot: QtBot) -> None:
    clipboard = QGuiApplication.clipboard()
    clipboard.clear()
    port = QtClipboardPort(clipboard)
    completed = Event()
    lease_closed_after_copy: list[bool] = []



    #### Copy and close one fabricated lease from a non-GUI worker.
    ####
    def copy_from_worker() -> None:
        with SecretLease.from_bytes(b"fabricated-password") as lease:
            port.copy(lease, lifetime_seconds=30)
            lease_closed_after_copy.append(lease.closed)
        completed.set()

    worker = Thread(target=copy_from_worker)
    worker.start()
    qtbot.waitUntil(completed.is_set, timeout=5000)
    worker.join()

    assert lease_closed_after_copy == [False]
    assert clipboard.text() == "fabricated-password"
    assert clipboard.mimeData().hasFormat(BONOBO_CLIPBOARD_MIME)
    port.clear_owned()



#### Preserve a newer clipboard value when Bonobo's ownership nonce is no longer current.
####
def test_clipboard_clear_owned_preserves_replacement(qtbot: QtBot) -> None:
    clipboard = QGuiApplication.clipboard()
    port = QtClipboardPort(clipboard)
    with SecretLease.from_bytes(b"fabricated-password") as lease:
        port.copy(lease, lifetime_seconds=30)
    replacement = QMimeData()
    replacement.setData("text/plain;charset=utf-8", QByteArray(b"replacement"))
    clipboard.setMimeData(replacement)

    port.clear_owned()

    assert clipboard.text() == "replacement"
    assert not clipboard.mimeData().hasFormat(BONOBO_CLIPBOARD_MIME)



#### Clear the still-owned clipboard value when its finite timer expires.
####
def test_clipboard_expiry_clears_only_the_owned_value(qtbot: QtBot) -> None:
    clipboard = QGuiApplication.clipboard()
    port = QtClipboardPort(clipboard)
    with SecretLease.from_bytes(b"fabricated-password") as lease:
        port.copy(lease, lifetime_seconds=1)

    qtbot.waitUntil(lambda: clipboard.text() == "", timeout=2000)

    assert clipboard.text() == ""



#### Build and open a leased URL entirely on the GUI thread before returning to the worker.
####
def test_browser_open_from_worker_is_synchronous_and_gui_thread_bound(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called_threads: list[QThread] = []
    opened_values: list[bytes] = []



    #### Record the platform call's thread and independently encoded test URL.
    ####
    def record_open(url: QUrl) -> bool:
        called_threads.append(QThread.currentThread())
        opened_values.append(bytes(url.toEncoded().data()))
        return True

    monkeypatch.setattr(QDesktopServices, "openUrl", record_open)
    port = QtBrowserPort()
    completed = Event()
    result: list[bool] = []



    #### Open and close one fabricated URL lease from a non-GUI worker.
    ####
    def open_from_worker() -> None:
        with SecretLease.from_bytes(b"https://fabricated.example.invalid/private") as lease:
            result.append(port.open(lease))
        completed.set()

    worker = Thread(target=open_from_worker)
    worker.start()
    qtbot.waitUntil(completed.is_set, timeout=5000)
    worker.join()
    application = QGuiApplication.instance()
    assert application is not None

    assert result == [True]
    assert called_threads == [application.thread()]
    assert opened_values == [b"https://fabricated.example.invalid/private"]
