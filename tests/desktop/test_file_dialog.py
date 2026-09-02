"""Verify native vault-file selection stays inside a GUI-thread Python adapter."""

from __future__ import annotations

from pathlib import Path
from threading import Event, Thread
from typing import cast

import pytest
from PySide6.QtCore import QThread
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFileDialog
from pytestqt.qtbot import QtBot

from bonobo_desktop.file_dialog import QtVaultFileDialog, VaultFileSelection



#### Select one private open locator on the Qt GUI thread from a worker caller.
####
#### The returned Python owner may expose only the caller-supplied display label
#### in diagnostics; its locator remains private even if a failure prints it.
####
def test_native_open_dialog_is_gui_thread_bound_and_path_private(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called_threads: list[QThread] = []
    private_locator = Path("fabricated-private") / "selected.psafe3"



    #### Record the native dialog thread and return one fabricated selection.
    ####
    def select_file(*_arguments: object, **_keywords: object) -> tuple[str, str]:
        called_threads.append(QThread.currentThread())
        return str(private_locator), "PasswordSafe vaults (*.psafe3)"

    monkeypatch.setattr(QFileDialog, "getOpenFileName", select_file)
    dialog = QtVaultFileDialog()
    completed = Event()
    selections: list[VaultFileSelection | None] = []



    #### Request native selection outside the GUI thread and retain its private result.
    ####
    def choose_from_worker() -> None:
        selections.append(dialog.select_open("Fabricated"))
        completed.set()

    worker = Thread(target=choose_from_worker)
    worker.start()
    qtbot.waitUntil(completed.is_set, timeout=5000)
    worker.join()
    application = QGuiApplication.instance()
    assert application is not None

    assert called_threads == [application.thread()]
    assert len(selections) == 1
    selection = cast(VaultFileSelection, selections[0])
    assert selection.locator == private_locator
    assert selection.display_label == "Fabricated"
    assert str(private_locator) not in repr(selection)



#### Treat native dialog cancellation as an empty private selection.
####
def test_native_create_dialog_cancellation_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_args, **_kwargs: ("", ""))

    assert QtVaultFileDialog().select_create("Fabricated") is None
