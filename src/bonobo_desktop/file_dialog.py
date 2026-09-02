"""Select vault locators through one private GUI-thread native Qt adapter.

QML emits only create or open intent.  This module alone converts a native
dialog result to a filesystem locator, and its Python result hides that locator
from representations while carrying only a caller-supplied safe display label.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QFileDialog

from .tasks import GuiThreadInvoker



_VAULT_FILTER = "PasswordSafe vaults (*.psafe3)"



#### Own one native selection without publishing its filesystem locator in diagnostics.
####
@dataclass(frozen=True, slots=True, repr=False)
class VaultFileSelection:
    locator: Path
    display_label: str



#### Describe the private native-selection surface consumed by the controller.
####
class VaultFileDialog(Protocol):



    #### Return a private existing-vault selection or a canceled result.
    ####
    def select_open(self, display_label: str) -> VaultFileSelection | None:
        raise NotImplementedError



    #### Return a private new-vault destination or a canceled result.
    ####
    def select_create(self, display_label: str) -> VaultFileSelection | None:
        raise NotImplementedError



#### Adapt native create and open dialogs to private Python selection owners.
####
class QtVaultFileDialog:
    _invoker: GuiThreadInvoker



    #### Initialize a synchronous bridge on the constructing GUI thread.
    ####
    def __init__(self) -> None:
        self._invoker = GuiThreadInvoker()



    #### Select an existing PasswordSafe file without exposing its locator to QML.
    ####
    def select_open(self, display_label: str) -> VaultFileSelection | None:



        #### Run the native open dialog on the Qt GUI thread.
        ####
        def choose() -> tuple[str, str]:
            title = QCoreApplication.translate("QtVaultFileDialog", "Open PasswordSafe vault")
            return QFileDialog.getOpenFileName(None, title, "", _VAULT_FILTER)

        return self._selection(self._invoker.call(choose), display_label)



    #### Select a PasswordSafe destination without exposing its locator to QML.
    ####
    def select_create(self, display_label: str) -> VaultFileSelection | None:



        #### Run the native save dialog on the Qt GUI thread.
        ####
        def choose() -> tuple[str, str]:
            title = QCoreApplication.translate("QtVaultFileDialog", "Create PasswordSafe vault")
            return QFileDialog.getSaveFileName(None, title, "", _VAULT_FILTER)

        return self._selection(self._invoker.call(choose), display_label)



    #### Convert one native tuple to a path-private owner or a canceled result.
    ####
    def _selection(self, value: tuple[str, str], display_label: str) -> VaultFileSelection | None:
        if not isinstance(display_label, str):
            raise TypeError("vault display label must be text")
        locator, _selected_filter = value
        if not locator:
            return None
        safe_label = display_label.strip() or QCoreApplication.translate("QtVaultFileDialog", "Vault")
        return VaultFileSelection(Path(locator), safe_label)
