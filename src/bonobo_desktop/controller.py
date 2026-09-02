"""Translate Qt user intent into serialized application-facade commands.

The QObject publishes only primitive non-secret snapshot state plus the closed
record model.  Paths, decision identities, secret owners, and exceptions stay
inside command closures and never become Qt properties or signal arguments.
"""

from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from PySide6.QtCore import Property, QObject, Signal, Slot

from bonobo_core.application import ApplicationSnapshot, CloseChoice, RecordKey, VaultApplication
from bonobo_core.passwordsafe import SecretBuffer, VaultSession

from .models import RecordListModel
from .tasks import FacadeExecutor



#### Project snapshots and submit immutable command closures for one desktop facade.
####
class DesktopController(QObject):
    snapshotChanged: ClassVar[Signal] = Signal()  # noqa: N815 - Qt metaobject API.
    passphraseChanged: ClassVar[Signal] = Signal()  # noqa: N815 - Qt metaobject API.
    commandRejected: ClassVar[Signal] = Signal()  # noqa: N815 - Qt metaobject API.
    _application: VaultApplication[VaultSession]
    _executor: FacadeExecutor[VaultApplication[VaultSession]]
    _passphrase: bytearray
    _records: RecordListModel
    _snapshot: ApplicationSnapshot



    #### Initialize primitive state from the facade's last committed safe snapshot.
    ####
    def __init__(
        self,
        application: VaultApplication[VaultSession],
        executor: FacadeExecutor[VaultApplication[VaultSession]],
    ) -> None:
        super().__init__()
        self._application = application
        self._executor = executor
        self._records = RecordListModel()
        self._passphrase = bytearray()
        self._snapshot = application.snapshot
        self._records.replace(self._snapshot.records)
        self._executor.resultReady.connect(self._accept_result)
        self._executor.commandFailed.connect(self.commandRejected.emit)



    #### Return the closed records model without exposing its retained DTO tuple.
    ####
    def _get_records(self) -> QObject:
        return self._records



    #### Return the current closed phase as its primitive stable string value.
    ####
    def _get_phase(self) -> str:
        return self._snapshot.phase.value



    #### Return the caller-supplied safe display label for the current vault.
    ####
    def _get_display_label(self) -> str:
        return self._snapshot.display_label



    #### Return whether accepted edits remain unpublished in the active session.
    ####
    def _get_dirty(self) -> bool:
        return self._snapshot.dirty



    #### Return the selected primitive key or zero when no safe record is selected.
    ####
    def _get_selected_key(self) -> int:
        selected = self._snapshot.selected
        return 0 if selected is None else selected.value



    #### Return only the closed localization key for the current safe failure.
    ####
    def _get_failure_key(self) -> str:
        failure = self._snapshot.failure
        return "" if failure is None else failure.presentation_key



    #### Return whether a private facade decision token is awaiting user intent.
    ####
    def _get_decision_required(self) -> bool:
        return self._snapshot.decision is not None



    #### Never return retained passphrase material through the Qt property getter.
    ####
    def _get_passphrase(self) -> str:
        return ""



    #### Replace transient input with one mutable UTF-8 copy and wipe the prior copy.
    ####
    def _set_passphrase(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("passphrase input must be text")
        self._wipe_passphrase()
        self._passphrase = bytearray(value, "utf-8")



    #### Report only whether transient input is present, never its contents or size.
    ####
    def _get_passphrase_present(self) -> bool:
        return bool(self._passphrase)



    records = Property(QObject, _get_records, constant=True)
    phase = Property(str, _get_phase, notify=snapshotChanged)
    displayLabel = Property(str, _get_display_label, notify=snapshotChanged)  # noqa: N815 - Qt property API.
    dirty = Property(bool, _get_dirty, notify=snapshotChanged)
    selectedKey = Property(int, _get_selected_key, notify=snapshotChanged)  # noqa: N815 - Qt property API.
    failureKey = Property(str, _get_failure_key, notify=snapshotChanged)  # noqa: N815 - Qt property API.
    decisionRequired = Property(bool, _get_decision_required, notify=snapshotChanged)  # noqa: N815 - Qt property API.
    passphrase = Property(str, _get_passphrase, _set_passphrase, notify=passphraseChanged)
    passphrasePresent = Property(  # noqa: N815 - Qt property API.
        bool,
        _get_passphrase_present,
        notify=passphraseChanged,
    )



    #### Consume and clear passphrase input before handing its owner to a worker.
    ####
    def _take_passphrase(self) -> SecretBuffer:
        data = self._passphrase
        self._passphrase = bytearray()
        self.passphraseChanged.emit()
        return SecretBuffer.take_ownership(data)



    #### Wipe any currently retained passphrase input without creating a secret owner.
    ####
    def _wipe_passphrase(self) -> None:
        self._passphrase[:] = b"\x00" * len(self._passphrase)
        self._passphrase = bytearray()



    #### Open one private path with transient input while publishing only its label.
    ####
    @Slot(str, str, result=bool, name="openVault")
    def open_vault(self, path: str, display_label: str) -> bool:
        source = Path(path)
        passphrase = self._take_passphrase()
        accepted = self._executor.submit(
            lambda application: application.open(source, passphrase, display_label),
            canceled=passphrase.close,
        )
        if not accepted:
            passphrase.close()
            self.commandRejected.emit()
        return accepted



    #### Create one private path with transient input while publishing only its label.
    ####
    @Slot(str, str, result=bool, name="createVault")
    def create_vault(self, path: str, display_label: str) -> bool:
        destination = Path(path)
        passphrase = self._take_passphrase()
        accepted = self._executor.submit(
            lambda application: application.create(destination, passphrase, display_label),
            canceled=passphrase.close,
        )
        if not accepted:
            passphrase.close()
            self.commandRejected.emit()
        return accepted



    #### Reauthenticate the private suspended source with cleared transient input.
    ####
    @Slot(result=bool, name="unlockVault")
    def unlock_vault(self) -> bool:
        passphrase = self._take_passphrase()
        accepted = self._executor.submit(
            lambda application: application.unlock(passphrase),
            canceled=passphrase.close,
        )
        if not accepted:
            passphrase.close()
            self.commandRejected.emit()
        return accepted



    #### Submit a safe search against the controller's current presentation generation.
    ####
    @Slot(str, result=bool, name="setSearch")
    def set_search(self, query: str) -> bool:
        generation = self._snapshot.generation
        return self._submit(lambda application: application.set_search(query, generation))



    #### Publish the active dirty session through the facade's revision-safe save.
    ####
    @Slot(result=bool)
    def save(self) -> bool:
        generation = self._snapshot.generation
        return self._submit(lambda application: application.save(generation))



    #### Request clean lock or authenticated encrypted suspension for dirty state.
    ####
    @Slot(result=bool)
    def lock(self) -> bool:
        generation = self._snapshot.generation
        return self._submit(lambda application: application.lock(generation))



    #### Request the facade's save/discard/cancel close-decision transition.
    ####
    @Slot(result=bool, name="requestClose")
    def request_close(self) -> bool:
        generation = self._snapshot.generation
        return self._submit(lambda application: application.request_close(generation))



    #### Resolve the current private decision token from one closed primitive choice.
    ####
    @Slot(str, result=bool, name="resolveClose")
    def resolve_close(self, choice: str) -> bool:
        try:
            selected_choice = CloseChoice(choice)
        except ValueError:
            self.commandRejected.emit()
            return False
        decision = self._snapshot.decision
        return self._submit(lambda application: application.resolve_close(decision, selected_choice))



    #### Copy one username after converting the primitive Qt key inside the closure.
    ####
    @Slot(int, result=bool, name="copyUsername")
    def copy_username(self, key: int) -> bool:
        generation = self._snapshot.generation
        record_key = RecordKey(key)
        return self._submit(lambda application: application.copy_username(record_key, generation))



    #### Copy one password after converting the primitive Qt key inside the closure.
    ####
    @Slot(int, result=bool, name="copyPassword")
    def copy_password(self, key: int) -> bool:
        generation = self._snapshot.generation
        record_key = RecordKey(key)
        return self._submit(lambda application: application.copy_password(record_key, generation))



    #### Open one stored website after converting the primitive Qt key inside the closure.
    ####
    @Slot(int, result=bool, name="openWebsite")
    def open_website(self, key: int) -> bool:
        generation = self._snapshot.generation
        record_key = RecordKey(key)
        return self._submit(lambda application: application.open_website(record_key, generation))



    #### Submit one fixed command and expose rejection only as a closed empty signal.
    ####
    def _submit(
        self,
        command: Callable[[VaultApplication[VaultSession]], ApplicationSnapshot],
    ) -> bool:
        accepted = self._executor.submit(command)
        if not accepted:
            self.commandRejected.emit()
        return accepted



    #### Accept one worker result on the GUI thread and emit exactly one state signal.
    ####
    @Slot(object)
    def _accept_result(self, value: object) -> None:
        if not isinstance(value, ApplicationSnapshot):
            self.commandRejected.emit()
            return
        self._snapshot = value
        self._records.replace(value.records)
        self.snapshotChanged.emit()
