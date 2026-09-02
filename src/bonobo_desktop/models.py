"""Adapt immutable application record summaries to one reset-only Qt list model.

The model exposes only primitive values from the closed application DTO.  It
never receives paths, URLs, UUIDs, revisions, secrets, or domain handles.
"""

from enum import IntEnum
from typing import cast, override

from PySide6.QtCore import QAbstractListModel, QByteArray, QModelIndex, QPersistentModelIndex, Qt

from bonobo_core.application import RecordSummary



#### Assign stable Qt role numbers to the complete approved record projection.
####
class _RecordRole(IntEnum):
    KEY = int(Qt.ItemDataRole.UserRole) + 1
    TITLE = KEY + 1
    GROUP = TITLE + 1
    USERNAME = GROUP + 1
    PROTECTED = USERNAME + 1



_ROLE_NAMES: dict[int, bytes] = {
    _RecordRole.KEY: b"key",
    _RecordRole.TITLE: b"title",
    _RecordRole.GROUP: b"group",
    _RecordRole.USERNAME: b"username",
    _RecordRole.PROTECTED: b"protected",
}
_ROOT_INDEX = QModelIndex()



#### Present one immutable record-snapshot tuple through reset-only Qt model updates.
####
class RecordListModel(QAbstractListModel):
    _records: tuple[RecordSummary, ...]



    #### Initialize an empty presentation model owned by the GUI thread.
    ####
    def __init__(self) -> None:
        super().__init__()
        self._records = ()



    #### Return the number of current safe summaries for a root-model query.
    ####
    @override
    def rowCount(
        self,
        parent: QModelIndex | QPersistentModelIndex = _ROOT_INDEX,
    ) -> int:
        return 0 if parent.isValid() else len(self._records)



    #### Return one primitive role value without exposing the retained DTO itself.
    ####
    @override
    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = int(Qt.ItemDataRole.DisplayRole),
    ) -> object | None:
        if not index.isValid() or index.row() < 0 or index.row() >= len(self._records):
            return None
        record = self._records[index.row()]
        if role == _RecordRole.KEY:
            return record.key.value
        if role == _RecordRole.TITLE:
            return record.title
        if role == _RecordRole.GROUP:
            return record.group
        if role == _RecordRole.USERNAME:
            return record.username
        if role == _RecordRole.PROTECTED:
            return record.protected
        return None



    #### Return a fresh closed role map so consumers cannot extend model state.
    ####
    @override
    def roleNames(self) -> dict[int, QByteArray]:
        # PySide accepts bytes at runtime and QML requires the brief's exact
        # bytes-valued role map, while the generated stub declares QByteArray.
        return cast(dict[int, QByteArray], dict(_ROLE_NAMES))



    #### Atomically replace the complete immutable snapshot through one model reset.
    ####
    def replace(self, records: tuple[RecordSummary, ...]) -> None:
        if not isinstance(records, tuple) or not all(isinstance(record, RecordSummary) for record in records):
            raise TypeError("record model replacement is invalid")
        self.beginResetModel()
        self._records = records
        self.endResetModel()
