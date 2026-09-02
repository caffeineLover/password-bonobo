"""Verify Qt list projections expose only the closed record-summary contract."""

from typing import cast

from PySide6.QtCore import QModelIndex, Qt
from pytestqt.qtbot import QtBot

from bonobo_core.application import RecordKey, RecordSummary
from bonobo_desktop.models import RecordListModel



#### Expose exactly the five approved primitive record roles and no secret-bearing fields.
####
def test_record_model_roles_are_closed_and_non_secret(qtbot: QtBot) -> None:
    model = RecordListModel()
    model.replace((RecordSummary(RecordKey(1), "Alpha", "Research", "sample-user", False),))

    assert set(model.roleNames().values()) == {b"key", b"title", b"group", b"username", b"protected"}
    assert model.rowCount() == 1
    roles = {name: role for role, name in cast(dict[int, bytes], model.roleNames()).items()}
    assert {name: model.data(model.index(0, 0), role) for name, role in roles.items()} == {
        b"key": 1,
        b"title": "Alpha",
        b"group": "Research",
        b"username": "sample-user",
        b"protected": False,
    }



#### Replace the complete immutable snapshot through one model reset rather than row-level mutation.
####
def test_record_model_replace_emits_one_reset(qtbot: QtBot) -> None:
    model = RecordListModel()
    replacement = (
        RecordSummary(RecordKey(1), "Alpha", "Research", "sample-user", False),
        RecordSummary(RecordKey(2), "Beta", "", "other-user", True),
    )

    with qtbot.waitSignal(model.modelReset, timeout=1000):
        model.replace(replacement)

    assert model.rowCount() == 2
    assert model.data(model.index(1, 0), Qt.ItemDataRole.UserRole + 1) == 2
    assert model.data(QModelIndex(), Qt.ItemDataRole.UserRole + 2) is None
