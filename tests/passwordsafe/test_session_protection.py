"""Verify explicit protected-record transitions and mutation blocking."""

from pathlib import Path

import pytest
from test_writer import _base_fields, _opened_source, _XorBackend

from bonobo_core.passwordsafe.constants import HeaderFieldType, RecordFieldType
from bonobo_core.passwordsafe.errors import ProtectedRecordError
from bonobo_core.passwordsafe.session import SetTextField, VaultSession



#### Open a format revision where the official protected field is representable.
####
def _protectable_session(tmp_path: Path) -> VaultSession:
    fields = tuple(
        (type_code, bytes.fromhex("0803"))
        if type_code == HeaderFieldType.VERSION
        else (type_code, payload)
        for type_code, payload in _base_fields()
    )
    _reader, opened, _source = _opened_source(tmp_path, _XorBackend(), fields=fields)
    return VaultSession(opened)



#### Block edits and deletion until an explicit unprotect creates a new revision.
####
def test_protected_record_requires_separate_unprotect(tmp_path: Path) -> None:
    session = _protectable_session(tmp_path)
    initial = session.records()[0]
    protected = session.protect(initial.handle, initial.revision)

    assert protected.protected
    with pytest.raises(ProtectedRecordError):
        session.apply(
            protected.handle,
            protected.revision,
            (SetTextField(RecordFieldType.TITLE, "Blocked"),),
        )
    with pytest.raises(ProtectedRecordError):
        session.delete(protected.handle, protected.revision)

    unprotected = session.unprotect(protected.handle, protected.revision)
    changed = session.apply(
        unprotected.handle,
        unprotected.revision,
        (SetTextField(RecordFieldType.TITLE, "Allowed"),),
    )
    assert not unprotected.protected
    assert changed.title == "Allowed"
    session.discard_and_lock()



#### Make redundant protection requests explicit no-op validation failures.
####
def test_protection_transition_must_change_state(tmp_path: Path) -> None:
    session = _protectable_session(tmp_path)
    initial = session.records()[0]

    with pytest.raises(ValueError, match="record is not protected"):
        session.unprotect(initial.handle, initial.revision)
    protected = session.protect(initial.handle, initial.revision)
    with pytest.raises(ValueError, match="record is already protected"):
        session.protect(protected.handle, protected.revision)
    session.discard_and_lock()
