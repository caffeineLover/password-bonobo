"""Verify that session secrets require explicit bounded leases and edits."""

from pathlib import Path

from bonobo_core.passwordsafe.constants import RecordFieldType
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.session import SetSecretField, VaultSession
from tests.passwordsafe.test_writer import _opened_source, _XorBackend



#### Reveal a password only through a separately owned, explicitly closed lease.
####
def test_password_requires_explicit_lease(tmp_path: Path) -> None:
    _reader, opened, _source = _opened_source(tmp_path, _XorBackend())
    session = VaultSession(opened)
    view = session.records()[0]

    assert "fabricated-credential" not in repr(view)
    assert not hasattr(view, "password")
    with session.reveal(view.handle, RecordFieldType.PASSWORD) as lease:
        assert bytes(lease.borrow()) == b"fabricated-credential"
    assert lease.closed
    session.lock()



#### Replace a password from mutable storage and consume the edit's owner.
####
def test_secret_edit_consumes_source_and_never_enters_view(tmp_path: Path) -> None:
    _reader, opened, _source = _opened_source(tmp_path, _XorBackend())
    session = VaultSession(opened)
    view = session.records()[0]
    password_storage = bytearray(b"fabricated-replacement")
    password = SecretBuffer.take_ownership(password_storage)

    changed = session.apply(
        view.handle,
        view.revision,
        (SetSecretField(RecordFieldType.PASSWORD, password),),
    )

    assert password.closed
    assert password_storage == bytearray(len(password_storage))
    assert "fabricated-replacement" not in repr(changed)
    with session.reveal(changed.handle, RecordFieldType.PASSWORD) as lease:
        assert bytes(lease.borrow()) == b"fabricated-replacement"
    session.discard_and_lock()



#### Refuse ordinary public-field reveal through the secret access boundary.
####
def test_reveal_rejects_nonsecret_fields(tmp_path: Path) -> None:
    _reader, opened, _source = _opened_source(tmp_path, _XorBackend())
    session = VaultSession(opened)
    view = session.records()[0]

    try:
        session.reveal(view.handle, RecordFieldType.TITLE)
    except ValueError as error:
        assert str(error) == "field is not secret"
    else:
        raise AssertionError("public field reveal should fail")
    session.lock()
