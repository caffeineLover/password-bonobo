"""Verify revision-safe PasswordSafe session views and ordinary mutations."""

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest

from bonobo_core.passwordsafe.constants import RecordFieldType
from bonobo_core.passwordsafe.errors import StaleRevisionError, UnsavedChangesError
from bonobo_core.passwordsafe.model import VaultDocument, documents_equal_exact
from bonobo_core.passwordsafe.reader import PasswordSafeReader
from bonobo_core.passwordsafe.schema import decode_record_field
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.session import NewRecord, SetTextField, VaultSession
from bonobo_core.passwordsafe.storage import LocalVaultStore
from bonobo_core.passwordsafe.writer import PasswordSafeWriter
from tests.passwordsafe.helpers import DeterministicRandomSource
from tests.passwordsafe.test_writer import _opened_source, _private_directory, _XorBackend



#### Open one authenticated source through the session ownership boundary.
####
def _session(tmp_path: Path) -> VaultSession:
    _reader, opened, _source = _opened_source(tmp_path, _XorBackend())
    return VaultSession(opened)



#### Authenticate a staged save against the exact frozen session revision.
####
@dataclass(slots=True)
class _SaveValidator:
    reader: PasswordSafeReader
    session: VaultSession
    document: VaultDocument



    #### Reopen and compare the staged ciphertext before publication.
    ####
    def __call__(self, path: Path) -> None:
        reopened = self.reader.reopen_candidate(path, self.session._crypto_state_for_service)
        try:
            if not documents_equal_exact(reopened.document, self.document):
                raise ValueError("candidate document does not match")
        finally:
            reopened.close()



#### Reject accidental use of the store's default validator in this focused test.
####
def _unexpected_validator(_path: Path) -> None:
    raise AssertionError("operation-specific validator was not selected")



#### Reject a second patch based on the revision that preceded the first patch.
####
def test_stale_patch_is_rejected(tmp_path: Path) -> None:
    session = _session(tmp_path)
    view = session.records()[0]

    changed = session.apply(
        view.handle,
        view.revision,
        (SetTextField(RecordFieldType.TITLE, "First"),),
    )

    assert changed.title == "First"
    assert changed.revision is session.revision
    with pytest.raises(StaleRevisionError):
        session.apply(
            view.handle,
            view.revision,
            (SetTextField(RecordFieldType.TITLE, "Second"),),
        )
    session.discard_and_lock()



#### Add mandatory fields in canonical order and consume the supplied password.
####
def test_add_consumes_password_and_advances_one_revision(tmp_path: Path) -> None:
    session = _session(tmp_path)
    revision = session.revision
    password_storage = bytearray(b"fabricated-new-password")
    password = SecretBuffer.take_ownership(password_storage)
    new_record = NewRecord(
        UUID("33333333-3333-4333-8333-333333333333"),
        "New Portal",
        password,
        username="bonobo",
    )

    added = session.add(new_record, revision)

    assert added.title == "New Portal"
    assert added.username == "bonobo"
    assert added.revision is session.revision
    assert added.revision is not revision
    assert password.closed
    assert password_storage == bytearray(len(password_storage))
    assert session.dirty
    session.discard_and_lock()



#### Preserve handles while moving a record and remove only the selected record.
####
def test_move_and_delete_each_create_one_revision(tmp_path: Path) -> None:
    session = _session(tmp_path)
    first = session.records()[0]
    password = SecretBuffer.from_bytes(b"fabricated-second-password")
    second = session.add(
        NewRecord(UUID("44444444-4444-4444-8444-444444444444"), "Second", password),
        first.revision,
    )

    moved = session.move(second.handle, second.revision, 0)
    after_move = session.revision
    session.delete(first.handle, after_move)

    assert moved.handle is second.handle
    assert moved.revision is after_move
    assert tuple(view.handle for view in session.records()) == (second.handle,)
    assert session.revision is not after_move
    session.discard_and_lock()



#### Freeze mutations during save and clear dirty state only after success.
####
def test_save_snapshot_freezes_mutation_until_finished(tmp_path: Path) -> None:
    session = _session(tmp_path)
    initial = session.records()[0]
    changed = session.apply(
        initial.handle,
        initial.revision,
        (SetTextField(RecordFieldType.TITLE, "Saved title"),),
    )

    snapshot = session._prepare_save()

    assert snapshot.revision is changed.revision
    with pytest.raises(RuntimeError, match="save is in progress"):
        session.delete(changed.handle, changed.revision)
    with pytest.raises(TypeError):
        session._finish_save()  # type: ignore[call-arg]
    assert session.dirty
    session._abort_save()
    session.discard_and_lock()
    assert session.locked



#### Keep a failed save dirty and reject ordinary locking of unsaved changes.
####
def test_abort_save_remains_dirty_and_lock_requires_discard(tmp_path: Path) -> None:
    session = _session(tmp_path)
    view = session.records()[0]
    session.apply(
        view.handle,
        view.revision,
        (SetTextField(RecordFieldType.TITLE, "Unsaved"),),
    )
    session._prepare_save()
    session._abort_save()

    with pytest.raises(UnsavedChangesError):
        session.lock()
    session.discard_and_lock()
    assert session.locked



#### Serialize and authenticate a changed frozen revision without touching secrets.
####
def test_changed_save_snapshot_reopens_successfully(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    session = VaultSession(opened)
    view = session.records()[0]
    changed = session.apply(
        view.handle,
        view.revision,
        (SetTextField(RecordFieldType.TITLE, "Reopened title"),),
    )
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "session-candidates"),
        random_source=DeterministicRandomSource(bytes(index % 197 for index in range(8192))),
    )

    snapshot = session._prepare_save()
    candidate = writer.write(snapshot, session._crypto_state_for_service)
    reopened = reader.reopen_candidate(candidate.path, session._crypto_state_for_service)

    assert reopened.document.revision is not changed.revision
    title = decode_record_field(reopened.document.records[0].fields[1], record_ordinal=0)
    assert title.value == "Reopened title"
    title.close()
    reopened.close()
    session._abort_save()
    session.discard_and_lock()



#### Adopt the authenticated published file as the next save baseline.
####
def test_finish_save_advances_published_baseline(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    working = _private_directory(tmp_path, "baseline-working")
    recovery = _private_directory(tmp_path, "baseline-recovery")
    store = LocalVaultStore(working, recovery, validator=_unexpected_validator)
    session = VaultSession(opened, source, store.capture(source))
    view = session.records()[0]
    session.apply(
        view.handle,
        view.revision,
        (SetTextField(RecordFieldType.TITLE, "Published title"),),
    )
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "baseline-candidates"),
        random_source=DeterministicRandomSource(bytes(index % 191 for index in range(8192))),
    )

    snapshot = session._prepare_save()
    validator = _SaveValidator(reader, session, snapshot)
    candidate = writer.write(snapshot, session._crypto_state_for_service)
    published = store.publish(source, candidate, session.baseline, validator=validator)
    reopened = reader.reopen_candidate(source, session._crypto_state_for_service)
    session._finish_save(reopened, published)

    assert session.path == source
    assert session.baseline == published.baseline
    assert session.source_snapshot.sha256 == published.sha256
    assert not session.dirty
    session.lock()
