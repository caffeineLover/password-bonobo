"""Verify the complete local PasswordSafe service orchestration.

The tests use only fabricated data and the deterministic codec backend already
qualified by lower-layer tests.  They exercise public workflows rather than raw
documents, cryptographic owners, or storage transaction internals.
"""

import hashlib
from pathlib import Path
from uuid import UUID

import pytest
from helpers import DeterministicRandomSource
from test_writer import _PASSPHRASE, _opened_source, _private_directory, _XorBackend

from bonobo_core.passwordsafe.constants import (
    CURRENT_FORMAT_VERSION,
    FILE_TAG,
    MINIMUM_ITERATIONS,
    SALT_BYTES,
    FormatVersion,
    RecordFieldType,
)
from bonobo_core.passwordsafe.errors import (
    AuthenticationError,
    ExternalModificationError,
    IncompatibleExportError,
    PasswordSafeError,
)
from bonobo_core.passwordsafe.model import VaultDocument, documents_equal_exact
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.service import SaveResult, VaultService
from bonobo_core.passwordsafe.session import NewRecord, SetTextField
from bonobo_core.passwordsafe.storage import StorageStage



#### Assemble one deterministic service over caller-owned private directories.
####
def _service(tmp_path: Path) -> VaultService:
    return VaultService(
        _XorBackend(),
        _private_directory(tmp_path, "service-working"),
        _private_directory(tmp_path, "service-recovery"),
        random_source=DeterministicRandomSource(bytes((index + 41) % 251 for index in range(131072))),
    )



#### Transfer one fabricated record with a separately owned password buffer.
####
def _new_record(title: str = "Alpha Portal") -> NewRecord:
    return NewRecord(
        UUID("33333333-3333-4333-8333-333333333333"),
        title,
        SecretBuffer.from_bytes(b"fabricated-credential"),
        username="bonobo",
        url="https://alpha.example.invalid",
    )



#### Read only the public envelope iteration count from one fabricated vault.
####
def _serialized_iterations(path: Path) -> int:
    offset = len(FILE_TAG) + SALT_BYTES
    return int.from_bytes(path.read_bytes()[offset:offset + 4], "little")



#### Create, edit, save, lock, and reopen through only the service boundary.
####
def test_create_edit_save_reopen_consumes_passphrases(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "fabricated.psafe3"
    create_passphrase = SecretBuffer.from_bytes(b"fabricated-master-input")

    session = service.create(path, create_passphrase, database_name="Synthetic")
    assert session.version == CURRENT_FORMAT_VERSION
    assert _serialized_iterations(path) == MINIMUM_ITERATIONS
    record = session.add(_new_record(), session.revision)
    result = service.save(session)
    session.lock()
    open_passphrase = SecretBuffer.from_bytes(b"fabricated-master-input")
    reopened = service.open(path, open_passphrase)

    assert isinstance(result, SaveResult)
    assert result.sha256 == reopened.source_snapshot.sha256
    assert create_passphrase.closed
    assert open_passphrase.closed
    assert reopened.records()[0].handle != record.handle
    assert reopened.records()[0].title == "Alpha Portal"
    reopened.lock()



#### Keep every record handle valid for the lifetime of its unlocked session.
####
def test_save_preserves_handles_for_continued_session_edits(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "continued-session.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-session-master"))
    added = session.add(_new_record(), session.revision)

    service.save(session)
    changed = session.apply(
        added.handle,
        session.revision,
        (SetTextField(RecordFieldType.TITLE, "Post-save title"),),
    )

    assert changed.handle is added.handle
    assert changed.title == "Post-save title"
    session.discard_and_lock()



#### Keep the committed session usable if retiring the old document reports failure.
####
def test_save_installs_published_state_before_old_owner_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    path = tmp_path / "post-publication-cleanup.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-cleanup-master"))
    added = session.add(_new_record(), session.revision)
    retiring = session._document
    production_close = VaultDocument.close



    #### Close the selected owner first, then simulate a late cleanup report.
    ####
    def close_with_reported_failure(document: VaultDocument) -> None:
        production_close(document)
        if document is retiring:
            raise RuntimeError("fabricated retired-document cleanup failure")

    monkeypatch.setattr(VaultDocument, "close", close_with_reported_failure)

    result = service.save(session)

    assert result.sha256 == session.baseline.sha256
    assert not session.dirty
    assert session.records()[0].handle is added.handle
    session.lock()



#### Keep terminal cleanup retryable while a retired plaintext owner remains live.
####
def test_lock_retries_a_still_live_retired_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    path = tmp_path / "retry-retired-owner.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-retry-master"))
    session.add(_new_record(), session.revision)
    retiring = session._document
    production_close = VaultDocument.close
    attempts = [0]



    #### Leave the retiring owner live twice before allowing deterministic cleanup.
    ####
    def close_after_two_failures(document: VaultDocument) -> None:
        if document is retiring:
            attempts[0] += 1
            if attempts[0] <= 2:
                raise RuntimeError("fabricated live retired-owner cleanup failure")
        production_close(document)



    monkeypatch.setattr(VaultDocument, "close", close_after_two_failures)

    service.save(session)

    with pytest.raises(RuntimeError, match="fabricated live retired-owner cleanup failure"):
        session.lock()
    assert session.locked
    assert not retiring.closed

    session.lock()

    assert retiring.closed
    assert attempts == [3]



#### Advance live state even when storage reports a fault after atomic replacement.
####
def test_post_replace_storage_fault_keeps_committed_session_consistent(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "post-replace-fault.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-post-replace-master"))
    added = session.add(_new_record(), session.revision)
    service._store.faults.raise_at(StorageStage.DIRECTORY_SYNC)

    with pytest.raises(PasswordSafeError):
        service.save(session)

    assert not session.dirty
    assert session.baseline.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert session.records()[0].handle is added.handle
    session.lock()



#### Rotate salt and wrapping material without retaining either raw passphrase.
####
def test_change_master_passphrase_rejects_the_previous_input(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "rotated.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-old-master"))
    replacement = SecretBuffer.from_bytes(b"fabricated-new-master")

    result = service.change_master_passphrase(session, replacement)
    session.lock()

    assert result.iterations_hardened is False
    assert replacement.closed
    with pytest.raises(AuthenticationError):
        service.open(path, SecretBuffer.from_bytes(b"fabricated-old-master"))
    reopened = service.open(path, SecretBuffer.from_bytes(b"fabricated-new-master"))
    reopened.lock()



#### Preserve stronger work factors by default and reject explicit weakening.
####
def test_passphrase_rotation_never_downgrades_iterations(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "strong-iterations.psafe3"
    stronger = MINIMUM_ITERATIONS + 1
    session = service.create(
        path,
        SecretBuffer.from_bytes(b"fabricated-strong-old-master"),
        iterations=stronger,
    )

    result = service.change_master_passphrase(
        session,
        SecretBuffer.from_bytes(b"fabricated-strong-new-master"),
    )
    downgrade = SecretBuffer.from_bytes(b"fabricated-downgrade-master")

    assert _serialized_iterations(path) == stronger
    assert result.iterations_hardened is False
    with pytest.raises(ValueError):
        service.change_master_passphrase(session, downgrade, iterations=MINIMUM_ITERATIONS)
    assert downgrade.closed
    session.lock()



#### Export the current revision independently without clearing session dirty state.
####
def test_export_preserves_source_state_and_supports_a_legacy_level(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = tmp_path / "source.psafe3"
    destination = tmp_path / "exported.psafe3"
    session = service.create(source, SecretBuffer.from_bytes(b"fabricated-source-master"))
    session.add(_new_record(), session.revision)
    baseline = session.baseline

    result = service.export(
        session,
        destination,
        SecretBuffer.from_bytes(b"fabricated-export-master"),
        target_version=FormatVersion.from_uint16(0x0302),
    )
    exported = service.open(destination, SecretBuffer.from_bytes(b"fabricated-export-master"))

    assert result.recovery is None
    assert session.dirty
    assert session.baseline == baseline
    assert exported.version == FormatVersion.from_uint16(0x0302)
    assert exported.records()[0].title == "Alpha Portal"
    exported.lock()
    session.discard_and_lock()



#### Restore one explicitly selected encrypted prior revision as a clean session.
####
def test_available_recovery_and_explicit_restore(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "recoverable.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-recovery-master"))
    session.add(_new_record(), session.revision)
    service.save(session)
    session.lock()
    recovery = service.available_recovery(path)[0]

    restored = service.restore(
        path,
        recovery,
        SecretBuffer.from_bytes(b"fabricated-recovery-master"),
    )

    assert restored.records() == ()
    assert restored.source_snapshot.sha256 == recovery.sha256
    restored.lock()



#### Bind recovery discovery and restore authorization to one destination vault.
####
def test_recovery_cannot_cross_vaults_that_share_a_passphrase(tmp_path: Path) -> None:
    service = _service(tmp_path)
    first_path = tmp_path / "first-recovery.psafe3"
    second_path = tmp_path / "second-recovery.psafe3"
    shared = b"fabricated-shared-recovery-master"
    first = service.create(first_path, SecretBuffer.from_bytes(shared))
    second = service.create(second_path, SecretBuffer.from_bytes(shared))
    first.add(_new_record("First vault"), first.revision)
    second.add(_new_record("Second vault"), second.revision)
    service.save(first)
    service.save(second)
    first_recovery = service.available_recovery(first_path)[0]

    with pytest.raises(PasswordSafeError):
        service.restore(second_path, first_recovery, SecretBuffer.from_bytes(shared))

    assert service.available_recovery(first_path) == (first_recovery,)
    assert service.available_recovery(second_path) != (first_recovery,)
    first.lock()
    second.lock()



#### Refuse creation over any preexisting destination without changing its bytes.
####
def test_create_refuses_to_replace_an_existing_destination(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "preexisting.psafe3"
    original = b"fabricated-preexisting-content"
    path.write_bytes(original)
    passphrase = SecretBuffer.from_bytes(b"fabricated-create-master")

    with pytest.raises(PasswordSafeError):
        service.create(path, passphrase)

    assert path.read_bytes() == original
    assert passphrase.closed



#### Remove the encrypted writer candidate even if destination anchoring fails.
####
def test_create_missing_parent_does_not_orphan_a_candidate(tmp_path: Path) -> None:
    service = _service(tmp_path)
    destination = tmp_path / "missing-parent" / "orphan.psafe3"
    working = tmp_path / "service-working"

    with pytest.raises(PasswordSafeError):
        service.create(
            destination,
            SecretBuffer.from_bytes(b"fabricated-missing-parent-master"),
        )

    assert not tuple(working.glob(".bonobo-*.candidate"))



#### Abort the frozen save while retaining dirty work after an external change.
####
def test_external_change_aborts_save_without_discarding_session_work(tmp_path: Path) -> None:
    service = _service(tmp_path)
    path = tmp_path / "externally-changed.psafe3"
    session = service.create(path, SecretBuffer.from_bytes(b"fabricated-external-master"))
    added = session.add(_new_record(), session.revision)
    path.write_bytes(b"fabricated-external-replacement")

    with pytest.raises(ExternalModificationError):
        service.save(session)

    assert session.dirty
    session.delete(added.handle, session.revision)
    session.discard_and_lock()



#### Reject a legacy export before writing when unknown fields are unrepresentable.
####
def test_legacy_export_rejects_unknown_fields_before_destination_creation(tmp_path: Path) -> None:
    _reader, opened, source = _opened_source(tmp_path, _XorBackend())
    opened.close()
    service = _service(tmp_path)
    session = service.open(source, SecretBuffer.from_bytes(_PASSPHRASE))
    destination = tmp_path / "incompatible-export.psafe3"
    export_passphrase = SecretBuffer.from_bytes(b"fabricated-incompatible-export")

    with pytest.raises(IncompatibleExportError):
        service.export(
            session,
            destination,
            export_passphrase,
            target_version=FormatVersion.from_uint16(0x0301),
        )

    assert not destination.exists()
    assert export_passphrase.closed
    session.lock()



#### Preserve every unknown field when export retains the authenticated version.
####
def test_same_version_export_preserves_unknown_fields_exactly(tmp_path: Path) -> None:
    reader, opened, source = _opened_source(tmp_path, _XorBackend())
    service = _service(tmp_path)
    session = service.open(source, SecretBuffer.from_bytes(_PASSPHRASE))
    destination = tmp_path / "same-version-export.psafe3"
    export_passphrase = SecretBuffer.from_bytes(b"fabricated-same-version-export")

    service.export(session, destination, export_passphrase)
    reopen_passphrase = SecretBuffer.from_bytes(b"fabricated-same-version-export")
    exported = reader.open(destination, reopen_passphrase)

    assert documents_equal_exact(opened.document, exported.document)
    exported.close()
    reopen_passphrase.close()
    opened.close()
    session.lock()
