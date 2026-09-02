"""Verify candidate cleanup when authenticated reopen rejects writer output."""

import builtins
import os
from collections.abc import Buffer, Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, Final, NoReturn, SupportsIndex

import pytest
from helpers import DeterministicRandomSource
from test_writer import _opened_source, _private_directory, _XorBackend

from bonobo_core.passwordsafe import writer as writer_module
from bonobo_core.passwordsafe.constants import EOF_MARKER, ResourceLimits
from bonobo_core.passwordsafe.crypto import CbcEncryptor, FieldAuthenticator, RandomSource
from bonobo_core.passwordsafe.errors import (
    IntegrityError,
    IntegrityReason,
    MalformedVaultError,
    ResourceLimitError,
    ResourceLimitReason,
    StorageError,
    StorageReason,
)
from bonobo_core.passwordsafe.model import RawField, RawRecord, VaultDocument
from bonobo_core.passwordsafe.reader import OpenedVault, PasswordSafeReader, VaultCryptoState
from bonobo_core.passwordsafe.writer import PasswordSafeWriter



#### Expose a declared length larger than the only yielded payload bytes.
####
class _UnderflowPayload:
    __slots__ = ("_closed",)



    #### Begin one live malformed stream used only at the writer boundary.
    ####
    def __init__(self) -> None:
        self._closed = False



    #### Report the fabricated four-byte declaration.
    ####
    @property
    def length(self) -> int:
        return 4



    #### Yield only three bytes so bounded preflight detects the underflow.
    ####
    def iter_chunks(self, _chunk_size: int) -> Iterator[memoryview[int]]:
        if self._closed:
            raise RuntimeError("test payload is closed")
        yield memoryview(b"bad")



    #### Return another independently terminal malformed payload owner.
    ####
    def retain(self) -> _UnderflowPayload:
        if self._closed:
            raise RuntimeError("test payload is closed")
        return type(self)()



    #### Make this test payload terminal without retaining its fabricated bytes.
    ####
    def close(self) -> None:
        self._closed = True



#### Fail only during the serialization pass after manifest preflight succeeds.
####
class _SecondPassFailurePayload:
    __slots__ = ("_closed", "_iterations")



    #### Begin one live two-pass payload with no prior traversal.
    ####
    def __init__(self) -> None:
        self._closed = False
        self._iterations = 0



    #### Report the exact complete first-pass byte count.
    ####
    @property
    def length(self) -> int:
        return 32



    #### Succeed during manifest traversal and fail after one writer chunk.
    ####
    def iter_chunks(self, _chunk_size: int) -> Iterator[memoryview[int]]:
        if self._closed:
            raise RuntimeError("test payload is closed")
        self._iterations += 1
        yield memoryview(bytes(16))
        if self._iterations > 1:
            raise OSError("fabricated payload failure")
        yield memoryview(bytes(16))



    #### Return one fresh two-pass owner for independent document retention.
    ####
    def retain(self) -> _SecondPassFailurePayload:
        if self._closed:
            raise RuntimeError("test payload is closed")
        return type(self)()



    #### Make this fabricated payload terminal.
    ####
    def close(self) -> None:
        self._closed = True



#### Supply valid initial material and fail on the first field-padding request.
####
class _PaddingFailureRandom:
    __slots__ = ("_calls", "_delegate")



    #### Begin one deterministic stream that permits keys and IV only.
    ####
    def __init__(self) -> None:
        self._delegate = DeterministicRandomSource(bytes(index % 197 for index in range(8192)))
        self._calls = 0



    #### Reject the fourth request, which is the first field's padding.
    ####
    def bytes(self, length: int) -> bytes:
        self._calls += 1
        if self._calls == 4:
            raise OSError("fabricated padding failure")
        return self._delegate.bytes(length)



#### Expose one stable memoryview so writer conversion attempts are observable.
####
class _ObservedPayload:
    __slots__ = ("_closed", "storage", "view")



    #### Own one mutable block-aligned fabricated payload.
    ####
    def __init__(self) -> None:
        self.storage = bytearray(range(32))
        self.view = memoryview(self.storage).toreadonly()
        self._closed = False



    #### Report the exact stable view length.
    ####
    @property
    def length(self) -> int:
        return len(self.view)



    #### Yield the same view object without materializing immutable plaintext.
    ####
    def iter_chunks(self, _chunk_size: int) -> Iterator[memoryview[int]]:
        if self._closed:
            raise RuntimeError("test payload is closed")
        yield self.view



    #### Return an independent observed owner for document retention.
    ####
    def retain(self) -> _ObservedPayload:
        if self._closed:
            raise RuntimeError("test payload is closed")
        return type(self)()



    #### Release the view and wipe its mutable backing storage.
    ####
    def close(self) -> None:
        if not self._closed:
            self.view.release()
            self.storage[:] = bytes(len(self.storage))
            self._closed = True



_FAULT_PAYLOAD: Final[bytes] = bytes(range(32))



#### Retain a document while replacing one optional unknown payload with underflow.
####
def _with_underflow(document: VaultDocument) -> VaultDocument:
    header = tuple(
        RawField(field.type_code, field.payload.retain(), field.ordinal, field.classification)
        for field in document.header_fields
    )
    records: list[RawRecord] = []
    try:
        for record in document.records:
            fields = tuple(
                RawField(
                    field.type_code,
                    _UnderflowPayload() if field.type_code == 0xE1 else field.payload.retain(),
                    field.ordinal,
                    field.classification,
                )
                for field in record.fields
            )
            records.append(RawRecord.create(fields, ordinal=record.ordinal))
        return VaultDocument.create(document.version, header, tuple(records), warnings=document.warnings)
    except BaseException:
        for field in header:
            field.payload.close()
        for record in records:
            for field in record.fields:
                field.payload.close()
        raise



#### Retain a document with one payload that fails only during serialization.
####
def _with_second_pass_failure(document: VaultDocument) -> VaultDocument:
    header = tuple(
        RawField(field.type_code, field.payload.retain(), field.ordinal, field.classification)
        for field in document.header_fields
    )
    records: list[RawRecord] = []
    try:
        for record in document.records:
            fields = tuple(
                RawField(
                    field.type_code,
                    _SecondPassFailurePayload() if field.type_code == 0xE1 else field.payload.retain(),
                    field.ordinal,
                    field.classification,
                )
                for field in record.fields
            )
            records.append(RawRecord.create(fields, ordinal=record.ordinal))
        return VaultDocument.create(document.version, header, tuple(records), warnings=document.warnings)
    except BaseException:
        for field in header:
            field.payload.close()
        for record in records:
            for field in record.fields:
                field.payload.close()
        raise



#### Retain a document with one payload whose exact view can detect conversion.
####
def _with_observed_payload(document: VaultDocument) -> tuple[VaultDocument, _ObservedPayload]:
    observed = _ObservedPayload()
    header = tuple(
        RawField(field.type_code, field.payload.retain(), field.ordinal, field.classification)
        for field in document.header_fields
    )
    records: list[RawRecord] = []
    try:
        for record in document.records:
            fields = tuple(
                RawField(
                    field.type_code,
                    observed if field.type_code == 0xE1 else field.payload.retain(),
                    field.ordinal,
                    field.classification,
                )
                for field in record.fields
            )
            records.append(RawRecord.create(fields, ordinal=record.ordinal))
        return VaultDocument.create(document.version, header, tuple(records), warnings=document.warnings), observed
    except BaseException:
        for field in header:
            field.payload.close()
        for record in records:
            for field in record.fields:
                field.payload.close()
        observed.close()
        raise



#### Retain one document while inserting a second mandatory header terminator.
####
def _with_duplicate_header_end(document: VaultDocument) -> VaultDocument:
    source_fields = (*document.header_fields, document.header_fields[-1])
    header = tuple(
        RawField(field.type_code, field.payload.retain(), ordinal, field.classification)
        for ordinal, field in enumerate(source_fields)
    )
    records = tuple(
        RawRecord.create(
            tuple(
                RawField(field.type_code, field.payload.retain(), field.ordinal, field.classification)
                for field in record.fields
            ),
            ordinal=record.ordinal,
        )
        for record in document.records
    )
    return VaultDocument.create(document.version, header, records, warnings=document.warnings)



#### Reject candidate reopen after serialization without retaining partial output.
####
def test_reopen_failure_removes_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 227 for index in range(8192))),
    )



    #### Fail the validation boundary after the encrypted file is complete.
    ####
    def reject_candidate(
        _reader: PasswordSafeReader,
        _path: Path,
        _crypto_state: VaultCryptoState,
    ) -> None:
        raise IntegrityError(IntegrityReason.HMAC_MISMATCH)



    monkeypatch.setattr(PasswordSafeReader, "reopen_candidate", reject_candidate)

    with pytest.raises(IntegrityError):
        writer.write(opened.document, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()



#### Remove an exclusive file when restrictive permission setup fails.
####
def test_permission_failure_closes_and_removes_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 223 for index in range(8192))),
    )



    #### Fail after exclusive creation but before the descriptor is transferred.
    ####
    def reject_permissions(
        _path: str,
        _mode: int,
        *,
        follow_symlinks: bool,
    ) -> None:
        del follow_symlinks
        raise OSError("fabricated permission failure")



    monkeypatch.setattr(os, "chmod", reject_permissions)

    with pytest.raises(StorageError):
        writer.write(opened.document, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()



#### Convert a malformed payload stream into a safe typed preparation failure.
####
def test_payload_underflow_fails_before_candidate_creation(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    malformed = _with_underflow(opened.document)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 219 for index in range(8192))),
    )

    with pytest.raises(StorageError):
        writer.write(malformed, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    malformed.close()
    opened.close()



#### Enforce the writer's independent encrypted-file ceiling before output exists.
####
def test_encrypted_candidate_budget_fails_before_candidate_creation(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 179 for index in range(8192))),
        limits=ResourceLimits(max_encrypted_file_bytes=1),
    )

    with pytest.raises(ResourceLimitError) as caught:
        writer.write(opened.document, opened.crypto_state)

    assert caught.value.reason == ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES
    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()



#### Enforce the writer's independent stretching-work ceiling before output exists.
####
def test_serialization_iteration_budget_fails_before_candidate_creation(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 177 for index in range(8192))),
        limits=ResourceLimits(max_iterations=1),
    )

    with pytest.raises(ResourceLimitError) as caught:
        writer.write(opened.document, opened.crypto_state)

    assert caught.value.reason == ResourceLimitReason.MAX_ITERATIONS
    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()



#### Enforce aggregate decoded-text policy before candidate output exists.
####
def test_decoded_text_budget_fails_before_candidate_creation(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 173 for index in range(8192))),
        limits=ResourceLimits(max_decoded_text_bytes=1),
    )

    with pytest.raises(ResourceLimitError) as caught:
        writer.write(opened.document, opened.crypto_state)

    assert caught.value.reason == ResourceLimitReason.MAX_DECODED_TEXT_BYTES
    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()



#### Reject invalid mandatory multiplicity before candidate output exists.
####
def test_schema_failure_happens_before_candidate_creation(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    malformed = _with_duplicate_header_end(opened.document)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 167 for index in range(8192))),
    )

    with pytest.raises(MalformedVaultError):
        writer.write(malformed, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    malformed.close()
    opened.close()



#### Remove output after a payload faults during the second streaming traversal.
####
def test_payload_chunk_failure_removes_partial_candidate(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    failing = _with_second_pass_failure(opened.document)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 193 for index in range(8192))),
    )

    with pytest.raises(StorageError):
        writer.write(failing, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    failing.close()
    opened.close()



#### Remove output after field padding randomness becomes unavailable.
####
def test_padding_failure_removes_partial_candidate(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=_PaddingFailureRandom(),
    )

    with pytest.raises(StorageError):
        writer.write(opened.document, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()



#### Wipe both fresh key buffers when joint ownership transfer is rejected.
####
def test_rejected_key_ownership_wipes_fresh_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 181 for index in range(8192))),
    )
    captured: list[bytearray] = []



    #### Retain test visibility of both transfers before simulating rejection.
    ####
    def reject_key_ownership(content_key: bytearray, hmac_key: bytearray) -> NoReturn:
        captured.extend((content_key, hmac_key))
        raise RuntimeError("fabricated key ownership rejection")



    monkeypatch.setattr(writer_module, "VaultKeys", reject_key_ownership)

    with pytest.raises(StorageError):
        writer.write(opened.document, opened.crypto_state)

    assert len(captured) == 2
    assert all(buffer == bytearray(32) for buffer in captured)
    assert list(candidate_directory.iterdir()) == []
    opened.close()



#### Stream opaque payload views without converting their storage to immutable bytes.
####
def test_opaque_payload_is_not_directly_converted_to_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    document, observed = _with_observed_payload(opened.document)
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "candidates"),
        random_source=DeterministicRandomSource(bytes(index % 163 for index in range(8192))),
    )
    converted_observed_storage = False



    #### Delegate ordinary conversions while detecting views into opaque storage.
    ####
    def observe_bytes(
        value: Buffer | Iterable[SupportsIndex] | SupportsIndex = b"",
    ) -> bytes:
        nonlocal converted_observed_storage
        if isinstance(value, memoryview) and value.obj is observed.storage:
            converted_observed_storage = True
        return builtins.bytes(value)



    monkeypatch.setattr(writer_module, "bytes", observe_bytes, raising=False)

    writer.write(document, opened.crypto_state)

    assert not converted_observed_storage
    document.close()
    opened.close()



#### Reject a candidate pathname replaced after authenticated snapshot capture.
####
def test_candidate_replacement_after_reopen_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 157 for index in range(8192))),
    )
    production_reopen = PasswordSafeReader.reopen_candidate
    replacement = b"fabricated-encrypted-replacement"



    #### Capture the verified candidate, then replace only its external name.
    ####
    def replace_after_reopen(
        selected_reader: PasswordSafeReader,
        path: Path,
        crypto_state: VaultCryptoState,
    ) -> OpenedVault:
        reopened = production_reopen(selected_reader, path, crypto_state)
        path.unlink()
        path.write_bytes(replacement)
        return reopened



    monkeypatch.setattr(PasswordSafeReader, "reopen_candidate", replace_after_reopen)

    with pytest.raises(StorageError) as caught:
        writer.write(opened.document, opened.crypto_state)

    assert caught.value.reason == StorageReason.VERIFICATION_FAILED
    assert source.read_bytes() == source_before
    assert [path.read_bytes() for path in candidate_directory.iterdir()] == [replacement]
    opened.close()



#### Close a newly opened identity guard when validation is interrupted.
####
def test_candidate_guard_closes_when_identity_check_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate_directory = _private_directory(tmp_path, "candidates")
    artifact, output = writer_module._open_candidate(candidate_directory)
    production_identity = writer_module._descriptor_identity
    production_open = writer_module._open_candidate_descriptor
    retained_descriptor: int | None = None



    #### Capture the platform-specific guard descriptor before validation.
    ####
    def observe_open(selected_artifact: writer_module._CandidateArtifact, selected_output: BinaryIO) -> int:
        nonlocal retained_descriptor
        retained_descriptor = production_open(selected_artifact, selected_output)
        return retained_descriptor

    monkeypatch.setattr(writer_module, "_open_candidate_descriptor", observe_open)



    #### Interrupt only validation of the newly retained descriptor.
    ####
    def interrupt_retained_identity(descriptor: int) -> tuple[int, int]:
        if descriptor == retained_descriptor:
            raise KeyboardInterrupt("identity validation interrupted")
        return production_identity(descriptor)

    monkeypatch.setattr(writer_module, "_descriptor_identity", interrupt_retained_identity)
    descriptor_closed = False
    try:
        with output, pytest.raises(KeyboardInterrupt):
            writer_module._retain_candidate_descriptor(artifact, output)
        assert retained_descriptor is not None
        try:
            os.fstat(retained_descriptor)
        except OSError:
            descriptor_closed = True
        assert descriptor_closed
    finally:
        if retained_descriptor is not None and not descriptor_closed:
            os.close(retained_descriptor)
        artifact.path.unlink(missing_ok=True)



#### Close the retained identity guard even when pathname removal is interrupted.
####
def test_candidate_guard_closes_when_removal_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 149 for index in range(8192))),
    )
    production_retain = writer_module._retain_candidate_descriptor
    retained_descriptor: int | None = None



    #### Capture the real retained descriptor before candidate authentication.
    ####
    def observe_retain(artifact: writer_module._CandidateArtifact, output: BinaryIO) -> int:
        nonlocal retained_descriptor
        retained_descriptor = production_retain(artifact, output)
        return retained_descriptor



    #### Cause the handled validation failure that initiates cleanup.
    ####
    def reject_candidate(
        _reader: PasswordSafeReader,
        _path: Path,
        _crypto_state: VaultCryptoState,
    ) -> None:
        raise IntegrityError(IntegrityReason.HMAC_MISMATCH)



    #### Interrupt pathname cleanup after the retained descriptor exists.
    ####
    def interrupt_removal(_artifact: writer_module._CandidateArtifact) -> bool:
        raise KeyboardInterrupt("candidate removal interrupted")

    monkeypatch.setattr(writer_module, "_retain_candidate_descriptor", observe_retain)
    monkeypatch.setattr(PasswordSafeReader, "reopen_candidate", reject_candidate)
    monkeypatch.setattr(writer_module._CandidateArtifact, "remove", interrupt_removal)
    descriptor_closed = False
    try:
        with pytest.raises(KeyboardInterrupt):
            writer.write(opened.document, opened.crypto_state)
        assert retained_descriptor is not None
        try:
            os.fstat(retained_descriptor)
        except OSError:
            descriptor_closed = True
        assert descriptor_closed
    finally:
        if retained_descriptor is not None and not descriptor_closed:
            os.close(retained_descriptor)
        for path in candidate_directory.iterdir():
            path.unlink()
        opened.close()



#### Surface candidate cleanup failure instead of reporting the earlier fault.
####
def test_cleanup_failure_is_observable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 151 for index in range(8192))),
    )
    production_unlink = Path.unlink



    #### Reject removal only for the writer's encrypted candidate artifact.
    ####
    def reject_candidate_unlink(path: Path, *, missing_ok: bool = False) -> None:
        if path.suffix == ".candidate":
            raise OSError("fabricated candidate cleanup failure")
        production_unlink(path, missing_ok=missing_ok)



    #### Cause the handled validation error that initiates candidate cleanup.
    ####
    def reject_candidate(
        _reader: PasswordSafeReader,
        _path: Path,
        _crypto_state: VaultCryptoState,
    ) -> None:
        raise IntegrityError(IntegrityReason.HMAC_MISMATCH)



    monkeypatch.setattr(Path, "unlink", reject_candidate_unlink)
    monkeypatch.setattr(PasswordSafeReader, "reopen_candidate", reject_candidate)

    with pytest.raises(StorageError) as caught:
        writer.write(opened.document, opened.crypto_state)

    assert caught.value.reason == StorageReason.PREPARATION_FAILED
    assert len(list(candidate_directory.iterdir())) == 1
    opened.close()



#### Remove candidates after every late framing, durability, or comparison failure.
####
@pytest.mark.parametrize(
    "stage",
    ["prefix", "field-header", "padding", "eof", "hmac", "flush", "sync", "compare"],
)
def test_late_writer_fault_removes_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    candidate_directory = _private_directory(tmp_path, "candidates")
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        candidate_directory,
        random_source=DeterministicRandomSource(bytes(index % 191 for index in range(8192))),
    )
    original_write = writer_module._write_all
    original_encrypt = writer_module._encrypt_bytes
    original_write_field = writer_module._write_field
    saw_eof = False
    encrypted_parts = 0



    #### Write real bytes, then fail at the caller-selected durable boundary.
    ####
    def fail_after_boundary(output: BinaryIO, data: bytes) -> None:
        nonlocal saw_eof
        original_write(output, data)
        if stage == "prefix" and len(data) == 152:
            raise OSError("fabricated prefix failure")
        if data == EOF_MARKER:
            saw_eof = True
            if stage == "eof":
                raise OSError("fabricated EOF failure")
        elif stage == "hmac" and saw_eof and len(data) == len(_FAULT_PAYLOAD):
            raise OSError("fabricated HMAC failure")



    #### Fail after the first field header has entered encrypted CBC output.
    ####
    def fail_after_field_header(
        output: BinaryIO,
        encryptor: CbcEncryptor,
        pending: bytearray,
        data: memoryview[int],
    ) -> None:
        nonlocal encrypted_parts
        original_encrypt(output, encryptor, pending, data)
        encrypted_parts += 1
        if stage == "field-header" and encrypted_parts == 1:
            raise OSError("fabricated field-header failure")



    #### Fail after a complete field frame, including its random padding.
    ####
    def fail_after_padding(
        output: BinaryIO,
        raw_field: RawField,
        encryptor: CbcEncryptor,
        authenticator: FieldAuthenticator,
        random_source: RandomSource,
        limits: ResourceLimits,
    ) -> None:
        original_write_field(output, raw_field, encryptor, authenticator, random_source, limits)
        if stage == "padding":
            raise OSError("fabricated after-padding failure")



    #### Flush buffered bytes, then reject the durability transition.
    ####
    def reject_flush(output: BinaryIO) -> None:
        output.flush()
        raise OSError("fabricated flush failure")



    #### Reject file synchronization after the complete candidate is flushed.
    ####
    def reject_sync(_descriptor: int) -> None:
        raise OSError("fabricated sync failure")



    monkeypatch.setattr(writer_module, "_write_all", fail_after_boundary)
    monkeypatch.setattr(writer_module, "_encrypt_bytes", fail_after_field_header)
    monkeypatch.setattr(writer_module, "_write_field", fail_after_padding)
    if stage == "flush":
        monkeypatch.setattr(writer_module, "_flush_and_sync", reject_flush)
    if stage == "sync":
        monkeypatch.setattr(os, "fsync", reject_sync)
    if stage == "compare":
        monkeypatch.setattr(writer_module, "documents_equal_exact", lambda *_args, **_kwargs: False)

    with pytest.raises(StorageError):
        writer.write(opened.document, opened.crypto_state)

    assert list(candidate_directory.iterdir()) == []
    assert source.read_bytes() == source_before
    opened.close()
