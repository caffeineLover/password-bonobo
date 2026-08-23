"""Verify the immutable ordered raw vault model and streaming evidence indexes.

The model keeps fabricated unknown and duplicate fields in exact source order.
Manifest hashes are tested separately from final byte-for-byte stream equality.
"""

import copy
import hashlib
import pickle
from collections.abc import Iterator

import pytest

from bonobo_core.passwordsafe.constants import FormatVersion
from bonobo_core.passwordsafe.model import (
    FieldClassification,
    PreservationWarning,
    PreservationWarningCode,
    RawField,
    RawRecord,
    VaultDocument,
    documents_equal_exact,
)
from bonobo_core.passwordsafe.payloads import InlinePayload, PayloadClosedError



VERSION_0311 = FormatVersion.from_uint16(0x0311)
FABRICATED_RECORD_UUID = bytes.fromhex("22222222222242228222222222222222")



#### Create one ordered raw field with independent mutable payload ownership.
####
def _field(type_code: int, payload: bytes, ordinal: int) -> RawField:
    return RawField(type_code, InlinePayload.from_bytes(payload), ordinal, FieldClassification.UNDERSTOOD)



#### Create one mandatory fabricated record while preserving field order.
####
def _record(title: bytes, ordinal: int) -> RawRecord:
    return RawRecord.create(
        (
            _field(0x01, FABRICATED_RECORD_UUID, 0),
            _field(0x03, title, 1),
            _field(0x06, b"fabricated-password", 2),
            _field(0xE0, b"opaque-one", 3),
            _field(0xE0, b"opaque-two", 4),
            _field(0xFF, b"", 5),
        ),
        ordinal=ordinal,
    )



#### Fail explicit close after recording the document's cleanup attempt.
####
class _FailingPayload:
    close_calls: int



    #### Begin with one fabricated declared byte and no cleanup attempts.
    ####
    def __init__(self) -> None:
        self.close_calls = 0



    #### Return the fabricated declared byte length.
    ####
    @property
    def length(self) -> int:
        return 1



    #### Yield one fabricated byte for protocol completeness.
    ####
    def iter_chunks(self, _chunk_size: int) -> Iterator[memoryview[int]]:
        return iter((memoryview(b"x"),))



    #### Record cleanup and raise one synthetic process-control failure.
    ####
    def close(self) -> None:
        self.close_calls += 1
        raise KeyboardInterrupt("synthetic payload cleanup failure")



#### Create two records with duplicate UUID data but distinct opaque handles.
####
def test_document_preserves_duplicate_uuid_records() -> None:
    document = VaultDocument.create(
        VERSION_0311,
        (_field(0x00, b"\x11\x03", 0), _field(0xFF, b"", 1)),
        (_record(b"Alpha", 0), _record(b"Beta", 1)),
    )

    assert document.records[0].handle != document.records[1].handle
    assert "22222222" not in repr(document.records[0].handle)
    assert document.semantic_manifest().record_count == 2
    document.close()



#### Preserve exact header, record, field, type, multiplicity, and ordinal order.
####
def test_document_manifest_retains_order_and_duplicate_fields() -> None:
    header = (_field(0xE1, b"header-unknown", 7), _field(0x00, b"\x11\x03", 2))
    document = VaultDocument.create(VERSION_0311, header, (_record(b"Alpha", 4),))

    manifest = document.semantic_manifest(chunk_size=3)

    assert manifest.version == VERSION_0311
    assert manifest.header_field_count == 2
    assert manifest.record_count == 1
    coordinates = [
        (entry.section, entry.record_ordinal, entry.field_ordinal, entry.type_code) for entry in manifest.entries
    ]
    assert coordinates == [
        ("header", None, 7, 0xE1),
        ("header", None, 2, 0x00),
        ("record", 4, 0, 0x01),
        ("record", 4, 1, 0x03),
        ("record", 4, 2, 0x06),
        ("record", 4, 3, 0xE0),
        ("record", 4, 4, 0xE0),
        ("record", 4, 5, 0xFF),
    ]
    assert manifest.entries[0].length == 14
    assert manifest.entries[0].sha256 == hashlib.sha256(b"header-unknown").hexdigest()
    document.close()



#### Compare exact streams after matching metadata instead of trusting hashes.
####
def test_exact_document_comparison_reads_payloads_after_matching_manifests(monkeypatch: pytest.MonkeyPatch) -> None:
    first = VaultDocument.create(VERSION_0311, (_field(0xE1, b"alpha", 0),), ())
    second = VaultDocument.create(VERSION_0311, (_field(0xE1, b"alpha", 0),), ())
    monkeypatch.setattr(hashlib, "sha256", lambda: _ConstantHash())

    assert first != second
    assert documents_equal_exact(first, second, chunk_size=2)

    different = VaultDocument.create(VERSION_0311, (_field(0xE1, b"alpHa", 0),), ())
    assert not documents_equal_exact(first, different, chunk_size=2)
    first.close()
    second.close()
    different.close()



#### Provide a constant digest to prove final equality does not use hash evidence.
####
class _ConstantHash:



    #### Ignore streamed data so distinct payloads receive identical evidence hashes.
    ####
    def update(self, _data: object) -> None:
        return None



    #### Return one fixed digest string for every payload.
    ####
    def hexdigest(self) -> str:
        return "0" * 64



#### Keep warnings structured and free from raw payload or record identity values.
####
def test_preservation_warning_representation_is_safe() -> None:
    warning = PreservationWarning(
        PreservationWarningCode.MALFORMED_OPTIONAL_FIELD,
        section="record",
        record_ordinal=3,
        field_ordinal=8,
        type_code=0xE0,
    )

    rendered = repr(warning)
    assert "fabricated-password" not in rendered
    assert "22222222" not in rendered



#### Close every distinct payload once and make document operations terminal.
####
def test_document_close_wipes_payloads_and_is_idempotent() -> None:
    payload = InlinePayload.from_bytes(b"fabricated-secret")
    field = RawField(0xE0, payload, 0, FieldClassification.UNKNOWN)
    document = VaultDocument.create(VERSION_0311, (field, field), ())

    document.close()
    document.close()

    assert payload.closed
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        document.semantic_manifest()



#### Continue closing distinct payloads before surfacing the first cleanup failure.
####
def test_document_close_attempts_all_payloads_after_failure() -> None:
    failing = _FailingPayload()
    retained = InlinePayload.from_bytes(b"fabricated-secret")
    document = VaultDocument.create(
        VERSION_0311,
        (
            RawField(0xE0, failing, 0, FieldClassification.UNKNOWN),
            RawField(0xE1, retained, 1, FieldClassification.UNKNOWN),
        ),
        (),
    )

    with pytest.raises(KeyboardInterrupt, match="synthetic payload cleanup failure"):
        document.close()

    assert document.closed
    assert failing.close_calls == 1
    assert retained.closed



#### Reject generic aliases of a document that owns closable field payloads.
####
def test_document_rejects_copy_and_pickle() -> None:
    document = VaultDocument.create(VERSION_0311, (_field(0xE1, b"secret", 0),), ())

    with pytest.raises(TypeError, match="vault document cannot be copied or serialized"):
        copy.copy(document)
    with pytest.raises(TypeError, match="vault document cannot be copied or serialized"):
        copy.deepcopy(document)
    with pytest.raises(TypeError, match="vault document cannot be copied or serialized"):
        pickle.dumps(document)

    document.close()
