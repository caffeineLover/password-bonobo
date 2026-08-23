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
    RecordHandle,
    RevisionToken,
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



    #### Retain is unused here but keeps this runtime protocol fake complete.
    ####
    def retain(self) -> _FailingPayload:
        return _FailingPayload()



#### Stream caller-selected chunks under one independently declared length.
####
class _ScriptedPayload:



    #### Retain fixed chunks, declaration, and optional iteration failure.
    ####
    def __init__(
        self,
        length: int,
        chunks: tuple[bytes, ...],
        *,
        failure: BaseException | None = None,
    ) -> None:
        self._length = length
        self._chunks = chunks
        self._failure = failure



    #### Return the intentionally independent declared length.
    ####
    @property
    def length(self) -> int:
        return self._length



    #### Yield scripted chunks before any configured caller-visible failure.
    ####
    def iter_chunks(self, _chunk_size: int) -> Iterator[memoryview[int]]:
        for chunk in self._chunks:
            yield memoryview(chunk)
        if self._failure is not None:
            raise self._failure



    #### Return a separate scripted payload lifetime without copying chunk bytes.
    ####
    def retain(self) -> _ScriptedPayload:
        return _ScriptedPayload(self._length, self._chunks, failure=self._failure)



    #### Complete the synthetic protocol lifetime without mutable storage.
    ####
    def close(self) -> None:
        return None



#### Record complete streamed observation independently from comparison results.
####
class _ObservedPayload(_ScriptedPayload):



    #### Retain an initially empty observation buffer beside scripted chunks.
    ####
    def __init__(self, length: int, chunks: tuple[bytes, ...]) -> None:
        super().__init__(length, chunks)
        self.observed = bytearray()



    #### Record every yielded byte so early comparison exit is directly visible.
    ####
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        for chunk in self._chunks:
            self.observed.extend(chunk)
            yield memoryview(chunk)



#### Fail selected close attempts before becoming terminal on a later retry.
####
class _RetryClosePayload(_ScriptedPayload):



    #### Retain ordered synthetic failures and cleanup attempt evidence.
    ####
    def __init__(self, failures: list[BaseException]) -> None:
        super().__init__(1, (b"x",))
        self.failures = failures
        self.close_calls = 0
        self.closed = False



    #### Raise the next failure or commit this synthetic payload terminal.
    ####
    def close(self) -> None:
        self.close_calls += 1
        if self.failures:
            raise self.failures.pop(0)
        self.closed = True



    #### Fork an independent successful lease for retained revision tests.
    ####
    def retain(self) -> _RetryClosePayload:
        return _RetryClosePayload([])



#### Build one document around a caller-selected raw header field sequence.
####
def _header_document(fields: tuple[RawField, ...]) -> VaultDocument:
    return VaultDocument.create(VERSION_0311, fields, ())



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

    pending_after_failure = document.closed
    assert not pending_after_failure
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



#### Retain independent document payload leases without copying plaintext bytes.
####
@pytest.mark.parametrize("close_original_first", [True, False])
def test_document_retain_survives_close_in_either_order(close_original_first: bool) -> None:
    storage = bytearray(b"fabricated-secret")
    payload = InlinePayload.take_ownership(storage)
    original = _header_document(
        (
            RawField(0xE0, payload, 0, FieldClassification.UNKNOWN),
            RawField(0xE1, payload, 1, FieldClassification.UNKNOWN),
        ),
    )
    retained = original.retain()

    first, second = (original, retained) if close_original_first else (retained, original)
    first.close()

    assert storage == bytearray(b"fabricated-secret")
    assert second.semantic_manifest().field_count == 2
    second.close()
    assert storage == bytearray(17)



#### Finalizing either document revision releases only its independent payload lease.
####
def test_document_retain_survives_original_finalizer() -> None:
    storage = bytearray(b"fabricated-secret")
    original = _header_document(
        (RawField(0xE0, InlinePayload.take_ownership(storage), 0, FieldClassification.UNKNOWN),),
    )
    retained = original.retain()

    original.__del__()

    assert retained.semantic_manifest().field_count == 1
    assert storage == bytearray(b"fabricated-secret")
    retained.__del__()
    assert storage == bytearray(17)



#### Keep opaque tokens immutable and hash-stable inside set and dictionary keys.
####
@pytest.mark.parametrize("factory", [RecordHandle, RevisionToken])
def test_identity_tokens_reject_mutation_copy_and_state(factory: type[RecordHandle] | type[RevisionToken]) -> None:
    token = factory()
    mapping = {token: "retained"}
    members = {token}

    with pytest.raises((AttributeError, TypeError)):
        token._token = object()
    with pytest.raises((AttributeError, TypeError)):
        del token._token
    with pytest.raises(TypeError, match="opaque identity cannot be copied or serialized"):
        copy.copy(token)
    with pytest.raises(TypeError, match="opaque identity cannot be copied or serialized"):
        copy.deepcopy(token)
    with pytest.raises(TypeError, match="opaque identity cannot be copied or serialized"):
        pickle.dumps(token)
    with pytest.raises(TypeError, match="opaque identity cannot be copied or serialized"):
        token.__getstate__()
    with pytest.raises(TypeError, match="opaque identity cannot be copied or serialized"):
        token.__setstate__({})

    assert mapping[token] == "retained"
    assert token in members



#### Return False rather than raising when ordered container counts differ.
####
def test_exact_comparison_is_total_for_container_count_mismatches() -> None:
    one_header = _header_document((_field(0xE0, b"a", 0),))
    two_headers = _header_document((_field(0xE0, b"a", 0), _field(0xE1, b"b", 1)))
    one_field_record = RawRecord.create((_field(0xE0, b"a", 0),), ordinal=0)
    two_field_record = RawRecord.create((_field(0xE0, b"a", 0), _field(0xE1, b"b", 1)), ordinal=0)
    one_record = VaultDocument.create(VERSION_0311, (), (one_field_record,))
    two_records = VaultDocument.create(VERSION_0311, (), (one_field_record, two_field_record))
    field_mismatch = VaultDocument.create(VERSION_0311, (), (two_field_record,))

    assert not documents_equal_exact(one_header, two_headers)
    assert not documents_equal_exact(one_record, two_records)
    assert not documents_equal_exact(one_record, field_mismatch)

    for document in (one_header, two_headers, one_record, two_records, field_mismatch):
        document.close()



#### Reject zero chunks and declared stream underflow or overflow as mismatches.
####
@pytest.mark.parametrize(
    "scripted",
    [
        _ScriptedPayload(2, (b"", b"ab")),
        _ScriptedPayload(2, (b"a",)),
        _ScriptedPayload(2, (b"abc",)),
    ],
)
def test_exact_comparison_rejects_invalid_payload_stream_lengths(scripted: _ScriptedPayload) -> None:
    expected = _header_document((_field(0xE0, b"ab", 0),))
    candidate = _header_document((RawField(0xE0, scripted, 0, FieldClassification.UNDERSTOOD),))

    assert not documents_equal_exact(expected, candidate, chunk_size=2)

    expected.close()
    candidate.close()



#### Accept different bounded chunk boundaries only when all bytes match exactly.
####
def test_exact_comparison_accepts_different_chunk_boundaries() -> None:
    first_payload = _ScriptedPayload(4, (b"a", b"bc", b"d"))
    second_payload = _ScriptedPayload(4, (b"ab", b"cd"))
    first = _header_document((RawField(0xE0, first_payload, 0, FieldClassification.UNKNOWN),))
    second = _header_document((RawField(0xE0, second_payload, 0, FieldClassification.UNKNOWN),))

    assert documents_equal_exact(first, second, chunk_size=3)

    first.close()
    second.close()



#### Propagate payload access failures instead of misclassifying them as inequality.
####
def test_exact_comparison_propagates_payload_exception() -> None:
    failure = KeyboardInterrupt("synthetic comparison failure")
    failing = _ScriptedPayload(1, (), failure=failure)
    first = _header_document((RawField(0xE0, failing, 0, FieldClassification.UNKNOWN),))
    second = _header_document((RawField(0xE0, InlinePayload.from_bytes(b"x"), 0, FieldClassification.UNKNOWN),))

    with pytest.raises(KeyboardInterrupt) as caught:
        documents_equal_exact(first, second)

    assert caught.value is failure
    first.close()
    second.close()



#### Drain both entered streams even when one underflows and the other overflows.
####
def test_exact_comparison_fully_counts_both_invalid_streams() -> None:
    underflow = _ObservedPayload(2, (b"a",))
    overflow = _ObservedPayload(2, (b"ab", b"c"))
    first = _header_document((RawField(0xE0, underflow, 0, FieldClassification.UNKNOWN),))
    second = _header_document((RawField(0xE0, overflow, 0, FieldClassification.UNKNOWN),))

    assert not documents_equal_exact(first, second, chunk_size=2)
    assert underflow.observed == b"a"
    assert overflow.observed == b"abc"

    first.close()
    second.close()



#### Continue bounded validation after an early byte mismatch exposes later overflow.
####
def test_exact_comparison_drains_after_early_byte_mismatch() -> None:
    first_payload = _ObservedPayload(2, (b"a", b"b"))
    second_payload = _ObservedPayload(2, (b"x", b"yz"))
    first = _header_document((RawField(0xE0, first_payload, 0, FieldClassification.UNKNOWN),))
    second = _header_document((RawField(0xE0, second_payload, 0, FieldClassification.UNKNOWN),))

    assert not documents_equal_exact(first, second, chunk_size=2)
    assert first_payload.observed == b"ab"
    assert second_payload.observed == b"xyz"

    first.close()
    second.close()



#### Retry only failed document payloads after exhausting every distinct owner.
####
@pytest.mark.parametrize(
    ("first_error", "last_error"),
    [
        (ValueError("first close failure"), KeyboardInterrupt("last close interruption")),
        (KeyboardInterrupt("first close interruption"), ValueError("last close failure")),
    ],
)
def test_document_close_is_exhaustive_and_retryable(
    first_error: BaseException,
    last_error: BaseException,
) -> None:
    first_payload = _RetryClosePayload([first_error])
    middle_payload = _RetryClosePayload([])
    last_payload = _RetryClosePayload([last_error])
    first_field = RawField(0xE0, first_payload, 0, FieldClassification.UNKNOWN)
    document = _header_document(
        (
            first_field,
            RawField(0xE1, middle_payload, 1, FieldClassification.UNKNOWN),
            first_field,
            RawField(0xE2, last_payload, 2, FieldClassification.UNKNOWN),
        ),
    )

    with pytest.raises(type(first_error)) as caught:
        document.close()

    assert caught.value is first_error
    initial_close_calls = [first_payload.close_calls, middle_payload.close_calls, last_payload.close_calls]
    assert initial_close_calls == [1, 1, 1]
    pending_after_failure = document.closed
    assert not pending_after_failure
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        document.semantic_manifest()

    document.close()

    closed_after_retry = document.closed
    assert closed_after_retry
    final_close_calls = [first_payload.close_calls, middle_payload.close_calls, last_payload.close_calls]
    assert final_close_calls == [2, 1, 2]
    assert first_payload.closed and middle_payload.closed and last_payload.closed



#### Finalization exhausts all payloads and suppresses failures until a retry.
####
def test_document_finalizer_is_exhaustive_and_retryable() -> None:
    first = _RetryClosePayload([ValueError("first finalizer failure")])
    second = _RetryClosePayload([KeyboardInterrupt("second finalizer failure")])
    document = _header_document(
        (
            RawField(0xE0, first, 0, FieldClassification.UNKNOWN),
            RawField(0xE1, second, 1, FieldClassification.UNKNOWN),
        ),
    )

    document.__del__()
    assert [first.close_calls, second.close_calls] == [1, 1]
    pending_after_failure = document.closed
    assert not pending_after_failure

    document.__del__()
    closed_after_retry = document.closed
    assert closed_after_retry
    assert [first.close_calls, second.close_calls] == [2, 2]



#### A failed original revision close never invalidates its retained revision.
####
def test_document_retryable_close_preserves_retained_revision() -> None:
    failure = ValueError("original revision close failure")
    payload = _RetryClosePayload([failure])
    original = _header_document((RawField(0xE0, payload, 0, FieldClassification.UNKNOWN),))
    retained = original.retain()

    with pytest.raises(ValueError) as caught:
        original.close()

    assert caught.value is failure
    assert retained.semantic_manifest().field_count == 1
    original.close()
    retained.close()
    assert original.closed and retained.closed
