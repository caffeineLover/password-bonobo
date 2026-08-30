"""Verify the official PasswordSafe field schema and lossless typed projections.

Expected table rows are literal transcriptions of the official format description,
not values generated from the production schemas under test.
"""

from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from bonobo_core.passwordsafe.constants import FieldKind, FormatVersion, HeaderFieldType, RecordFieldType
from bonobo_core.passwordsafe.errors import IncompatibleExportError, MalformedVaultError
from bonobo_core.passwordsafe.model import FieldClassification, RawField
from bonobo_core.passwordsafe.payloads import FieldPayload, InlinePayload
from bonobo_core.passwordsafe.schema import (
    HEADER_SCHEMA,
    RECORD_SCHEMA,
    FieldMultiplicity,
    MandatoryRole,
    SecretClassification,
    decode_header_field,
    decode_record_field,
    encode_header_field,
    encode_record_field,
    ensure_fields_representable,
)
from bonobo_core.passwordsafe.secrets import SecretBuffer



#### Build one independently owned raw field for a focused codec assertion.
####
def _raw(type_code: int, data: bytes, *, ordinal: int = 0) -> RawField:
    return RawField(type_code, InlinePayload.from_bytes(data), ordinal, FieldClassification.UNDERSTOOD)



#### Read one small test payload without depending on a production codec helper.
####
def _payload_bytes(payload: FieldPayload) -> bytes:
    return b"".join(bytes(chunk) for chunk in payload.iter_chunks(64))



#### Refuse every payload read so opaque projection tests detect materialization.
####
class _ExplodingPayload:
    length = 4



    #### Fail if a schema decoder attempts to expose recognized opaque bytes.
    ####
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        del chunk_size
        raise AssertionError("opaque payload was read")



    #### This test payload does not support retention because decoding must borrow it.
    ####
    def retain(self) -> FieldPayload:
        raise AssertionError("opaque payload was retained")



    #### Keep cleanup inert because this helper owns no mutable storage.
    ####
    def close(self) -> None:
        return



#### Match every official header field's representation and policy metadata.
####
def test_official_header_schema_is_complete_and_literal() -> None:
    expected = (
        (0x00, "uint16", 0x0300, "single", "public", "header-required", False, 2, False),
        (0x01, "uuid", 0x0300, "single", "public", "optional", False, 16, False),
        (0x02, "text", 0x0300, "single", "public", "optional", True, None, False),
        (0x03, "text", 0x0301, "single", "public", "optional", True, None, False),
        (0x04, "time", 0x0300, "single", "public", "optional", True, 4, True),
        (0x05, "text", 0x0300, "single", "public", "optional", True, None, False),
        (0x06, "text", 0x0300, "single", "public", "optional", True, None, False),
        (0x07, "text", 0x0302, "single", "public", "optional", True, None, False),
        (0x08, "text", 0x0302, "single", "public", "optional", True, None, False),
        (0x09, "text", 0x0302, "single", "public", "optional", True, None, False),
        (0x0A, "text", 0x0302, "single", "public", "optional", True, None, False),
        (0x0B, "text", 0x0305, "single", "public", "optional", True, None, False),
        (0x0C, "opaque", 0x0300, "single", "potentially-secret", "optional", False, None, False),
        (0x0D, "opaque", 0x0300, "single", "potentially-secret", "optional", False, None, False),
        (0x0E, "opaque", 0x0300, "single", "potentially-secret", "optional", False, None, False),
        (0x0F, "text", 0x0307, "single", "public", "optional", True, None, False),
        (0x10, "text", 0x030A, "single", "public", "optional", True, None, False),
        (0x11, "text", 0x030B, "multiple", "public", "optional", True, None, False),
        (0x12, "binary", 0x030C, "single", "secret", "optional", True, 20, False),
        (0x13, "time", 0x030E, "single", "public", "optional", True, 4, True),
        (0xFF, "empty", 0x0300, "single", "public", "terminator", False, 0, False),
    )
    observed = tuple(
        (
            int(type_code), spec.kind.value, spec.since.value, spec.multiplicity.value, spec.secrecy.value,
            spec.mandatory_role.value, spec.editable, spec.fixed_length, spec.allow_historical_time,
        )
        for type_code, spec in HEADER_SCHEMA.items()
    )
    assert observed == expected



#### Match every official record field through custom text plus sentinels.
####
def test_official_record_schema_is_complete_and_literal() -> None:
    expected = (
        (0x01, "uuid", 0x0300, "single", "public", "record-required", False, 16),
        (0x02, "text", 0x0300, "single", "public", "optional", True, None),
        (0x03, "text", 0x0300, "single", "public", "record-required", True, None),
        (0x04, "text", 0x0300, "single", "public", "optional", True, None),
        (0x05, "text", 0x0300, "single", "potentially-secret", "optional", True, None),
        (0x06, "text", 0x0300, "single", "secret", "record-required", True, None),
        (0x07, "time", 0x0300, "single", "public", "optional", True, 4),
        (0x08, "time", 0x0300, "single", "public", "optional", True, 4),
        (0x09, "time", 0x0300, "single", "public", "optional", True, 4),
        (0x0A, "time", 0x0300, "single", "public", "optional", True, 4),
        (0x0B, "opaque", 0x0300, "single", "potentially-secret", "optional", False, 4),
        (0x0C, "time", 0x0300, "single", "public", "optional", True, 4),
        (0x0D, "text", 0x0300, "single", "public", "optional", True, None),
        (0x0E, "text", 0x0300, "single", "public", "optional", True, None),
        (0x0F, "text", 0x0300, "single", "secret", "optional", True, None),
        (0x10, "text", 0x0302, "single", "public", "optional", True, None),
        (0x11, "uint32", 0x0304, "single", "public", "optional", True, 4),
        (0x12, "text", 0x0305, "single", "public", "optional", True, None),
        (0x13, "uint16", 0x0305, "single", "public", "optional", True, 2),
        (0x14, "text", 0x0306, "single", "public", "optional", True, None),
        (0x15, "uint8", 0x0308, "single", "public", "optional", True, 1),
        (0x16, "text", 0x0309, "single", "public", "optional", True, None),
        (0x17, "uint16", 0x0309, "single", "public", "optional", True, 2),
        (0x18, "text", 0x030A, "single", "public", "optional", True, None),
        (0x19, "uint32", 0x030D, "single", "public", "optional", True, 4),
        (0x1A, "opaque", 0x030D, "single", "potentially-secret", "optional", False, 16),
        (0x1B, "binary", 0x030D, "single", "secret", "optional", True, None),
        (0x1C, "text", 0x030D, "single", "secret", "optional", True, None),
        (0x1D, "text", 0x030D, "single", "secret", "optional", True, None),
        (0x1E, "text", 0x030D, "single", "secret", "optional", True, None),
        (0x1F, "text", 0x030D, "single", "secret", "optional", True, None),
        (0x20, "text", 0x030D, "single", "potentially-secret", "optional", True, None),
        (0x21, "uint8", 0x030E, "single", "public", "optional", True, 1),
        (0x22, "uint8", 0x030E, "single", "public", "optional", True, 1),
        (0x23, "uint8", 0x030E, "single", "public", "optional", True, 1),
        (0x24, "time", 0x030E, "single", "public", "optional", True, 4),
        (0x25, "opaque", 0x030F, "single", "potentially-secret", "optional", False, None),
        (0x26, "opaque", 0x030F, "single", "potentially-secret", "attachment-required", False, None),
        (0x27, "opaque", 0x030F, "single", "potentially-secret", "optional", False, None),
        (0x28, "opaque", 0x030F, "single", "potentially-secret", "optional", False, 4),
        (0x29, "opaque", 0x030F, "single", "potentially-secret", "optional", False, None),
        (0x2A, "opaque", 0x0310, "single", "potentially-secret", "passkey-required", False, None),
        (0x2B, "opaque", 0x0310, "single", "potentially-secret", "passkey-required", False, None),
        (0x2C, "opaque", 0x0310, "single", "potentially-secret", "passkey-required", False, None),
        (0x2D, "opaque", 0x0310, "single", "potentially-secret", "passkey-required", False, 4),
        (0x2E, "opaque", 0x0310, "single", "potentially-secret", "passkey-required", False, None),
        (0x2F, "opaque", 0x0310, "single", "potentially-secret", "passkey-required", False, 4),
        (0x30, "text", 0x0311, "single", "potentially-secret", "optional", True, None),
        (0xDF, "opaque", 0x0300, "multiple", "potentially-secret", "optional", False, None),
        (0xFF, "empty", 0x0300, "single", "public", "terminator", False, 0),
    )
    observed = tuple(
        (
            int(type_code), spec.kind.value, spec.since.value, spec.multiplicity.value, spec.secrecy.value,
            spec.mandatory_role.value, spec.editable, spec.fixed_length,
        )
        for type_code, spec in RECORD_SCHEMA.items()
    )
    assert observed == expected
    assert RECORD_SCHEMA[RecordFieldType.ATTACHMENT_CONTENT].kind is FieldKind.OPAQUE
    assert RECORD_SCHEMA[RecordFieldType.ATTACHMENT_CONTENT].since == FormatVersion.from_uint16(0x030F)
    assert HEADER_SCHEMA[HeaderFieldType.EMPTY_GROUPS].multiplicity is FieldMultiplicity.MULTIPLE
    assert RECORD_SCHEMA[RecordFieldType.PASSWORD].secrecy is SecretClassification.SECRET
    assert RECORD_SCHEMA[RecordFieldType.TITLE].mandatory_role is MandatoryRole.RECORD_REQUIRED



#### Prevent runtime mutation from changing the authoritative schema tables.
####
def test_field_specs_are_immutable() -> None:
    spec = RECORD_SCHEMA[RecordFieldType.TITLE]
    with pytest.raises(FrozenInstanceError):
        # Exercise the runtime guard through the assignment static typing already rejects.
        spec.editable = False  # type: ignore[misc]



#### Decode all fixed-width integers and timestamps in little-endian order.
####
@pytest.mark.parametrize(
    ("type_code", "data", "expected"),
    [
        (RecordFieldType.DOUBLE_CLICK_ACTION, b"\x34\x12", 0x1234),
        (RecordFieldType.KEYBOARD_SHORTCUT, b"\x78\x56\x34\x12", 0x12345678),
        (RecordFieldType.PROTECTED, b"\x80", 0x80),
        (RecordFieldType.CREATION_TIME, b"\x04\x03\x02\x01", 0x01020304),
        (RecordFieldType.CREATION_TIME, b"89aBCdEf", 0x89ABCDEF),
    ],
)
def test_record_decoder_validates_little_endian_and_historical_time(
    type_code: RecordFieldType,
    data: bytes,
    expected: int,
) -> None:
    raw = _raw(type_code, data)
    decoded = decode_record_field(raw, record_ordinal=2)
    assert decoded.raw is raw
    assert decoded.value == expected
    assert decoded.warning is None
    decoded.close()
    raw.payload.close()



#### Decode an RFC 4122 UUID without replacing its original payload owner.
####
def test_uuid_projection_retains_original_raw_field() -> None:
    expected = UUID("22222222-2222-4222-8222-222222222222")
    raw = _raw(RecordFieldType.UUID, expected.bytes)
    decoded = decode_record_field(raw, record_ordinal=0)
    assert decoded.raw is raw
    assert decoded.value == expected
    assert _payload_bytes(raw.payload) == expected.bytes
    decoded.close()
    raw.payload.close()



#### Decode the mandatory header version as its exact supported value object.
####
def test_header_version_projection_uses_little_endian_uint16() -> None:
    raw = _raw(HeaderFieldType.VERSION, b"\x11\x03")
    decoded = decode_header_field(raw)
    assert decoded.raw is raw
    assert decoded.value == FormatVersion.from_uint16(0x0311)
    decoded.close()
    raw.payload.close()



#### Keep malformed optional UTF-8 byte-for-byte and return only a safe warning.
####
@pytest.mark.parametrize("data", [b"\xef\xbb\xbftext", b"\xff", b"\xc0\x80"])
def test_malformed_optional_text_is_preserved_without_typed_value(data: bytes) -> None:
    raw = _raw(RecordFieldType.URL, data, ordinal=7)
    decoded = decode_record_field(raw, record_ordinal=3)
    assert decoded.raw is raw
    assert decoded.value is None
    assert decoded.warning is not None
    assert decoded.warning.record_ordinal == 3
    assert decoded.warning.field_ordinal == 7
    assert decoded.warning.type_code == 0x0D
    assert data not in repr(decoded.warning).encode("utf-8")
    assert _payload_bytes(raw.payload) == data
    decoded.close()
    raw.payload.close()



#### Fail closed when a mandatory title is empty or malformed UTF-8.
####
@pytest.mark.parametrize("data", [b"", b"\xff", b"\xef\xbb\xbfTitle"])
def test_malformed_mandatory_text_fails_closed(data: bytes) -> None:
    raw = _raw(RecordFieldType.TITLE, data)
    with pytest.raises(MalformedVaultError, match="vault content is malformed") as caught:
        decode_record_field(raw, record_ordinal=0)
    if data:
        assert data not in repr(caught.value).encode("utf-8")
    assert _payload_bytes(raw.payload) == data
    raw.payload.close()



#### Return secret text through an owned buffer whose repr never contains it.
####
def test_secret_projection_owns_and_wipes_password_bytes() -> None:
    raw = _raw(RecordFieldType.PASSWORD, b"fabricated-password")
    decoded = decode_record_field(raw, record_ordinal=0)
    assert isinstance(decoded.value, SecretBuffer)
    secret = decoded.value
    borrowed = secret.borrow()
    assert bytes(borrowed) == b"fabricated-password"
    assert "fabricated-password" not in repr(decoded)
    decoded.close()
    assert bytes(borrowed) == bytes(len(borrowed))
    assert secret.closed
    assert _payload_bytes(raw.payload) == b"fabricated-password"
    raw.payload.close()



#### Recognize attachment content without reading or exposing its opaque payload.
####
def test_opaque_projection_never_materializes_payload() -> None:
    raw = RawField(RecordFieldType.ATTACHMENT_CONTENT, _ExplodingPayload(), 0, FieldClassification.UNDERSTOOD)
    decoded = decode_record_field(raw, record_ordinal=0)
    assert decoded.raw is raw
    assert decoded.value is None
    assert decoded.warning is None
    decoded.close()



#### Allocate a new payload only for an explicit edit and retain raw coordinates.
####
def test_explicit_text_edit_replaces_only_the_target_payload() -> None:
    original = _raw(RecordFieldType.TITLE, b"Original", ordinal=4)
    edited = encode_record_field(original, "Changed")
    assert edited is not original
    assert edited.payload is not original.payload
    assert edited.type_code == original.type_code
    assert edited.ordinal == original.ordinal
    assert _payload_bytes(edited.payload) == b"Changed"
    assert _payload_bytes(original.payload) == b"Original"
    edited.payload.close()
    original.payload.close()



#### Encode supported header values in canonical explicit-edit representation.
####
@pytest.mark.parametrize(
    ("type_code", "value", "expected"),
    [
        (HeaderFieldType.LAST_SAVE_TIME, 0x01020304, b"\x04\x03\x02\x01"),
        (HeaderFieldType.DATABASE_NAME, "Caf\u00e9", b"Caf\xc3\xa9"),
    ],
)
def test_header_encoder_uses_canonical_explicit_edit_representation(
    type_code: HeaderFieldType,
    value: int | str,
    expected: bytes,
) -> None:
    original = _raw(type_code, b"old")
    edited = encode_header_field(original, value)
    assert _payload_bytes(edited.payload) == expected
    assert _payload_bytes(original.payload) == b"old"
    edited.payload.close()
    original.payload.close()



#### Reject a legacy target before output when any field is too new or unknown.
####
def test_export_preflight_rejects_custom_and_unknown_fields() -> None:
    custom = _raw(RecordFieldType.CUSTOM_TEXT_FIELD, b"010001n020001v")
    unknown = _raw(0xE0, b"unknown", ordinal=1)
    with pytest.raises(IncompatibleExportError, match="vault export is incompatible"):
        ensure_fields_representable(
            (custom,), section="record", target_version=FormatVersion.from_uint16(0x0310),
        )
    with pytest.raises(IncompatibleExportError, match="vault export is incompatible"):
        ensure_fields_representable(
            (unknown,), section="record", target_version=FormatVersion.from_uint16(0x0311),
        )
    custom.payload.close()
    unknown.payload.close()
