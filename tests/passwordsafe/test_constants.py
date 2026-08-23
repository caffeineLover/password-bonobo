"""Verify PasswordSafe V3 constants retain their independently specified values.

The tests define format expectations directly so parser implementation cannot
silently redefine envelope or field identifiers.
"""

from dataclasses import FrozenInstanceError

import pytest

from bonobo_core.passwordsafe.constants import (
    BLOCK_BYTES,
    CURRENT_FORMAT_VERSION,
    EOF_MARKER,
    FIELD_FIRST_BLOCK_DATA_BYTES,
    FILE_TAG,
    HMAC_BYTES,
    IV_BYTES,
    MINIMUM_ITERATIONS,
    SALT_BYTES,
    FieldKind,
    FormatVersion,
    HeaderFieldType,
    RecordFieldType,
    ResourceLimits,
)



#### Encode the approved current format level as two little-endian bytes.
####
#### The test derives the bytes from the PasswordSafe V3 format description,
#### keeping this foundational conversion independent of later codec code.
####
def test_format_version_round_trip() -> None:
    version = FormatVersion.from_uint16(0x0311)

    assert version.to_bytes() == b"\x11\x03"
    assert version.supported
    assert version == CURRENT_FORMAT_VERSION



#### Reject version values that do not fit the unsigned two-byte field.
####
def test_format_version_rejects_out_of_range_values() -> None:
    with pytest.raises(ValueError, match="format version must fit uint16"):
        FormatVersion.from_uint16(-1)

    with pytest.raises(ValueError, match="format version must fit uint16"):
        FormatVersion.from_uint16(0x1_0000)



#### Expose only the approved editable PasswordSafe V3 version range.
####
def test_format_version_support_range_is_inclusive() -> None:
    assert FormatVersion.from_uint16(0x0300).supported
    assert FormatVersion.from_uint16(0x0311).supported
    assert not FormatVersion.from_uint16(0x02FF).supported
    assert not FormatVersion.from_uint16(0x0312).supported



#### Preserve the fixed envelope sizes defined by PasswordSafe V3.
####
def test_envelope_constants_match_the_v3_format() -> None:
    assert FILE_TAG == b"PWS3"
    assert EOF_MARKER == b"PWS3-EOFPWS3-EOF"
    assert BLOCK_BYTES == 16
    assert SALT_BYTES == 32
    assert IV_BYTES == 16
    assert HMAC_BYTES == 32
    assert FIELD_FIRST_BLOCK_DATA_BYTES == 11
    assert MINIMUM_ITERATIONS == 262_144



#### Retain the official field identifiers without collapsing header and record scopes.
####
def test_field_enums_preserve_official_type_codes() -> None:
    assert HeaderFieldType.VERSION.value == 0x00
    assert HeaderFieldType.UUID.value == 0x01
    assert HeaderFieldType.YUBICO.value == 0x12
    assert HeaderFieldType.END.value == 0xFF
    assert RecordFieldType.UUID.value == 0x01
    assert RecordFieldType.PASSWORD.value == 0x06
    assert RecordFieldType.ATTACHMENT_CONTENT.value == 0x29
    assert RecordFieldType.PASSKEY_PRIVATE_KEY.value == 0x2E
    assert RecordFieldType.CUSTOM_TEXT_FIELD.value == 0x30
    assert RecordFieldType.END.value == 0xFF
    assert FieldKind.OPAQUE.value == "opaque"



#### Keep resource budgets immutable so downstream parsing cannot widen them in place.
####
def test_resource_limits_have_approved_immutable_defaults() -> None:
    limits = ResourceLimits()

    assert limits.max_iterations == 10_000_000
    assert limits.max_records == 1_000_000
    assert limits.max_fields == 2_000_000
    assert limits.max_inline_payload_bytes == 1_048_576
    assert limits.max_decoded_text_bytes == 16_777_216
    assert limits.io_chunk_bytes == 65_536
    with pytest.raises(FrozenInstanceError):
        limits.__setattr__("max_records", 1)



#### Accept a caller policy only when every value stays within the approved ceiling.
####
#### A caller may narrow all budgets at once, but the exact defaults remain the
#### widest valid policy and therefore establish each construction boundary.
####
def test_resource_limits_accept_exact_approved_ceilings() -> None:
    limits = ResourceLimits(
        max_iterations=10_000_000,
        max_records=1_000_000,
        max_fields=2_000_000,
        max_inline_payload_bytes=1_048_576,
        max_decoded_text_bytes=16_777_216,
        io_chunk_bytes=65_536,
    )

    assert limits == ResourceLimits()



#### Reject nonpositive and widened iteration budgets at the construction boundary.
####
def test_resource_limits_reject_invalid_iteration_budget() -> None:
    for value in (0, -1, 10_000_001):
        with pytest.raises(ValueError, match="max_iterations"):
            ResourceLimits(max_iterations=value)



#### Reject nonpositive and widened record budgets at the construction boundary.
####
def test_resource_limits_reject_invalid_record_budget() -> None:
    for value in (0, -1, 1_000_001):
        with pytest.raises(ValueError, match="max_records"):
            ResourceLimits(max_records=value)



#### Reject nonpositive and widened field budgets at the construction boundary.
####
def test_resource_limits_reject_invalid_field_budget() -> None:
    for value in (0, -1, 2_000_001):
        with pytest.raises(ValueError, match="max_fields"):
            ResourceLimits(max_fields=value)



#### Reject nonpositive and widened inline payload budgets at construction.
####
def test_resource_limits_reject_invalid_inline_payload_budget() -> None:
    for value in (0, -1, 1_048_577):
        with pytest.raises(ValueError, match="max_inline_payload_bytes"):
            ResourceLimits(max_inline_payload_bytes=value)



#### Reject nonpositive and widened decoded-text budgets at construction.
####
def test_resource_limits_reject_invalid_decoded_text_budget() -> None:
    for value in (0, -1, 16_777_217):
        with pytest.raises(ValueError, match="max_decoded_text_bytes"):
            ResourceLimits(max_decoded_text_bytes=value)



#### Reject nonpositive and widened chunk budgets so streaming always progresses.
####
def test_resource_limits_reject_invalid_io_chunk_budget() -> None:
    for value in (0, -1, 65_537):
        with pytest.raises(ValueError, match="io_chunk_bytes"):
            ResourceLimits(io_chunk_bytes=value)
