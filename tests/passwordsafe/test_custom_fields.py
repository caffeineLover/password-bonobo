"""Verify lossless parsing and targeted edits of official custom text fields."""

import copy
import gc
import pickle
import weakref

import pytest

from bonobo_core.passwordsafe.constants import FormatVersion
from bonobo_core.passwordsafe.custom_fields import (
    CustomField,
    CustomProperty,
    encode_custom_fields,
    ensure_custom_fields_representable,
    parse_custom_fields,
    replace_custom_value,
)
from bonobo_core.passwordsafe.errors import IncompatibleExportError
from bonobo_core.passwordsafe.secrets import SecretBuffer



#### Close every independently owned custom field after one assertion finishes.
####
def _close_fields(fields: tuple[CustomField, ...]) -> None:
    for custom_field in fields:
        custom_field.close()



#### Parse and re-encode canonical property bytes without normalization.
####
def test_custom_fields_round_trip_exact_bytes_and_order() -> None:
    encoded = b"7f0003xyz010004Name020005Value0300011"
    parsed = parse_custom_fields(encoded)
    assert len(parsed) == 1
    assert parsed[0].name == "Name"
    assert parsed[0].sensitive
    assert tuple(item.property_id for item in parsed[0].properties) == (0x7F, 0x01, 0x02, 0x03)
    assert encode_custom_fields(parsed) == encoded
    with parsed[0].reveal_value(max_bytes=16) as lease:
        assert bytes(lease.borrow()) == b"Value"
    _close_fields(parsed)



#### Preserve separators, multiple fields, and an allowed trailing separator.
####
def test_custom_field_separators_round_trip_exactly() -> None:
    encoded = b"010003One0200011000000010003Two0200012000000"
    parsed = parse_custom_fields(encoded)
    assert tuple(item.name for item in parsed) == ("One", "Two")
    assert encode_custom_fields(parsed) == encoded
    _close_fields(parsed)



#### Reject noncanonical, truncated, duplicate, or invalid property sequences safely.
####
@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"000000",
        b"010001n000000000000",
        b"010001n010001x020001v",
        b"010001n020001v020001x",
        b"010000020001v",
        b"010001n020000",
        b"010001n020001v0300012",
        b"010001n020001v03000210",
        b"010001n020001\xff",
        b"010001n020004\xef\xbb\xbfx",
        b"0A0001x010001n020001v",
        b"01000Annnnnnnnnn020001v",
        b"040001x010001n020001v040001y",
        b"010001n020005x",
    ],
)
def test_custom_field_parser_rejects_malformed_grammar(encoded: bytes) -> None:
    with pytest.raises(ValueError) as caught:
        parse_custom_fields(encoded)
    if encoded:
        assert encoded not in repr(caught.value).encode("utf-8")



#### Require names to be unique across custom fields, including Unicode names.
####
def test_custom_field_names_are_unique_and_nonempty() -> None:
    duplicate = b"010004Name0200011000000010004Name0200012"
    with pytest.raises(ValueError, match="custom field names must be unique"):
        parse_custom_fields(duplicate)



#### Replace only the selected value while retaining unknown property bytes.
####
def test_unknown_custom_property_survives_value_edit() -> None:
    encoded = b"010004Name020005Value7f0003xyz"
    parsed = parse_custom_fields(encoded)
    replacement = SecretBuffer.from_bytes(b"Other")
    edited = replace_custom_value(parsed, name="Name", value=replacement)
    assert replacement.closed
    assert encode_custom_fields(edited) == b"010004Name020005Other7f0003xyz"
    assert encode_custom_fields(parsed) == encoded
    _close_fields(edited)
    _close_fields(parsed)



#### Replace sensitivity in place and leave unrelated custom fields exact.
####
def test_targeted_replacement_changes_only_value_and_sensitivity_properties() -> None:
    encoded = b"010003One7f0003abc020003old0300010000000010003Two020004same"
    parsed = parse_custom_fields(encoded)
    replacement = SecretBuffer.from_bytes(b"new")
    edited = replace_custom_value(parsed, name="One", value=replacement, sensitive=True)
    assert encode_custom_fields(edited) == b"010003One7f0003abc020003new0300011000000010003Two020004same"
    assert encode_custom_fields(parsed) == encoded
    _close_fields(edited)
    _close_fields(parsed)



#### Insert an explicitly requested sensitivity property directly after value.
####
def test_targeted_replacement_inserts_missing_sensitivity_after_value() -> None:
    parsed = parse_custom_fields(b"010004Name7f0003xyz020003old")
    edited = replace_custom_value(
        parsed, name="Name", value=SecretBuffer.from_bytes(b"new"), sensitive=False,
    )
    assert encode_custom_fields(edited) == b"010004Name7f0003xyz020003new0300010"
    _close_fields(edited)
    _close_fields(parsed)



#### Consume and wipe replacement ownership even when the target does not exist.
####
def test_failed_replacement_still_closes_supplied_secret() -> None:
    parsed = parse_custom_fields(b"010004Name020005Value")
    replacement = SecretBuffer.from_bytes(b"Other")
    with pytest.raises(ValueError, match="custom field was not found"):
        replace_custom_value(parsed, name="Missing", value=replacement)
    assert replacement.closed
    assert encode_custom_fields(parsed) == b"010004Name020005Value"
    _close_fields(parsed)



#### Reject replacement bytes that are empty, invalid UTF-8, BOM-prefixed, or too long.
####
@pytest.mark.parametrize(
    "data",
    [b"", b"\xff", b"\xef\xbb\xbfvalue", b"x" * 65_536],
    ids=("empty", "invalid-utf8", "bom", "too-long"),
)
def test_replacement_value_obeys_official_text_and_length_rules(data: bytes) -> None:
    parsed = parse_custom_fields(b"010004Name020005Value")
    replacement = SecretBuffer.from_bytes(data)
    with pytest.raises(ValueError):
        replace_custom_value(parsed, name="Name", value=replacement)
    assert replacement.closed
    assert encode_custom_fields(parsed) == b"010004Name020005Value"
    _close_fields(parsed)



#### Reject legacy export before writer or service code creates output.
####
def test_custom_fields_block_legacy_export_preflight() -> None:
    parsed = parse_custom_fields(b"010004Name020005Value")
    with pytest.raises(IncompatibleExportError, match="vault export is incompatible"):
        ensure_custom_fields_representable(parsed, FormatVersion.from_uint16(0x0310))
    ensure_custom_fields_representable(parsed, FormatVersion.from_uint16(0x0311))
    _close_fields(parsed)



#### Reject generic copying, pickling, and direct state access for both owner types.
####
@pytest.mark.parametrize("owner_type", [CustomField, CustomProperty])
def test_custom_owners_reject_copy_pickle_and_state(owner_type: type[CustomField] | type[CustomProperty]) -> None:
    parsed = parse_custom_fields(b"010004Name020005Value")
    owner = parsed[0] if owner_type is CustomField else parsed[0].properties[0]
    with pytest.raises(TypeError, match=r"custom .* cannot be copied or serialized"):
        copy.copy(owner)
    with pytest.raises(TypeError, match=r"custom .* cannot be copied or serialized"):
        copy.deepcopy(owner)
    with pytest.raises(TypeError, match=r"custom .* cannot be copied or serialized"):
        pickle.dumps(owner)
    with pytest.raises(TypeError, match=r"custom .* cannot be copied or serialized"):
        owner.__getstate__()
    with pytest.raises(TypeError, match=r"custom .* cannot be copied or serialized"):
        owner.__setstate__({})
    _close_fields(parsed)



#### Make forgotten custom owners terminal through their defensive finalizers.
####
def test_custom_field_finalizer_closes_all_properties() -> None:
    parsed = parse_custom_fields(b"010004Name020005Value7f0003xyz")
    custom_field = parsed[0]
    properties = custom_field.properties
    field_reference = weakref.ref(custom_field)
    del parsed
    del custom_field
    gc.collect()
    assert field_reference() is None
    assert all(item.closed for item in properties)



#### Retry a transient property-close failure before finalizer ownership is severed.
####
def test_custom_field_finalizer_retries_failed_property(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = parse_custom_fields(b"010004Name020005Value")
    custom_field = parsed[0]
    properties = custom_field.properties
    original = CustomProperty.close
    attempts = 0



    #### Fail the first cleanup call once, then use the real deterministic wipe.
    ####
    def fail_once(custom_property: CustomProperty) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("synthetic close failure")
        original(custom_property)

    monkeypatch.setattr(CustomProperty, "close", fail_once)
    field_reference = weakref.ref(custom_field)
    del parsed
    del custom_field
    gc.collect()

    assert field_reference() is None
    assert attempts == 3
    assert all(item.closed for item in properties)



#### Accept the maximum four-hex-digit property length without over-reading.
####
def test_custom_property_accepts_ffff_byte_boundary() -> None:
    encoded = b"010001n02ffff" + b"x" * 0xFFFF
    parsed = parse_custom_fields(encoded)
    assert parsed[0].properties[1].value_length == 0xFFFF
    assert encode_custom_fields(parsed) == encoded
    _close_fields(parsed)



#### Reject reinitialization without altering a live custom owner's bytes.
####
def test_custom_owners_cannot_be_reinitialized() -> None:
    parsed = parse_custom_fields(b"010004Name020005Value")
    custom_field = parsed[0]
    custom_property = custom_field.properties[0]
    with pytest.raises(TypeError, match="custom field cannot be reinitialized"):
        CustomField.__init__(custom_field, (), name="Other", sensitive=False)
    with pytest.raises(TypeError, match="custom property cannot be reinitialized"):
        CustomProperty.__init__(custom_property, 0x01, bytearray(b"010005Other"))
    assert encode_custom_fields(parsed) == b"010004Name020005Value"
    _close_fields(parsed)
