"""Verify lossless parsing and targeted edits of official custom text fields."""

import copy
import gc
import pickle
import weakref

import pytest

import bonobo_core.passwordsafe.custom_fields as custom_fields_module
from bonobo_core.passwordsafe.constants import FormatVersion, RecordFieldType
from bonobo_core.passwordsafe.custom_fields import (
    CustomField,
    CustomProperty,
    encode_custom_fields,
    ensure_custom_fields_representable,
    parse_custom_fields,
    replace_custom_value,
)
from bonobo_core.passwordsafe.errors import IncompatibleExportError, ResourceLimitError
from bonobo_core.passwordsafe.model import FieldClassification, RawField
from bonobo_core.passwordsafe.payloads import FieldPayload, InlinePayload
from bonobo_core.passwordsafe.schema import encode_record_field
from bonobo_core.passwordsafe.secrets import SecretBuffer



#### Close every independently owned custom field after one assertion finishes.
####
def _close_fields(fields: tuple[CustomField, ...]) -> None:
    for custom_field in fields:
        custom_field.close()



#### Build one exact custom raw field for the targeted edit boundary.
####
def _raw_custom(data: bytes, *, ordinal: int = 0) -> RawField:
    return RawField(
        RecordFieldType.CUSTOM_TEXT_FIELD,
        InlinePayload.from_bytes(data),
        ordinal,
        FieldClassification.UNDERSTOOD,
    )



#### Read one small payload for preservation assertions without production codecs.
####
def _payload_bytes(payload: FieldPayload) -> bytes:
    return b"".join(bytes(chunk) for chunk in payload.iter_chunks(64))



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



#### Parse, reveal, and re-encode a present empty value without normalization.
####
def test_custom_field_value_may_be_empty() -> None:
    encoded = b"010004Name0200007f0003xyz"
    parsed = parse_custom_fields(encoded)
    assert encode_custom_fields(parsed) == encoded
    with parsed[0].reveal_value(max_bytes=1) as lease:
        assert bytes(lease.borrow()) == b""
    edited = replace_custom_value(
        parsed,
        name="Name",
        value=SecretBuffer.from_bytes(b"filled"),
    )
    assert encode_custom_fields(edited) == b"010004Name020006filled7f0003xyz"
    _close_fields(edited)
    _close_fields(parsed)



#### Encode an explicit empty replacement while retaining unrelated properties.
####
def test_custom_value_edit_accepts_empty_secret_buffer() -> None:
    parsed = parse_custom_fields(b"010004Name7f0003xyz020005Value")
    replacement = SecretBuffer.from_bytes(b"")
    edited = replace_custom_value(parsed, name="Name", value=replacement)
    assert replacement.closed
    assert encode_custom_fields(edited) == b"010004Name7f0003xyz020000"
    _close_fields(edited)
    _close_fields(parsed)



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



#### Reject generic UTF-8 replacement for the structured custom field payload.
####
def test_custom_raw_field_rejects_generic_text_encoding() -> None:
    raw = _raw_custom(b"010004Name020005Value")
    with pytest.raises(ValueError, match="field is not editable"):
        encode_record_field(raw, "arbitrary text")
    assert _payload_bytes(raw.payload) == b"010004Name020005Value"
    raw.payload.close()



#### Target one custom value while retaining exact unknown and unrelated bytes.
####
def test_targeted_custom_raw_edit_preserves_source_and_structural_metadata() -> None:
    original = b"7f0003xyz010004Name040003abc020005Value0300010"
    raw = _raw_custom(original, ordinal=9)
    replacement = SecretBuffer.from_bytes(b"Other")
    edited = custom_fields_module.replace_custom_raw_field_value(
        raw,
        name="Name",
        value=replacement,
        sensitive=True,
    )
    assert replacement.closed
    assert edited.type_code == raw.type_code
    assert edited.ordinal == 9
    assert edited.classification is raw.classification
    assert _payload_bytes(raw.payload) == original
    assert _payload_bytes(edited.payload) == b"7f0003xyz010004Name040003abc020005Other0300011"
    edited.payload.close()
    raw.payload.close()



#### Consume replacement ownership when raw custom parsing fails before editing.
####
def test_targeted_custom_raw_edit_cleans_failure_ownership() -> None:
    original = b"010004Name020005x"
    raw = _raw_custom(original)
    replacement = SecretBuffer.from_bytes(b"Other")
    with pytest.raises(ValueError):
        custom_fields_module.replace_custom_raw_field_value(
            raw,
            name="Name",
            value=replacement,
        )
    assert replacement.closed
    assert _payload_bytes(raw.payload) == original
    raw.payload.close()



#### Wipe source plaintext if custom-field secret ownership transfer fails.
####
@pytest.mark.parametrize("error_type", [ValueError, KeyboardInterrupt])
def test_targeted_custom_raw_edit_wipes_failed_source_transfer(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    original = b"010004Name020005Value"
    raw = _raw_custom(original)
    replacement = SecretBuffer.from_bytes(b"Other")
    replacement_view = replacement.borrow()
    retained: list[bytearray] = []
    close_calls = 0
    original_close = SecretBuffer.close
    failure = error_type("synthetic secret transfer failure")



    #### Retain the exact offered source and fail after possible adoption.
    ####
    def fail_transfer(_cls: type[SecretBuffer], candidate: bytearray) -> SecretBuffer:
        retained.append(candidate)
        raise failure



    #### Count only cleanup of the caller-supplied replacement owner.
    ####
    def track_close(owner: SecretBuffer) -> None:
        nonlocal close_calls
        if owner is replacement:
            close_calls += 1
        original_close(owner)

    monkeypatch.setattr(SecretBuffer, "take_ownership", classmethod(fail_transfer))
    monkeypatch.setattr(SecretBuffer, "close", track_close)
    with pytest.raises(error_type) as caught:
        custom_fields_module.replace_custom_raw_field_value(
            raw,
            name="Name",
            value=replacement,
        )
    assert caught.value is failure
    assert len(retained) == 1
    assert bytes(retained[0]) == bytes(len(retained[0]))
    assert close_calls == 1
    assert replacement.closed
    assert bytes(replacement_view) == bytes(len(replacement_view))
    assert _payload_bytes(raw.payload) == original
    raw.payload.close()



#### Wipe all custom temporaries if result payload ownership transfer fails.
####
@pytest.mark.parametrize("error_type", [ValueError, KeyboardInterrupt])
def test_targeted_custom_raw_edit_wipes_failed_result_transfer(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    original = b"7f0003xyz010004Name020005Value"
    raw = _raw_custom(original)
    replacement = SecretBuffer.from_bytes(b"Other")
    replacement_view = replacement.borrow()
    source_candidates: list[bytearray] = []
    result_candidates: list[bytearray] = []
    close_calls = 0
    original_secret_transfer = SecretBuffer.take_ownership
    original_close = SecretBuffer.close
    failure = error_type("synthetic payload transfer failure")



    #### Track every secret candidate while preserving ordinary adoption behavior.
    ####
    def track_secret_transfer(_cls: type[SecretBuffer], candidate: bytearray) -> SecretBuffer:
        source_candidates.append(candidate)
        return original_secret_transfer(candidate)



    #### Retain the exact result candidate and fail after possible adoption.
    ####
    def fail_result_transfer(_cls: type[InlinePayload], candidate: bytearray) -> InlinePayload:
        result_candidates.append(candidate)
        raise failure



    #### Count only cleanup of the caller-supplied replacement owner.
    ####
    def track_close(owner: SecretBuffer) -> None:
        nonlocal close_calls
        if owner is replacement:
            close_calls += 1
        original_close(owner)

    monkeypatch.setattr(SecretBuffer, "take_ownership", classmethod(track_secret_transfer))
    monkeypatch.setattr(InlinePayload, "take_ownership", classmethod(fail_result_transfer))
    monkeypatch.setattr(SecretBuffer, "close", track_close)
    with pytest.raises(error_type) as caught:
        custom_fields_module.replace_custom_raw_field_value(
            raw,
            name="Name",
            value=replacement,
        )
    assert caught.value is failure
    assert source_candidates
    assert all(bytes(candidate) == bytes(len(candidate)) for candidate in source_candidates)
    assert len(result_candidates) == 1
    assert bytes(result_candidates[0]) == bytes(len(result_candidates[0]))
    assert close_calls == 1
    assert replacement.closed
    assert bytes(replacement_view) == bytes(len(replacement_view))
    assert _payload_bytes(raw.payload) == original
    raw.payload.close()



#### Wipe parsed and edited property candidates on failed secret adoption.
####
@pytest.mark.parametrize("transfer_number", [2, 7], ids=("parsed-property", "edited-property"))
@pytest.mark.parametrize("error_type", [ValueError, KeyboardInterrupt])
def test_targeted_custom_raw_edit_wipes_failed_property_transfer(
    monkeypatch: pytest.MonkeyPatch,
    transfer_number: int,
    error_type: type[BaseException],
) -> None:
    original = b"7f0003xyz010004Name020005Value"
    raw = _raw_custom(original)
    replacement = SecretBuffer.from_bytes(b"Other")
    replacement_view = replacement.borrow()
    retained: list[bytearray] = []
    close_calls = 0
    original_secret_transfer = SecretBuffer.take_ownership
    original_close = SecretBuffer.close
    failure = error_type("synthetic property transfer failure")



    #### Fail one selected adoption after retaining its exact candidate.
    ####
    def fail_selected_transfer(_cls: type[SecretBuffer], candidate: bytearray) -> SecretBuffer:
        retained.append(candidate)
        if len(retained) == transfer_number:
            raise failure
        return original_secret_transfer(candidate)



    #### Count only cleanup of the caller-supplied replacement owner.
    ####
    def track_close(owner: SecretBuffer) -> None:
        nonlocal close_calls
        if owner is replacement:
            close_calls += 1
        original_close(owner)

    monkeypatch.setattr(SecretBuffer, "take_ownership", classmethod(fail_selected_transfer))
    monkeypatch.setattr(SecretBuffer, "close", track_close)
    with pytest.raises(error_type) as caught:
        custom_fields_module.replace_custom_raw_field_value(
            raw,
            name="Name",
            value=replacement,
        )
    assert caught.value is failure
    assert len(retained) == transfer_number
    assert all(bytes(candidate) == bytes(len(candidate)) for candidate in retained)
    assert close_calls == 1
    assert replacement.closed
    assert bytes(replacement_view) == bytes(len(replacement_view))
    assert _payload_bytes(raw.payload) == original
    raw.payload.close()



#### Reject result growth by encoded byte size before payload publication.
####
@pytest.mark.parametrize(
    ("original", "replacement_bytes", "max_bytes"),
    [
        (b"010004Name020001x", b"12345", 20),
        (b"010001N020001x", "éé".encode(), 16),
        (b"7f0003xyz010001N020001x", b"1234", 25),
    ],
    ids=("growth", "multibyte-utf8", "unknown-overhead"),
)
def test_targeted_custom_raw_edit_enforces_symmetric_result_byte_bound(
    monkeypatch: pytest.MonkeyPatch,
    original: bytes,
    replacement_bytes: bytes,
    max_bytes: int,
) -> None:
    raw = _raw_custom(original)
    replacement = SecretBuffer.from_bytes(replacement_bytes)
    replacement_view = replacement.borrow()
    source_candidates: list[bytearray] = []
    result_candidates: list[bytearray] = []
    payload_calls = 0
    close_calls = 0
    original_secret_transfer = SecretBuffer.take_ownership
    original_encode = custom_fields_module._encode_custom_fields_owned
    original_close = SecretBuffer.close



    #### Track every adopted source/property candidate for deterministic cleanup.
    ####
    def track_secret_transfer(_cls: type[SecretBuffer], candidate: bytearray) -> SecretBuffer:
        source_candidates.append(candidate)
        return original_secret_transfer(candidate)



    #### Retain the encoded result candidate so rejection can prove its wipe.
    ####
    def track_result(fields: tuple[CustomField, ...]) -> bytearray:
        candidate = original_encode(fields)
        result_candidates.append(candidate)
        return candidate



    #### Fail if an oversized result reaches payload ownership publication.
    ####
    def reject_payload_call(_cls: type[InlinePayload], candidate: bytearray) -> InlinePayload:
        nonlocal payload_calls
        payload_calls += 1
        raise AssertionError(f"oversized candidate reached payload factory: {len(candidate)}")



    #### Count only cleanup of the caller-supplied replacement owner.
    ####
    def track_close(owner: SecretBuffer) -> None:
        nonlocal close_calls
        if owner is replacement:
            close_calls += 1
        original_close(owner)

    monkeypatch.setattr(SecretBuffer, "take_ownership", classmethod(track_secret_transfer))
    monkeypatch.setattr(custom_fields_module, "_encode_custom_fields_owned", track_result)
    monkeypatch.setattr(InlinePayload, "take_ownership", classmethod(reject_payload_call))
    monkeypatch.setattr(SecretBuffer, "close", track_close)
    with pytest.raises(ResourceLimitError, match="vault resource limit exceeded"):
        custom_fields_module.replace_custom_raw_field_value(
            raw,
            name="Name" if b"Name" in original else "N",
            value=replacement,
            max_bytes=max_bytes,
        )
    assert payload_calls == 0
    assert len(result_candidates) == 1
    assert bytes(result_candidates[0]) == bytes(len(result_candidates[0]))
    assert source_candidates
    assert all(bytes(candidate) == bytes(len(candidate)) for candidate in source_candidates)
    assert close_calls == 1
    assert replacement.closed
    assert bytes(replacement_view) == bytes(len(replacement_view))
    assert _payload_bytes(raw.payload) == original
    raw.payload.close()



#### Accept an exact-bound result and allow it to be re-edited under that bound.
####
def test_targeted_custom_raw_edit_accepts_exact_result_bound_and_reedit() -> None:
    raw = _raw_custom(b"010004Name020001x")
    edited = custom_fields_module.replace_custom_raw_field_value(
        raw,
        name="Name",
        value=SecretBuffer.from_bytes(b"12345"),
        max_bytes=21,
    )
    assert edited.payload.length == 21
    assert _payload_bytes(edited.payload) == b"010004Name02000512345"
    reedited = custom_fields_module.replace_custom_raw_field_value(
        edited,
        name="Name",
        value=SecretBuffer.from_bytes(b""),
        max_bytes=21,
    )
    assert _payload_bytes(reedited.payload) == b"010004Name020000"
    reedited.payload.close()
    edited.payload.close()
    raw.payload.close()



#### Permit a shrinking edit when both source and result fit the same bound.
####
def test_targeted_custom_raw_edit_allows_shrinking_with_symmetric_bound() -> None:
    original = b"010001N020008abcdefgh"
    raw = _raw_custom(original)
    edited = custom_fields_module.replace_custom_raw_field_value(
        raw,
        name="N",
        value=SecretBuffer.from_bytes(b""),
        max_bytes=len(original),
    )
    assert _payload_bytes(edited.payload) == b"010001N020000"
    assert _payload_bytes(raw.payload) == original
    edited.payload.close()
    raw.payload.close()



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
    [b"\xff", b"\xef\xbb\xbfvalue", b"x" * 65_536],
    ids=("invalid-utf8", "bom", "too-long"),
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
