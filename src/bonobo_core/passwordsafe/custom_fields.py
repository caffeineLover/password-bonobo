"""Parse, own, preserve, and selectively edit PasswordSafe custom text fields.

The official ``0x0311`` grammar stores ordered property entries separated by
``000000``.  Every property keeps its exact canonical source bytes in wipeable
storage, including unknown identifiers.  Targeted edits retain all other owners.
"""

from contextlib import suppress
from typing import NoReturn, SupportsIndex

from .constants import MAX_DECODED_TEXT_BYTES, MAX_IO_CHUNK_BYTES, FormatVersion, RecordFieldType
from .errors import (
    IncompatibleExportError,
    IncompatibleExportReason,
    ResourceLimitError,
    ResourceLimitReason,
)
from .model import RawField
from .payloads import InlinePayload
from .secrets import SecretBuffer, SecretLease



_SEPARATOR = b"000000"
_CUSTOM_FIELD_VERSION = FormatVersion.from_uint16(0x0311)



#### Own one exact custom-property encoding in mutable wipeable storage.
####
#### The stored bytes include the six-byte lowercase identifier/length header.
#### Unknown properties use the same owner and therefore retain exact ordering and
#### bytes without gaining invented semantics.
####
class CustomProperty:
    __slots__ = ("__weakref__", "_closed", "_encoded", "_value_length", "property_id")



    #### Adopt one complete validated property encoding without another copy.
    ####
    #### Reinitialization wipes the newly offered buffer before rejecting it, so a
    #### failed ownership transfer cannot strand an additional plaintext copy.
    ####
    def __init__(self, property_id: int, encoded: bytearray) -> None:
        if hasattr(self, "_encoded"):
            if isinstance(encoded, bytearray):
                encoded[:] = bytes(len(encoded))
            raise TypeError("custom property cannot be reinitialized")
        if isinstance(property_id, bool) or not isinstance(property_id, int) or not 1 <= property_id <= 0xFF:
            if isinstance(encoded, bytearray):
                encoded[:] = bytes(len(encoded))
            raise ValueError("custom property identifier must fit nonzero uint8")
        if not isinstance(encoded, bytearray):
            raise TypeError("custom property ownership requires a bytearray")
        try:
            value_length = _validate_complete_property_encoding(property_id, encoded)
        except BaseException:
            encoded[:] = bytes(len(encoded))
            raise
        self.property_id = property_id
        self._value_length = value_length
        self._encoded = SecretBuffer.take_ownership(encoded)
        self._closed = False



    #### Report the exact property value length without exposing its bytes.
    ####
    @property
    def value_length(self) -> int:
        return self._value_length



    #### Report whether exact property storage has already been wiped.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Borrow the complete exact encoding for bounded internal serialization.
    ####
    def _borrow_encoded(self) -> memoryview[int]:
        return self._encoded.borrow()



    #### Copy only this property's value into a new mutable owned buffer.
    ####
    def _copy_value(self) -> bytearray:
        encoded = self._encoded.borrow()
        return bytearray(encoded[6:])



    #### Fork one independently wipeable owner with byte-identical encoding.
    ####
    def retain(self) -> CustomProperty:
        return type(self)(self.property_id, bytearray(self._encoded.borrow()))



    #### Wipe this property's complete encoding exactly once.
    ####
    def close(self) -> None:
        if not self._closed:
            self._encoded.close()
            self._closed = True



    #### Defensively wipe forgotten property bytes without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Render only identifier, length, and lifecycle metadata.
    ####
    def __repr__(self) -> str:
        return (
            f"CustomProperty(property_id={self.property_id}, "
            f"value_length={self.value_length}, closed={self.closed})"
        )



    #### Reject shallow copying that would alias wipeable property storage.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("custom property cannot be copied or serialized")



    #### Reject deep copying that would duplicate a possibly sensitive value.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("custom property cannot be copied or serialized")



    #### Reject direct state extraction before property bytes are inspected.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("custom property cannot be copied or serialized")



    #### Reject fabricated state injection into a live property owner.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("custom property cannot be copied or serialized")



    #### Reject legacy serialization reduction for custom property owners.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("custom property cannot be copied or serialized")



    #### Reject protocol-specific serialization of custom property owners.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("custom property cannot be copied or serialized")



#### Own one ordered custom field and all of its exact property encodings.
####
#### The decoded name is retained only for unique targeting.  The custom value is
#### available solely through an explicit bounded secret lease, regardless of its
#### sensitivity flag, so unknown client display conventions cannot disclose it.
####
class CustomField:
    __slots__ = (
        "__weakref__",
        "_closed",
        "_closing",
        "name",
        "properties",
        "sensitive",
        "separator_after",
    )



    #### Adopt an ordered property tuple already validated by the parser or editor.
    ####
    def __init__(
        self,
        properties: tuple[CustomProperty, ...],
        *,
        name: str,
        sensitive: bool,
        separator_after: bool = False,
    ) -> None:
        if hasattr(self, "properties"):
            for item in properties:
                with suppress(BaseException):
                    item.close()
            raise TypeError("custom field cannot be reinitialized")
        if not isinstance(properties, tuple) or not all(isinstance(item, CustomProperty) for item in properties):
            raise TypeError("custom field properties must be an immutable owner tuple")
        if not isinstance(name, str) or not name:
            raise ValueError("custom field name cannot be empty")
        if not isinstance(sensitive, bool) or not isinstance(separator_after, bool):
            raise TypeError("custom field flags must be boolean")
        self.properties = properties
        self.name = name
        self.sensitive = sensitive
        self.separator_after = separator_after
        self._closed = False
        self._closing = False



    #### Report whether every owned property has been made terminal.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Return a short-lived separately owned lease of this custom value.
    ####
    def reveal_value(self, *, max_bytes: int) -> SecretLease:
        self._require_open()
        value_property = _property_by_id(self.properties, 0x02)
        value = value_property._copy_value()
        try:
            return SecretLease.from_bytes(bytes(value), max_bytes=max_bytes)
        finally:
            value[:] = bytes(len(value))



    #### Fork every property into an independently closable custom field owner.
    ####
    def retain(self) -> CustomField:
        self._require_open()
        retained: list[CustomProperty] = []
        try:
            retained = [item.retain() for item in self.properties]
            return type(self)(
                tuple(retained),
                name=self.name,
                sensitive=self.sensitive,
                separator_after=self.separator_after,
            )
        except BaseException:
            for item in retained:
                with suppress(BaseException):
                    item.close()
            raise



    #### Reject operations after cleanup begins or completes.
    ####
    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise RuntimeError("custom field is closed")



    #### Close every property exhaustively and retain failures for a retry.
    ####
    def close(self) -> None:
        if self._closed:
            return
        self._closing = True
        first_failure: BaseException | None = None
        pending: list[CustomProperty] = []
        for item in self.properties:
            try:
                item.close()
            except BaseException as error:
                pending.append(item)
                if first_failure is None:
                    first_failure = error
        if not pending:
            self._closed = True
            self._closing = False
        else:
            self.properties = tuple(pending)
        if first_failure is not None:
            raise first_failure



    #### Defensively exhaust cleanup and sever property references at shutdown.
    ####
    def __del__(self) -> None:
        for _attempt in range(2):
            try:
                self.close()
            except BaseException:
                continue
            break
        if not getattr(self, "_closed", False):
            for item in getattr(self, "properties", ()):
                with suppress(BaseException):
                    item.close()
        with suppress(BaseException):
            self._closed = True
            self._closing = False
            self.properties = ()



    #### Render only property count, sensitivity, and lifecycle metadata.
    ####
    def __repr__(self) -> str:
        return (
            f"CustomField(property_count={len(self.properties)}, "
            f"sensitive={self.sensitive}, closed={self.closed})"
        )



    #### Reject shallow copying that would alias an owned property graph.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("custom field cannot be copied or serialized")



    #### Reject deep copying that would duplicate sensitive custom values.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("custom field cannot be copied or serialized")



    #### Reject direct state extraction before custom properties are inspected.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("custom field cannot be copied or serialized")



    #### Reject fabricated state injection into a live custom field owner.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("custom field cannot be copied or serialized")



    #### Reject legacy serialization reduction for custom field owners.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("custom field cannot be copied or serialized")



    #### Reject protocol-specific serialization of custom field owners.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("custom field cannot be copied or serialized")



#### Parse canonical custom fields in one bounded linear pass.
####
#### Bytes already supplied by the caller cannot be wiped.  Every retained property
#### is copied once into a mutable owner, and all partial owners close on failure.
####
def parse_custom_fields(
    encoded: bytes | SecretBuffer,
    *,
    max_bytes: int = MAX_DECODED_TEXT_BYTES,
) -> tuple[CustomField, ...]:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 0 < max_bytes <= MAX_DECODED_TEXT_BYTES:
        raise ValueError("custom field byte limit must be a positive approved integer")
    if isinstance(encoded, bytes):
        source = memoryview(encoded)
    elif isinstance(encoded, SecretBuffer):
        source = encoded.borrow()
    else:
        raise TypeError("custom field input must be bytes or SecretBuffer")
    if not source or len(source) > max_bytes:
        raise ValueError("custom field input length is invalid")
    fields: list[CustomField] = []
    properties: list[CustomProperty] = []
    names: set[str] = set()
    identifiers: set[int] = set()
    offset = 0
    try:
        while offset < len(source):
            if _is_separator(source, offset):
                if not properties:
                    raise ValueError("custom field separator cannot delimit an empty field")
                fields.append(_finish_field(properties, names, separator_after=True))
                properties = []
                identifiers = set()
                offset += len(_SEPARATOR)
                continue
            if len(source) - offset < 6:
                raise ValueError("custom property header is truncated")
            property_id = _parse_lower_hex(source[offset:offset + 2])
            value_length = _parse_lower_hex(source[offset + 2:offset + 6])
            if property_id == 0:
                raise ValueError("custom property identifier zero is reserved")
            if property_id in identifiers:
                raise ValueError("custom property identifiers must be unique")
            value_offset = offset + 6
            if value_length > len(source) - value_offset:
                raise ValueError("custom property value is truncated")
            end = value_offset + value_length
            _validate_property_value(source[value_offset:end])
            properties.append(CustomProperty(property_id, bytearray(source[offset:end])))
            identifiers.add(property_id)
            offset = end
        if properties:
            fields.append(_finish_field(properties, names, separator_after=False))
            properties = []
        if not fields:
            raise ValueError("custom field input contains no fields")
        return tuple(fields)
    except BaseException:
        for item in properties:
            with suppress(BaseException):
                item.close()
        for custom_field in fields:
            with suppress(BaseException):
                custom_field.close()
        raise
    finally:
        source.release()



#### Serialize exact property bytes and separator placement in original order.
####
def encode_custom_fields(fields: tuple[CustomField, ...]) -> bytes:
    output = _encode_custom_fields_owned(fields)
    try:
        return bytes(output)
    finally:
        output[:] = bytes(len(output))



#### Serialize custom fields into newly owned mutable storage for raw edits.
####
def _encode_custom_fields_owned(fields: tuple[CustomField, ...]) -> bytearray:
    if not isinstance(fields, tuple) or not all(isinstance(item, CustomField) for item in fields):
        raise TypeError("custom fields must be an immutable CustomField tuple")
    output = bytearray()
    try:
        for index, custom_field in enumerate(fields):
            custom_field._require_open()
            if index < len(fields) - 1 and not custom_field.separator_after:
                raise ValueError("adjacent custom fields require a separator")
            for item in custom_field.properties:
                output.extend(item._borrow_encoded())
            if custom_field.separator_after:
                output.extend(_SEPARATOR)
        return output
    except BaseException:
        output[:] = bytes(len(output))
        raise



#### Replace one named value and optional sensitivity while retaining all else.
####
#### Ownership of ``value`` is consumed on success and every failure.  The source
#### fields remain independently usable; the result owns retained or new properties.
####
def replace_custom_value(
    fields: tuple[CustomField, ...],
    *,
    name: str,
    value: SecretBuffer,
    sensitive: bool | None = None,
) -> tuple[CustomField, ...]:
    if not isinstance(fields, tuple) or not all(isinstance(item, CustomField) for item in fields):
        value.close()
        raise TypeError("custom fields must be an immutable CustomField tuple")
    if not isinstance(name, str) or not name:
        value.close()
        raise ValueError("custom field target name cannot be empty")
    if not isinstance(value, SecretBuffer):
        raise TypeError("custom value replacement requires SecretBuffer ownership")
    sensitivity_input: object = sensitive
    if sensitivity_input is not None and not isinstance(sensitivity_input, bool):
        value.close()
        raise TypeError("custom sensitivity edit must be boolean")
    result: list[CustomField] = []
    found = False
    try:
        replacement = bytearray(value.borrow())
        try:
            if len(replacement) > 0xFFFF:
                raise ValueError("custom value length is invalid")
            _validate_property_value(memoryview(replacement))
            for custom_field in fields:
                if custom_field.name != name:
                    result.append(custom_field.retain())
                    continue
                if found:
                    raise ValueError("custom field target is ambiguous")
                found = True
                result.append(_replace_one_field(custom_field, replacement, sensitive))
            if not found:
                raise ValueError("custom field was not found")
            return tuple(result)
        finally:
            replacement[:] = bytes(len(replacement))
    except BaseException:
        for custom_field in result:
            with suppress(BaseException):
                custom_field.close()
        raise
    finally:
        value.close()



#### Replace one named property through the structured raw-field boundary.
####
def replace_custom_raw_field_value(
    raw: RawField,
    *,
    name: str,
    value: SecretBuffer,
    sensitive: bool | None = None,
    max_bytes: int = MAX_DECODED_TEXT_BYTES,
) -> RawField:
    if not isinstance(value, SecretBuffer):
        raise TypeError("custom value replacement requires SecretBuffer ownership")
    source: SecretBuffer | None = None
    parsed: tuple[CustomField, ...] = ()
    edited: tuple[CustomField, ...] = ()
    replacement_consumed = False
    try:
        if not isinstance(raw, RawField):
            raise TypeError("custom raw edit requires RawField")
        if raw.type_code != RecordFieldType.CUSTOM_TEXT_FIELD:
            raise ValueError("raw field is not a custom text field")
        materialized = _materialize_raw_custom_field(raw, max_bytes=max_bytes)
        source = SecretBuffer.take_ownership(materialized)
        parsed = parse_custom_fields(source, max_bytes=max_bytes)
        replacement_consumed = True
        edited = replace_custom_value(
            parsed,
            name=name,
            value=value,
            sensitive=sensitive,
        )
        encoded = _encode_custom_fields_owned(edited)
        payload = InlinePayload.take_ownership(encoded)
        try:
            return RawField(raw.type_code, payload, raw.ordinal, raw.classification)
        except BaseException:
            payload.close()
            raise
    finally:
        if not replacement_consumed:
            value.close()
        for custom_field in edited:
            with suppress(BaseException):
                custom_field.close()
        for custom_field in parsed:
            with suppress(BaseException):
                custom_field.close()
        if source is not None:
            source.close()



#### Reject any nonempty custom-field set for a target older than ``0x0311``.
####
def ensure_custom_fields_representable(
    fields: tuple[CustomField, ...],
    target_version: FormatVersion,
) -> None:
    if not isinstance(target_version, FormatVersion) or not target_version.supported:
        raise IncompatibleExportError(IncompatibleExportReason.TARGET_VERSION_UNSUPPORTED)
    if fields and target_version < _CUSTOM_FIELD_VERSION:
        raise IncompatibleExportError(IncompatibleExportReason.UNREPRESENTABLE_FIELD)



#### Materialize one structured custom payload within the approved text bound.
####
def _materialize_raw_custom_field(raw: RawField, *, max_bytes: int) -> bytearray:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 0 < max_bytes <= MAX_DECODED_TEXT_BYTES:
        raise ValueError("custom field byte limit must be a positive approved integer")
    if raw.payload.length > max_bytes:
        raise ResourceLimitError(ResourceLimitReason.MAX_DECODED_TEXT_BYTES)
    data = bytearray()
    try:
        for chunk in raw.payload.iter_chunks(MAX_IO_CHUNK_BYTES):
            data.extend(chunk)
            if len(data) > raw.payload.length:
                raise ValueError("custom payload stream exceeds its declaration")
        if len(data) != raw.payload.length:
            raise ValueError("custom payload stream does not match its declaration")
        return data
    except BaseException:
        data[:] = bytes(len(data))
        raise



#### Validate one complete canonical property header and its declared length.
####
def _validate_complete_property_encoding(property_id: int, encoded: bytearray) -> int:
    if len(encoded) < 6:
        raise ValueError("custom property encoding is truncated")
    observed_id = _parse_lower_hex(memoryview(encoded)[:2])
    value_length = _parse_lower_hex(memoryview(encoded)[2:6])
    if observed_id != property_id or value_length != len(encoded) - 6:
        raise ValueError("custom property encoding does not match metadata")
    _validate_property_value(memoryview(encoded)[6:])
    return value_length



#### Report whether the next six bytes are the one allowed separator token.
####
def _is_separator(source: memoryview[int], offset: int) -> bool:
    return len(source) - offset >= 6 and all(source[offset + index] == 0x30 for index in range(6))



#### Parse a fixed lowercase hexadecimal slice without locale or normalization.
####
def _parse_lower_hex(characters: memoryview[int]) -> int:
    value = 0
    for character in characters:
        if 0x30 <= character <= 0x39:
            digit = character - 0x30
        elif 0x61 <= character <= 0x66:
            digit = character - 0x61 + 10
        else:
            raise ValueError("custom property metadata must be lowercase hexadecimal")
        value = value * 16 + digit
    return value



#### Validate one property value as strict UTF-8 without a byte-order marker.
####
def _validate_property_value(value: memoryview[int]) -> None:
    if len(value) >= 3 and value[0] == 0xEF and value[1] == 0xBB and value[2] == 0xBF:
        raise ValueError("custom property UTF-8 cannot contain a byte-order marker")
    bytes(value).decode("utf-8", errors="strict")



#### Validate one completed field and transfer its property-owner list.
####
def _finish_field(
    properties: list[CustomProperty],
    names: set[str],
    *,
    separator_after: bool,
) -> CustomField:
    name_property = _property_by_id(tuple(properties), 0x01)
    _property_by_id(tuple(properties), 0x02)
    if name_property.value_length == 0:
        raise ValueError("custom field name cannot be empty")
    name_bytes = name_property._copy_value()
    try:
        name = name_bytes.decode("utf-8")
    finally:
        name_bytes[:] = bytes(len(name_bytes))
    if not name or name in names:
        raise ValueError("custom field names must be unique")
    sensitivity_property = _optional_property_by_id(tuple(properties), 0x03)
    sensitive = False
    if sensitivity_property is not None:
        sensitivity = sensitivity_property._copy_value()
        try:
            if sensitivity not in (bytearray(b"0"), bytearray(b"1")):
                raise ValueError("custom field sensitivity must be zero or one")
            sensitive = sensitivity == bytearray(b"1")
        finally:
            sensitivity[:] = bytes(len(sensitivity))
    names.add(name)
    return CustomField(tuple(properties), name=name, sensitive=sensitive, separator_after=separator_after)



#### Return one required property from an already uniqueness-checked tuple.
####
def _property_by_id(properties: tuple[CustomProperty, ...], property_id: int) -> CustomProperty:
    item = _optional_property_by_id(properties, property_id)
    if item is None:
        raise ValueError("custom field is missing a required property")
    return item



#### Return one optional property without reordering or copying its owner.
####
def _optional_property_by_id(
    properties: tuple[CustomProperty, ...],
    property_id: int,
) -> CustomProperty | None:
    for item in properties:
        if item.property_id == property_id:
            return item
    return None



#### Replace only value/sensitivity owners within one named custom field.
####
def _replace_one_field(
    custom_field: CustomField,
    replacement: bytearray,
    sensitive: bool | None,
) -> CustomField:
    has_sensitivity = _optional_property_by_id(custom_field.properties, 0x03) is not None
    properties: list[CustomProperty] = []
    try:
        for item in custom_field.properties:
            if item.property_id == 0x02:
                properties.append(_new_property(0x02, memoryview(replacement)))
                if sensitive is not None and not has_sensitivity:
                    properties.append(_new_property(0x03, memoryview(b"1" if sensitive else b"0")))
            elif item.property_id == 0x03 and sensitive is not None:
                properties.append(_new_property(0x03, memoryview(b"1" if sensitive else b"0")))
            else:
                properties.append(item.retain())
        return CustomField(
            tuple(properties),
            name=custom_field.name,
            sensitive=custom_field.sensitive if sensitive is None else sensitive,
            separator_after=custom_field.separator_after,
        )
    except BaseException:
        for item in properties:
            with suppress(BaseException):
                item.close()
        raise



#### Construct one canonical replacement property from validated value bytes.
####
def _new_property(property_id: int, value: memoryview[int]) -> CustomProperty:
    header = f"{property_id:02x}{len(value):04x}".encode("ascii")
    encoded = bytearray(header)
    encoded.extend(value)
    return CustomProperty(property_id, encoded)
