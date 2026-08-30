"""Define official PasswordSafe V3 field metadata and lossless typed codecs.

Typed values borrow their structural identity from an unchanged ``RawField``.
Only explicit encoder calls allocate replacement payloads.  Recognized opaque data
is never materialized here, and malformed optional bytes remain preservable.
"""

from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Literal, NoReturn, SupportsIndex
from uuid import UUID

from .constants import (
    MAX_DECODED_TEXT_BYTES,
    MAX_IO_CHUNK_BYTES,
    FieldKind,
    FormatVersion,
    HeaderFieldType,
    RecordFieldType,
)
from .errors import (
    IncompatibleExportError,
    IncompatibleExportReason,
    MalformedReason,
    MalformedVaultError,
    ResourceLimitError,
    ResourceLimitReason,
)
from .model import PreservationWarning, PreservationWarningCode, RawField, SectionName
from .payloads import InlinePayload
from .secrets import SecretBuffer



type TypedValue = FormatVersion | UUID | str | int | bytes | SecretBuffer | None
type SchemaSection = Literal["header", "record"]
_UTF8_BOM = b"\xef\xbb\xbf"



#### Describe whether one official field may occur once or repeatedly.
####
class FieldMultiplicity(StrEnum):
    SINGLE = "single"
    MULTIPLE = "multiple"



#### Classify how strongly typed values must be protected after decoding.
####
#### Potentially secret fields include user-authored metadata and opaque values
#### whose content cannot safely be classified without exposing it.
####
class SecretClassification(StrEnum):
    PUBLIC = "public"
    # These serialized enum values are classification labels, never credentials.
    SECRET = "secret"  # nosec B105
    POTENTIALLY_SECRET = "potentially-secret"  # nosec B105



#### Identify unconditional and conditional mandatory structure roles.
####
#### The reader later validates cross-field attachment and passkey groups.  This
#### schema still records those roles so no caller mistakes them for ordinary
#### optional content during validation or export preflight.
####
class MandatoryRole(StrEnum):
    OPTIONAL = "optional"
    HEADER_REQUIRED = "header-required"
    RECORD_REQUIRED = "record-required"
    ATTACHMENT_REQUIRED = "attachment-required"
    PASSKEY_REQUIRED = "passkey-required"
    TERMINATOR = "terminator"



#### Describe one official field's wire, version, ownership, and edit contract.
####
@dataclass(frozen=True, slots=True)
class FieldSpec:
    kind: FieldKind
    since: FormatVersion
    multiplicity: FieldMultiplicity
    secrecy: SecretClassification
    mandatory_role: MandatoryRole
    editable: bool
    fixed_length: int | None = None
    allow_historical_time: bool = False



    #### Validate immutable schema metadata after dataclass initialization.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.kind, FieldKind):
            raise TypeError("field kind must use FieldKind")
        if not isinstance(self.since, FormatVersion):
            raise TypeError("field introduction must use FormatVersion")
        if not isinstance(self.multiplicity, FieldMultiplicity):
            raise TypeError("field multiplicity must use its closed enum")
        if not isinstance(self.secrecy, SecretClassification):
            raise TypeError("field secrecy must use its closed enum")
        if not isinstance(self.mandatory_role, MandatoryRole):
            raise TypeError("mandatory role must use its closed enum")
        if self.fixed_length is not None and (
            isinstance(self.fixed_length, bool) or self.fixed_length < 0
        ):
            raise ValueError("fixed field length must be nonnegative")



    #### Report whether this field requires protected typed-value ownership.
    ####
    @property
    def secret(self) -> bool:
        return self.secrecy is not SecretClassification.PUBLIC



    #### Report whether the first release deliberately withholds typed content.
    ####
    @property
    def opaque(self) -> bool:
        return self.kind is FieldKind.OPAQUE



    #### Report whether this field participates in any mandatory structure rule.
    ####
    @property
    def mandatory(self) -> bool:
        return self.mandatory_role is not MandatoryRole.OPTIONAL



#### Pair one typed projection with the exact raw field that remains authoritative.
####
#### A secret projection owns a separate mutable buffer and wipes it on close.
#### Generic copy and serialization are rejected to avoid duplicating that owner.
####
class DecodedField:
    __slots__ = ("__weakref__", "_closed", "raw", "value", "warning")



    #### Adopt a typed projection without taking ownership of its raw field.
    ####
    def __init__(
        self,
        raw: RawField,
        value: TypedValue,
        warning: PreservationWarning | None = None,
    ) -> None:
        if hasattr(self, "raw"):
            if isinstance(value, SecretBuffer):
                value.close()
            raise TypeError("decoded field cannot be reinitialized")
        self.raw = raw
        self.value = value
        self.warning = warning
        self._closed = False



    #### Report whether owned typed secret material has been wiped.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Wipe any separately owned secret projection exactly once.
    ####
    def close(self) -> None:
        if not self._closed:
            if isinstance(self.value, SecretBuffer):
                self.value.close()
            self._closed = True



    #### Defensively wipe a forgotten typed secret without closing the raw field.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Render only structural metadata, never a typed or raw value.
    ####
    def __repr__(self) -> str:
        return f"DecodedField(type_code={self.raw.type_code}, closed={self.closed})"



    #### Reject shallow copying of a possibly secret typed projection.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("decoded field cannot be copied or serialized")



    #### Reject deep copying of raw and possibly secret projection owners.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("decoded field cannot be copied or serialized")



    #### Reject direct state extraction before inspecting a typed value.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("decoded field cannot be copied or serialized")



    #### Reject fabricated state injection into a live projection owner.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("decoded field cannot be copied or serialized")



    #### Reject legacy serialization reduction for typed field projections.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("decoded field cannot be copied or serialized")



    #### Reject protocol-specific serialization of typed field projections.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("decoded field cannot be copied or serialized")



#### Construct a schema version literal without exporting mutable lookup state.
####
def _version(value: int) -> FormatVersion:
    return FormatVersion.from_uint16(value)



#### Construct one concise official field specification.
####
def _spec(
    kind: FieldKind,
    since: int,
    *,
    multiplicity: FieldMultiplicity = FieldMultiplicity.SINGLE,
    secrecy: SecretClassification = SecretClassification.PUBLIC,
    role: MandatoryRole = MandatoryRole.OPTIONAL,
    editable: bool = True,
    fixed_length: int | None = None,
    historical_time: bool = False,
) -> FieldSpec:
    return FieldSpec(
        kind,
        _version(since),
        multiplicity,
        secrecy,
        role,
        editable=editable,
        fixed_length=fixed_length,
        allow_historical_time=historical_time,
    )



_P = SecretClassification.PUBLIC
_S = SecretClassification.SECRET
_PS = SecretClassification.POTENTIALLY_SECRET
_O = MandatoryRole.OPTIONAL
_HR = MandatoryRole.HEADER_REQUIRED
_RR = MandatoryRole.RECORD_REQUIRED
_AR = MandatoryRole.ATTACHMENT_REQUIRED
_PR = MandatoryRole.PASSKEY_REQUIRED
_T = MandatoryRole.TERMINATOR

HEADER_SCHEMA: Mapping[HeaderFieldType, FieldSpec] = MappingProxyType({
    HeaderFieldType.VERSION: _spec(FieldKind.UINT16, 0x0300, role=_HR, editable=False, fixed_length=2),
    HeaderFieldType.UUID: _spec(FieldKind.UUID, 0x0300, editable=False, fixed_length=16),
    HeaderFieldType.PREFERENCES: _spec(FieldKind.TEXT, 0x0300),
    HeaderFieldType.TREE_DISPLAY_STATUS: _spec(FieldKind.TEXT, 0x0301),
    HeaderFieldType.LAST_SAVE_TIME: _spec(FieldKind.TIME, 0x0300, fixed_length=4, historical_time=True),
    HeaderFieldType.LAST_SAVE_BY: _spec(FieldKind.TEXT, 0x0300),
    HeaderFieldType.LAST_SAVE_WHAT: _spec(FieldKind.TEXT, 0x0300),
    HeaderFieldType.LAST_SAVE_USER: _spec(FieldKind.TEXT, 0x0302),
    HeaderFieldType.LAST_SAVE_HOST: _spec(FieldKind.TEXT, 0x0302),
    HeaderFieldType.DATABASE_NAME: _spec(FieldKind.TEXT, 0x0302),
    HeaderFieldType.DATABASE_DESCRIPTION: _spec(FieldKind.TEXT, 0x0302),
    HeaderFieldType.DATABASE_FILTERS: _spec(FieldKind.TEXT, 0x0305),
    HeaderFieldType.RESERVED_0C: _spec(FieldKind.OPAQUE, 0x0300, secrecy=_PS, editable=False),
    HeaderFieldType.RESERVED_0D: _spec(FieldKind.OPAQUE, 0x0300, secrecy=_PS, editable=False),
    HeaderFieldType.RESERVED_0E: _spec(FieldKind.OPAQUE, 0x0300, secrecy=_PS, editable=False),
    HeaderFieldType.RECENTLY_USED_ENTRIES: _spec(FieldKind.TEXT, 0x0307),
    HeaderFieldType.NAMED_PASSWORD_POLICIES: _spec(FieldKind.TEXT, 0x030A),
    HeaderFieldType.EMPTY_GROUPS: _spec(FieldKind.TEXT, 0x030B, multiplicity=FieldMultiplicity.MULTIPLE),
    HeaderFieldType.YUBICO: _spec(FieldKind.BINARY, 0x030C, secrecy=_S, fixed_length=20),
    HeaderFieldType.LAST_MASTER_PASSWORD_CHANGE: _spec(
        FieldKind.TIME, 0x030E, fixed_length=4, historical_time=True,
    ),
    HeaderFieldType.END: _spec(FieldKind.EMPTY, 0x0300, role=_T, editable=False, fixed_length=0),
})

RECORD_SCHEMA: Mapping[RecordFieldType, FieldSpec] = MappingProxyType({
    RecordFieldType.UUID: _spec(FieldKind.UUID, 0x0300, role=_RR, editable=False, fixed_length=16),
    RecordFieldType.GROUP: _spec(FieldKind.TEXT, 0x0300),
    RecordFieldType.TITLE: _spec(FieldKind.TEXT, 0x0300, role=_RR),
    RecordFieldType.USERNAME: _spec(FieldKind.TEXT, 0x0300),
    RecordFieldType.NOTES: _spec(FieldKind.TEXT, 0x0300, secrecy=_PS),
    RecordFieldType.PASSWORD: _spec(FieldKind.TEXT, 0x0300, secrecy=_S, role=_RR),
    RecordFieldType.CREATION_TIME: _spec(FieldKind.TIME, 0x0300, fixed_length=4, historical_time=True),
    RecordFieldType.PASSWORD_MODIFICATION_TIME: _spec(FieldKind.TIME, 0x0300, fixed_length=4, historical_time=True),
    RecordFieldType.LAST_ACCESS_TIME: _spec(FieldKind.TIME, 0x0300, fixed_length=4, historical_time=True),
    RecordFieldType.PASSWORD_EXPIRY_TIME: _spec(FieldKind.TIME, 0x0300, fixed_length=4, historical_time=True),
    RecordFieldType.RESERVED_0B: _spec(FieldKind.OPAQUE, 0x0300, secrecy=_PS, editable=False, fixed_length=4),
    RecordFieldType.LAST_MODIFICATION_TIME: _spec(FieldKind.TIME, 0x0300, fixed_length=4, historical_time=True),
    RecordFieldType.URL: _spec(FieldKind.TEXT, 0x0300),
    RecordFieldType.AUTOTYPE: _spec(FieldKind.TEXT, 0x0300),
    RecordFieldType.PASSWORD_HISTORY: _spec(FieldKind.TEXT, 0x0300, secrecy=_S),
    RecordFieldType.PASSWORD_POLICY: _spec(FieldKind.TEXT, 0x0302),
    RecordFieldType.PASSWORD_EXPIRY_INTERVAL: _spec(FieldKind.UINT32, 0x0304, fixed_length=4),
    RecordFieldType.RUN_COMMAND: _spec(FieldKind.TEXT, 0x0305),
    RecordFieldType.DOUBLE_CLICK_ACTION: _spec(FieldKind.UINT16, 0x0305, fixed_length=2),
    RecordFieldType.EMAIL: _spec(FieldKind.TEXT, 0x0306),
    RecordFieldType.PROTECTED: _spec(FieldKind.UINT8, 0x0308, fixed_length=1),
    RecordFieldType.OWN_SYMBOLS: _spec(FieldKind.TEXT, 0x0309),
    RecordFieldType.SHIFT_DOUBLE_CLICK_ACTION: _spec(FieldKind.UINT16, 0x0309, fixed_length=2),
    RecordFieldType.PASSWORD_POLICY_NAME: _spec(FieldKind.TEXT, 0x030A),
    RecordFieldType.KEYBOARD_SHORTCUT: _spec(FieldKind.UINT32, 0x030D, fixed_length=4),
    RecordFieldType.RESERVED_1A: _spec(FieldKind.OPAQUE, 0x030D, secrecy=_PS, editable=False, fixed_length=16),
    RecordFieldType.TWO_FACTOR_KEY: _spec(FieldKind.BINARY, 0x030D, secrecy=_S),
    RecordFieldType.CREDIT_CARD_NUMBER: _spec(FieldKind.TEXT, 0x030D, secrecy=_S),
    RecordFieldType.CREDIT_CARD_EXPIRATION: _spec(FieldKind.TEXT, 0x030D, secrecy=_S),
    RecordFieldType.CREDIT_CARD_VERIFICATION_VALUE: _spec(FieldKind.TEXT, 0x030D, secrecy=_S),
    RecordFieldType.CREDIT_CARD_PIN: _spec(FieldKind.TEXT, 0x030D, secrecy=_S),
    RecordFieldType.QR_CODE: _spec(FieldKind.TEXT, 0x030D, secrecy=_PS),
    RecordFieldType.TOTP_CONFIG: _spec(FieldKind.UINT8, 0x030E, fixed_length=1),
    RecordFieldType.TOTP_LENGTH: _spec(FieldKind.UINT8, 0x030E, fixed_length=1),
    RecordFieldType.TOTP_TIME_STEP: _spec(FieldKind.UINT8, 0x030E, fixed_length=1),
    RecordFieldType.TOTP_START_TIME: _spec(FieldKind.TIME, 0x030E, fixed_length=4, historical_time=True),
    RecordFieldType.ATTACHMENT_TITLE: _spec(FieldKind.OPAQUE, 0x030F, secrecy=_PS, editable=False),
    RecordFieldType.ATTACHMENT_MEDIA_TYPE: _spec(FieldKind.OPAQUE, 0x030F, secrecy=_PS, role=_AR, editable=False),
    RecordFieldType.ATTACHMENT_FILE_NAME: _spec(FieldKind.OPAQUE, 0x030F, secrecy=_PS, editable=False),
    RecordFieldType.ATTACHMENT_MODIFICATION_TIME: _spec(
        FieldKind.OPAQUE, 0x030F, secrecy=_PS, editable=False, fixed_length=4,
    ),
    RecordFieldType.ATTACHMENT_CONTENT: _spec(FieldKind.OPAQUE, 0x030F, secrecy=_PS, editable=False),
    RecordFieldType.PASSKEY_CREDENTIAL_ID: _spec(FieldKind.OPAQUE, 0x0310, secrecy=_PS, role=_PR, editable=False),
    RecordFieldType.PASSKEY_RELYING_PARTY_ID: _spec(FieldKind.OPAQUE, 0x0310, secrecy=_PS, role=_PR, editable=False),
    RecordFieldType.PASSKEY_USER_HANDLE: _spec(FieldKind.OPAQUE, 0x0310, secrecy=_PS, role=_PR, editable=False),
    RecordFieldType.PASSKEY_ALGORITHM_ID: _spec(
        FieldKind.OPAQUE, 0x0310, secrecy=_PS, role=_PR, editable=False, fixed_length=4,
    ),
    RecordFieldType.PASSKEY_PRIVATE_KEY: _spec(FieldKind.OPAQUE, 0x0310, secrecy=_PS, role=_PR, editable=False),
    RecordFieldType.PASSKEY_SIGN_COUNT: _spec(
        FieldKind.OPAQUE, 0x0310, secrecy=_PS, role=_PR, editable=False, fixed_length=4,
    ),
    RecordFieldType.CUSTOM_TEXT_FIELD: _spec(FieldKind.TEXT, 0x0311, secrecy=_PS),
    RecordFieldType.UNKNOWN_TESTING: _spec(
        FieldKind.OPAQUE, 0x0300, multiplicity=FieldMultiplicity.MULTIPLE, secrecy=_PS, editable=False,
    ),
    RecordFieldType.END: _spec(FieldKind.EMPTY, 0x0300, role=_T, editable=False, fixed_length=0),
})



#### Decode one known or unknown header field without replacing its raw payload.
####
def decode_header_field(
    raw: RawField,
    *,
    max_decoded_bytes: int = MAX_DECODED_TEXT_BYTES,
) -> DecodedField:
    spec = _lookup_header_spec(raw.type_code)
    return _decode_field(raw, spec, section="header", record_ordinal=None, max_decoded_bytes=max_decoded_bytes)



#### Decode one known or unknown record field at safe structural coordinates.
####
def decode_record_field(
    raw: RawField,
    *,
    record_ordinal: int,
    max_decoded_bytes: int = MAX_DECODED_TEXT_BYTES,
) -> DecodedField:
    if isinstance(record_ordinal, bool) or not isinstance(record_ordinal, int) or record_ordinal < 0:
        raise ValueError("record ordinal must be a nonnegative integer")
    spec = _lookup_record_spec(raw.type_code)
    return _decode_field(
        raw,
        spec,
        section="record",
        record_ordinal=record_ordinal,
        max_decoded_bytes=max_decoded_bytes,
    )



#### Encode one explicit editable header-field replacement in canonical form.
####
def encode_header_field(raw: RawField, value: TypedValue) -> RawField:
    spec = _lookup_header_spec(raw.type_code)
    if spec is None:
        raise ValueError("unknown header fields cannot be edited")
    return _encode_field(raw, spec, value)



#### Encode one explicit editable record-field replacement in canonical form.
####
def encode_record_field(raw: RawField, value: TypedValue) -> RawField:
    spec = _lookup_record_spec(raw.type_code)
    if spec is None:
        raise ValueError("unknown record fields cannot be edited")
    return _encode_field(raw, spec, value)



#### Prove every raw field is representable before legacy output is created.
####
def ensure_fields_representable(
    fields: tuple[RawField, ...],
    *,
    section: SchemaSection,
    target_version: FormatVersion,
) -> None:
    if not isinstance(target_version, FormatVersion) or not target_version.supported:
        raise IncompatibleExportError(IncompatibleExportReason.TARGET_VERSION_UNSUPPORTED)
    if section not in ("header", "record"):
        raise ValueError("section must be header or record")
    for raw in fields:
        spec = _lookup_header_spec(raw.type_code) if section == "header" else _lookup_record_spec(raw.type_code)
        if spec is None or spec.since > target_version:
            raise IncompatibleExportError(IncompatibleExportReason.UNREPRESENTABLE_FIELD)



#### Look up one header code without treating unknown bytes as enum failures.
####
def _lookup_header_spec(type_code: int) -> FieldSpec | None:
    try:
        field_type = HeaderFieldType(type_code)
    except ValueError:
        return None
    return HEADER_SCHEMA.get(field_type)



#### Look up one record code without treating extension bytes as enum failures.
####
def _lookup_record_spec(type_code: int) -> FieldSpec | None:
    try:
        field_type = RecordFieldType(type_code)
    except ValueError:
        return None
    return RECORD_SCHEMA.get(field_type)



#### Decode one field according to schema while retaining malformed optional bytes.
####
def _decode_field(
    raw: RawField,
    spec: FieldSpec | None,
    *,
    section: SectionName,
    record_ordinal: int | None,
    max_decoded_bytes: int,
) -> DecodedField:
    if spec is None:
        warning = _warning(raw, section, record_ordinal, PreservationWarningCode.UNKNOWN_FIELD)
        return DecodedField(raw, None, warning)
    malformed = _length_is_malformed(raw, spec)
    if malformed:
        return _handle_malformed(raw, spec, section, record_ordinal)
    if spec.kind is FieldKind.OPAQUE:
        return DecodedField(raw, None)
    data = _materialize(raw, max_decoded_bytes)
    transfer = False
    try:
        value = _decode_materialized(raw, spec, data)
        transfer = isinstance(value, SecretBuffer)
        return DecodedField(raw, value)
    except (UnicodeDecodeError, ValueError):
        return _handle_malformed(raw, spec, section, record_ordinal)
    finally:
        if not transfer:
            data[:] = bytes(len(data))



#### Detect fixed-size and present-conditional structural violations by length.
####
def _length_is_malformed(raw: RawField, spec: FieldSpec) -> bool:
    length = raw.payload.length
    if spec.kind is FieldKind.TIME and spec.allow_historical_time and length == 8:
        return False
    if spec.fixed_length is not None and length != spec.fixed_length:
        return True
    return spec.mandatory_role in (
        MandatoryRole.HEADER_REQUIRED,
        MandatoryRole.RECORD_REQUIRED,
        MandatoryRole.ATTACHMENT_REQUIRED,
        MandatoryRole.PASSKEY_REQUIRED,
    ) and length == 0



#### Return a safe warning for optional malformed bytes or fail mandatory closed.
####
def _handle_malformed(
    raw: RawField,
    spec: FieldSpec,
    section: SectionName,
    record_ordinal: int | None,
) -> DecodedField:
    if spec.mandatory:
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
    warning = _warning(raw, section, record_ordinal, PreservationWarningCode.MALFORMED_OPTIONAL_FIELD)
    return DecodedField(raw, None, warning)



#### Create one warning using structural coordinates and no payload-derived text.
####
def _warning(
    raw: RawField,
    section: SectionName,
    record_ordinal: int | None,
    code: PreservationWarningCode,
) -> PreservationWarning:
    return PreservationWarning(code, section, record_ordinal, raw.ordinal, raw.type_code)



#### Read one bounded nonopaque payload and verify its exact declared length.
####
def _materialize(raw: RawField, maximum: int) -> bytearray:
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 0 < maximum <= MAX_DECODED_TEXT_BYTES:
        raise ValueError("decoded byte bound must be a positive approved integer")
    if raw.payload.length > maximum:
        raise ResourceLimitError(ResourceLimitReason.MAX_DECODED_TEXT_BYTES)
    data = bytearray()
    try:
        for chunk in raw.payload.iter_chunks(MAX_IO_CHUNK_BYTES):
            data.extend(chunk)
            if len(data) > raw.payload.length:
                raise ValueError("payload stream exceeds its declaration")
        if len(data) != raw.payload.length:
            raise ValueError("payload stream does not match its declaration")
        return data
    except BaseException:
        data[:] = bytes(len(data))
        raise



#### Decode validated bytes into one typed value without changing the raw field.
####
def _decode_materialized(raw: RawField, spec: FieldSpec, data: bytearray) -> TypedValue:
    if spec.kind is FieldKind.EMPTY:
        return None
    if spec.kind is FieldKind.UUID:
        if len(data) != 16 or data[8] & 0xC0 != 0x80:
            raise ValueError("invalid RFC 4122 UUID")
        return UUID(bytes=bytes(data))
    if spec.kind is FieldKind.TEXT:
        _validate_utf8(data)
        if spec.secret:
            return SecretBuffer.take_ownership(data)
        return data.decode("utf-8")
    if spec.kind is FieldKind.TIME:
        if len(data) == 8 and spec.allow_historical_time:
            return _decode_historical_time(data)
        return int.from_bytes(data, "little")
    if spec.kind in (FieldKind.UINT8, FieldKind.UINT16, FieldKind.UINT32):
        value = int.from_bytes(data, "little")
        if raw.type_code == HeaderFieldType.VERSION:
            return FormatVersion.from_uint16(value)
        return value
    if spec.kind is FieldKind.BINARY:
        if spec.secret:
            return SecretBuffer.take_ownership(data)
        return bytes(data)
    raise ValueError("field kind cannot be decoded")



#### Validate strict UTF-8 whose first scalar is not a byte-order marker.
####
def _validate_utf8(data: bytearray) -> None:
    if len(data) >= len(_UTF8_BOM) and bytes(data[:3]) == _UTF8_BOM:
        raise ValueError("UTF-8 byte-order marker is forbidden")
    data.decode("utf-8", errors="strict")



#### Parse exactly eight ASCII hexadecimal timestamp digits without normalization.
####
def _decode_historical_time(data: bytearray) -> int:
    value = 0
    for character in data:
        if 0x30 <= character <= 0x39:
            digit = character - 0x30
        elif 0x41 <= character <= 0x46:
            digit = character - 0x41 + 10
        elif 0x61 <= character <= 0x66:
            digit = character - 0x61 + 10
        else:
            raise ValueError("historical timestamp must be hexadecimal")
        value = value * 16 + digit
    return value



#### Build one new inline payload only at an explicit editable-field boundary.
####
def _encode_field(raw: RawField, spec: FieldSpec, value: TypedValue) -> RawField:
    if not spec.editable or spec.kind in (FieldKind.OPAQUE, FieldKind.EMPTY):
        raise ValueError("field is not editable")
    data = _encode_value(spec, value)
    payload = InlinePayload.take_ownership(data)
    return RawField(raw.type_code, payload, raw.ordinal, raw.classification)



#### Encode one typed edit into the official canonical wire representation.
####
def _encode_value(spec: FieldSpec, value: TypedValue) -> bytearray:
    if spec.kind is FieldKind.UUID:
        if not isinstance(value, UUID) or value.bytes[8] & 0xC0 != 0x80:
            raise ValueError("UUID edit must use an RFC 4122 UUID")
        return bytearray(value.bytes)
    if spec.kind is FieldKind.TEXT:
        if isinstance(value, SecretBuffer):
            data = bytearray(value.borrow())
            try:
                _validate_utf8(data)
                if spec.mandatory and not data:
                    raise ValueError("mandatory text cannot be empty")
                return data
            except BaseException:
                data[:] = bytes(len(data))
                raise
        if not isinstance(value, str) or spec.secrecy is SecretClassification.SECRET:
            raise TypeError("text edit uses the wrong typed value")
        data = bytearray(value.encode("utf-8"))
        if bytes(data[:3]) == _UTF8_BOM or (spec.mandatory and not data):
            data[:] = bytes(len(data))
            raise ValueError("text edit violates field requirements")
        return data
    if spec.kind in (FieldKind.TIME, FieldKind.UINT8, FieldKind.UINT16, FieldKind.UINT32):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("integer field edit requires an integer")
        width = spec.fixed_length
        if width is None or not 0 <= value < 1 << (width * 8):
            raise ValueError("integer field edit is outside its wire range")
        return bytearray(value.to_bytes(width, "little"))
    if spec.kind is FieldKind.BINARY:
        if spec.secret:
            if not isinstance(value, SecretBuffer):
                raise TypeError("secret binary edit requires SecretBuffer")
            data = bytearray(value.borrow())
        elif isinstance(value, bytes):
            data = bytearray(value)
        else:
            raise TypeError("binary edit uses the wrong typed value")
        if spec.fixed_length is not None and len(data) != spec.fixed_length:
            data[:] = bytes(len(data))
            raise ValueError("binary edit has the wrong length")
        return data
    raise ValueError("field kind is not editable")
