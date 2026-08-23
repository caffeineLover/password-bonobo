"""Represent PasswordSafe plaintext as an exact ordered closable raw document.

Fields retain type, payload, ordinal, multiplicity, and validation classification.
Opaque handles and revisions never derive from vault data.  Semantic manifests are
bounded evidence indexes; final equality always compares complete payload streams.
"""

import hashlib
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType
from typing import Literal, NoReturn, Self, SupportsIndex

from .constants import MAX_IO_CHUNK_BYTES, FormatVersion
from .payloads import FieldPayload, PayloadClosedError



SectionName = Literal["header", "record"]



#### Classify how schema validation understood one retained raw field.
####
class FieldClassification(StrEnum):
    UNDERSTOOD = "understood"
    UNKNOWN = "unknown"
    MALFORMED = "understood-but-malformed"



#### Identify one closed safe reason for retaining nonfatal source content.
####
class PreservationWarningCode(StrEnum):
    MALFORMED_OPTIONAL_FIELD = "malformed-optional-field"
    DUPLICATE_OPTIONAL_FIELD = "duplicate-optional-field"
    UNKNOWN_FIELD = "unknown-field"



#### Report one retained nonfatal condition without raw values or record identity.
####
@dataclass(frozen=True, slots=True)
class PreservationWarning:
    code: PreservationWarningCode
    section: SectionName
    record_ordinal: int | None
    field_ordinal: int
    type_code: int



    #### Validate safe structural coordinates without accepting arbitrary text.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.code, PreservationWarningCode):
            raise TypeError("warning code must use the preservation warning enum")
        _validate_section(self.section, self.record_ordinal)
        _validate_ordinal(self.field_ordinal, "field ordinal")
        _validate_type_code(self.type_code)



#### Seal one process-local identity token against mutation or reconstruction.
####
#### Subclasses add domain meaning without changing this token's fixed safe
#### representation, identity-only equality, stable hash, or terminal sealing.
####
class _OpaqueIdentity:
    __slots__ = ("_sealed", "_token")

    _sealed: bool
    _token: object



    #### Create and seal one token independently of all vault and secret data.
    ####
    def __init__(self) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("opaque identity cannot be reinitialized")
        object.__setattr__(self, "_token", object())
        object.__setattr__(self, "_sealed", True)



    #### Reject assignment after construction so hashes and lookup identity persist.
    ####
    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise TypeError("opaque identity is immutable")



    #### Reject deletion after construction so hashes and lookup identity persist.
    ####
    def __delattr__(self, _name: str) -> NoReturn:
        raise TypeError("opaque identity is immutable")



    #### Compare exact token type and identity without reading vault data.
    ####
    def __eq__(self, other: object) -> bool:
        return type(self) is type(other) and isinstance(other, _OpaqueIdentity) and self._token is other._token



    #### Hash the sealed token for stable process-local lookup tables.
    ####
    def __hash__(self) -> int:
        return hash(self._token)



    #### Render a fixed type label without exposing identity-bearing values.
    ####
    def __repr__(self) -> str:
        return f"{type(self).__name__}(<opaque>)"



    #### Reject shallow copies instead of creating another identity-bearing alias.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("opaque identity cannot be copied or serialized")



    #### Reject deep copies instead of duplicating process-local identity state.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("opaque identity cannot be copied or serialized")



    #### Reject direct state extraction from sealed identity state.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("opaque identity cannot be copied or serialized")



    #### Reject fabricated state injection without mutating the sealed token.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("opaque identity cannot be copied or serialized")



    #### Prevent process-local identity from escaping through serialization.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("opaque identity cannot be copied or serialized")



    #### Prevent protocol-specific serialization of session-scoped identity.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("opaque identity cannot be copied or serialized")



#### Identify one record by opaque session-local object identity.
####
#### The sealed token is independent of UUID and field content, and cannot be
#### copied, serialized, assigned, deleted, or rendered as an identifying value.
####
class RecordHandle(_OpaqueIdentity):
    __slots__ = ()



#### Identify one copy-on-write document revision independently of secret data.
####
#### Sealing makes stale-revision equality and hash lookup stable for the complete
#### process-local lifetime while all generic reconstruction routes stay closed.
####
class RevisionToken(_OpaqueIdentity):
    __slots__ = ()



#### Retain one field's exact wire type, ordered position, and payload owner.
####
#### Raw fields borrow their payload from the enclosing document lifecycle.  Their
#### representation omits the potentially secret payload owner entirely.
####
@dataclass(eq=False, frozen=True, slots=True)
class RawField:
    type_code: int
    payload: FieldPayload = field(repr=False, compare=False)
    ordinal: int
    classification: FieldClassification



    #### Validate immutable structural metadata without reading payload bytes.
    ####
    def __post_init__(self) -> None:
        _validate_type_code(self.type_code)
        _validate_ordinal(self.ordinal, "field ordinal")
        if not isinstance(self.classification, FieldClassification):
            raise TypeError("field classification must use the closed enum")
        if not isinstance(self.payload, FieldPayload):
            raise TypeError("field payload must implement the streaming protocol")



#### Retain one record's exact field sequence and opaque in-session identity.
####
@dataclass(eq=False, frozen=True, slots=True)
class RawRecord:
    fields: tuple[RawField, ...]
    ordinal: int
    handle: RecordHandle = field(repr=False, compare=False)



    #### Validate exact tuple structure and safe ordinal metadata.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.fields, tuple) or not all(isinstance(item, RawField) for item in self.fields):
            raise TypeError("record fields must be an immutable RawField tuple")
        _validate_ordinal(self.ordinal, "record ordinal")
        if not isinstance(self.handle, RecordHandle):
            raise TypeError("record handle must be opaque")



    #### Create one record with a fresh handle independent of UUID field data.
    ####
    @classmethod
    def create(cls, fields: tuple[RawField, ...], *, ordinal: int) -> Self:
        return cls(fields=fields, ordinal=ordinal, handle=RecordHandle())



#### Index one payload by ordered structural coordinates and bounded SHA-256.
####
@dataclass(frozen=True, slots=True)
class ManifestEntry:
    section: SectionName
    record_ordinal: int | None
    field_ordinal: int
    type_code: int
    length: int
    sha256: str



    #### Validate that manifest metadata cannot conceal invalid model coordinates.
    ####
    def __post_init__(self) -> None:
        _validate_section(self.section, self.record_ordinal)
        _validate_ordinal(self.field_ordinal, "field ordinal")
        _validate_type_code(self.type_code)
        _validate_ordinal(self.length, "payload length")
        if len(self.sha256) != 64 or any(character not in "0123456789abcdef" for character in self.sha256):
            raise ValueError("manifest SHA-256 must be lowercase hexadecimal")



#### Retain an ordered bounded evidence index for one document revision.
####
@dataclass(frozen=True, slots=True)
class SemanticManifest:
    version: FormatVersion
    entries: tuple[ManifestEntry, ...]
    header_field_count: int
    record_count: int
    field_count: int



    #### Validate exact aggregate counts without interpreting payload hashes as truth.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.version, FormatVersion):
            raise TypeError("manifest version must use FormatVersion")
        _validate_ordinal(self.header_field_count, "header field count")
        _validate_ordinal(self.record_count, "record count")
        _validate_ordinal(self.field_count, "field count")
        if self.field_count != len(self.entries):
            raise ValueError("manifest field count must match ordered entries")



#### Own one exact ordered raw document and all distinct payloads it references.
####
#### Closing wipes or terminals every distinct payload once.  Copy-on-write callers
#### construct explicit revisions and keep shared owners under one session lifetime;
#### generic copying and serialization are prohibited.
####
@dataclass(eq=False, frozen=True, slots=True)
class VaultDocument:
    version: FormatVersion
    header_fields: tuple[RawField, ...]
    records: tuple[RawRecord, ...]
    revision: RevisionToken = field(repr=False, compare=False)
    warnings: tuple[PreservationWarning, ...]
    _closed: bool = field(default=False, init=False, repr=False, compare=False)
    _closing: bool = field(default=False, init=False, repr=False, compare=False)
    _pending_payloads: tuple[FieldPayload, ...] = field(default=(), init=False, repr=False, compare=False)



    #### Validate immutable containers and identity without traversing payload bytes.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.version, FormatVersion):
            raise TypeError("document version must use FormatVersion")
        if not isinstance(self.header_fields, tuple) or not all(
            isinstance(item, RawField) for item in self.header_fields
        ):
            raise TypeError("header fields must be an immutable RawField tuple")
        if not isinstance(self.records, tuple) or not all(isinstance(item, RawRecord) for item in self.records):
            raise TypeError("records must be an immutable RawRecord tuple")
        if not isinstance(self.revision, RevisionToken):
            raise TypeError("document revision must be opaque")
        if not isinstance(self.warnings, tuple) or not all(
            isinstance(item, PreservationWarning) for item in self.warnings
        ):
            raise TypeError("warnings must be an immutable PreservationWarning tuple")
        distinct_payloads: dict[int, FieldPayload] = {}
        for raw_field in _iter_fields(self):
            distinct_payloads.setdefault(id(raw_field.payload), raw_field.payload)
        object.__setattr__(self, "_pending_payloads", tuple(distinct_payloads.values()))



    #### Create an initial revision while repairing any accidentally repeated handle.
    ####
    @classmethod
    def create(
        cls,
        version: FormatVersion,
        header_fields: tuple[RawField, ...],
        records: tuple[RawRecord, ...],
        *,
        warnings: tuple[PreservationWarning, ...] = (),
        revision: RevisionToken | None = None,
    ) -> Self:
        distinct_records: list[RawRecord] = []
        handles: set[RecordHandle] = set()
        for record in records:
            retained = record
            if record.handle in handles:
                retained = RawRecord.create(record.fields, ordinal=record.ordinal)
            handles.add(retained.handle)
            distinct_records.append(retained)
        return cls(
            version=version,
            header_fields=header_fields,
            records=tuple(distinct_records),
            revision=revision if revision is not None else RevisionToken(),
            warnings=warnings,
        )



    #### Report whether document-owned payload cleanup has become terminal.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Stream every payload into an ordered bounded evidence manifest.
    ####
    def semantic_manifest(self, *, chunk_size: int = MAX_IO_CHUNK_BYTES) -> SemanticManifest:
        self._require_open()
        _validate_chunk_size(chunk_size)
        entries: list[ManifestEntry] = []
        for raw_field in self.header_fields:
            entries.append(_manifest_entry("header", None, raw_field, chunk_size))
        for record in self.records:
            for raw_field in record.fields:
                entries.append(_manifest_entry("record", record.ordinal, raw_field, chunk_size))
        return SemanticManifest(
            version=self.version,
            entries=tuple(entries),
            header_field_count=len(self.header_fields),
            record_count=len(self.records),
            field_count=len(entries),
        )



    #### Fork every distinct payload lease for an independently closable revision.
    ####
    def retain(self, *, revision: RevisionToken | None = None) -> Self:
        self._require_open()
        retained_payloads: dict[int, FieldPayload] = {}
        try:
            header_fields = _retain_fields(self.header_fields, retained_payloads)
            records = tuple(
                RawRecord(
                    fields=_retain_fields(record.fields, retained_payloads),
                    ordinal=record.ordinal,
                    handle=record.handle,
                )
                for record in self.records
            )
            return type(self)(
                version=self.version,
                header_fields=header_fields,
                records=records,
                revision=revision if revision is not None else RevisionToken(),
                warnings=self.warnings,
            )
        except BaseException:
            for payload in retained_payloads.values():
                with suppress(BaseException):
                    payload.close()
            raise



    #### Close each distinct payload once and make model operations terminal.
    ####
    def close(self) -> None:
        if self._closed:
            return
        object.__setattr__(self, "_closing", True)
        pending_payloads: list[FieldPayload] = []
        first_failure: BaseException | None = None
        for payload in self._pending_payloads:
            try:
                payload.close()
            except BaseException as error:
                pending_payloads.append(payload)
                if first_failure is None:
                    first_failure = error
        object.__setattr__(self, "_pending_payloads", tuple(pending_payloads))
        if not pending_payloads:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_closing", False)
        if first_failure is not None:
            raise first_failure



    #### Reject operations after document-owned payloads may have been wiped.
    ####
    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise PayloadClosedError()



    #### Enter only a live document without copying any raw field owners.
    ####
    def __enter__(self) -> Self:
        self._require_open()
        return self



    #### Close every owned payload on normal or exceptional context exit.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Defensively close forgotten payload owners without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Reject shallow copies that would alias closable payload ownership.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("vault document cannot be copied or serialized")



    #### Reject deep copies that would duplicate or alias secret-bearing payloads.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("vault document cannot be copied or serialized")



    #### Reject direct state extraction before payload owners are inspected.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("vault document cannot be copied or serialized")



    #### Reject fabricated state injection without mutating this document.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("vault document cannot be copied or serialized")



    #### Reject legacy serialization reduction for a resource-owning document.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("vault document cannot be copied or serialized")



    #### Reject protocol-specific reduction before payload state is inspected.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("vault document cannot be copied or serialized")



#### Compare complete ordered documents through bounded exact payload streams.
####
#### Manifest hashes are deliberately not consulted.  Handles and revision tokens
#### are session-local identities, so semantic equality compares source structure,
#### classifications, warnings, and every declared payload byte instead.
####
def documents_equal_exact(
    first: VaultDocument,
    second: VaultDocument,
    *,
    chunk_size: int = MAX_IO_CHUNK_BYTES,
) -> bool:
    _validate_chunk_size(chunk_size)
    first._require_open()
    second._require_open()
    if first.version != second.version or first.warnings != second.warnings:
        return False
    if len(first.header_fields) != len(second.header_fields) or len(first.records) != len(second.records):
        return False
    if not _field_sequences_equal(first.header_fields, second.header_fields, chunk_size):
        return False
    for first_record, second_record in zip(first.records, second.records, strict=True):
        if first_record.ordinal != second_record.ordinal:
            return False
        if not _field_sequences_equal(first_record.fields, second_record.fields, chunk_size):
            return False
    return True



#### Yield every header and record field in exact document traversal order.
####
def _iter_fields(document: VaultDocument) -> Iterator[RawField]:
    yield from document.header_fields
    for record in document.records:
        yield from record.fields



#### Retain one ordered field sequence while sharing duplicate payload leases.
####
def _retain_fields(
    fields: tuple[RawField, ...],
    retained_payloads: dict[int, FieldPayload],
) -> tuple[RawField, ...]:
    retained_fields: list[RawField] = []
    for raw_field in fields:
        identity = id(raw_field.payload)
        payload = retained_payloads.get(identity)
        if payload is None:
            payload = raw_field.payload.retain()
            retained_payloads[identity] = payload
        retained_fields.append(
            RawField(
                type_code=raw_field.type_code,
                payload=payload,
                ordinal=raw_field.ordinal,
                classification=raw_field.classification,
            )
        )
    return tuple(retained_fields)



#### Hash one payload incrementally and retain only safe structural evidence.
####
def _manifest_entry(
    section: SectionName,
    record_ordinal: int | None,
    raw_field: RawField,
    chunk_size: int,
) -> ManifestEntry:
    digest = hashlib.sha256()
    observed_length = 0
    for chunk in raw_field.payload.iter_chunks(chunk_size):
        digest.update(chunk)
        observed_length += len(chunk)
    if observed_length != raw_field.payload.length:
        raise ValueError("field payload stream length does not match its declaration")
    return ManifestEntry(
        section=section,
        record_ordinal=record_ordinal,
        field_ordinal=raw_field.ordinal,
        type_code=raw_field.type_code,
        length=observed_length,
        sha256=digest.hexdigest(),
    )



#### Compare matching field metadata and complete bounded payload streams.
####
def _field_sequences_equal(
    first: tuple[RawField, ...],
    second: tuple[RawField, ...],
    chunk_size: int,
) -> bool:
    if len(first) != len(second):
        return False
    for first_field, second_field in zip(first, second, strict=True):
        if (
            first_field.type_code != second_field.type_code
            or first_field.ordinal != second_field.ordinal
            or first_field.classification != second_field.classification
            or first_field.payload.length != second_field.payload.length
        ):
            return False
        if not _payloads_equal(first_field.payload, second_field.payload, chunk_size):
            return False
    return True



#### Compare two streams exactly even when their iterator chunk boundaries differ.
####
def _payloads_equal(first: FieldPayload, second: FieldPayload, chunk_size: int) -> bool:
    first_iterator = iter(first.iter_chunks(chunk_size))
    second_iterator = iter(second.iter_chunks(chunk_size))
    first_buffer = b""
    second_buffer = b""
    first_offset = 0
    second_offset = 0
    first_done = False
    second_done = False
    first_observed = 0
    second_observed = 0
    equal = True
    try:
        while not (first_done and second_done):
            if first_offset == len(first_buffer) and not first_done:
                try:
                    chunk = next(first_iterator)
                except StopIteration:
                    first_done = True
                else:
                    chunk_length = len(chunk)
                    if not 0 < chunk_length <= chunk_size:
                        equal = False
                        first_done = True
                    else:
                        first_observed += chunk_length
                        if first_observed > first.length:
                            equal = False
                        if first_observed > first.length + chunk_size:
                            first_done = True
                        else:
                            first_buffer = bytes(chunk)
                            first_offset = 0
            if second_offset == len(second_buffer) and not second_done:
                try:
                    chunk = next(second_iterator)
                except StopIteration:
                    second_done = True
                else:
                    chunk_length = len(chunk)
                    if not 0 < chunk_length <= chunk_size:
                        equal = False
                        second_done = True
                    else:
                        second_observed += chunk_length
                        if second_observed > second.length:
                            equal = False
                        if second_observed > second.length + chunk_size:
                            second_done = True
                        else:
                            second_buffer = bytes(chunk)
                            second_offset = 0
            first_available = len(first_buffer) - first_offset
            second_available = len(second_buffer) - second_offset
            if first_available and second_available:
                compared = min(first_available, second_available)
                if first_buffer[first_offset:first_offset + compared] != second_buffer[
                    second_offset:second_offset + compared
                ]:
                    equal = False
                first_offset += compared
                second_offset += compared
            elif first_available and second_done:
                equal = False
                first_offset = len(first_buffer)
            elif second_available and first_done:
                equal = False
                second_offset = len(second_buffer)
        return (
            equal
            and first_observed == first.length
            and second_observed == second.length
            and first_offset == len(first_buffer)
            and second_offset == len(second_buffer)
        )
    finally:
        _close_iterator(first_iterator)
        _close_iterator(second_iterator)



#### Release suspended generators after comparison success, mismatch, or failure.
####
def _close_iterator(iterator: Iterator[memoryview[int]]) -> None:
    close = getattr(iterator, "close", None)
    if callable(close):
        with suppress(BaseException):
            close()



#### Validate warning section coordinates without arbitrary section text.
####
def _validate_section(section: SectionName, record_ordinal: int | None) -> None:
    if section not in ("header", "record"):
        raise ValueError("section must be header or record")
    if section == "header" and record_ordinal is not None:
        raise ValueError("header entries cannot have a record ordinal")
    if section == "record" and record_ordinal is None:
        raise ValueError("record entries require a record ordinal")
    if record_ordinal is not None:
        _validate_ordinal(record_ordinal, "record ordinal")



#### Validate one nonnegative structural ordinal or aggregate count.
####
def _validate_ordinal(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} cannot be negative")



#### Validate one exact unsigned field type code.
####
def _validate_type_code(type_code: int) -> None:
    if isinstance(type_code, bool) or not isinstance(type_code, int):
        raise TypeError("field type code must be an integer")
    if not 0 <= type_code <= 0xFF:
        raise ValueError("field type code must fit one byte")



#### Validate caller-controlled manifest and comparison chunk bounds.
####
def _validate_chunk_size(chunk_size: int) -> None:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk size must be an integer")
    if not 0 < chunk_size <= MAX_IO_CHUNK_BYTES:
        raise ValueError("chunk size must be within the approved I/O bound")
