"""Provide revision-safe PasswordSafe sessions and explicit secret access.

Sessions expose immutable public record summaries while retaining the authenticated
document, key material, and secret payloads behind explicit lifetime boundaries.
Every accepted mutation creates one copy-on-write document revision.
"""

from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Literal, Self
from uuid import UUID

from .constants import FieldKind, FormatVersion, RecordFieldType
from .errors import ProtectedRecordError, StaleRevisionError, UnsavedChangesError
from .model import (
    FieldClassification,
    PreservationWarning,
    RawField,
    RawRecord,
    RecordHandle,
    RevisionToken,
    VaultDocument,
    documents_equal_exact,
)
from .payloads import FieldPayload, InlinePayload
from .pending import SuspendedSession
from .reader import OpenedVault, VaultCryptoState
from .schema import RECORD_SCHEMA, decode_record_field, encode_new_record_field, encode_record_field
from .secrets import MAX_SECRET_LEASE_BYTES, SecretBuffer, SecretLease
from .snapshots import EncryptedSnapshot
from .storage import FileBaseline, PublishedFile



ChangeKind = Literal["add", "edit", "move", "delete", "protect", "unprotect"]



#### Describe one accepted mutation without retaining record content or secrets.
####
@dataclass(frozen=True, slots=True)
class Change:
    kind: ChangeKind
    handle: RecordHandle = field(repr=False)
    revision: RevisionToken = field(repr=False)



#### Present immutable nonsecret record fields tied to one document revision.
####
@dataclass(frozen=True, slots=True)
class RecordView:
    handle: RecordHandle = field(repr=False)
    revision: RevisionToken = field(repr=False)
    title: str
    group: str
    username: str
    url: str
    protected: bool



#### Transfer the minimum canonical values needed to add one record.
####
@dataclass(frozen=True, slots=True)
class NewRecord:
    uuid: UUID
    title: str
    password: SecretBuffer = field(repr=False)
    username: str = ""
    group: str = ""
    url: str = ""



    #### Validate public value types before session ownership is transferred.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.uuid, UUID):
            raise TypeError("new record UUID must use UUID")
        if not isinstance(self.title, str):
            raise TypeError("new record title must be text")
        if not isinstance(self.password, SecretBuffer):
            raise TypeError("new record password must use SecretBuffer")
        if not all(isinstance(value, str) for value in (self.username, self.group, self.url)):
            raise TypeError("new record public fields must be text")



#### Replace one public text field with a validated string.
####
@dataclass(frozen=True, slots=True)
class SetTextField:
    field_type: RecordFieldType
    value: str



    #### Validate the edit's closed field identifier and typed value.
    ####
    def __post_init__(self) -> None:
        _validate_field_type(self.field_type)
        if not isinstance(self.value, str):
            raise TypeError("text edit value must be text")



#### Replace one secret text or binary field from a mutable owner.
####
@dataclass(frozen=True, slots=True)
class SetSecretField:
    field_type: RecordFieldType
    value: SecretBuffer = field(repr=False)



    #### Validate the edit's closed field identifier and secret owner.
    ####
    def __post_init__(self) -> None:
        _validate_field_type(self.field_type)
        if not isinstance(self.value, SecretBuffer):
            raise TypeError("secret edit value must use SecretBuffer")



#### Replace one nonsecret binary field with immutable API input bytes.
####
@dataclass(frozen=True, slots=True)
class SetBytesField:
    field_type: RecordFieldType
    value: bytes = field(repr=False)



    #### Validate the edit's closed field identifier and binary value.
    ####
    def __post_init__(self) -> None:
        _validate_field_type(self.field_type)
        if not isinstance(self.value, bytes):
            raise TypeError("binary edit value must be bytes")



#### Replace one official unsigned 32-bit record field.
####
@dataclass(frozen=True, slots=True)
class SetUInt32Field:
    field_type: RecordFieldType
    value: int



    #### Validate the edit's closed field identifier and integer value.
    ####
    def __post_init__(self) -> None:
        _validate_field_type(self.field_type)
        _validate_integer(self.value, "uint32 edit value")



#### Replace one official timestamp field with its unsigned wire value.
####
@dataclass(frozen=True, slots=True)
class SetTimeField:
    field_type: RecordFieldType
    value: int



    #### Validate the edit's closed field identifier and timestamp value.
    ####
    def __post_init__(self) -> None:
        _validate_field_type(self.field_type)
        _validate_integer(self.value, "time edit value")



#### Remove one named optional editable field occurrence.
####
@dataclass(frozen=True, slots=True)
class RemoveField:
    field_type: RecordFieldType



    #### Validate the edit's closed field identifier.
    ####
    def __post_init__(self) -> None:
        _validate_field_type(self.field_type)



RecordEdit = SetTextField | SetSecretField | SetBytesField | SetUInt32Field | SetTimeField | RemoveField



#### Own one authenticated editable document and serialize all state transitions.
####
class VaultSession:
    __slots__ = (
        "_baseline",
        "_changes",
        "_document",
        "_lock",
        "_locked",
        "_opened",
        "_original_document",
        "_path",
        "_retired_resources",
        "_save_snapshot",
        "_suspended",
    )



    #### Adopt an authenticated vault and begin one clean unlocked session.
    ####
    def __init__(
        self,
        opened: OpenedVault,
        path: Path | None = None,
        baseline: FileBaseline | None = None,
    ) -> None:
        if not isinstance(opened, OpenedVault):
            raise TypeError("session requires an authenticated opened vault")
        if (path is None) != (baseline is None):
            raise TypeError("session path and baseline must be supplied together")
        if path is not None and not isinstance(path, Path):
            raise TypeError("session path must use Path")
        if baseline is not None and not isinstance(baseline, FileBaseline):
            raise TypeError("session baseline must use FileBaseline")
        if baseline is not None and (
            opened.source_snapshot.size != baseline.size
            or opened.source_snapshot.sha256 != baseline.sha256
        ):
            raise ValueError("session baseline does not match the authenticated snapshot")
        self._opened = opened
        self._document = opened.document
        self._original_document = opened.document
        self._changes: tuple[Change, ...] = ()
        self._save_snapshot: VaultDocument | None = None
        self._suspended: SuspendedSession | None = None
        self._path = path
        self._baseline = baseline
        self._retired_resources: list[VaultDocument | OpenedVault] = []
        self._locked = False
        self._lock = RLock()



    #### Return the opaque identity of the current document revision.
    ####
    @property
    def revision(self) -> RevisionToken:
        with self._lock:
            self._require_active()
            return self._document.revision



    #### Report whether accepted mutations have not yet completed a save.
    ####
    @property
    def dirty(self) -> bool:
        with self._lock:
            return bool(self._changes) or self._suspended is not None



    #### Report whether document and key ownership has become terminal.
    ####
    @property
    def locked(self) -> bool:
        with self._lock:
            return self._locked



    #### Return immutable structural change evidence without record values.
    ####
    @property
    def changes(self) -> tuple[Change, ...]:
        with self._lock:
            return self._changes



    #### Borrow authenticated key state for the coordinated writer boundary.
    ####
    @property
    def _crypto_state_for_service(self) -> VaultCryptoState:
        with self._lock:
            self._require_active()
            return self._opened.crypto_state



    #### Return path-free pending identity retained until save or discard cleanup.
    ####
    @property
    def _suspended_for_service(self) -> SuspendedSession | None:
        with self._lock:
            return self._suspended



    #### Borrow the encrypted source baseline for publication checks.
    ####
    @property
    def source_snapshot(self) -> EncryptedSnapshot:
        with self._lock:
            self._require_active()
            return self._opened.source_snapshot



    #### Return the exact authenticated PasswordSafe format level in this session.
    ####
    @property
    def version(self) -> FormatVersion:
        with self._lock:
            self._require_active()
            return self._document.version



    #### Return the authoritative local destination bound by the service layer.
    ####
    @property
    def path(self) -> Path:
        with self._lock:
            self._require_active()
            if self._path is None:
                raise RuntimeError("vault session is not bound to local storage")
            return self._path



    #### Return the path-free evidence required for the next publication check.
    ####
    @property
    def baseline(self) -> FileBaseline:
        with self._lock:
            self._require_active()
            if self._baseline is None:
                raise RuntimeError("vault session is not bound to local storage")
            return self._baseline



    #### Return fresh immutable summaries for every record in current order.
    ####
    def records(self) -> tuple[RecordView, ...]:
        with self._lock:
            self._require_active()
            return tuple(self._view(record) for record in self._document.records)



    #### Apply one nonempty typed patch after handle and revision validation.
    ####
    def apply(
        self,
        handle: RecordHandle,
        expected_revision: RevisionToken,
        edits: tuple[RecordEdit, ...],
    ) -> RecordView:
        with self._lock:
            self._require_mutable(expected_revision)
            record = self._find_record(handle)
            if self._is_protected(record):
                raise ProtectedRecordError()
            if not isinstance(edits, tuple) or not edits:
                raise ValueError("record patch must contain at least one edit")
            fields = self._edited_fields(record, edits)
            planned = tuple(
                RawRecord(fields, item.ordinal, item.handle) if item.handle is handle else item
                for item in self._document.records
            )
            self._commit(planned, "edit", handle)
            return self._view(self._find_record(handle))



    #### Add one canonical record while consuming its mutable password owner.
    ####
    def add(self, new_record: NewRecord, expected_revision: RevisionToken) -> RecordView:
        if not isinstance(new_record, NewRecord):
            raise TypeError("new record must use NewRecord")
        with self._lock:
            try:
                self._require_mutable(expected_revision)
                fields = _new_record_fields(new_record)
                new_raw = RawRecord.create(fields, ordinal=len(self._document.records))
                self._commit((*self._document.records, new_raw), "add", new_raw.handle)
                return self._view(self._find_record(new_raw.handle))
            finally:
                new_record.password.close()



    #### Move one record to a checked ordinal while preserving its opaque handle.
    ####
    def move(
        self,
        handle: RecordHandle,
        expected_revision: RevisionToken,
        new_ordinal: int,
    ) -> RecordView:
        with self._lock:
            self._require_mutable(expected_revision)
            record = self._find_record(handle)
            if isinstance(new_ordinal, bool) or not isinstance(new_ordinal, int):
                raise TypeError("record ordinal must be an integer")
            if not 0 <= new_ordinal < len(self._document.records):
                raise ValueError("record ordinal is outside the session")
            if record.ordinal == new_ordinal:
                raise ValueError("record is already at that ordinal")
            planned = list(self._document.records)
            planned.pop(record.ordinal)
            planned.insert(new_ordinal, record)
            self._commit(tuple(planned), "move", handle)
            return self._view(self._find_record(handle))



    #### Delete one unprotected record after current-revision validation.
    ####
    def delete(self, handle: RecordHandle, expected_revision: RevisionToken) -> None:
        with self._lock:
            self._require_mutable(expected_revision)
            record = self._find_record(handle)
            if self._is_protected(record):
                raise ProtectedRecordError()
            planned = tuple(item for item in self._document.records if item.handle is not handle)
            self._commit(planned, "delete", handle)



    #### Add or enable the protected marker as one distinct revision.
    ####
    def protect(self, handle: RecordHandle, expected_revision: RevisionToken) -> RecordView:
        with self._lock:
            self._require_mutable(expected_revision)
            record = self._find_record(handle)
            if self._is_protected(record):
                raise ValueError("record is already protected")
            return self._change_protection(record, protected=True)



    #### Remove the protected marker as one distinct revision before later edits.
    ####
    def unprotect(self, handle: RecordHandle, expected_revision: RevisionToken) -> RecordView:
        with self._lock:
            self._require_mutable(expected_revision)
            record = self._find_record(handle)
            if not self._is_protected(record):
                raise ValueError("record is not protected")
            return self._change_protection(record, protected=False)



    #### Reveal one understood secret field through a separate bounded mutable lease.
    ####
    def reveal(
        self,
        handle: RecordHandle,
        field_type: RecordFieldType,
        *,
        max_bytes: int = MAX_SECRET_LEASE_BYTES,
    ) -> SecretLease:
        with self._lock:
            self._require_active()
            _validate_field_type(field_type)
            spec = RECORD_SCHEMA[field_type]
            if not spec.secret or spec.opaque:
                raise ValueError("field is not secret")
            record = self._find_record(handle)
            matching = tuple(field for field in record.fields if field.type_code == field_type)
            if len(matching) != 1:
                raise ValueError("secret field occurrence is unavailable")
            decoded = decode_record_field(matching[0], record_ordinal=record.ordinal, max_decoded_bytes=max_bytes)
            try:
                if not isinstance(decoded.value, SecretBuffer):
                    raise ValueError("secret field occurrence is unavailable")
                return SecretLease.copy_of(decoded.value, max_bytes=max_bytes)
            finally:
                decoded.close()



    #### Freeze one independently closable immutable revision for a save attempt.
    ####
    def _prepare_save(self) -> VaultDocument:
        with self._lock:
            self._require_active()
            if self._save_snapshot is not None:
                raise RuntimeError("save is already in progress")
            snapshot = self._document.retain(revision=self._document.revision)
            self._save_snapshot = snapshot
            return snapshot



    #### Retain an independent current revision without changing dirty/save state.
    ####
    def _export_snapshot(self) -> VaultDocument:
        with self._lock:
            self._require_active()
            if self._save_snapshot is not None:
                raise RuntimeError("save is in progress")
            return self._document.retain(revision=self._document.revision)



    #### Complete a frozen save and establish the current revision as clean.
    ####
    def _finish_save(
        self,
        opened: OpenedVault,
        published: PublishedFile,
    ) -> None:
        with self._lock:
            snapshot = self._require_save_snapshot()
            if not isinstance(opened, OpenedVault):
                raise TypeError("published save must use OpenedVault")
            if not isinstance(published, PublishedFile):
                raise TypeError("published save must use PublishedFile")
            if self._path is not None and published.path != self._path:
                raise ValueError("published save path does not match the session")
            if (
                opened.source_snapshot.size != published.size
                or opened.source_snapshot.sha256 != published.sha256
                or not documents_equal_exact(snapshot, opened.document)
            ):
                raise ValueError("published save does not match the frozen revision")
            opened.document._adopt_session_identity(snapshot)
            previous_opened = self._opened
            previous_document = self._document
            previous_original = self._original_document
            self._opened = opened
            self._document = opened.document
            self._original_document = opened.document
            self._save_snapshot = None
            self._path = published.path
            self._baseline = published.baseline
            self._changes = ()
            self._retire_resource(snapshot)
            if previous_document is not previous_original:
                self._retire_resource(previous_document)
            self._retire_resource(previous_opened)



    #### Release a failed save snapshot while retaining all unsaved mutations.
    ####
    def _abort_save(self) -> None:
        with self._lock:
            snapshot = self._require_save_snapshot()
            snapshot.close()
            self._save_snapshot = None



    #### Construct one dirty session from an authenticated pending artifact.
    ####
    @classmethod
    def _resume(
        cls,
        opened: OpenedVault,
        path: Path,
        baseline: FileBaseline,
        suspended: SuspendedSession,
    ) -> Self:
        if not isinstance(opened, OpenedVault):
            raise TypeError("resumed session requires an authenticated pending vault")
        if not isinstance(path, Path):
            raise TypeError("resumed session path must use Path")
        if not isinstance(baseline, FileBaseline):
            raise TypeError("resumed session baseline must use FileBaseline")
        if not isinstance(suspended, SuspendedSession):
            raise TypeError("resumed session metadata must use SuspendedSession")
        if (
            opened.source_snapshot.size != suspended.size
            or opened.source_snapshot.sha256 != suspended.sha256
            or baseline.sha256 != suspended.source_sha256
        ):
            raise ValueError("resumed session does not match its authenticated bindings")
        session = cls.__new__(cls)
        session._opened = opened
        session._document = opened.document
        session._original_document = opened.document
        session._changes = ()
        session._save_snapshot = None
        session._path = path
        session._baseline = baseline
        session._retired_resources = []
        session._suspended = suspended
        session._locked = False
        session._lock = RLock()
        return session



    #### Close one frozen dirty revision only after pending publication commits.
    ####
    def _finish_suspend(self) -> None:
        with self._lock:
            snapshot = self._require_save_snapshot()
            first_failure: BaseException | None = None
            try:
                snapshot.close()
            except BaseException as error:
                first_failure = error
                if not snapshot.closed:
                    self._retired_resources.append(snapshot)
            self._save_snapshot = None
            try:
                self._close_resources()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
            if first_failure is not None:
                raise first_failure



    #### Forget one pending identity only after exact artifact cleanup succeeds.
    ####
    def _finish_pending_cleanup(self, suspended: SuspendedSession) -> None:
        with self._lock:
            if self._suspended != suspended:
                raise ValueError("pending cleanup does not match the resumed session")
            self._suspended = None



    #### Close a clean session without implicitly saving or discarding changes.
    ####
    def lock(self) -> None:
        with self._lock:
            if self._locked and self._retired_resources:
                self._close_retired_resources()
                return
            self._require_active()
            if self._save_snapshot is not None:
                raise RuntimeError("save is in progress")
            if self._changes:
                raise UnsavedChangesError()
            self._close_resources()



    #### Explicitly discard dirty state and close document, keys, and snapshot.
    ####
    def discard_and_lock(self) -> None:
        with self._lock:
            self._require_active()
            if self._save_snapshot is not None:
                self._save_snapshot.close()
                self._save_snapshot = None
            self._close_resources()



    #### Defensively discard forgotten in-memory state without performing a save.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            if hasattr(self, "_locked") and not self._locked:
                self.discard_and_lock()
        with suppress(BaseException):
            if hasattr(self, "_retired_resources") and self._retired_resources:
                with self._lock:
                    self._close_retired_resources()



    #### Create a typed immutable public projection for one current raw record.
    ####
    def _view(self, record: RawRecord) -> RecordView:
        return RecordView(
            handle=record.handle,
            revision=self._document.revision,
            title=_public_text(record, RecordFieldType.TITLE),
            group=_public_text(record, RecordFieldType.GROUP),
            username=_public_text(record, RecordFieldType.USERNAME),
            url=_public_text(record, RecordFieldType.URL),
            protected=self._is_protected(record),
        )



    #### Find exactly one current record through its session-local opaque handle.
    ####
    def _find_record(self, handle: RecordHandle) -> RawRecord:
        if not isinstance(handle, RecordHandle):
            raise TypeError("record handle must be opaque")
        for record in self._document.records:
            if record.handle is handle:
                return record
        raise ValueError("record handle is not in this session")



    #### Report whether the optional protected marker has a nonzero value.
    ####
    def _is_protected(self, record: RawRecord) -> bool:
        matching = tuple(field for field in record.fields if field.type_code == RecordFieldType.PROTECTED)
        if not matching:
            return False
        decoded = decode_record_field(matching[0], record_ordinal=record.ordinal)
        try:
            return isinstance(decoded.value, int) and decoded.value != 0
        finally:
            decoded.close()



    #### Build one patched field sequence without mutating the current revision.
    ####
    def _edited_fields(self, record: RawRecord, edits: tuple[RecordEdit, ...]) -> tuple[RawField, ...]:
        field_types: set[RecordFieldType] = set()
        replacements: dict[RecordFieldType, RawField | None] = {}
        created: list[FieldPayload] = []
        secret_owners: list[SecretBuffer] = []
        try:
            for edit in edits:
                if not isinstance(
                    edit,
                    (SetTextField, SetSecretField, SetBytesField, SetUInt32Field, SetTimeField, RemoveField),
                ):
                    raise TypeError("record patch contains an unsupported edit")
                if edit.field_type in field_types:
                    raise ValueError("record patch repeats a field type")
                field_types.add(edit.field_type)
                matching = tuple(field for field in record.fields if field.type_code == edit.field_type)
                if len(matching) > 1:
                    raise ValueError("record field occurrence is ambiguous")
                replacement = self._encode_edit(edit, matching[0] if matching else None)
                replacements[edit.field_type] = replacement
                if replacement is not None:
                    created.append(replacement.payload)
                if isinstance(edit, SetSecretField):
                    secret_owners.append(edit.value)
            planned: list[RawField] = []
            for raw in record.fields:
                try:
                    field_type = RecordFieldType(raw.type_code)
                except ValueError:
                    planned.append(raw)
                    continue
                if field_type not in replacements:
                    planned.append(raw)
                    continue
                replacement = replacements.pop(field_type)
                if replacement is not None:
                    planned.append(replacement)
            terminator = next(
                (index for index, raw in enumerate(planned) if raw.type_code == RecordFieldType.END),
                len(planned),
            )
            for replacement in replacements.values():
                if replacement is not None:
                    planned.insert(terminator, replacement)
                    terminator += 1
            return tuple(planned)
        except BaseException:
            for payload in created:
                with suppress(BaseException):
                    payload.close()
            raise
        finally:
            for owner in secret_owners:
                owner.close()



    #### Validate one edit against the official schema and encode its replacement.
    ####
    def _encode_edit(self, edit: RecordEdit, raw: RawField | None) -> RawField | None:
        spec = RECORD_SCHEMA[edit.field_type]
        if spec.opaque or not spec.editable or spec.kind is FieldKind.EMPTY:
            raise ValueError("field is not editable")
        if isinstance(edit, RemoveField):
            if spec.mandatory:
                raise ValueError("mandatory field cannot be removed")
            if raw is None:
                raise ValueError("record field occurrence is unavailable")
            return None
        if isinstance(edit, SetTextField) and (spec.kind is not FieldKind.TEXT or spec.secret):
            raise TypeError("field does not accept public text edits")
        if isinstance(edit, SetSecretField) and (
            spec.kind not in (FieldKind.TEXT, FieldKind.BINARY) or not spec.secret
        ):
            raise TypeError("field does not accept secret edits")
        if isinstance(edit, SetBytesField) and (spec.kind is not FieldKind.BINARY or spec.secret):
            raise TypeError("field does not accept public binary edits")
        if isinstance(edit, SetUInt32Field) and spec.kind is not FieldKind.UINT32:
            raise TypeError("field does not accept uint32 edits")
        if isinstance(edit, SetTimeField) and spec.kind is not FieldKind.TIME:
            raise TypeError("field does not accept time edits")
        if spec.since > self._document.version:
            raise ValueError("field is not representable at this format version")
        value = edit.value
        encoded = (
            encode_record_field(raw, value)
            if raw is not None
            else encode_new_record_field(edit.field_type, value, ordinal=len(self._document.records))
        )
        return RawField(encoded.type_code, encoded.payload, encoded.ordinal, FieldClassification.UNDERSTOOD)



    #### Commit one protected-state transition without permitting other edits.
    ####
    def _change_protection(self, record: RawRecord, *, protected: bool) -> RecordView:
        matching = tuple(field for field in record.fields if field.type_code == RecordFieldType.PROTECTED)
        if len(matching) > 1:
            raise ValueError("protected field occurrence is ambiguous")
        if protected:
            spec = RECORD_SCHEMA[RecordFieldType.PROTECTED]
            if spec.since > self._document.version:
                raise ValueError("protected field is not representable at this format version")
            encoded = (
                encode_record_field(matching[0], 1)
                if matching
                else encode_new_record_field(RecordFieldType.PROTECTED, 1, ordinal=len(record.fields))
            )
            replacement = RawField(
                encoded.type_code,
                encoded.payload,
                encoded.ordinal,
                FieldClassification.UNDERSTOOD,
            )
            fields = (
                tuple(replacement if raw is matching[0] else raw for raw in record.fields)
                if matching
                else _insert_before_end(record.fields, replacement)
            )
            kind: ChangeKind = "protect"
        else:
            fields = tuple(raw for raw in record.fields if raw.type_code != RecordFieldType.PROTECTED)
            kind = "unprotect"
        planned = tuple(
            RawRecord(fields, item.ordinal, item.handle) if item.handle is record.handle else item
            for item in self._document.records
        )
        self._commit(planned, kind, record.handle)
        return self._view(self._find_record(record.handle))



    #### Fork one full document revision, remap warnings, and retire the predecessor.
    ####
    def _commit(
        self,
        planned_records: tuple[RawRecord, ...],
        kind: ChangeKind,
        handle: RecordHandle,
    ) -> None:
        previous = self._document
        revised = _fork_document(previous, planned_records)
        try:
            previous.close()
        except BaseException:
            revised.close()
            raise
        self._document = revised
        self._changes = (*self._changes, Change(kind, handle, revised.revision))



    #### Reject mutation while locked, frozen for save, or based on stale state.
    ####
    def _require_mutable(self, expected_revision: RevisionToken) -> None:
        self._require_active()
        if not isinstance(expected_revision, RevisionToken):
            raise TypeError("expected revision must be opaque")
        if expected_revision is not self._document.revision:
            raise StaleRevisionError()
        if self._save_snapshot is not None:
            raise RuntimeError("save is in progress")



    #### Reject access after deterministic session locking completes.
    ####
    def _require_active(self) -> None:
        if self._locked:
            raise RuntimeError("vault session is locked")



    #### Return the active save snapshot or reject an unmatched completion call.
    ####
    def _require_save_snapshot(self) -> VaultDocument:
        self._require_active()
        if self._save_snapshot is None:
            raise RuntimeError("save is not in progress")
        return self._save_snapshot



    #### Close current plaintext, original aggregate resources, and key material.
    ####
    def _close_resources(self) -> None:
        owners: list[VaultDocument | OpenedVault] = []
        if self._document is not self._original_document:
            owners.append(self._document)
        owners.append(self._opened)
        owners.extend(self._retired_resources)
        pending: list[VaultDocument | OpenedVault] = []
        first_failure: BaseException | None = None
        seen: set[int] = set()
        for owner in owners:
            if id(owner) in seen:
                continue
            seen.add(id(owner))
            try:
                owner.close()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
            if not owner.closed:
                pending.append(owner)
        self._retired_resources = pending
        self._locked = True
        self._changes = ()
        if first_failure is not None:
            raise first_failure



    #### Retire one superseded owner without destabilizing committed live state.
    ####
    def _retire_resource(self, owner: VaultDocument | OpenedVault) -> None:
        try:
            owner.close()
        except BaseException:
            if not owner.closed:
                self._retired_resources.append(owner)



    #### Retry every superseded owner and preserve any still-live cleanup graph.
    ####
    def _close_retired_resources(self) -> None:
        pending: list[VaultDocument | OpenedVault] = []
        first_failure: BaseException | None = None
        for owner in self._retired_resources:
            try:
                owner.close()
            except BaseException as error:
                if not owner.closed:
                    pending.append(owner)
                if first_failure is None:
                    first_failure = error
        self._retired_resources = pending
        if first_failure is not None:
            raise first_failure



#### Validate one record-field enum without accepting an arbitrary integer.
####
def _validate_field_type(field_type: RecordFieldType) -> None:
    if not isinstance(field_type, RecordFieldType):
        raise TypeError("record field type must use RecordFieldType")



#### Validate integer API values without treating booleans as numeric edits.
####
def _validate_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")



#### Decode one optional public text value without exposing secret projections.
####
def _public_text(record: RawRecord, field_type: RecordFieldType) -> str:
    matching = tuple(field for field in record.fields if field.type_code == field_type)
    if not matching:
        return ""
    decoded = decode_record_field(matching[0], record_ordinal=record.ordinal)
    try:
        return decoded.value if isinstance(decoded.value, str) else ""
    finally:
        decoded.close()



#### Insert one new optional field immediately before the record terminator.
####
def _insert_before_end(fields: tuple[RawField, ...], replacement: RawField) -> tuple[RawField, ...]:
    planned = list(fields)
    index = next(
        (ordinal for ordinal, raw in enumerate(planned) if raw.type_code == RecordFieldType.END),
        len(planned),
    )
    planned.insert(index, replacement)
    return tuple(planned)



#### Encode one complete new record including immutable UUID and terminator fields.
####
def _new_record_fields(new_record: NewRecord) -> tuple[RawField, ...]:
    fields: list[RawField] = []
    try:
        uuid_payload = InlinePayload.take_ownership(bytearray(new_record.uuid.bytes))
        fields.append(RawField(RecordFieldType.UUID, uuid_payload, 0, FieldClassification.UNDERSTOOD))
        optional_values = (
            (RecordFieldType.GROUP, new_record.group),
            (RecordFieldType.TITLE, new_record.title),
            (RecordFieldType.USERNAME, new_record.username),
            (RecordFieldType.PASSWORD, new_record.password),
            (RecordFieldType.URL, new_record.url),
        )
        for field_type, value in optional_values:
            if isinstance(value, str) and not value and field_type not in (
                RecordFieldType.TITLE,
                RecordFieldType.PASSWORD,
            ):
                continue
            fields.append(encode_new_record_field(field_type, value, ordinal=len(fields)))
        end_payload = InlinePayload.take_ownership(bytearray())
        fields.append(RawField(RecordFieldType.END, end_payload, len(fields), FieldClassification.UNDERSTOOD))
        return tuple(fields)
    except BaseException:
        for raw in fields:
            with suppress(BaseException):
                raw.payload.close()
        raise



#### Retain one copy-on-write document from a planned record order and field set.
####
def _fork_document(document: VaultDocument, planned_records: tuple[RawRecord, ...]) -> VaultDocument:
    old_fields = {
        id(raw): (record.ordinal, raw.ordinal, raw.type_code)
        for record in document.records
        for raw in record.fields
    }
    old_by_coordinates = {coordinates: identity for identity, coordinates in old_fields.items()}
    retained_payloads: dict[int, FieldPayload] = {}
    result_payloads: dict[int, FieldPayload] = {}
    remapped: dict[int, tuple[int, int]] = {}
    try:
        header = tuple(
            _retain_field(raw, raw.ordinal, retained_payloads, result_payloads)
            for raw in document.header_fields
        )
        records: list[RawRecord] = []
        for record_ordinal, planned in enumerate(planned_records):
            fields: list[RawField] = []
            for field_ordinal, raw in enumerate(planned.fields):
                if id(raw) in old_fields:
                    copied = _retain_field(raw, field_ordinal, retained_payloads, result_payloads)
                    remapped[id(raw)] = (record_ordinal, field_ordinal)
                else:
                    copied = RawField(raw.type_code, raw.payload, field_ordinal, raw.classification)
                    result_payloads.setdefault(id(raw.payload), raw.payload)
                fields.append(copied)
            records.append(RawRecord(tuple(fields), record_ordinal, planned.handle))
        warnings = _remap_warnings(document.warnings, old_by_coordinates, remapped)
        return VaultDocument.create(
            document.version,
            header,
            tuple(records),
            warnings=warnings,
            revision=RevisionToken(),
        )
    except BaseException:
        for payload in result_payloads.values():
            with suppress(BaseException):
                payload.close()
        raise



#### Retain one old payload lease while rebuilding an immutable raw field ordinal.
####
def _retain_field(
    raw: RawField,
    ordinal: int,
    retained_payloads: dict[int, FieldPayload],
    result_payloads: dict[int, FieldPayload],
) -> RawField:
    identity = id(raw.payload)
    payload = retained_payloads.get(identity)
    if payload is None:
        payload = raw.payload.retain()
        retained_payloads[identity] = payload
        result_payloads[id(payload)] = payload
    return RawField(raw.type_code, payload, ordinal, raw.classification)



#### Update retained record-warning coordinates and discard warnings for edits.
####
def _remap_warnings(
    warnings: tuple[PreservationWarning, ...],
    old_by_coordinates: dict[tuple[int, int, int], int],
    remapped: dict[int, tuple[int, int]],
) -> tuple[PreservationWarning, ...]:
    revised: list[PreservationWarning] = []
    for warning in warnings:
        if warning.section == "header":
            revised.append(warning)
            continue
        if warning.record_ordinal is None:
            continue
        identity = old_by_coordinates.get((warning.record_ordinal, warning.field_ordinal, warning.type_code))
        location = remapped.get(identity) if identity is not None else None
        if location is not None:
            revised.append(PreservationWarning(warning.code, "record", location[0], location[1], warning.type_code))
    return tuple(revised)
