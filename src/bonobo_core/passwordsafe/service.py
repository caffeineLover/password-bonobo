"""Coordinate authenticated PasswordSafe sessions and local publication.

The synchronous facade is the only public composition root for Botan, the
lossless codec, revision-safe sessions, and transactional local storage.  It
consumes transient passphrase owners and never exposes raw documents or keys.
"""

from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Final
from uuid import UUID

from .botan import BotanBackend
from .constants import (
    CURRENT_FORMAT_VERSION,
    MINIMUM_ITERATIONS,
    FormatVersion,
    HeaderFieldType,
    ResourceLimits,
)
from .crypto import RandomSource, SystemRandomSource, TwofishBackend
from .errors import ExternalModificationError, PasswordSafeError, StorageError, StorageReason
from .model import (
    FieldClassification,
    PreservationWarning,
    RawField,
    RawRecord,
    VaultDocument,
    documents_equal_exact,
)
from .payloads import FieldPayload, InlinePayload
from .pending import PendingSessionStore, SuspendedSession, _CommittedPendingError
from .reader import OpenedVault, PasswordSafeReader, VaultCryptoState
from .schema import ensure_fields_representable
from .secrets import SecretBuffer
from .session import VaultSession
from .snapshots import EncryptedSnapshot
from .storage import (
    LocalVaultStore,
    PublishedFile,
    RecoveryRevision,
    _CommittedPublicationError,
)
from .writer import PasswordSafeWriter



_DEFAULT_LIMITS: Final[ResourceLimits] = ResourceLimits()



#### Report safe committed-file and preservation evidence after publication.
####
@dataclass(frozen=True, slots=True)
class SaveResult:
    size: int
    sha256: str
    iterations_hardened: bool
    recovery: RecoveryRevision | None
    warnings: tuple[PreservationWarning, ...]



    #### Reject fabricated result metadata before it reaches public callers.
    ####
    def __post_init__(self) -> None:
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("save result size must be a nonnegative integer")
        if len(self.sha256) != 64 or any(character not in "0123456789abcdef" for character in self.sha256):
            raise ValueError("save result SHA-256 must be lowercase hexadecimal")
        if not isinstance(self.iterations_hardened, bool):
            raise TypeError("iteration hardening evidence must be boolean")
        if self.recovery is not None and not isinstance(self.recovery, RecoveryRevision):
            raise TypeError("save result recovery must use RecoveryRevision")
        if not isinstance(self.warnings, tuple) or not all(
            isinstance(item, PreservationWarning) for item in self.warnings
        ):
            raise TypeError("save result warnings must use PreservationWarning values")



#### Signal that source publication committed while later save work failed closed.
####
class _CommittedSaveError(StorageError):
    __slots__ = ("suspended",)



    #### Retain only a path-free selector when pending cleanup did not commit.
    ####
    def __init__(self, suspended: SuspendedSession | None) -> None:
        super().__init__(StorageReason.PUBLICATION_FAILED)
        self.suspended = suspended



#### Signal that pending publication committed before live-session cleanup failed.
####
class _CommittedSuspendError(StorageError):
    __slots__ = ("suspended",)



    #### Carry only the path-free selector needed for facade reconciliation.
    ####
    def __init__(self, suspended: SuspendedSession) -> None:
        super().__init__(StorageReason.PUBLICATION_FAILED)
        self.suspended = suspended



#### Authenticate a staged ordinary save against its frozen exact document.
####
@dataclass(slots=True)
class _RetainedCandidateValidator:
    reader: PasswordSafeReader
    crypto_state: VaultCryptoState
    document: VaultDocument



    #### Reopen with retained wrapping state and compare every plaintext byte.
    ####
    def __call__(self, path: Path) -> None:
        opened = self.reader.reopen_candidate(path, self.crypto_state)
        try:
            if not documents_equal_exact(opened.document, self.document):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
        finally:
            opened.close()



#### Authenticate a retained pending descriptor snapshot without reopening its name.
####
@dataclass(slots=True)
class _RetainedPendingValidator:
    reader: PasswordSafeReader
    crypto_state: VaultCryptoState
    document: VaultDocument



    #### Consume one encrypted snapshot and compare every authenticated plaintext byte.
    ####
    def __call__(self, snapshot: EncryptedSnapshot) -> None:
        opened = self.reader.reopen_snapshot(snapshot, self.crypto_state)
        try:
            if not documents_equal_exact(opened.document, self.document):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
        finally:
            opened.close()



#### Authenticate a staged fresh-envelope candidate with transient input.
####
@dataclass(slots=True)
class _FreshCandidateValidator:
    reader: PasswordSafeReader
    passphrase: SecretBuffer
    document: VaultDocument



    #### Open with the transient passphrase and compare the intended revision.
    ####
    def __call__(self, path: Path) -> None:
        opened = self.reader.open(path, self.passphrase)
        try:
            if not documents_equal_exact(opened.document, self.document):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
        finally:
            opened.close()



#### Authenticate a selected recovery without asserting current-document equality.
####
@dataclass(slots=True)
class _RecoveryValidator:
    reader: PasswordSafeReader
    passphrase: SecretBuffer



    #### Require a complete authenticated open before recovery publication.
    ####
    def __call__(self, path: Path) -> None:
        opened = self.reader.open(path, self.passphrase)
        opened.close()



#### Reject store validation that lacks operation-specific authentication state.
####
def _reject_unscoped_candidate(_path: Path) -> None:
    raise StorageError(StorageReason.VERIFICATION_FAILED)



#### Compose and coordinate the complete local PasswordSafe core.
####
class VaultService:
    __slots__ = ("_limits", "_lock", "_pending", "_random", "_reader", "_store", "_writer")



    #### Assemble explicit codec dependencies for production or qualified tests.
    ####
    def __init__(
        self,
        backend: TwofishBackend,
        working_directory: Path,
        recovery_directory: Path,
        *,
        random_source: RandomSource | None = None,
        limits: ResourceLimits = _DEFAULT_LIMITS,
    ) -> None:
        if not isinstance(backend, TwofishBackend):
            raise TypeError("service backend must implement TwofishBackend")
        if not isinstance(limits, ResourceLimits):
            raise TypeError("service limits must use ResourceLimits")
        selected_random = SystemRandomSource() if random_source is None else random_source
        if not isinstance(selected_random, RandomSource):
            raise TypeError("service randomness must implement RandomSource")
        self._limits = limits
        self._random = selected_random
        self._reader = PasswordSafeReader(backend, working_directory, limits=limits)
        self._writer = PasswordSafeWriter(
            backend,
            self._reader,
            working_directory,
            random_source=selected_random,
            limits=limits,
        )
        self._store = LocalVaultStore(
            working_directory,
            recovery_directory,
            validator=_reject_unscoped_candidate,
            random_source=selected_random,
        )
        self._pending = PendingSessionStore(
            recovery_directory,
            working_directory,
            random_source=selected_random,
        )
        self._lock = RLock()



    #### Load and qualify Botan before publishing a usable service facade.
    ####
    @classmethod
    def with_botan(
        cls,
        library_path: Path,
        working_directory: Path,
        recovery_directory: Path,
        *,
        limits: ResourceLimits = _DEFAULT_LIMITS,
    ) -> VaultService:
        return cls(
            BotanBackend.open(library_path),
            working_directory,
            recovery_directory,
            limits=limits,
        )



    #### Create, validate, exclusively publish, and reopen one empty vault.
    ####
    def create(
        self,
        path: Path,
        passphrase: SecretBuffer,
        *,
        database_name: str = "",
        iterations: int = MINIMUM_ITERATIONS,
    ) -> VaultSession:
        document: VaultDocument | None = None
        opened: OpenedVault | None = None
        try:
            _validate_passphrase(passphrase)
            destination = _absolute_path(path)
            with self._lock:
                document = _new_document(database_name, self._random)
                candidate = self._writer.write_new(document, passphrase, iterations=iterations)
                opened = _open_and_compare(self._reader, candidate.path, passphrase, document)
                published = self._store.publish_new(
                    destination,
                    candidate,
                    validator=_FreshCandidateValidator(self._reader, passphrase, document),
                )
                session = VaultSession(opened, destination, published.baseline)
                opened = None
                return session
        finally:
            if opened is not None:
                _close_without_masking(opened)
            if document is not None:
                _close_without_masking(document)
            _close_without_masking(passphrase)



    #### Capture, authenticate, and bind one unchanged local encrypted vault.
    ####
    def open(self, path: Path, passphrase: SecretBuffer) -> VaultSession:
        opened: OpenedVault | None = None
        try:
            _validate_passphrase(passphrase)
            destination = _absolute_path(path)
            with self._lock, self._pending.guard_open(destination):
                baseline = self._store.capture(destination)
                opened = self._reader.open(destination, passphrase)
                if (
                    opened.source_snapshot.size != baseline.size
                    or opened.source_snapshot.sha256 != baseline.sha256
                ):
                    raise ExternalModificationError()
                session = VaultSession(opened, destination, baseline)
                opened = None
                return session
        finally:
            if opened is not None:
                _close_without_masking(opened)
            _close_without_masking(passphrase)



    #### Serialize and publish one frozen session revision without a passphrase.
    ####
    def save(self, session: VaultSession) -> SaveResult:
        _validate_session(session)
        with self._lock:
            source = session.path
            suspended = session._suspended_for_service
            initial_iterations = session._crypto_state_for_service.iterations
            selected_iterations = session._crypto_state_for_service.serialization_iterations
            snapshot = session._prepare_save()
            opened: OpenedVault | None = None
            committed = False
            completed = False
            publication_failed = False
            try:
                candidate = self._writer.write(snapshot, session._crypto_state_for_service)
                opened = self._reader.reopen_candidate(
                    candidate.path,
                    session._crypto_state_for_service,
                )
                if not documents_equal_exact(snapshot, opened.document):
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                try:
                    published = self._store.publish(
                        source,
                        candidate,
                        session.baseline,
                        validator=_RetainedCandidateValidator(
                            self._reader,
                            session._crypto_state_for_service,
                            snapshot,
                        ),
                    )
                except _CommittedPublicationError as error:
                    published = error.published
                    publication_failed = True
                committed = True
                warnings = opened.document.warnings
                session._finish_save(opened, published)
                opened = None
                if suspended is not None:
                    self._pending.discard(source, suspended)
                    session._finish_pending_cleanup(suspended)
                completed = True
                result = _save_result(
                    published,
                    iterations_hardened=selected_iterations > initial_iterations,
                    warnings=warnings,
                )
                if publication_failed:
                    raise _CommittedSaveError(session._suspended_for_service) from None
                return result
            except _CommittedSaveError:
                raise
            except BaseException:
                if committed:
                    raise _CommittedSaveError(session._suspended_for_service) from None
                raise
            finally:
                if opened is not None:
                    _close_without_masking(opened)
                if not completed and not committed:
                    with suppress(BaseException):
                        session._abort_save()



    #### Durably suspend one dirty revision without replacing its source file.
    ####
    def suspend(self, session: VaultSession) -> SuspendedSession:
        _validate_session(session)
        with self._lock:
            if not session.dirty:
                raise ValueError("only a dirty session can be suspended")
            source = session.path
            baseline = session.baseline
            expected = session._suspended_for_service
            if self._store.capture(source) != baseline:
                raise ExternalModificationError()
            snapshot = session._prepare_save()
            committed = False
            suspended: SuspendedSession | None = None
            published = False
            try:
                try:
                    candidate = self._writer.write(snapshot, session._crypto_state_for_service)
                    try:
                        suspended = self._pending.publish(
                            source,
                            candidate,
                            baseline,
                            expected=expected,
                            validator=_RetainedPendingValidator(
                                self._reader,
                                session._crypto_state_for_service,
                                snapshot,
                            ),
                        )
                    except _CommittedPendingError as error:
                        suspended = error.suspended
                        published = True
                        self._pending.verify(source, suspended)
                    else:
                        published = True
                    if self._store.capture(source) != baseline:
                        self._pending.discard(source, suspended)
                        raise ExternalModificationError()
                    session._finish_suspend()
                    committed = True
                except BaseException:
                    if published and suspended is not None and self._pending_is_authoritative(source, suspended):
                        with suppress(BaseException):
                            session._finish_suspend()
                        committed = True
                        raise _CommittedSuspendError(suspended) from None
                    raise
                return suspended
            finally:
                if not committed and not session.locked:
                    with suppress(BaseException):
                        session._abort_save()



    #### Conservatively reconcile whether a published pending selector remains exact.
    ####
    def _pending_is_authoritative(self, source: Path, suspended: SuspendedSession) -> bool:
        try:
            self._pending.verify(source, suspended)
        except PasswordSafeError:
            return False
        except BaseException:
            return True
        return True



    #### Reauthenticate unchanged source and pending ciphertext into a dirty session.
    ####
    def resume(
        self,
        path: Path,
        passphrase: SecretBuffer,
        suspended: SuspendedSession,
    ) -> VaultSession:
        pending_snapshot: EncryptedSnapshot | None = None
        source_opened: OpenedVault | None = None
        pending_opened: OpenedVault | None = None
        try:
            _validate_passphrase(passphrase)
            if not isinstance(suspended, SuspendedSession):
                raise TypeError("resume metadata must use SuspendedSession")
            destination = _absolute_path(path)
            with self._lock:
                current = self._store.capture(destination)
                opened_pending = self._pending.open(destination, suspended)
                pending_snapshot = opened_pending.snapshot
                source_baseline = opened_pending.source_baseline
                if (
                    current != source_baseline
                    or current.sha256 != suspended.source_sha256
                ):
                    raise ExternalModificationError()
                source_opened = self._reader.open(destination, passphrase)
                if (
                    source_opened.source_snapshot.size != current.size
                    or source_opened.source_snapshot.sha256 != current.sha256
                    or self._store.capture(destination) != current
                ):
                    raise ExternalModificationError()
                pending_opened = self._reader.open_snapshot(pending_snapshot, passphrase)
                pending_snapshot = None
                if (
                    pending_opened.source_snapshot.size != suspended.size
                    or pending_opened.source_snapshot.sha256 != suspended.sha256
                ):
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                if self._store.capture(destination) != current:
                    raise ExternalModificationError()
                self._pending.verify(destination, suspended)
                session = VaultSession._resume(
                    pending_opened,
                    destination,
                    source_baseline,
                    suspended,
                )
                pending_opened = None
                return session
        finally:
            if pending_opened is not None:
                _close_without_masking(pending_opened)
            if source_opened is not None:
                _close_without_masking(source_opened)
            if pending_snapshot is not None:
                _close_without_masking(pending_snapshot)
            if isinstance(passphrase, SecretBuffer):
                _close_without_masking(passphrase)



    #### Explicitly remove only one selected unchanged pending artifact and slot.
    ####
    def discard_suspended(self, path: Path, suspended: SuspendedSession) -> None:
        destination = _absolute_path(path)
        if not isinstance(suspended, SuspendedSession):
            raise TypeError("discard metadata must use SuspendedSession")
        with self._lock:
            self._pending.discard(destination, suspended)



    #### Replace salt and wrapping material through a transactional session save.
    ####
    def change_master_passphrase(
        self,
        session: VaultSession,
        passphrase: SecretBuffer,
        *,
        iterations: int | None = None,
    ) -> SaveResult:
        _validate_passphrase(passphrase)
        try:
            _validate_session(session)
            with self._lock:
                initial_iterations = session._crypto_state_for_service.iterations
                selected_iterations = (
                    max(initial_iterations, MINIMUM_ITERATIONS)
                    if iterations is None
                    else iterations
                )
                if (
                    isinstance(selected_iterations, bool)
                    or not isinstance(selected_iterations, int)
                    or selected_iterations < initial_iterations
                ):
                    raise ValueError("passphrase rotation cannot reduce the iteration count")
                snapshot = session._prepare_save()
                opened: OpenedVault | None = None
                committed = False
                completed = False
                publication_failed = False
                try:
                    candidate = self._writer.write_new(
                        snapshot,
                        passphrase,
                        iterations=selected_iterations,
                        excluded_salt=session._crypto_state_for_service.salt,
                    )
                    opened = _open_and_compare(self._reader, candidate.path, passphrase, snapshot)
                    try:
                        published = self._store.publish(
                            session.path,
                            candidate,
                            session.baseline,
                            validator=_FreshCandidateValidator(self._reader, passphrase, snapshot),
                        )
                    except _CommittedPublicationError as error:
                        published = error.published
                        publication_failed = True
                    committed = True
                    warnings = opened.document.warnings
                    session._finish_save(opened, published)
                    opened = None
                    completed = True
                    result = _save_result(
                        published,
                        iterations_hardened=selected_iterations > initial_iterations,
                        warnings=warnings,
                    )
                    if publication_failed:
                        raise StorageError(StorageReason.PUBLICATION_FAILED) from None
                    return result
                finally:
                    if opened is not None:
                        _close_without_masking(opened)
                    if not completed and not committed:
                        with suppress(BaseException):
                            session._abort_save()
        finally:
            _close_without_masking(passphrase)



    #### Publish an independently keyed copy without changing source-session state.
    ####
    def export(
        self,
        session: VaultSession,
        destination: Path,
        passphrase: SecretBuffer,
        *,
        target_version: FormatVersion | None = None,
        iterations: int = MINIMUM_ITERATIONS,
    ) -> SaveResult:
        snapshot: VaultDocument | None = None
        exported: VaultDocument | None = None
        try:
            _validate_passphrase(passphrase)
            output = _absolute_path(destination)
            _validate_session(session)
            with self._lock:
                snapshot = session._export_snapshot()
                selected_version = snapshot.version if target_version is None else target_version
                if not isinstance(selected_version, FormatVersion):
                    raise TypeError("export target version must use FormatVersion")
                exported = (
                    snapshot.retain(revision=snapshot.revision)
                    if selected_version == snapshot.version
                    else _retarget_document(snapshot, selected_version)
                )
                candidate = self._writer.write_new(
                    exported,
                    passphrase,
                    iterations=iterations,
                    excluded_salt=session._crypto_state_for_service.salt,
                )
                published = self._store.publish_new(
                    output,
                    candidate,
                    validator=_FreshCandidateValidator(self._reader, passphrase, exported),
                )
                return _save_result(published, iterations_hardened=False, warnings=exported.warnings)
        finally:
            if exported is not None:
                _close_without_masking(exported)
            if snapshot is not None:
                _close_without_masking(snapshot)
            _close_without_masking(passphrase)



    #### Return path-free metadata for every currently visible recovery revision.
    ####
    def available_recovery(self, path: Path) -> tuple[RecoveryRevision, ...]:
        return self._store.available_recovery(_absolute_path(path))



    #### Explicitly authenticate, restore, reopen, and bind a selected revision.
    ####
    def restore(
        self,
        path: Path,
        recovery: RecoveryRevision,
        passphrase: SecretBuffer,
    ) -> VaultSession:
        opened: OpenedVault | None = None
        try:
            _validate_passphrase(passphrase)
            destination = _absolute_path(path)
            with self._lock:
                baseline = self._store.capture(destination)
                published = self._store.restore(
                    destination,
                    recovery,
                    baseline,
                    validator=_RecoveryValidator(self._reader, passphrase),
                )
                opened = self._reader.open(destination, passphrase)
                if (
                    opened.source_snapshot.size != published.size
                    or opened.source_snapshot.sha256 != published.sha256
                ):
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                session = VaultSession(opened, destination, published.baseline)
                opened = None
                return session
        finally:
            if opened is not None:
                _close_without_masking(opened)
            _close_without_masking(passphrase)



#### Create the canonical empty current-version document and own its payloads.
####
def _new_document(database_name: str, random_source: RandomSource) -> VaultDocument:
    if not isinstance(database_name, str):
        raise TypeError("database name must be text")
    uuid_bytes = random_source.bytes(16)
    if len(uuid_bytes) != 16:
        raise ValueError("random source returned an invalid UUID length")
    database_uuid = UUID(bytes=uuid_bytes, version=4).bytes
    values: list[tuple[HeaderFieldType, bytes]] = [
        (HeaderFieldType.VERSION, CURRENT_FORMAT_VERSION.to_bytes()),
        (HeaderFieldType.UUID, database_uuid),
    ]
    if database_name:
        values.append((HeaderFieldType.DATABASE_NAME, database_name.encode("utf-8")))
    values.append((HeaderFieldType.END, b""))
    fields: list[RawField] = []
    try:
        for ordinal, (field_type, value) in enumerate(values):
            fields.append(
                RawField(
                    field_type,
                    InlinePayload.from_bytes(value),
                    ordinal,
                    FieldClassification.UNDERSTOOD,
                )
            )
        return VaultDocument.create(CURRENT_FORMAT_VERSION, tuple(fields), ())
    except BaseException:
        _close_field_payloads(fields)
        raise



#### Prove legacy compatibility and clone one document at the selected level.
####
def _retarget_document(document: VaultDocument, target_version: FormatVersion) -> VaultDocument:
    ensure_fields_representable(document.header_fields, section="header", target_version=target_version)
    for record in document.records:
        ensure_fields_representable(record.fields, section="record", target_version=target_version)
    retained: list[RawField] = []
    try:
        header_fields: list[RawField] = []
        for raw in document.header_fields:
            payload = (
                InlinePayload.from_bytes(target_version.to_bytes())
                if raw.type_code == HeaderFieldType.VERSION
                else raw.payload.retain()
            )
            cloned = RawField(raw.type_code, payload, raw.ordinal, raw.classification)
            retained.append(cloned)
            header_fields.append(cloned)
        records: list[RawRecord] = []
        for record in document.records:
            fields: list[RawField] = []
            for raw in record.fields:
                cloned = RawField(raw.type_code, raw.payload.retain(), raw.ordinal, raw.classification)
                retained.append(cloned)
                fields.append(cloned)
            records.append(RawRecord(tuple(fields), record.ordinal, record.handle))
        return VaultDocument.create(
            target_version,
            tuple(header_fields),
            tuple(records),
            warnings=document.warnings,
            revision=document.revision,
        )
    except BaseException:
        _close_field_payloads(retained)
        raise



#### Open a fresh-envelope destination and compare the intended exact document.
####
def _open_and_compare(
    reader: PasswordSafeReader,
    path: Path,
    passphrase: SecretBuffer,
    document: VaultDocument,
) -> OpenedVault:
    opened = reader.open(path, passphrase)
    if not documents_equal_exact(opened.document, document):
        opened.close()
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    return opened



#### Convert storage evidence into the stable public service result.
####
def _save_result(
    published: PublishedFile,
    *,
    iterations_hardened: bool,
    warnings: tuple[PreservationWarning, ...],
) -> SaveResult:
    return SaveResult(
        published.size,
        published.sha256,
        iterations_hardened,
        published.recovery,
        warnings,
    )



#### Close every distinct retained field payload after failed document assembly.
####
def _close_field_payloads(fields: list[RawField]) -> None:
    seen: set[int] = set()
    for raw in fields:
        if id(raw.payload) in seen:
            continue
        seen.add(id(raw.payload))
        _close_without_masking(raw.payload)



#### Validate and normalize one caller path without resolving a missing leaf.
####
def _absolute_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("vault path must use Path")
    absolute = path.absolute()
    if not absolute.name:
        raise ValueError("vault path must name a file")
    return absolute



#### Require the explicit mutable owner used for transient passphrase input.
####
def _validate_passphrase(passphrase: SecretBuffer) -> None:
    if not isinstance(passphrase, SecretBuffer):
        raise TypeError("passphrase must use SecretBuffer")



#### Require a live typed session before beginning service orchestration.
####
def _validate_session(session: VaultSession) -> None:
    if not isinstance(session, VaultSession):
        raise TypeError("service operation requires VaultSession")
    if session.locked:
        raise RuntimeError("vault session is locked")



#### Close one resource owner without replacing an active operation failure.
####
def _close_without_masking(
    owner: EncryptedSnapshot | FieldPayload | OpenedVault | SecretBuffer | VaultDocument,
) -> None:
    with suppress(BaseException):
        owner.close()
