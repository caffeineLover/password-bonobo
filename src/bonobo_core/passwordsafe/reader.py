"""Authenticate PasswordSafe V3 snapshots before publishing ordered documents.

The reader owns the fail-closed boundary between encrypted snapshots and the raw
lossless model.  It streams CBC and HMAC work through a private builder, validates
all mandatory structure after authentication, and publishes closable aggregate
owners only when no quarantined payload remains unverified.
"""

import hashlib
import hmac
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Final, NoReturn, Protocol, Self, SupportsIndex, cast

from .constants import (
    BLOCK_BYTES,
    EOF_MARKER,
    FIELD_HEADER_BYTES,
    FILE_TAG,
    HMAC_BYTES,
    IV_BYTES,
    KEY_CHECK_BYTES,
    MINIMUM_ITERATIONS,
    SALT_BYTES,
    WRAPPED_KEY_BYTES,
    FieldKind,
    FormatVersion,
    HeaderFieldType,
    RecordFieldType,
    ResourceLimits,
)
from .crypto import (
    CbcDecryptor,
    DerivedKey,
    FieldAuthenticator,
    TwofishBackend,
    VaultKeys,
    stretch_passphrase,
    unwrap_vault_keys,
)
from .custom_fields import CustomField, parse_custom_fields
from .errors import (
    AuthenticationError,
    AuthenticationReason,
    IntegrityError,
    IntegrityReason,
    MalformedReason,
    MalformedVaultError,
    PasswordSafeError,
    ResourceLimitError,
    ResourceLimitReason,
    StorageError,
    StorageReason,
    UnsupportedFormatError,
    UnsupportedFormatReason,
)
from .model import (
    FieldClassification,
    PreservationWarning,
    PreservationWarningCode,
    RawField,
    RawRecord,
    SemanticManifest,
    VaultDocument,
)
from .payloads import EncryptedSpan, EncryptedSpanPayload, FieldPayload, InlinePayload, SnapshotReader
from .schema import (
    HEADER_SCHEMA,
    RECORD_SCHEMA,
    DecodedField,
    FieldMultiplicity,
    FieldSpec,
    MandatoryRole,
    decode_header_field,
    decode_record_field,
)
from .secrets import SecretBuffer
from .snapshots import EncryptedSnapshot



_FIXED_PREFIX_BYTES: Final[int] = (
    len(FILE_TAG) + SALT_BYTES + 4 + KEY_CHECK_BYTES + WRAPPED_KEY_BYTES + IV_BYTES
)
_FIXED_SUFFIX_BYTES: Final[int] = len(EOF_MARKER) + HMAC_BYTES
_MINIMUM_FILE_BYTES: Final[int] = _FIXED_PREFIX_BYTES + BLOCK_BYTES + _FIXED_SUFFIX_BYTES
_CLOSE_ATTEMPTS: Final[int] = 3
_OWNER_CONSTRUCTION_TOKEN: Final[object] = object()
_DEFAULT_LIMITS: Final[ResourceLimits] = ResourceLimits()



#### Describe the deterministic close state used by aggregate cleanup loops.
####
class _Closable(Protocol):



    #### Report whether the owner has reached terminal cleanup.
    ####
    @property
    def closed(self) -> bool:
        raise NotImplementedError



    #### Attempt deterministic cleanup and permit a later retry after failure.
    ####
    def close(self) -> None:
        raise NotImplementedError



#### Reject generic duplication of aggregate owners with borrowed dependencies.
####
class _ExclusiveOwner:
    __slots__ = ()



    #### Reject shallow copies that would alias one cleanup graph.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("reader owner cannot be copied or serialized")



    #### Reject deep copies that would duplicate secret-bearing ownership.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("reader owner cannot be copied or serialized")



    #### Reject direct state extraction before any secret owner is inspected.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("reader owner cannot be copied or serialized")



    #### Reject fabricated state injection without mutating live ownership.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("reader owner cannot be copied or serialized")



    #### Reject legacy serialization reduction for live resource graphs.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("reader owner cannot be copied or serialized")



    #### Reject protocol-specific reduction before owner state is traversed.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("reader owner cannot be copied or serialized")



#### Retain authenticated wrapping and vault-key material for later safe saves.
####
#### Deferred payloads borrow the current content key, so an ``OpenedVault`` closes
#### its document before this state.  The state never owns the raw passphrase.
####
class VaultCryptoState(_ExclusiveOwner):
    __slots__ = (
        "_closed",
        "_closing",
        "_derived_key",
        "_hardened_derived_key",
        "_vault_keys",
        "iterations",
        "iv",
        "salt",
    )



    #### Adopt authenticated owners only through the reader's publication path.
    ####
    def __init__(
        self,
        salt: bytes,
        iterations: int,
        iv: bytes,
        derived_key: DerivedKey,
        vault_keys: VaultKeys,
        hardened_derived_key: DerivedKey | None,
        *,
        _token: object,
    ) -> None:
        if _token is not _OWNER_CONSTRUCTION_TOKEN:
            raise TypeError("vault crypto state must be created by the authenticated reader")
        if hasattr(self, "_derived_key"):
            raise TypeError("vault crypto state cannot be reinitialized")
        if len(salt) != SALT_BYTES or len(iv) != IV_BYTES:
            raise ValueError("vault crypto metadata has an invalid fixed size")
        self.salt = salt
        self.iterations = iterations
        self.iv = iv
        self._derived_key = derived_key
        self._vault_keys = vault_keys
        self._hardened_derived_key = hardened_derived_key
        self._closed = False
        self._closing = False



    #### Expose the retained wrapping-key owner for authenticated serialization.
    ####
    @property
    def derived_key(self) -> DerivedKey:
        if self._closed or self._closing:
            raise RuntimeError("vault crypto state is closed")
        return self._derived_key



    #### Expose the independent current K/L owners required by deferred spans.
    ####
    @property
    def vault_keys(self) -> VaultKeys:
        if self._closed or self._closing:
            raise RuntimeError("vault crypto state is closed")
        return self._vault_keys



    #### Expose prepared minimum-iteration material when caller policy allowed it.
    ####
    @property
    def hardened_derived_key(self) -> DerivedKey | None:
        if self._closed or self._closing:
            raise RuntimeError("vault crypto state is closed")
        return self._hardened_derived_key



    #### Return the iteration count selected for the next ordinary serialization.
    ####
    #### A weak source is upgraded only when unlock prepared matching derived
    #### material while the caller's passphrase was still transiently available.
    ####
    @property
    def serialization_iterations(self) -> int:
        if self._closed or self._closing:
            raise RuntimeError("vault crypto state is closed")
        if self._hardened_derived_key is not None:
            return MINIMUM_ITERATIONS
        return self.iterations



    #### Return the retained derived owner matching serialization iterations.
    ####
    @property
    def serialization_derived_key(self) -> DerivedKey:
        if self._closed or self._closing:
            raise RuntimeError("vault crypto state is closed")
        if self._hardened_derived_key is not None:
            return self._hardened_derived_key
        return self._derived_key



    #### Report whether every retained secret owner has been wiped.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Wipe every independent owner, retaining failed children for a retry.
    ####
    def close(self) -> None:
        if self._closed:
            return
        self._closing = True
        first_failure: BaseException | None = None
        for owner in (self._vault_keys, self._derived_key, self._hardened_derived_key):
            if owner is None or owner.closed:
                continue
            try:
                owner.close()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
        self._closed = (
            self._vault_keys.closed
            and self._derived_key.closed
            and (self._hardened_derived_key is None or self._hardened_derived_key.closed)
        )
        self._closing = not self._closed
        if first_failure is not None:
            raise first_failure



    #### Enter only a live authenticated key state.
    ####
    def __enter__(self) -> Self:
        self.derived_key.borrow()
        return self



    #### Wipe retained keys after normal or exceptional aggregate use.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exception is None:
            self.close()
        else:
            with suppress(BaseException):
                self.close()



    #### Defensively wipe forgotten key state without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Render only lifecycle state and never salt, iteration, IV, or key material.
    ####
    def __repr__(self) -> str:
        return f"VaultCryptoState(closed={self.closed})"



#### Own one fully authenticated document, its keys, manifest, and source snapshot.
####
#### Cleanup follows the dependency order document, cryptographic state, snapshot.
#### A failed child remains available for explicit retry instead of being orphaned.
####
class OpenedVault(_ExclusiveOwner):
    __slots__ = ("_closed", "_crypto_state", "_document", "_manifest", "_source_snapshot")



    #### Adopt a complete publication graph only after reader validation succeeds.
    ####
    def __init__(
        self,
        document: VaultDocument,
        crypto_state: VaultCryptoState,
        manifest: SemanticManifest,
        source_snapshot: EncryptedSnapshot,
        *,
        _token: object,
    ) -> None:
        if _token is not _OWNER_CONSTRUCTION_TOKEN:
            raise TypeError("opened vaults must be created by the authenticated reader")
        if hasattr(self, "_document"):
            raise TypeError("opened vault cannot be reinitialized")
        self._document = document
        self._crypto_state = crypto_state
        self._manifest = manifest
        self._source_snapshot = source_snapshot
        self._closed = False



    #### Return the authenticated ordered document while this owner is live.
    ####
    @property
    def document(self) -> VaultDocument:
        self._require_open()
        return self._document



    #### Return retained authenticated key state needed by the writer.
    ####
    @property
    def crypto_state(self) -> VaultCryptoState:
        self._require_open()
        return self._crypto_state



    #### Return the redacted baseline manifest computed before publication.
    ####
    @property
    def manifest(self) -> SemanticManifest:
        self._require_open()
        return self._manifest



    #### Return the immutable encrypted snapshot owned by this aggregate.
    ####
    @property
    def source_snapshot(self) -> EncryptedSnapshot:
        self._require_open()
        return self._source_snapshot



    #### Report whether the complete dependency graph is terminal.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Close every owner in dependency order and surface the first cleanup fault.
    ####
    def close(self) -> None:
        if self._closed:
            return
        first_failure = _drive_close(self._document)
        if not self._document.closed:
            if first_failure is not None:
                raise first_failure
            raise RuntimeError("opened vault document cleanup did not complete")
        crypto_failure = _drive_close(self._crypto_state)
        if first_failure is None:
            first_failure = crypto_failure
        snapshot_failure = _drive_close(self._source_snapshot)
        if first_failure is None:
            first_failure = snapshot_failure
        self._closed = self._document.closed and self._crypto_state.closed and self._source_snapshot.closed
        if first_failure is not None:
            raise first_failure



    #### Reject property access after aggregate cleanup begins or completes.
    ####
    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("opened vault is closed")



    #### Enter one authenticated aggregate without changing ownership.
    ####
    def __enter__(self) -> Self:
        self._require_open()
        return self



    #### Close document, keys, and snapshot at aggregate context exit.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exception is None:
            self.close()
        else:
            with suppress(BaseException):
                self.close()



    #### Defensively release a forgotten publication graph without raising.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Render only safe counts and lifecycle metadata.
    ####
    def __repr__(self) -> str:
        return f"OpenedVault(closed={self.closed})"



#### Retain one parsed field and its quarantine-owned payload before publication.
####
@dataclass(slots=True)
class _BuilderField:
    type_code: int
    payload: FieldPayload
    ordinal: int
    classification: FieldClassification = FieldClassification.UNDERSTOOD



#### Own all partial payloads while parsing and schema validation remain private.
####
class _QuarantinedBuilder:
    __slots__ = ("_closed", "_header", "_records", "_transferred")



    #### Begin one empty header route with no publishable document object.
    ####
    def __init__(self) -> None:
        self._header: list[_BuilderField] = []
        self._records: list[list[_BuilderField]] = []
        self._closed = False
        self._transferred = False



    #### Append one payload only after parser resource counts have accepted it.
    ####
    def add_field(self, *, header: bool, record_ordinal: int, type_code: int, payload: FieldPayload) -> None:
        target = self._header if header else self._record(record_ordinal)
        target.append(_BuilderField(type_code, payload, len(target)))



    #### Create or return one exact private record slot in traversal order.
    ####
    def _record(self, ordinal: int) -> list[_BuilderField]:
        if ordinal == len(self._records):
            self._records.append([])
        if not 0 <= ordinal < len(self._records):
            raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        return self._records[ordinal]



    #### Expose private header items solely to post-HMAC validation helpers.
    ####
    @property
    def header(self) -> list[_BuilderField]:
        return self._header



    #### Expose private record items solely to post-HMAC validation helpers.
    ####
    @property
    def records(self) -> list[list[_BuilderField]]:
        return self._records



    #### Convert validated private fields into the first public document owner.
    ####
    def build(
        self,
        version: FormatVersion,
        warnings: tuple[PreservationWarning, ...],
    ) -> VaultDocument:
        header_fields = tuple(_raw_field(item) for item in self._header)
        records = tuple(
            RawRecord.create(tuple(_raw_field(item) for item in fields), ordinal=record_ordinal)
            for record_ordinal, fields in enumerate(self._records)
        )
        document = VaultDocument.create(version, header_fields, records, warnings=warnings)
        self._transferred = True
        self._closed = True
        return document



    #### Report whether payload cleanup or ownership transfer is terminal.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Close every distinct partial payload and retain failed owners for retry.
    ####
    def close(self) -> None:
        if self._closed:
            return
        if self._transferred:
            self._closed = True
            return
        pending: list[FieldPayload] = []
        seen: set[int] = set()
        first_failure: BaseException | None = None
        for item in (*self._header, *(field for record in self._records for field in record)):
            if id(item.payload) in seen:
                continue
            seen.add(id(item.payload))
            try:
                item.payload.close()
            except BaseException as error:
                pending.append(item.payload)
                if first_failure is None:
                    first_failure = error
        self._closed = not pending
        if first_failure is not None:
            raise first_failure



#### Describe the authenticated fixed envelope without retaining source context.
####
@dataclass(frozen=True, slots=True)
class _Envelope:
    salt: bytes
    iterations: int
    password_check: bytes
    wrapped_keys: bytes
    iv: bytes
    encrypted_offset: int
    encrypted_length: int
    stored_hmac: bytes



#### Capture, authenticate, and transfer one local encrypted snapshot on success.
####
class PasswordSafeReader(_ExclusiveOwner):
    __slots__ = ("_backend", "_has_quarantined_document", "_limits", "_lock", "_private_directory")



    #### Retain a verified backend, private snapshot directory, and immutable limits.
    ####
    def __init__(
        self,
        backend: TwofishBackend,
        private_directory: Path,
        *,
        limits: ResourceLimits = _DEFAULT_LIMITS,
    ) -> None:
        if hasattr(self, "_backend"):
            raise TypeError("PasswordSafeReader cannot be reinitialized")
        if not isinstance(backend, TwofishBackend):
            raise TypeError("reader backend must implement TwofishBackend")
        if not isinstance(private_directory, Path):
            raise TypeError("reader private directory must be a Path")
        if not isinstance(limits, ResourceLimits):
            raise TypeError("reader limits must use ResourceLimits")
        backend.self_test()
        self._backend = backend
        self._private_directory = private_directory
        self._limits = limits
        self._lock = RLock()
        self._has_quarantined_document = False



    #### Report only whether private parsing state is currently unpublished.
    ####
    @property
    def has_quarantined_document(self) -> bool:
        with self._lock:
            return self._has_quarantined_document



    #### Capture a pathname once, then delegate to the shared authenticated path.
    ####
    #### This boundary owns and closes its snapshot on every failed Exception or
    #### BaseException.  The caller-owned passphrase remains live and unchanged.
    ####
    def open(self, path: Path, passphrase: SecretBuffer) -> OpenedVault:
        snapshot: EncryptedSnapshot | None = None
        try:
            if not isinstance(path, Path):
                raise StorageError(StorageReason.PREPARATION_FAILED)
            try:
                with path.open("rb") as source:
                    snapshot = EncryptedSnapshot.capture(
                        source,
                        self._private_directory,
                        chunk_size=self._limits.io_chunk_bytes,
                        max_bytes=self._limits.max_encrypted_file_bytes,
                    )
            except PasswordSafeError:
                raise
            except Exception:
                raise StorageError(StorageReason.PREPARATION_FAILED) from None
            opened = self.open_snapshot(snapshot, passphrase)
            snapshot = None
            return opened
        finally:
            if snapshot is not None:
                _cleanup_without_masking(snapshot)



    #### Reopen one encrypted candidate with authenticated retained wrapping state.
    ####
    #### Candidate verification accepts only the salt and iteration policy chosen
    #### from the live source state.  It never needs or reconstructs a passphrase.
    ####
    def reopen_candidate(self, path: Path, crypto_state: VaultCryptoState) -> OpenedVault:
        if not isinstance(path, Path):
            raise TypeError("candidate path must be a Path")
        if not isinstance(crypto_state, VaultCryptoState):
            raise TypeError("candidate crypto state must use VaultCryptoState")
        snapshot: EncryptedSnapshot | None = None
        try:
            try:
                with path.open("rb") as source:
                    snapshot = EncryptedSnapshot.capture(
                        source,
                        self._private_directory,
                        chunk_size=self._limits.io_chunk_bytes,
                        max_bytes=self._limits.max_encrypted_file_bytes,
                    )
            except PasswordSafeError:
                raise
            except Exception:
                raise StorageError(StorageReason.PREPARATION_FAILED) from None
            with self._lock:
                opened = self._reopen_candidate_locked(snapshot, crypto_state)
            snapshot = None
            return opened
        finally:
            if snapshot is not None:
                _cleanup_without_masking(snapshot)



    #### Reopen a candidate under caller-supplied fresh passphrase policy.
    ####
    #### Creation, passphrase change, and independent export use this path because
    #### no retained source-derived state may authorize their new salt.  A mismatch
    #### closes the authenticated aggregate before exposing a fixed storage error.
    ####
    def reopen_candidate_with_passphrase(
        self,
        path: Path,
        passphrase: SecretBuffer,
        *,
        expected_salt: bytes,
        expected_iterations: int,
    ) -> OpenedVault:
        if not isinstance(expected_salt, bytes) or len(expected_salt) != SALT_BYTES:
            raise ValueError("expected candidate salt must be exactly 32 bytes")
        if (
            isinstance(expected_iterations, bool)
            or not isinstance(expected_iterations, int)
            or not 1 <= expected_iterations <= self._limits.max_iterations
        ):
            raise ValueError("expected candidate iterations are outside reader limits")
        opened = self.open(path, passphrase)
        if (
            opened.crypto_state.salt != expected_salt
            or opened.crypto_state.iterations != expected_iterations
        ):
            opened.close()
            raise StorageError(StorageReason.VERIFICATION_FAILED)
        return opened



    #### Authenticate a caller snapshot through the same quarantine used by open.
    ####
    #### Success transfers snapshot ownership to ``OpenedVault``.  Failure leaves
    #### the caller's snapshot live while closing every reader-created owner.
    ####
    def open_snapshot(self, snapshot: EncryptedSnapshot, passphrase: SecretBuffer) -> OpenedVault:
        if not isinstance(snapshot, EncryptedSnapshot):
            raise TypeError("reader snapshot must be EncryptedSnapshot")
        if not isinstance(passphrase, SecretBuffer):
            raise TypeError("reader passphrase must be SecretBuffer")
        with self._lock:
            if snapshot.size > self._limits.max_encrypted_file_bytes:
                raise ResourceLimitError(ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES)
            return self._open_snapshot_locked(snapshot, passphrase)



    #### Run one complete authenticated transaction while the reader lock is held.
    ####
    def _open_snapshot_locked(self, snapshot: EncryptedSnapshot, passphrase: SecretBuffer) -> OpenedVault:
        envelope: _Envelope | None = None
        derived_key: DerivedKey | None = None
        self._has_quarantined_document = True
        try:
            envelope = _read_envelope(snapshot, self._limits)
            derived_key = stretch_passphrase(
                passphrase,
                envelope.salt,
                envelope.iterations,
                limits=self._limits,
            )
            calculated_check = hashlib.sha256(derived_key.borrow()).digest()
            if not hmac.compare_digest(calculated_check, envelope.password_check):
                raise AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED)
            transferred_derived = derived_key
            derived_key = None
            return self._publish_authenticated_snapshot(
                snapshot,
                envelope,
                transferred_derived,
                passphrase,
            )
        except PasswordSafeError as error:
            raise error from None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE) from None
        finally:
            self._has_quarantined_document = False
            if derived_key is not None:
                _cleanup_without_masking(derived_key)



    #### Verify one candidate envelope against retained source-derived material.
    ####
    def _reopen_candidate_locked(
        self,
        snapshot: EncryptedSnapshot,
        crypto_state: VaultCryptoState,
    ) -> OpenedVault:
        self._has_quarantined_document = True
        derived_key: DerivedKey | None = None
        try:
            envelope = _read_envelope(snapshot, self._limits)
            if (
                envelope.salt != crypto_state.salt
                or envelope.iterations != crypto_state.serialization_iterations
            ):
                raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE)
            selected = crypto_state.serialization_derived_key
            calculated_check = hashlib.sha256(selected.borrow()).digest()
            if not hmac.compare_digest(calculated_check, envelope.password_check):
                raise IntegrityError(IntegrityReason.HMAC_MISMATCH)
            derived_key = DerivedKey(bytearray(selected.borrow()))
            transferred = derived_key
            derived_key = None
            return self._publish_authenticated_snapshot(snapshot, envelope, transferred, None)
        except PasswordSafeError as error:
            raise error from None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE) from None
        finally:
            self._has_quarantined_document = False
            if derived_key is not None:
                _cleanup_without_masking(derived_key)



    #### Publish one quarantined document while adopting supplied derived owners.
    ####
    #### This helper owns both supplied key objects on every success and failure.
    #### The snapshot transfers only when a complete ``OpenedVault`` is returned.
    ####
    def _publish_authenticated_snapshot(
        self,
        snapshot: EncryptedSnapshot,
        envelope: _Envelope,
        derived_key: DerivedKey,
        hardening_passphrase: SecretBuffer | None,
    ) -> OpenedVault:
        owned_derived: DerivedKey | None = derived_key
        owned_hardened: DerivedKey | None = None
        vault_keys: VaultKeys | None = None
        builder: _QuarantinedBuilder | None = None
        document: VaultDocument | None = None
        crypto_state: VaultCryptoState | None = None
        published = False
        try:
            vault_keys = unwrap_vault_keys(self._backend, derived_key, envelope.wrapped_keys)
            builder, calculated_hmac = _decrypt_fields(
                snapshot,
                envelope,
                self._backend,
                vault_keys,
                self._limits,
            )
            if not hmac.compare_digest(calculated_hmac, envelope.stored_hmac):
                raise IntegrityError(IntegrityReason.HMAC_MISMATCH)
            version = _validate_version_first(builder, self._limits)
            warnings = _validate_schema(builder, version, self._limits)
            document = builder.build(version, warnings)
            builder = None
            if (
                hardening_passphrase is not None
                and envelope.iterations < MINIMUM_ITERATIONS
                and self._limits.max_iterations >= MINIMUM_ITERATIONS
            ):
                owned_hardened = stretch_passphrase(
                    hardening_passphrase,
                    envelope.salt,
                    MINIMUM_ITERATIONS,
                    limits=self._limits,
                )
            crypto_state = VaultCryptoState(
                envelope.salt,
                envelope.iterations,
                envelope.iv,
                derived_key,
                vault_keys,
                owned_hardened,
                _token=_OWNER_CONSTRUCTION_TOKEN,
            )
            owned_derived = None
            vault_keys = None
            owned_hardened = None
            manifest = document.semantic_manifest(chunk_size=self._limits.io_chunk_bytes)
            opened = OpenedVault(
                document,
                crypto_state,
                manifest,
                snapshot,
                _token=_OWNER_CONSTRUCTION_TOKEN,
            )
            document = None
            crypto_state = None
            published = True
            return opened
        finally:
            if not published:
                for owner in (builder, document, crypto_state, vault_keys, owned_hardened, owned_derived):
                    if owner is not None:
                        _cleanup_without_masking(owner)



#### Read and validate all fixed-size envelope and final marker boundaries.
####
def _read_envelope(snapshot: EncryptedSnapshot, limits: ResourceLimits) -> _Envelope:
    if snapshot.size < _MINIMUM_FILE_BYTES:
        raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE)
    prefix = snapshot.read_at(0, _FIXED_PREFIX_BYTES)
    if prefix[:len(FILE_TAG)] != FILE_TAG:
        raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE)
    offset = len(FILE_TAG)
    salt = prefix[offset:offset + SALT_BYTES]
    offset += SALT_BYTES
    iterations = int.from_bytes(prefix[offset:offset + 4], "little")
    offset += 4
    if iterations == 0:
        raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE)
    if iterations > limits.max_iterations:
        raise ResourceLimitError(ResourceLimitReason.MAX_ITERATIONS)
    password_check = prefix[offset:offset + KEY_CHECK_BYTES]
    offset += KEY_CHECK_BYTES
    wrapped_keys = prefix[offset:offset + WRAPPED_KEY_BYTES]
    offset += WRAPPED_KEY_BYTES
    iv = prefix[offset:offset + IV_BYTES]
    encrypted_length = snapshot.size - _FIXED_PREFIX_BYTES - _FIXED_SUFFIX_BYTES
    if encrypted_length <= 0 or encrypted_length % BLOCK_BYTES:
        raise MalformedVaultError(MalformedReason.INVALID_ENVELOPE)
    suffix = snapshot.read_at(snapshot.size - _FIXED_SUFFIX_BYTES, _FIXED_SUFFIX_BYTES)
    if suffix[:len(EOF_MARKER)] != EOF_MARKER:
        raise IntegrityError(IntegrityReason.UNEXPECTED_EOF)
    return _Envelope(
        salt,
        iterations,
        password_check,
        wrapped_keys,
        iv,
        _FIXED_PREFIX_BYTES,
        encrypted_length,
        suffix[len(EOF_MARKER):],
    )



#### Decrypt every bounded field frame and return only a private builder plus HMAC.
####
def _decrypt_fields(
    snapshot: EncryptedSnapshot,
    envelope: _Envelope,
    backend: TwofishBackend,
    vault_keys: VaultKeys,
    limits: ResourceLimits,
) -> tuple[_QuarantinedBuilder, bytes]:
    builder = _QuarantinedBuilder()
    authenticator = FieldAuthenticator(vault_keys.hmac_key)
    header = True
    record_ordinal = 0
    field_count = 0
    ciphertext_position = 0
    previous_block = envelope.iv
    try:
        with CbcDecryptor(backend, vault_keys.content_key, envelope.iv) as decryptor:
            while ciphertext_position < envelope.encrypted_length:
                if not header and record_ordinal >= limits.max_records:
                    raise ResourceLimitError(ResourceLimitReason.MAX_RECORDS)
                remaining_ciphertext = envelope.encrypted_length - ciphertext_position
                if remaining_ciphertext < BLOCK_BYTES:
                    raise MalformedVaultError(MalformedReason.INVALID_FIELD)
                absolute_offset = envelope.encrypted_offset + ciphertext_position
                first_ciphertext = snapshot.read_at(absolute_offset, BLOCK_BYTES)
                first_plaintext = bytearray(decryptor.transform(first_ciphertext))
                try:
                    payload_length = int.from_bytes(first_plaintext[:4], "little")
                    type_code = first_plaintext[4]
                    framed_length = FIELD_HEADER_BYTES + payload_length
                    padded_length = ((framed_length + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
                    if padded_length > remaining_ciphertext:
                        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
                    field_count += 1
                    if field_count > limits.max_fields:
                        raise ResourceLimitError(ResourceLimitReason.MAX_FIELDS)
                    if type_code == 0xFF and payload_length != 0:
                        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
                    payload = _consume_field_payload(
                        snapshot,
                        backend,
                        vault_keys,
                        decryptor,
                        authenticator,
                        first_plaintext,
                        absolute_offset,
                        padded_length,
                        payload_length,
                        previous_block,
                        limits,
                    )
                finally:
                    first_plaintext[:] = bytes(len(first_plaintext))
                try:
                    builder.add_field(
                        header=header,
                        record_ordinal=record_ordinal,
                        type_code=type_code,
                        payload=payload,
                    )
                except BaseException:
                    _cleanup_payload_without_masking(payload)
                    raise
                ciphertext_position += padded_length
                previous_block = snapshot.read_at(
                    envelope.encrypted_offset + ciphertext_position - BLOCK_BYTES,
                    BLOCK_BYTES,
                )
                if type_code == HeaderFieldType.END and header:
                    header = False
                elif type_code == RecordFieldType.END and not header:
                    record_ordinal += 1
                    if record_ordinal > limits.max_records:
                        raise ResourceLimitError(ResourceLimitReason.MAX_RECORDS)
            if header or (builder.records and builder.records[-1][-1].type_code != RecordFieldType.END):
                raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        return builder, authenticator.digest()
    except BaseException:
        _cleanup_without_masking(builder)
        raise
    finally:
        authenticator.close()



#### Consume one frame continuously while authenticating only declared payload bytes.
####
def _consume_field_payload(
    snapshot: EncryptedSnapshot,
    backend: TwofishBackend,
    vault_keys: VaultKeys,
    decryptor: CbcDecryptor,
    authenticator: FieldAuthenticator,
    first_plaintext: bytearray,
    ciphertext_offset: int,
    ciphertext_length: int,
    payload_length: int,
    previous_block: bytes,
    limits: ResourceLimits,
) -> FieldPayload:
    inline = bytearray() if payload_length <= limits.max_inline_payload_bytes else None
    digest = hashlib.sha256()
    consumed = 0
    try:
        first_count = min(payload_length, BLOCK_BYTES - FIELD_HEADER_BYTES)
        if first_count:
            first_view = memoryview(first_plaintext)
            first_chunk = first_view[FIELD_HEADER_BYTES:FIELD_HEADER_BYTES + first_count]
            try:
                authenticator.update(cast(bytes, first_chunk))
                digest.update(first_chunk)
                if inline is not None:
                    inline.extend(first_chunk)
            finally:
                first_chunk.release()
                first_view.release()
            consumed = first_count
        block_offset = BLOCK_BYTES
        while block_offset < ciphertext_length:
            ciphertext = snapshot.read_at(ciphertext_offset + block_offset, BLOCK_BYTES)
            plaintext = bytearray(decryptor.transform(ciphertext))
            plaintext_view = memoryview(plaintext)
            try:
                payload_count = min(payload_length - consumed, BLOCK_BYTES)
                if payload_count:
                    chunk = plaintext_view[:payload_count]
                    try:
                        authenticator.update(cast(bytes, chunk))
                        digest.update(chunk)
                        if inline is not None:
                            inline.extend(chunk)
                    finally:
                        chunk.release()
                    consumed += payload_count
            finally:
                plaintext_view.release()
                plaintext[:] = bytes(len(plaintext))
            block_offset += BLOCK_BYTES
        if consumed != payload_length:
            raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        if inline is not None:
            payload = InlinePayload.take_ownership(inline)
            inline = None
            return payload
        span = EncryptedSpan(
            backend=backend,
            content_key=vault_keys.content_key,
            previous_block=previous_block,
            ciphertext_offset=ciphertext_offset,
            ciphertext_length=ciphertext_length,
            frame_offset=FIELD_HEADER_BYTES,
            payload_length=payload_length,
        )
        # EncryptedSnapshot exposes a read-only ``size`` property while the older
        # protocol models it as an attribute.  Runtime behavior is the exact bounded
        # surface, so narrow only this static variance mismatch.
        deferred = EncryptedSpanPayload(cast(SnapshotReader, snapshot), span)
        try:
            verification = hashlib.sha256()
            observed = 0
            for verification_chunk in deferred.iter_chunks(limits.io_chunk_bytes):
                verification.update(verification_chunk)
                observed += len(verification_chunk)
            if observed != payload_length or not hmac.compare_digest(verification.digest(), digest.digest()):
                raise MalformedVaultError(MalformedReason.INVALID_FIELD)
            return deferred
        except BaseException:
            _cleanup_without_masking(deferred)
            raise
    finally:
        if inline is not None:
            inline[:] = bytes(len(inline))



#### Validate that Version is first, unique, exact-width, and currently supported.
####
def _validate_version_first(builder: _QuarantinedBuilder, limits: ResourceLimits) -> FormatVersion:
    return _validate_version_fields(builder.header, limits)



#### Validate Version against one borrowed field sequence without taking ownership.
####
def _validate_version_fields(fields: list[_BuilderField], limits: ResourceLimits) -> FormatVersion:
    if not fields or fields[0].type_code != HeaderFieldType.VERSION:
        raise MalformedVaultError(MalformedReason.MISSING_MANDATORY_FIELD)
    if sum(item.type_code == HeaderFieldType.VERSION for item in fields) != 1:
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
    version_payload = fields[0].payload
    if version_payload.length != 2:
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
    raw = _materialize_exact(version_payload, limits.io_chunk_bytes)
    try:
        version = FormatVersion.from_uint16(int.from_bytes(raw, "little"))
    finally:
        raw[:] = bytes(len(raw))
    if not version.supported:
        raise UnsupportedFormatError(UnsupportedFormatReason.UNSUPPORTED_VERSION)
    return version



#### Validate all authenticated schema rules and return only safe warnings.
####
def _validate_schema(
    builder: _QuarantinedBuilder,
    version: FormatVersion,
    limits: ResourceLimits,
) -> tuple[PreservationWarning, ...]:
    return _validate_schema_fields(builder.header, builder.records, version, limits)



#### Validate borrowed header and record sequences through the shared schema rules.
####
def _validate_schema_fields(
    header: list[_BuilderField],
    records: list[list[_BuilderField]],
    version: FormatVersion,
    limits: ResourceLimits,
) -> tuple[PreservationWarning, ...]:
    if not header or header[-1].type_code != HeaderFieldType.END:
        raise MalformedVaultError(MalformedReason.MISSING_MANDATORY_FIELD)
    warnings: list[PreservationWarning] = []
    decoded_total = 0
    decoded_total = _validate_field_sequence(
        header,
        section="header",
        record_ordinal=None,
        version=version,
        limits=limits,
        warnings=warnings,
        decoded_total=decoded_total,
    )
    for record_ordinal, fields in enumerate(records):
        if not fields or fields[-1].type_code != RecordFieldType.END:
            raise MalformedVaultError(MalformedReason.MISSING_MANDATORY_FIELD)
        decoded_total = _validate_field_sequence(
            fields,
            section="record",
            record_ordinal=record_ordinal,
            version=version,
            limits=limits,
            warnings=warnings,
            decoded_total=decoded_total,
        )
        _validate_record_mandatory(fields)
        _validate_conditional_groups(fields)
    return tuple(warnings)



#### Reapply authenticated schema and budget policy to an intended save revision.
####
#### Borrowed adapters permit exact reuse of reader validation without adopting or
#### mutating the document's payload owners, classifications, or warning evidence.
####
def validate_document_for_serialization(document: VaultDocument, limits: ResourceLimits) -> None:
    if not isinstance(document, VaultDocument):
        raise TypeError("serialization document must use VaultDocument")
    if not isinstance(limits, ResourceLimits):
        raise TypeError("serialization limits must use ResourceLimits")
    if len(document.records) > limits.max_records:
        raise ResourceLimitError(ResourceLimitReason.MAX_RECORDS)
    field_count = len(document.header_fields)
    if field_count > limits.max_fields:
        raise ResourceLimitError(ResourceLimitReason.MAX_FIELDS)
    if any(field.ordinal != ordinal for ordinal, field in enumerate(document.header_fields)):
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
    for record_ordinal, record in enumerate(document.records):
        if record.ordinal != record_ordinal:
            raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        if any(field.ordinal != ordinal for ordinal, field in enumerate(record.fields)):
            raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        if len(record.fields) > limits.max_fields - field_count:
            raise ResourceLimitError(ResourceLimitReason.MAX_FIELDS)
        field_count += len(record.fields)
    header = [
        _BuilderField(field.type_code, field.payload, field.ordinal)
        for field in document.header_fields
    ]
    records = [
        [_BuilderField(field.type_code, field.payload, field.ordinal) for field in record.fields]
        for record in document.records
    ]
    version = _validate_version_fields(header, limits)
    if version != document.version:
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
    warnings = _validate_schema_fields(header, records, version, limits)
    borrowed_fields = (*header, *(field for record in records for field in record))
    document_fields = (
        *document.header_fields,
        *(field for record in document.records for field in record.fields),
    )
    if any(
        borrowed.classification is not existing.classification
        for borrowed, existing in zip(borrowed_fields, document_fields, strict=True)
    ) or warnings != document.warnings:
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)



#### Classify and validate one exact field sequence after stored-HMAC success.
####
def _validate_field_sequence(
    fields: list[_BuilderField],
    *,
    section: str,
    record_ordinal: int | None,
    version: FormatVersion,
    limits: ResourceLimits,
    warnings: list[PreservationWarning],
    decoded_total: int,
) -> int:
    occurrences: dict[int, int] = {}
    for item in fields:
        spec = _field_spec(section, item.type_code)
        raw = _raw_field(item)
        if spec is None:
            item.classification = FieldClassification.UNKNOWN
            warnings.append(
                PreservationWarning(
                    PreservationWarningCode.UNKNOWN_FIELD,
                    "header" if section == "header" else "record",
                    record_ordinal,
                    item.ordinal,
                    item.type_code,
                )
            )
            continue
        if spec.since > version:
            raise UnsupportedFormatError(UnsupportedFormatReason.UNSUPPORTED_MANDATORY_CONTENT)
        occurrences[item.type_code] = occurrences.get(item.type_code, 0) + 1
        if occurrences[item.type_code] > 1 and spec.multiplicity is FieldMultiplicity.SINGLE:
            if spec.mandatory:
                raise MalformedVaultError(MalformedReason.INVALID_FIELD)
            warnings.append(
                PreservationWarning(
                    PreservationWarningCode.DUPLICATE_OPTIONAL_FIELD,
                    "header" if section == "header" else "record",
                    record_ordinal,
                    item.ordinal,
                    item.type_code,
                )
            )
        if spec.kind is FieldKind.TEXT:
            if item.payload.length > limits.max_decoded_text_bytes - decoded_total:
                raise ResourceLimitError(ResourceLimitReason.MAX_DECODED_TEXT_BYTES)
            decoded_total += item.payload.length
        decoded = _decode_one(raw, section, record_ordinal, limits)
        try:
            if decoded.warning is not None:
                item.classification = FieldClassification.MALFORMED
                warnings.append(decoded.warning)
            if section == "record" and item.type_code == RecordFieldType.CUSTOM_TEXT_FIELD:
                _validate_custom_projection(decoded, item, record_ordinal, warnings)
        finally:
            decoded.close()
    return decoded_total



#### Decode one authenticated nonopaque field through the existing schema boundary.
####
def _decode_one(
    raw: RawField,
    section: str,
    record_ordinal: int | None,
    limits: ResourceLimits,
) -> DecodedField:
    if section == "header":
        return decode_header_field(raw, max_decoded_bytes=limits.max_decoded_text_bytes)
    if record_ordinal is None:
        raise MalformedVaultError(MalformedReason.INVALID_FIELD)
    return decode_record_field(
        raw,
        record_ordinal=record_ordinal,
        max_decoded_bytes=limits.max_decoded_text_bytes,
    )



#### Retain malformed custom grammar as one optional preservation warning.
####
def _validate_custom_projection(
    decoded: DecodedField,
    item: _BuilderField,
    record_ordinal: int | None,
    warnings: list[PreservationWarning],
) -> None:
    if not isinstance(decoded.value, SecretBuffer) or record_ordinal is None:
        return
    custom_fields: tuple[CustomField, ...] = ()
    try:
        custom_fields = parse_custom_fields(decoded.value)
    except (TypeError, ValueError):
        item.classification = FieldClassification.MALFORMED
        warnings.append(
            PreservationWarning(
                PreservationWarningCode.MALFORMED_OPTIONAL_FIELD,
                "record",
                record_ordinal,
                item.ordinal,
                item.type_code,
            )
        )
    finally:
        for custom_field in custom_fields:
            _cleanup_without_masking(custom_field)



#### Require exactly one UUID, Title, and Password in each authenticated record.
####
def _validate_record_mandatory(fields: list[_BuilderField]) -> None:
    for type_code in (RecordFieldType.UUID, RecordFieldType.TITLE, RecordFieldType.PASSWORD):
        if sum(item.type_code == type_code for item in fields) != 1:
            raise MalformedVaultError(MalformedReason.MISSING_MANDATORY_FIELD)



#### Enforce conditional attachment and passkey groups without normalizing bytes.
####
def _validate_conditional_groups(fields: list[_BuilderField]) -> None:
    present = {item.type_code for item in fields}
    attachment_types = {field.value for field in RecordFieldType if 0x25 <= field.value <= 0x29}
    passkey_types = {field.value for field in RecordFieldType if 0x2A <= field.value <= 0x2F}
    if present & attachment_types:
        required_attachment = {
            field.value
            for field, spec in RECORD_SCHEMA.items()
            if spec.mandatory_role is MandatoryRole.ATTACHMENT_REQUIRED
        }
        if not required_attachment <= present:
            raise MalformedVaultError(MalformedReason.MISSING_MANDATORY_FIELD)
    if present & passkey_types:
        required_passkeys = {
            field.value
            for field, spec in RECORD_SCHEMA.items()
            if spec.mandatory_role is MandatoryRole.PASSKEY_REQUIRED
        }
        if not required_passkeys <= present:
            raise MalformedVaultError(MalformedReason.MISSING_MANDATORY_FIELD)



#### Look up known field metadata without rejecting unknown extension bytes.
####
def _field_spec(section: str, type_code: int) -> FieldSpec | None:
    try:
        if section == "header":
            return HEADER_SCHEMA.get(HeaderFieldType(type_code))
        return RECORD_SCHEMA.get(RecordFieldType(type_code))
    except ValueError:
        return None



#### Materialize one already-bounded structural payload and verify exact length.
####
def _materialize_exact(payload: FieldPayload, chunk_size: int) -> bytearray:
    data = bytearray()
    try:
        for chunk in payload.iter_chunks(chunk_size):
            data.extend(chunk)
            if len(data) > payload.length:
                raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        if len(data) != payload.length:
            raise MalformedVaultError(MalformedReason.INVALID_FIELD)
        return data
    except BaseException:
        data[:] = bytes(len(data))
        raise



#### Convert private field metadata while preserving its exact payload owner.
####
def _raw_field(item: _BuilderField) -> RawField:
    return RawField(item.type_code, item.payload, item.ordinal, item.classification)



#### Drive one retryable owner toward terminal cleanup and return its first fault.
####
def _drive_close(owner: _Closable) -> BaseException | None:
    first_failure: BaseException | None = None
    for _attempt in range(_CLOSE_ATTEMPTS):
        if owner.closed:
            break
        try:
            owner.close()
        except BaseException as error:
            if first_failure is None:
                first_failure = error
    return first_failure



#### Clean a partial owner exhaustively without replacing an active failure.
####
def _cleanup_without_masking(owner: _Closable) -> None:
    with suppress(BaseException):
        _drive_close(owner)



#### Retry one protocol payload close without requiring lifecycle introspection.
####
def _cleanup_payload_without_masking(payload: FieldPayload) -> None:
    for _attempt in range(_CLOSE_ATTEMPTS):
        try:
            payload.close()
        except BaseException:
            continue
        return
