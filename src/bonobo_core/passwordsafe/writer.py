"""Serialize ordered PasswordSafe documents into authenticated candidates.

The writer validates an intended document before opening output, emits fresh
writer-owned cryptographic material through bounded field streams, then delegates
candidate authentication to the reader and compares every plaintext payload byte.
It never publishes a destination or writes plaintext storage.
"""

import hashlib
import os
import stat
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Final

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
    ResourceLimits,
)
from .crypto import (
    CbcEncryptor,
    DerivedKey,
    FieldAuthenticator,
    RandomSource,
    SystemRandomSource,
    TwofishBackend,
    VaultKeys,
    stretch_passphrase,
    wrap_vault_keys,
)
from .errors import PasswordSafeError, ResourceLimitError, ResourceLimitReason, StorageError, StorageReason
from .model import RawField, SemanticManifest, VaultDocument, documents_equal_exact
from .reader import (
    OpenedVault,
    PasswordSafeReader,
    VaultCryptoState,
    validate_document_for_serialization,
)
from .secrets import SecretBuffer



_MAX_FIELD_BYTES: Final[int] = 0xFFFF_FFFF
_SALT_ATTEMPTS: Final[int] = 32
_DEFAULT_LIMITS: Final[ResourceLimits] = ResourceLimits()
_FIXED_CANDIDATE_BYTES: Final[int] = (
    len(FILE_TAG) + SALT_BYTES + 4 + KEY_CHECK_BYTES + WRAPPED_KEY_BYTES + IV_BYTES + len(EOF_MARKER) + HMAC_BYTES
)



#### Retain safe evidence for one complete, reopened encrypted candidate.
####
#### The path is intentionally excluded from representations.  Storage owns the
#### later publication or deletion of the still-encrypted file.
####
@dataclass(frozen=True, slots=True)
class EncryptedCandidate:
    path: Path = field(repr=False)
    sha256: str
    manifest: SemanticManifest
    reopened_manifest: SemanticManifest



    #### Validate redacted evidence without opening or rendering the candidate.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("candidate path must be a Path")
        if len(self.sha256) != 64 or any(character not in "0123456789abcdef" for character in self.sha256):
            raise ValueError("candidate SHA-256 must be lowercase hexadecimal")
        if not isinstance(self.manifest, SemanticManifest):
            raise TypeError("candidate manifest must use SemanticManifest")
        if not isinstance(self.reopened_manifest, SemanticManifest):
            raise TypeError("reopened manifest must use SemanticManifest")



#### Retain the stable identity of one exclusively created candidate pathname.
####
@dataclass(frozen=True, slots=True)
class _CandidateArtifact:
    path: Path = field(repr=False)
    identity: tuple[int, int]



    #### Remove only the pathname that still denotes the created regular file.
    ####
    def remove(self) -> bool:
        try:
            if _path_identity(self.path) != self.identity:
                return True
            self.path.unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False



#### Borrow the exact wrapping material selected for one candidate envelope.
####
@dataclass(frozen=True, slots=True)
class _SerializationMaterial:
    salt: bytes
    iterations: int
    derived_key: DerivedKey



#### Reopen an ordinary candidate through the established positional boundary.
####
@dataclass(frozen=True, slots=True)
class _RetainedCandidateReopener:
    reader: PasswordSafeReader
    crypto_state: VaultCryptoState



    #### Preserve the reader call shape used by transaction fault injection.
    ####
    def __call__(self, path: Path) -> OpenedVault:
        return self.reader.reopen_candidate(path, self.crypto_state)



#### Reopen a fresh-envelope candidate under its exact selected policy.
####
@dataclass(frozen=True, slots=True)
class _FreshCandidateReopener:
    reader: PasswordSafeReader
    passphrase: SecretBuffer
    salt: bytes
    iterations: int



    #### Authenticate the candidate without retaining passphrase ownership.
    ####
    def __call__(self, path: Path) -> OpenedVault:
        return self.reader.reopen_candidate_with_passphrase(
            path,
            self.passphrase,
            expected_salt=self.salt,
            expected_iterations=self.iterations,
        )



#### Prepare independently randomized candidates and verify them before return.
####
class PasswordSafeWriter:
    __slots__ = ("_backend", "_candidate_directory", "_limits", "_random", "_reader")



    #### Retain the trusted codec dependencies and caller-owned private directory.
    ####
    def __init__(
        self,
        backend: TwofishBackend,
        reader: PasswordSafeReader,
        candidate_directory: Path,
        *,
        random_source: RandomSource | None = None,
        limits: ResourceLimits = _DEFAULT_LIMITS,
    ) -> None:
        if not isinstance(backend, TwofishBackend):
            raise TypeError("writer backend must implement TwofishBackend")
        if not isinstance(reader, PasswordSafeReader):
            raise TypeError("writer reader must use PasswordSafeReader")
        if not isinstance(candidate_directory, Path):
            raise TypeError("candidate directory must be a Path")
        if not isinstance(limits, ResourceLimits):
            raise TypeError("writer limits must use ResourceLimits")
        selected_random = SystemRandomSource() if random_source is None else random_source
        if not isinstance(selected_random, RandomSource):
            raise TypeError("writer randomness must implement RandomSource")
        backend.self_test()
        self._backend = backend
        self._reader = reader
        self._candidate_directory = candidate_directory
        self._random = selected_random
        self._limits = limits



    #### Serialize, authenticate, reopen, and exactly compare one intended revision.
    ####
    #### Success leaves only encrypted output for the storage layer.  Every failure
    #### closes key state and removes any partially or completely written candidate.
    ####
    def write(self, document: VaultDocument, crypto_state: VaultCryptoState) -> EncryptedCandidate:
        if not isinstance(document, VaultDocument):
            raise TypeError("writer document must use VaultDocument")
        if not isinstance(crypto_state, VaultCryptoState):
            raise TypeError("writer crypto state must use VaultCryptoState")
        material = _SerializationMaterial(
            crypto_state.salt,
            crypto_state.serialization_iterations,
            crypto_state.serialization_derived_key,
        )
        reopen = _RetainedCandidateReopener(self._reader, crypto_state)
        return self._write_verified(document, material, reopen)



    #### Serialize under a new salt and transient caller-owned passphrase.
    ####
    #### This path retains no raw passphrase.  It closes the derived owner after
    #### exact candidate reopen while leaving passphrase disposal to its caller.
    ####
    def write_new(
        self,
        document: VaultDocument,
        passphrase: SecretBuffer,
        *,
        iterations: int = MINIMUM_ITERATIONS,
        excluded_salt: bytes | None = None,
    ) -> EncryptedCandidate:
        if not isinstance(document, VaultDocument):
            raise TypeError("writer document must use VaultDocument")
        if not isinstance(passphrase, SecretBuffer):
            raise TypeError("writer passphrase must use SecretBuffer")
        if (
            isinstance(iterations, bool)
            or not isinstance(iterations, int)
            or not MINIMUM_ITERATIONS <= iterations <= self._limits.max_iterations
        ):
            raise ValueError("new candidate iterations are outside writer policy")
        if excluded_salt is not None and (
            not isinstance(excluded_salt, bytes) or len(excluded_salt) != SALT_BYTES
        ):
            raise ValueError("excluded salt must be exactly 32 bytes")
        salt: bytes | None = None
        for _attempt in range(_SALT_ATTEMPTS):
            candidate_salt = self._random.bytes(SALT_BYTES)
            if len(candidate_salt) != SALT_BYTES:
                raise ValueError("random source returned an invalid salt length")
            if candidate_salt != excluded_salt:
                salt = candidate_salt
                break
        if salt is None:
            raise ValueError("random source could not produce an independent salt")
        derived_key = stretch_passphrase(passphrase, salt, iterations, limits=self._limits)
        try:
            material = _SerializationMaterial(salt, iterations, derived_key)
            reopen = _FreshCandidateReopener(self._reader, passphrase, salt, iterations)
            return self._write_verified(document, material, reopen)
        finally:
            derived_key.close()



    #### Write, authenticate, and compare one candidate under selected material.
    ####
    def _write_verified(
        self,
        document: VaultDocument,
        material: _SerializationMaterial,
        reopen: Callable[[Path], OpenedVault],
    ) -> EncryptedCandidate:
        _validate_document(document, material.iterations, self._limits)
        artifact: _CandidateArtifact | None = None
        vault_keys: VaultKeys | None = None
        reopened: OpenedVault | None = None
        succeeded = False
        result: EncryptedCandidate | None = None
        failure: BaseException | None = None
        try:
            manifest = document.semantic_manifest(chunk_size=self._limits.io_chunk_bytes)
            vault_keys = _new_vault_keys(self._random)
            iv = self._random.bytes(IV_BYTES)
            if len(iv) != IV_BYTES:
                raise ValueError("random source returned an invalid IV length")
            artifact, output = _open_candidate(self._candidate_directory)
            with output:
                _write_candidate(
                    output,
                    document,
                    material,
                    vault_keys,
                    iv,
                    self._backend,
                    self._random,
                    self._limits,
                )
                _flush_and_sync(output)
            reopened = reopen(artifact.path)
            if not documents_equal_exact(
                document,
                reopened.document,
                chunk_size=self._limits.io_chunk_bytes,
            ):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            reopened_manifest = reopened.manifest
            verified_sha256 = reopened.source_snapshot.sha256
            if not _candidate_matches(artifact, verified_sha256, self._limits.io_chunk_bytes):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            reopened.close()
            reopened = None
            result = EncryptedCandidate(
                artifact.path,
                verified_sha256,
                manifest,
                reopened_manifest,
            )
            succeeded = True
        except BaseException as error:
            failure = error
        finally:
            if reopened is not None:
                with suppress(BaseException):
                    reopened.close()
            if vault_keys is not None:
                with suppress(BaseException):
                    vault_keys.close()
            if artifact is not None and not succeeded and not artifact.remove() and isinstance(failure, Exception):
                raise StorageError(StorageReason.PREPARATION_FAILED) from None
        if failure is not None:
            if isinstance(failure, PasswordSafeError):
                raise failure from None
            if not isinstance(failure, Exception):
                raise failure
            raise StorageError(StorageReason.PREPARATION_FAILED) from None
        if result is None:
            raise StorageError(StorageReason.PREPARATION_FAILED)
        return result



#### Create fresh joint keys and wipe both buffers unless ownership transfers.
####
def _new_vault_keys(random_source: RandomSource) -> VaultKeys:
    content_key = bytearray()
    hmac_key = bytearray()
    transferred = False
    try:
        content_key[:] = random_source.bytes(HMAC_BYTES)
        hmac_key[:] = random_source.bytes(HMAC_BYTES)
        keys = VaultKeys(content_key, hmac_key)
        transferred = True
        return keys
    finally:
        if not transferred:
            content_key[:] = bytes(len(content_key))
            hmac_key[:] = bytes(len(hmac_key))



#### Create one exclusive owner-only encrypted output in the private directory.
####
def _open_candidate(directory: Path) -> tuple[_CandidateArtifact, BinaryIO]:
    descriptor: int | None = None
    candidate_path: Path | None = None
    try:
        resolved = directory.resolve(strict=True)
        if not resolved.is_dir():
            raise OSError
        descriptor, raw_path = tempfile.mkstemp(prefix=".bonobo-", suffix=".candidate", dir=resolved)
        candidate_path = Path(raw_path)
        os.chmod(raw_path, 0o600, follow_symlinks=False)
        identity = _descriptor_identity(descriptor)
        output = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = None
        return _CandidateArtifact(candidate_path, identity), output
    except Exception:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if candidate_path is not None:
            with suppress(OSError):
                candidate_path.unlink()
        raise StorageError(StorageReason.PREPARATION_FAILED) from None



#### Return one regular file's stable device and inode identity.
####
def _descriptor_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError
    return metadata.st_dev, metadata.st_ino



#### Resolve a pathname identity without following a symbolic link.
####
def _path_identity(path: Path) -> tuple[int, int]:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError
    return metadata.st_dev, metadata.st_ino



#### Verify that the created pathname still contains the authenticated ciphertext.
####
def _candidate_matches(artifact: _CandidateArtifact, expected_sha256: str, chunk_size: int) -> bool:
    try:
        if _path_identity(artifact.path) != artifact.identity:
            return False
        digest = _sha256_file(artifact.path, chunk_size)
        return digest == expected_sha256 and _path_identity(artifact.path) == artifact.identity
    except OSError:
        return False



#### Emit the fixed envelope, encrypted field stream, EOF marker, and HMAC.
####
def _write_candidate(
    output: BinaryIO,
    document: VaultDocument,
    material: _SerializationMaterial,
    vault_keys: VaultKeys,
    iv: bytes,
    backend: TwofishBackend,
    random_source: RandomSource,
    limits: ResourceLimits,
) -> None:
    prefix = b"".join(
        (
            FILE_TAG,
            material.salt,
            material.iterations.to_bytes(4, "little"),
            hashlib.sha256(material.derived_key.borrow()).digest(),
            wrap_vault_keys(backend, material.derived_key, vault_keys),
            iv,
        )
    )
    _write_all(output, prefix)
    authenticator = FieldAuthenticator(vault_keys.hmac_key)
    try:
        with CbcEncryptor(backend, vault_keys.content_key, iv) as encryptor:
            for raw_field in _iter_document_fields(document):
                _write_field(output, raw_field, encryptor, authenticator, random_source, limits)
        _write_all(output, EOF_MARKER)
        _write_all(output, authenticator.digest())
    finally:
        authenticator.close()



#### Yield every header and record field in exact authenticated order.
####
def _iter_document_fields(document: VaultDocument) -> tuple[RawField, ...]:
    fields = list(document.header_fields)
    for record in document.records:
        fields.extend(record.fields)
    return tuple(fields)



#### Stream one framed payload and field-local random padding into CBC blocks.
####
def _write_field(
    output: BinaryIO,
    raw_field: RawField,
    encryptor: CbcEncryptor,
    authenticator: FieldAuthenticator,
    random_source: RandomSource,
    limits: ResourceLimits,
) -> None:
    pending = bytearray()
    observed = 0
    try:
        header = raw_field.payload.length.to_bytes(4, "little") + bytes((raw_field.type_code,))
        _encrypt_bytes(output, encryptor, pending, memoryview(header))
        for chunk in raw_field.payload.iter_chunks(limits.io_chunk_bytes):
            if not chunk:
                raise ValueError("field payload yielded an empty chunk")
            observed += len(chunk)
            if observed > raw_field.payload.length:
                raise ValueError("field payload exceeded its declared length")
            authenticator.update(chunk)
            _encrypt_bytes(output, encryptor, pending, chunk)
        if observed != raw_field.payload.length:
            raise ValueError("field payload did not reach its declared length")
        padding_length = (-(FIELD_HEADER_BYTES + raw_field.payload.length)) % BLOCK_BYTES
        padding = random_source.bytes(padding_length)
        if len(padding) != padding_length:
            raise ValueError("random source returned an invalid padding length")
        _encrypt_bytes(output, encryptor, pending, memoryview(padding))
        if pending:
            raise ValueError("field padding did not complete a CBC block")
    finally:
        pending[:] = bytes(len(pending))
        pending.clear()



#### Encrypt one bounded plaintext view while retaining at most one partial block.
####
def _encrypt_bytes(
    output: BinaryIO,
    encryptor: CbcEncryptor,
    pending: bytearray,
    data: memoryview[int],
) -> None:
    position = 0
    while position < len(data):
        copied = min(BLOCK_BYTES - len(pending), len(data) - position)
        pending.extend(data[position:position + copied])
        position += copied
        if len(pending) == BLOCK_BYTES:
            _write_all(output, encryptor.transform(bytes(pending)))
            pending[:] = bytes(len(pending))
            pending.clear()



#### Write every byte or fail without accepting a short binary write.
####
def _write_all(output: BinaryIO, data: bytes) -> None:
    position = 0
    while position < len(data):
        written = output.write(data[position:])
        if written is None or written <= 0:
            raise OSError("candidate output made no progress")
        position += written



#### Flush language buffers and synchronize complete candidate bytes to storage.
####
def _flush_and_sync(output: BinaryIO) -> None:
    output.flush()
    os.fsync(output.fileno())



#### Validate structure and level compatibility before creating output storage.
####
def _validate_document(
    document: VaultDocument,
    iterations: int,
    limits: ResourceLimits,
) -> None:
    validate_document_for_serialization(document, limits)
    if iterations > limits.max_iterations:
        raise ResourceLimitError(ResourceLimitReason.MAX_ITERATIONS)
    candidate_size = _FIXED_CANDIDATE_BYTES
    for raw_field in _iter_document_fields(document):
        if raw_field.payload.length > _MAX_FIELD_BYTES:
            raise ResourceLimitError(ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES)
        framed_length = FIELD_HEADER_BYTES + raw_field.payload.length
        padded_length = ((framed_length + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
        if padded_length > limits.max_encrypted_file_bytes - candidate_size:
            raise ResourceLimitError(ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES)
        candidate_size += padded_length



#### Hash one encrypted candidate in bounded chunks for publication evidence.
####
def _sha256_file(path: Path, chunk_size: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
