"""Publish authenticated encrypted candidates through local atomic replacement.

The store records path-free source baselines, stages owner-only ciphertext beside
the destination, revalidates it, serializes cooperating writers, and preserves one
encrypted prior revision for explicit recovery.  It never interprets plaintext.
"""

import hashlib
import os
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Final, Protocol, cast

from .constants import MAX_ENCRYPTED_FILE_BYTES, MAX_IO_CHUNK_BYTES
from .crypto import RandomSource, SystemRandomSource
from .errors import ExternalModificationError, PasswordSafeError, StorageError, StorageReason
from .snapshots import _validate_private_directory
from .writer import EncryptedCandidate



if os.name == "nt":
    from ._windows_security import WindowsDirectoryAnchor, open_regular_file



#### Describe the POSIX advisory-lock members used through the non-Windows runtime branch.
####
class _PosixLockApi(Protocol):
    LOCK_EX: int
    LOCK_UN: int
    flock: Callable[[int, int], None]



#### Describe the Windows byte-range lock members used through the Windows runtime branch.
####
class _WindowsLockApi(Protocol):
    LK_LOCK: int
    LK_UNLCK: int
    locking: Callable[[int, int, int], None]



_OWNER_FILE_MODE: Final[int] = 0o600
_RECOVERY_NAME_ATTEMPTS: Final[int] = 32
_RECOVERY_NONCE_BYTES: Final[int] = 32
_HEX_DIGEST_LENGTH: Final[int] = 64
_RECOVERY_SLOT_PREFIX: Final[str] = ".bonobo-recovery-"
_RECOVERY_SLOT_SUFFIX: Final[str] = ".slot"
_MAX_SLOT_IDENTIFIERS: Final[int] = 64



#### Describe one path-free observation of a regular encrypted destination.
####
@dataclass(frozen=True, slots=True)
class FileBaseline:
    size: int
    sha256: str
    modified_ns: int
    device: int | None
    inode: int | None
    windows_file_id: int | None



    #### Validate immutable file evidence without accepting a pathname.
    ####
    def __post_init__(self) -> None:
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("baseline size must be a nonnegative integer")
        _validate_digest(self.sha256, "baseline")
        if isinstance(self.modified_ns, bool) or not isinstance(self.modified_ns, int) or self.modified_ns < 0:
            raise ValueError("baseline modification time must be a nonnegative integer")
        for value in (self.device, self.inode, self.windows_file_id):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError("baseline file identities must be nonnegative integers")



#### Present path-free metadata for one encrypted recovery artifact.
####
@dataclass(frozen=True, slots=True)
class RecoveryRevision:
    identifier: str
    created_ns: int
    size: int
    sha256: str



    #### Validate safe public metadata without accepting any artifact pathname.
    ####
    def __post_init__(self) -> None:
        _validate_digest(self.identifier, "recovery identifier")
        _validate_digest(self.sha256, "recovery")
        if isinstance(self.created_ns, bool) or not isinstance(self.created_ns, int) or self.created_ns < 0:
            raise ValueError("recovery timestamp must be a nonnegative integer")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("recovery size must be a nonnegative integer")



#### Retain private artifact identity outside caller-visible recovery metadata.
####
@dataclass(frozen=True, slots=True)
class _RecoveryArtifact:
    revision: RecoveryRevision
    baseline: FileBaseline



#### Persist one visible revision plus older artifacts awaiting safe cleanup.
####
@dataclass(frozen=True, slots=True)
class _RecoverySlot:
    current: str
    obsolete: tuple[str, ...] = ()



#### Report the verified encrypted identity committed at one destination.
####
@dataclass(frozen=True, slots=True)
class PublishedFile:
    path: Path = field(repr=False)
    size: int
    sha256: str
    baseline: FileBaseline
    recovery: RecoveryRevision | None



    #### Validate publication evidence without reading the destination again.
    ####
    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("published path must use Path")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("published size must be a nonnegative integer")
        _validate_digest(self.sha256, "published file")
        if not isinstance(self.baseline, FileBaseline):
            raise TypeError("published baseline must use FileBaseline")
        if self.recovery is not None and not isinstance(self.recovery, RecoveryRevision):
            raise TypeError("published recovery must use RecoveryRevision")



#### Preserve verified publication evidence when a later durability or cleanup step fails.
####
class _CommittedPublicationError(StorageError):
    __slots__ = ("published",)



    #### Carry evidence for internal state reconciliation without exposing platform details.
    ####
    def __init__(self, published: PublishedFile) -> None:
        super().__init__(StorageReason.PUBLICATION_FAILED)
        self.published = published



CandidateValidator = Callable[[Path], None]



#### Identify one injectable local-publication transaction boundary.
####
class StorageStage(StrEnum):
    CREATE = "create"
    PERMISSION = "permission"
    WRITE = "write"
    FILE_SYNC = "file-sync"
    REOPEN = "reopen"
    COMPARE = "compare"
    LOCK = "lock"
    BASELINE_RECHECK = "baseline-recheck"
    RECOVERY_WRITE = "recovery-write"
    RECOVERY_SYNC = "recovery-sync"
    REPLACE = "replace"
    DIRECTORY_SYNC = "directory-sync"
    PUBLISHED_VERIFICATION = "published-verification"
    CLEANUP = "cleanup"



#### Mark a deliberate test-only transaction interruption without path data.
####
class _InjectedStorageFaultError(RuntimeError):
    pass



#### Arm at most one deterministic publication-stage failure for fault tests.
####
class StorageFaults:
    __slots__ = ("_lock", "_stage")



    #### Begin with no configured fault stage.
    ####
    def __init__(self) -> None:
        self._stage: StorageStage | None = None
        self._lock = RLock()



    #### Configure one stage to fail on its next transaction traversal.
    ####
    def raise_at(self, stage: StorageStage) -> None:
        if not isinstance(stage, StorageStage):
            raise TypeError("storage fault stage must use StorageStage")
        with self._lock:
            self._stage = stage



    #### Clear any configured failure without affecting active storage state.
    ####
    def clear(self) -> None:
        with self._lock:
            self._stage = None



    #### Raise once when a transaction crosses the configured stage.
    ####
    def _hit(self, stage: StorageStage) -> None:
        with self._lock:
            if self._stage is stage:
                self._stage = None
                raise _InjectedStorageFaultError()



#### Define the anchored operations held across one complete publication.
####
class _PublicationAnchor(Protocol):



    #### Create one persistent owner-only child relative to the held directory.
    ####
    def create_persistent(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        raise NotImplementedError



    #### Open one existing regular child without following symbolic links.
    ####
    def open_child(self, name: str) -> tuple[int, tuple[int, int]] | None:
        raise NotImplementedError



    #### Open one existing child with the access required for retained replacement.
    ####
    def open_child_for_replace(self, name: str) -> tuple[int, tuple[int, int]] | None:
        raise NotImplementedError



    #### Validate privacy and identity through the retained child descriptor.
    ####
    def private_child_is_safe(self, descriptor: int, identity: tuple[int, int]) -> bool:
        raise NotImplementedError



    #### Replace one child by retained descriptor under the held directory.
    ####
    def replace_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        raise NotImplementedError



    #### Publish one retained complete child only if the destination is absent.
    ####
    def publish_new_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        raise NotImplementedError



    #### Remove only the child still matching one retained open identity.
    ####
    def remove_if_same(self, descriptor: int, name: str, identity: tuple[int, int]) -> bool:
        raise NotImplementedError



    #### Report whether the retained directory still owns its original pathname.
    ####
    def stable(self) -> bool:
        raise NotImplementedError



    #### Synchronize directory entries where the platform supports it.
    ####
    def synchronize(self) -> None:
        raise NotImplementedError



    #### Release the retained validated directory handle.
    ####
    def close(self) -> None:
        raise NotImplementedError



#### Hold a no-symlink POSIX directory descriptor across one publication.
####
class _PosixPublicationAnchor:
    __slots__ = ("_fd", "_identity", "_path")



    #### Retain one already validated directory descriptor and identity.
    ####
    def __init__(self, path: Path, descriptor: int) -> None:
        self._path = path
        self._fd = descriptor
        metadata = os.fstat(descriptor)
        self._identity = (metadata.st_dev, metadata.st_ino)



    #### Walk and open every directory component without following symlinks.
    ####
    @classmethod
    def open(cls, path: Path) -> _PosixPublicationAnchor | None:
        descriptor = -1
        try:
            absolute = path.absolute()
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(absolute.anchor, flags)
            for component in absolute.parts[1:]:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError
            anchor = cls(absolute, descriptor)
            descriptor = -1
            return anchor
        except Exception:
            if descriptor >= 0:
                with suppress(BaseException):
                    os.close(descriptor)
            return None



    #### Create one owner-only regular child relative to the stable descriptor.
    ####
    def create_persistent(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        if not self.stable() or Path(name).name != name:
            return None
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, _OWNER_FILE_MODE, dir_fd=self._fd)
        except FileExistsError:
            return None
        try:
            os.fchmod(descriptor, _OWNER_FILE_MODE)
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if not stat.S_ISREG(metadata.st_mode) or not self.stable():
                raise OSError
            return descriptor, identity, name
        except BaseException:
            os.close(descriptor)
            with suppress(BaseException):
                os.unlink(name, dir_fd=self._fd)
            raise



    #### Open one regular child relative to the retained descriptor.
    ####
    def open_child(self, name: str) -> tuple[int, tuple[int, int]] | None:
        if not self.stable() or Path(name).name != name:
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(name, flags, dir_fd=self._fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not self.stable():
            os.close(descriptor)
            return None
        return descriptor, (metadata.st_dev, metadata.st_ino)



    #### Retain the same POSIX child descriptor used for later rename checks.
    ####
    def open_child_for_replace(self, name: str) -> tuple[int, tuple[int, int]] | None:
        return self.open_child(name)



    #### Confirm the retained regular child still has its exact POSIX identity.
    ####
    def private_child_is_safe(self, descriptor: int, identity: tuple[int, int]) -> bool:
        metadata = os.fstat(descriptor)
        return stat.S_ISREG(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity



    #### Atomically replace one child after the retained source identity check.
    ####
    def replace_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        metadata = os.fstat(descriptor)
        if not self.stable() or (metadata.st_dev, metadata.st_ino) != identity:
            return False
        if Path(source_name).name != source_name or Path(destination_name).name != destination_name:
            return False



        #### POSIX has no universal conditional rename-by-handle primitive.  Make
        #### the latest practical name-to-inode check directly beside rename;
        #### same-UID namespace mutation inside that final syscall gap remains
        #### outside the local adapter's documented guarantee.
        named = os.stat(source_name, dir_fd=self._fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != identity:
            return False
        os.replace(source_name, destination_name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
        return self.stable()



    #### Link a complete staged inode into an absent destination, then unstage it.
    ####
    def publish_new_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        metadata = os.fstat(descriptor)
        if not self.stable() or (metadata.st_dev, metadata.st_ino) != identity:
            return False
        if Path(source_name).name != source_name or Path(destination_name).name != destination_name:
            return False
        named = os.stat(source_name, dir_fd=self._fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != identity:
            return False
        os.link(
            source_name,
            destination_name,
            src_dir_fd=self._fd,
            dst_dir_fd=self._fd,
            follow_symlinks=False,
        )
        os.unlink(source_name, dir_fd=self._fd)
        return self.stable()



    #### Remove only a named child still matching the retained open descriptor.
    ####
    def remove_if_same(self, descriptor: int, name: str, identity: tuple[int, int]) -> bool:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != identity:
            return False
        try:
            named = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return opened.st_nlink == 0
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != identity:
            return False
        os.unlink(name, dir_fd=self._fd)
        return True



    #### Compare the pathname with the identity retained by the open descriptor.
    ####
    def stable(self) -> bool:
        try:
            metadata = self._path.lstat()
        except OSError:
            return False
        return not stat.S_ISLNK(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == self._identity



    #### Synchronize the retained directory descriptor.
    ####
    def synchronize(self) -> None:
        os.fsync(self._fd)



    #### Close the retained descriptor exactly once.
    ####
    def close(self) -> None:
        descriptor = self._fd
        if descriptor >= 0:
            os.close(descriptor)
            self._fd = -1



#### Serialize local publications and retain encrypted recovery artifacts.
####
class LocalVaultStore:
    __slots__ = (
        "_faults",
        "_lock",
        "_pending",
        "_random",
        "_recovery_directory",
        "_validator",
        "_working_directory",
    )



    #### Validate private directories and retain injected validation dependencies.
    ####
    def __init__(
        self,
        working_directory: Path,
        recovery_directory: Path,
        *,
        validator: CandidateValidator,
        random_source: RandomSource | None = None,
    ) -> None:
        if not callable(validator):
            raise TypeError("candidate validator must be callable")
        selected_random = SystemRandomSource() if random_source is None else random_source
        if not isinstance(selected_random, RandomSource):
            raise TypeError("storage randomness must implement RandomSource")
        self._working_directory = _require_private_directory(working_directory)
        self._recovery_directory = _require_private_directory(recovery_directory)
        self._validator = validator
        self._random = selected_random
        self._pending: dict[Path, FileBaseline] = {}
        self._faults = StorageFaults()
        self._lock = RLock()



    #### Expose the deterministic stage seam used only by transaction fault tests.
    ####
    @property
    def faults(self) -> StorageFaults:
        return self._faults



    #### Capture the current regular destination as a bounded path-free baseline.
    ####
    def capture(self, path: Path) -> FileBaseline:
        _validate_path(path, "captured path")
        try:
            return _capture_regular_file(path)
        except StorageError:
            raise
        except Exception:
            raise StorageError(StorageReason.PREPARATION_FAILED) from None



    #### Publish one authenticated writer candidate over its unchanged baseline.
    ####
    def publish(
        self,
        destination: Path,
        candidate: EncryptedCandidate,
        baseline: FileBaseline,
        *,
        validator: CandidateValidator | None = None,
    ) -> PublishedFile:
        _validate_path(destination, "publication destination")
        if not isinstance(candidate, EncryptedCandidate):
            raise TypeError("publication candidate must use EncryptedCandidate")
        if not isinstance(baseline, FileBaseline):
            raise TypeError("publication baseline must use FileBaseline")
        return self._publish_source(
            destination,
            candidate.path,
            candidate.sha256,
            baseline,
            consume_source=True,
            selected_recovery=None,
            validator=validator,
        )



    #### Publish one authenticated candidate without replacing an existing entry.
    ####
    def publish_new(
        self,
        destination: Path,
        candidate: EncryptedCandidate,
        *,
        validator: CandidateValidator | None = None,
    ) -> PublishedFile:
        _validate_path(destination, "publication destination")
        if not isinstance(candidate, EncryptedCandidate):
            raise TypeError("publication candidate must use EncryptedCandidate")
        return self._publish_source(
            destination,
            candidate.path,
            candidate.sha256,
            None,
            consume_source=True,
            selected_recovery=None,
            validator=validator,
        )



    #### Enumerate regular encrypted recoveries without exposing their paths.
    ####
    def available_recovery(self, destination: Path) -> tuple[RecoveryRevision, ...]:
        _validate_path(destination, "recovery destination")
        with self._lock:
            try:
                slot = self._read_recovery_slot(_vault_locator(destination))
                if slot is None:
                    return ()
                artifact = self._recovery_artifact(slot.current)
            except StorageError:
                return ()
            return (artifact.revision,)



    #### Explicitly authenticate and republish one selected recovery revision.
    ####
    def restore(
        self,
        destination: Path,
        recovery: RecoveryRevision,
        baseline: FileBaseline,
        *,
        validator: CandidateValidator,
    ) -> PublishedFile:
        _validate_path(destination, "restore destination")
        if not isinstance(recovery, RecoveryRevision):
            raise TypeError("restore recovery must use RecoveryRevision")
        if not isinstance(baseline, FileBaseline):
            raise TypeError("restore baseline must use FileBaseline")
        if not callable(validator):
            raise TypeError("recovery validator must be callable")
        try:
            artifact = self._recovery_artifact(recovery.identifier)
        except FileNotFoundError:
            raise StorageError(StorageReason.VERIFICATION_FAILED) from None
        locator = _vault_locator(destination)
        if artifact.revision != recovery or not self._recovery_is_visible(locator, recovery.identifier):
            raise StorageError(StorageReason.VERIFICATION_FAILED)
        return self._publish_source(
            destination,
            self._recovery_directory / recovery.identifier,
            recovery.sha256,
            baseline,
            consume_source=False,
            selected_recovery=recovery,
            validator=validator,
        )



    #### Return safe temporary identifiers still awaiting cleanup or publication.
    ####
    def pending_candidates(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(path.name for path in self._pending)



    #### Stage, validate, lock, recover, replace, verify, and clean one source.
    ####
    def _publish_source(
        self,
        destination: Path,
        source: Path,
        expected_sha256: str,
        baseline: FileBaseline | None,
        *,
        consume_source: bool,
        selected_recovery: RecoveryRevision | None,
        validator: CandidateValidator | None = None,
    ) -> PublishedFile:
        _validate_digest(expected_sha256, "candidate")
        with self._lock:
            anchor: _PublicationAnchor | None = None
            destination_name = ""
            staged: Path | None = None
            staged_descriptor = -1
            staged_identity: tuple[int, int] | None = None
            staged_baseline: FileBaseline | None = None
            source_baseline: FileBaseline | None = None
            new_recovery: _RecoveryArtifact | None = None
            previous_slot: _RecoverySlot | None = None
            replaced = False
            failure: BaseException | None = None
            result: PublishedFile | None = None
            locator = _vault_locator(destination)
            try:
                source_baseline = _capture_regular_file(source)
                if source_baseline.sha256 != expected_sha256:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                anchor, anchored_destination = _open_publication_destination(destination)
                destination_name = anchored_destination.name
                staged, staged_identity, staged_baseline = self._stage_candidate(
                    anchor,
                    anchored_destination.parent,
                    source,
                )
                if staged_baseline.sha256 != expected_sha256:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                self._faults._hit(StorageStage.REOPEN)
                selected_validator = self._validator if validator is None else validator
                selected_validator(staged)
                self._faults._hit(StorageStage.COMPARE)
                if not anchor.stable() or _capture_anchor_child(anchor, staged.name) != staged_baseline:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                retained = anchor.open_child_for_replace(staged.name)
                if retained is None:
                    raise StorageError(StorageReason.PREPARATION_FAILED)
                staged_descriptor, retained_identity = retained
                if (
                    retained_identity != staged_identity
                    or _capture_open_descriptor(staged_descriptor) != staged_baseline
                ):
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                self._faults._hit(StorageStage.LOCK)
                with _destination_lock(self._working_directory, destination):
                    self._faults._hit(StorageStage.BASELINE_RECHECK)
                    transaction_slot: _RecoverySlot | None = None
                    if baseline is not None:
                        if not anchor.stable() or _capture_anchor_child(anchor, destination_name) != baseline:
                            raise ExternalModificationError()
                        previous_slot = self._read_recovery_slot(locator)
                        new_recovery = self._create_recovery(anchor, destination_name, baseline, locator)
                        transaction_slot = _transaction_recovery_slot(
                            new_recovery.revision.identifier,
                            previous_slot,
                            selected_recovery,
                        )
                        self._write_recovery_slot(locator, transaction_slot)
                        if not anchor.stable() or _capture_anchor_child(anchor, destination_name) != baseline:
                            raise ExternalModificationError()
                    if _capture_anchor_child(anchor, staged.name) != staged_baseline:
                        raise StorageError(StorageReason.VERIFICATION_FAILED)
                    self._faults._hit(StorageStage.REPLACE)
                    if staged_identity is None:
                        raise StorageError(StorageReason.PUBLICATION_FAILED)
                    if baseline is None:
                        try:
                            published = anchor.publish_new_child(
                                staged_descriptor,
                                staged_identity,
                                staged.name,
                                destination_name,
                            )
                        except FileExistsError:
                            raise ExternalModificationError() from None
                    else:
                        published = anchor.replace_child(
                            staged_descriptor,
                            staged_identity,
                            staged.name,
                            destination_name,
                        )
                    if not published:
                        raise StorageError(StorageReason.PUBLICATION_FAILED)
                    replaced = True
                    self._pending.pop(staged, None)
                    self._faults._hit(StorageStage.DIRECTORY_SYNC)
                    anchor.synchronize()
                    self._faults._hit(StorageStage.PUBLISHED_VERIFICATION)
                    published_baseline = _capture_anchor_child(anchor, destination_name)
                    if (
                        published_baseline.sha256 != expected_sha256
                        or published_baseline.size != staged_baseline.size
                    ):
                        raise StorageError(StorageReason.VERIFICATION_FAILED)
                    if new_recovery is not None and transaction_slot is not None:
                        self._commit_recovery(locator, new_recovery, transaction_slot)
                    result = PublishedFile(
                        destination,
                        published_baseline.size,
                        published_baseline.sha256,
                        published_baseline,
                        None if new_recovery is None else new_recovery.revision,
                    )
            except BaseException as error:
                failure = error
            finally:
                cleanup_failed = False
                if replaced and result is None and anchor is not None and staged_baseline is not None:
                    try:
                        published_baseline = _capture_anchor_child(anchor, destination_name)
                        if (
                            published_baseline.sha256 == expected_sha256
                            and published_baseline.size == staged_baseline.size
                        ):
                            result = PublishedFile(
                                destination,
                                published_baseline.size,
                                published_baseline.sha256,
                                published_baseline,
                                None if new_recovery is None else new_recovery.revision,
                            )
                    except BaseException:
                        pass
                if staged is not None and not replaced:
                    try:
                        if anchor is None or staged_identity is None:
                            cleanup_failed = True
                        else:
                            if staged_descriptor < 0:
                                reopened = anchor.open_child_for_replace(staged.name)
                                if reopened is not None and reopened[1] == staged_identity:
                                    staged_descriptor = reopened[0]
                            if staged_descriptor < 0:
                                cleanup_failed = True
                            else:
                                cleanup_failed = not anchor.remove_if_same(
                                    staged_descriptor,
                                    staged.name,
                                    staged_identity,
                                )
                            self._pending.pop(staged, None)
                    except BaseException:
                        cleanup_failed = True
                if new_recovery is not None and result is None and not replaced:
                    cleanup_failed = not self._restore_recovery_slot(locator, previous_slot) or cleanup_failed
                    cleanup_failed = (
                        not _remove_if_same(
                            self._recovery_directory / new_recovery.revision.identifier,
                            new_recovery.baseline,
                        )
                        or cleanup_failed
                    )
                if consume_source and source_baseline is not None:
                    try:
                        self._faults._hit(StorageStage.CLEANUP)
                    except _InjectedStorageFaultError:
                        cleanup_failed = True
                    else:
                        cleanup_failed = not _remove_if_same(source, source_baseline) or cleanup_failed
                if staged_descriptor >= 0:
                    try:
                        os.close(staged_descriptor)
                    except OSError:
                        cleanup_failed = True
                if anchor is not None:
                    try:
                        anchor.close()
                    except OSError:
                        cleanup_failed = True
                if cleanup_failed and failure is None:
                    failure = StorageError(StorageReason.PUBLICATION_FAILED)
            if failure is not None:
                if not isinstance(failure, Exception):
                    raise failure
                if replaced and result is not None:
                    raise _CommittedPublicationError(result) from None
                if isinstance(failure, (ExternalModificationError, StorageError)):
                    raise failure from None
                if isinstance(failure, PasswordSafeError):
                    raise StorageError(StorageReason.VERIFICATION_FAILED) from None
                raise StorageError(StorageReason.PUBLICATION_FAILED) from None
            if result is None:
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            return result



    #### Copy one encrypted source into an exclusive owner-only adjacent file.
    ####
    def _stage_candidate(
        self,
        anchor: _PublicationAnchor,
        parent: Path,
        source: Path,
    ) -> tuple[Path, tuple[int, int], FileBaseline]:
        descriptor = -1
        identity: tuple[int, int] | None = None
        staged: Path | None = None
        try:
            self._faults._hit(StorageStage.CREATE)
            name = f".bonobo-{secrets.token_hex(16)}.publish"
            created = anchor.create_persistent(name)
            if created is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            descriptor, identity, cleanup_name = created
            if cleanup_name != name:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            staged = parent / name
            self._faults._hit(StorageStage.PERMISSION)
            self._faults._hit(StorageStage.WRITE)
            _copy_path_to_descriptor(source, descriptor)
            self._faults._hit(StorageStage.FILE_SYNC)
            os.fsync(descriptor)
            baseline = _capture_open_descriptor(descriptor)
            self._pending[staged] = baseline
            os.close(descriptor)
            descriptor = -1
            return staged, identity, baseline
        except BaseException:
            if descriptor >= 0 and identity is not None and staged is not None:
                with suppress(BaseException):
                    anchor.remove_if_same(descriptor, staged.name, identity)
            if descriptor >= 0:
                with suppress(BaseException):
                    os.close(descriptor)
            raise



    #### Preserve the unchanged destination in one exclusive recovery artifact.
    ####
    def _create_recovery(
        self,
        anchor: _PublicationAnchor,
        destination_name: str,
        baseline: FileBaseline,
        locator: str,
    ) -> _RecoveryArtifact:
        for _attempt in range(_RECOVERY_NAME_ATTEMPTS):
            nonce = self._random.bytes(_RECOVERY_NONCE_BYTES)
            if len(nonce) != _RECOVERY_NONCE_BYTES:
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            identifier = hashlib.sha256(locator.encode("utf-8") + nonce).hexdigest()
            path = self._recovery_directory / identifier
            temporary = self._recovery_directory / f".bonobo-{secrets.token_hex(16)}.recovery"
            descriptor = -1
            try:
                descriptor, temporary = _create_private_child(self._recovery_directory, temporary.name)
                self._faults._hit(StorageStage.RECOVERY_WRITE)
                _copy_anchor_child_to_descriptor(anchor, destination_name, descriptor)
                self._faults._hit(StorageStage.RECOVERY_SYNC)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                observed = _capture_regular_file(temporary)
                if observed.size != baseline.size or observed.sha256 != baseline.sha256:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                os.link(temporary, path, follow_symlinks=False)
                temporary.unlink()
                _synchronize_directory(self._recovery_directory)
                published = _capture_regular_file(path)
                if published != observed:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                return _RecoveryArtifact(_recovery_revision(path, published), published)
            except FileExistsError:
                with suppress(OSError):
                    temporary.unlink()
                continue
            except BaseException:
                if descriptor >= 0:
                    with suppress(BaseException):
                        os.close(descriptor)
                with suppress(BaseException):
                    temporary.unlink()
                raise
        raise StorageError(StorageReason.PUBLICATION_FAILED)



    #### Read one durable private slot or report that no revision is associated.
    ####
    def _read_recovery_slot(self, locator: str) -> _RecoverySlot | None:
        path = self._recovery_directory / _recovery_slot_name(locator)
        try:
            descriptor = _open_regular_descriptor(path)
        except FileNotFoundError:
            return None
        try:
            metadata = os.fstat(descriptor)
            maximum = _MAX_SLOT_IDENTIFIERS * (_HEX_DIGEST_LENGTH + 1)
            if metadata.st_size <= 0 or metadata.st_size > maximum:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            payload = _read_descriptor_bytes(descriptor, maximum)
        finally:
            os.close(descriptor)
        try:
            identifiers = tuple(payload.decode("ascii").splitlines())
        except UnicodeError:
            raise StorageError(StorageReason.VERIFICATION_FAILED) from None
        if not identifiers or len(identifiers) > _MAX_SLOT_IDENTIFIERS or len(set(identifiers)) != len(identifiers):
            raise StorageError(StorageReason.VERIFICATION_FAILED)
        for identifier in identifiers:
            try:
                _validate_digest(identifier, "recovery identifier")
            except ValueError:
                raise StorageError(StorageReason.VERIFICATION_FAILED) from None
        return _RecoverySlot(identifiers[0], identifiers[1:])



    #### Atomically publish and synchronize one private recovery association.
    ####
    def _write_recovery_slot(self, locator: str, slot: _RecoverySlot) -> None:
        path = self._recovery_directory / _recovery_slot_name(locator)
        temporary = self._recovery_directory / f".bonobo-{secrets.token_hex(16)}.slot"
        descriptor = -1
        try:
            descriptor, temporary = _create_private_child(self._recovery_directory, temporary.name)
            payload = ("\n".join((slot.current, *slot.obsolete)) + "\n").encode("ascii")
            _write_descriptor_bytes(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            _synchronize_directory(self._recovery_directory)
        except BaseException:
            if descriptor >= 0:
                with suppress(BaseException):
                    os.close(descriptor)
            with suppress(BaseException):
                temporary.unlink()
            raise



    #### Restore the prior slot and synchronize cleanup after pre-replace failure.
    ####
    def _restore_recovery_slot(self, locator: str, previous: _RecoverySlot | None) -> bool:
        try:
            if previous is not None:
                self._write_recovery_slot(locator, previous)
            else:
                path = self._recovery_directory / _recovery_slot_name(locator)
                with suppress(FileNotFoundError):
                    path.unlink()
                _synchronize_directory(self._recovery_directory)
            return True
        except (OSError, StorageError):
            return False



    #### Keep the new prior revision and remove every superseded artifact safely.
    ####
    def _commit_recovery(
        self,
        locator: str,
        recovery: _RecoveryArtifact,
        transaction_slot: _RecoverySlot,
    ) -> None:
        cleanup_failed = False
        for identifier in transaction_slot.obsolete:
            try:
                artifact = self._recovery_artifact(identifier)
            except FileNotFoundError:
                continue
            except StorageError:
                cleanup_failed = True
                continue
            cleanup_failed = (
                not _remove_if_same(self._recovery_directory / identifier, artifact.baseline) or cleanup_failed
            )
        if cleanup_failed:
            raise StorageError(StorageReason.PUBLICATION_FAILED)
        self._write_recovery_slot(locator, _RecoverySlot(recovery.revision.identifier))



    #### Resolve and verify one private recovery artifact from safe metadata.
    ####
    def _recovery_artifact(self, identifier: str) -> _RecoveryArtifact:
        try:
            _validate_digest(identifier, "recovery identifier")
        except ValueError:
            raise StorageError(StorageReason.VERIFICATION_FAILED) from None
        path = self._recovery_directory / identifier
        baseline = _capture_regular_file(path)
        return _RecoveryArtifact(_recovery_revision(path, baseline), baseline)



    #### Confirm that at least one durable private slot advertises an identifier.
    ####
    def _recovery_is_visible(self, locator: str, identifier: str) -> bool:
        try:
            _validate_digest(locator, "vault locator")
            slot = self._read_recovery_slot(locator)
        except (OSError, ValueError):
            raise StorageError(StorageReason.PREPARATION_FAILED) from None
        return slot is not None and slot.current == identifier



    #### Remove one unchanged pending file and forget its safe identifier.
    ####
    def _remove_pending(self, path: Path, baseline: FileBaseline | None) -> bool:
        if baseline is None:
            return False
        removed = _remove_if_same(path, baseline)
        if removed:
            self._pending.pop(path, None)
        return removed



#### Retain a validated destination-directory handle for one full transaction.
####
def _open_publication_destination(destination: Path) -> tuple[_PublicationAnchor, Path]:
    try:
        absolute = destination.absolute()
        if not absolute.name:
            raise OSError
        anchor: _PublicationAnchor | None
        if os.name == "nt":
            anchor = WindowsDirectoryAnchor.open_public(absolute.parent)
        else:
            anchor = _PosixPublicationAnchor.open(absolute.parent)
        if anchor is None:
            raise OSError
        return anchor, absolute
    except Exception:
        raise StorageError(StorageReason.PREPARATION_FAILED) from None



#### Resolve and validate an existing caller-owned private directory.
####
def _require_private_directory(directory: Path) -> Path:
    _validate_path(directory, "private directory")
    try:
        absolute = directory.absolute()
        resolved = directory.resolve(strict=True)
        if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
            raise OSError
        anchor = _validate_private_directory(resolved)
        if anchor is None:
            raise OSError
        anchor.close()
        return resolved
    except Exception:
        raise StorageError(StorageReason.PREPARATION_FAILED) from None



#### Create one named owner-only child without following a Windows reparse point.
####
def _create_private_child(directory: Path, name: str) -> tuple[int, Path]:
    if Path(name).name != name:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    path = directory / name
    if os.name == "nt":
        anchor = WindowsDirectoryAnchor.open(directory)
        if anchor is None:
            raise StorageError(StorageReason.PREPARATION_FAILED)
        try:
            created = anchor.create_persistent(name)
            if created is None:
                raise FileExistsError
            descriptor, _identity, cleanup_name = created
            if cleanup_name != name:
                os.close(descriptor)
                raise StorageError(StorageReason.PREPARATION_FAILED)
            return descriptor, path
        finally:
            anchor.close()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, _OWNER_FILE_MODE)
    try:
        os.chmod(path, _OWNER_FILE_MODE, follow_symlinks=False)
        return descriptor, path
    except BaseException:
        os.close(descriptor)
        with suppress(BaseException):
            path.unlink()
        raise



#### Capture one regular file through a no-follow descriptor and bounded hash.
####
def _capture_regular_file(path: Path) -> FileBaseline:
    descriptor = -1
    try:
        descriptor = _open_regular_descriptor(path)
        return _capture_open_descriptor(descriptor)
    except FileNotFoundError:
        raise
    except StorageError:
        raise
    except Exception:
        raise StorageError(StorageReason.PREPARATION_FAILED) from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)



#### Capture one retained regular descriptor with a bounded stable hash.
####
def _capture_open_descriptor(descriptor: int) -> FileBaseline:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ENCRYPTED_FILE_BYTES:
        raise OSError
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, MAX_IO_CHUNK_BYTES)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_ENCRYPTED_FILE_BYTES:
            raise OSError
        digest.update(chunk)
    after = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or size != after.st_size
    ):
        raise OSError
    return FileBaseline(
        size,
        digest.hexdigest(),
        after.st_mtime_ns,
        after.st_dev if after.st_dev >= 0 else None,
        after.st_ino if after.st_ino >= 0 else None,
        after.st_ino if os.name == "nt" and after.st_ino >= 0 else None,
    )



#### Capture one regular child relative to a retained directory anchor.
####
def _capture_anchor_child(anchor: _PublicationAnchor, name: str) -> FileBaseline:
    opened = anchor.open_child(name)
    if opened is None:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    descriptor, _identity = opened
    try:
        return _capture_open_descriptor(descriptor)
    finally:
        os.close(descriptor)



#### Copy one regular encrypted file completely into an already open descriptor.
####
def _copy_path_to_descriptor(source: Path, destination_descriptor: int) -> None:
    source_descriptor = -1
    try:
        source_descriptor = _open_regular_descriptor(source)
        _copy_descriptor_to_descriptor(source_descriptor, destination_descriptor)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)



#### Copy one anchored regular child completely into an open descriptor.
####
def _copy_anchor_child_to_descriptor(
    anchor: _PublicationAnchor,
    name: str,
    destination_descriptor: int,
) -> None:
    opened = anchor.open_child(name)
    if opened is None:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    source_descriptor, _identity = opened
    try:
        _copy_descriptor_to_descriptor(source_descriptor, destination_descriptor)
    finally:
        os.close(source_descriptor)



#### Stream one regular source descriptor completely into an open destination.
####
def _copy_descriptor_to_descriptor(source_descriptor: int, destination_descriptor: int) -> None:
    metadata = os.fstat(source_descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ENCRYPTED_FILE_BYTES:
        raise OSError
    os.lseek(source_descriptor, 0, os.SEEK_SET)
    copied = 0
    while True:
        remaining = MAX_ENCRYPTED_FILE_BYTES - copied
        chunk = os.read(source_descriptor, min(MAX_IO_CHUNK_BYTES, remaining + 1))
        if not chunk:
            break
        if len(chunk) > remaining:
            raise OSError
        _write_descriptor_bytes(destination_descriptor, chunk)
        copied += len(chunk)
    if copied != metadata.st_size:
        raise OSError



#### Open one regular path without following its final symbolic-link target.
####
def _open_regular_descriptor(path: Path) -> int:
    if os.name == "nt":
        descriptor = open_regular_file(path)
        if descriptor is None:
            raise OSError
        return descriptor
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    return os.open(path, flags)



#### Read one already bounded descriptor completely from its current offset.
####
def _read_descriptor_bytes(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(MAX_IO_CHUNK_BYTES, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise StorageError(StorageReason.VERIFICATION_FAILED)



#### Write every byte to one descriptor despite permitted partial OS writes.
####
def _write_descriptor_bytes(descriptor: int, payload: bytes) -> None:
    position = 0
    while position < len(payload):
        written = os.write(descriptor, payload[position:])
        if written <= 0:
            raise OSError
        position += written



#### Hold a cross-process lock file while one destination baseline is rechecked.
####
@contextmanager
def _destination_lock(working_directory: Path, destination: Path) -> Iterator[None]:
    name = f"{_vault_locator(destination)}.lock"
    with _named_process_lock(working_directory, name):
        yield



#### Hold one cross-process lock shared by every hard link to a source identity.
####
@contextmanager
def _source_identity_lock(working_directory: Path, baseline: FileBaseline) -> Iterator[None]:
    name = f"source-{_source_identity_locator(baseline)}.lock"
    with _named_process_lock(working_directory, name):
        yield



#### Acquire one private named lock using the established platform primitives.
####
@contextmanager
def _named_process_lock(working_directory: Path, name: str) -> Iterator[None]:
    path = working_directory / name
    descriptor = -1
    try:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, _OWNER_FILE_MODE)
        os.chmod(path, _OWNER_FILE_MODE, follow_symlinks=False)
        if os.name == "nt":
            _lock_windows_descriptor(descriptor)
        else:
            _lock_posix_descriptor(descriptor)
        yield
    finally:
        if descriptor >= 0:
            with suppress(BaseException):
                if os.name == "nt":
                    _unlock_windows_descriptor(descriptor)
                else:
                    _unlock_posix_descriptor(descriptor)
            with suppress(BaseException):
                os.close(descriptor)



#### Derive a private stable lock locator from path-free device/file identity.
####
def _source_identity_locator(baseline: FileBaseline) -> str:
    if not isinstance(baseline, FileBaseline):
        raise TypeError("source identity must use FileBaseline")
    file_id = baseline.windows_file_id if os.name == "nt" else baseline.inode
    if baseline.device is None or file_id is None:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    identity = f"{baseline.device}:{file_id}".encode("ascii")
    return hashlib.sha256(identity).hexdigest()



#### Acquire an exclusive POSIX advisory lock on a stable private lock file.
####
def _lock_posix_descriptor(descriptor: int) -> None:
    import fcntl

    lock_api = cast(_PosixLockApi, fcntl)
    lock_api.flock(descriptor, lock_api.LOCK_EX)



#### Release one previously acquired POSIX advisory file lock.
####
def _unlock_posix_descriptor(descriptor: int) -> None:
    import fcntl

    lock_api = cast(_PosixLockApi, fcntl)
    lock_api.flock(descriptor, lock_api.LOCK_UN)



#### Acquire a blocking Windows byte-range lock on a stable private lock file.
####
def _lock_windows_descriptor(descriptor: int) -> None:
    import msvcrt

    lock_api = cast(_WindowsLockApi, msvcrt)
    if os.fstat(descriptor).st_size == 0:
        os.write(descriptor, b"\x00")
        os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    lock_api.locking(descriptor, lock_api.LK_LOCK, 1)



#### Release one previously acquired Windows byte-range lock.
####
def _unlock_windows_descriptor(descriptor: int) -> None:
    import msvcrt

    lock_api = cast(_WindowsLockApi, msvcrt)
    os.lseek(descriptor, 0, os.SEEK_SET)
    lock_api.locking(descriptor, lock_api.LK_UNLCK, 1)



#### Synchronize a replaced directory entry on platforms that support it.
####
def _synchronize_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)



#### Remove one pathname only while all captured file evidence still matches.
####
def _remove_if_same(path: Path, baseline: FileBaseline) -> bool:
    try:
        if _capture_regular_file(path) != baseline:
            return False
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except (OSError, StorageError):
        return False



#### Build path-free recovery metadata from one captured private artifact.
####
def _recovery_revision(path: Path, baseline: FileBaseline) -> RecoveryRevision:
    return RecoveryRevision(
        path.name,
        baseline.modified_ns,
        baseline.size,
        baseline.sha256,
    )



#### Build a private slot name from one already normalized vault locator.
####
def _recovery_slot_name(locator: str) -> str:
    _validate_digest(locator, "vault locator")
    return f"{_RECOVERY_SLOT_PREFIX}{locator}{_RECOVERY_SLOT_SUFFIX}"



#### Parse one private slot filename without accepting other directory entries.
####
def _locator_from_slot_name(name: str) -> str | None:
    if not name.startswith(_RECOVERY_SLOT_PREFIX) or not name.endswith(_RECOVERY_SLOT_SUFFIX):
        return None
    locator = name[len(_RECOVERY_SLOT_PREFIX): -len(_RECOVERY_SLOT_SUFFIX)]
    try:
        _validate_digest(locator, "vault locator")
    except ValueError:
        return None
    return locator



#### Retain every older slot artifact until a successful commit removes it.
####
def _transaction_recovery_slot(
    current: str,
    previous: _RecoverySlot | None,
    selected: RecoveryRevision | None,
) -> _RecoverySlot:
    obsolete: dict[str, None] = {}
    if previous is not None:
        for identifier in (previous.current, *previous.obsolete):
            if identifier != current:
                obsolete[identifier] = None
    if selected is not None and previous is not None and selected.identifier in obsolete:
        obsolete[selected.identifier] = None
    if len(obsolete) + 1 > _MAX_SLOT_IDENTIFIERS:
        raise StorageError(StorageReason.PUBLICATION_FAILED)
    return _RecoverySlot(current, tuple(obsolete))



#### Derive one stable path-free locator for locks and in-process recovery slots.
####
def _vault_locator(path: Path) -> str:
    try:
        normalized = os.path.normcase(str(path.resolve(strict=False))).encode("utf-8")
    except (OSError, UnicodeError):
        raise StorageError(StorageReason.PREPARATION_FAILED) from None
    return hashlib.sha256(normalized).hexdigest()



#### Validate one lowercase SHA-256 value used as safe structural evidence.
####
def _validate_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or len(value) != _HEX_DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{label} SHA-256 must be lowercase hexadecimal")



#### Validate public filesystem parameters before any path operation begins.
####
def _validate_path(path: Path, label: str) -> None:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must use Path")
