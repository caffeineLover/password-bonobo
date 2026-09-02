"""Persist authenticated dirty sessions as private encrypted pending artifacts.

The store publishes one path-free slot per stable source locator.  It reuses the
reviewed private-directory, anchored descriptor, bounded hashing, synchronization,
and exact-identity cleanup primitives from snapshot and publication storage.
"""

import os
import secrets
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Final, Never

from ._darwin_security import require_no_extended_acl as _require_no_extended_acl
from .constants import MAX_ENCRYPTED_FILE_BYTES, MAX_IO_CHUNK_BYTES
from .crypto import RandomSource, SystemRandomSource
from .errors import ExternalModificationError, PasswordSafeError, StorageError, StorageReason
from .snapshots import EncryptedSnapshot, _validate_private_directory
from .storage import (
    FileBaseline,
    _capture_anchor_child,
    _capture_open_descriptor,
    _capture_regular_file,
    _copy_path_to_descriptor,
    _destination_lock,
    _PosixPublicationAnchor,
    _PublicationAnchor,
    _read_descriptor_bytes,
    _require_private_directory,
    _source_identity_lock,
    _validate_digest,
    _vault_locator,
    _write_descriptor_bytes,
)
from .writer import EncryptedCandidate



if os.name == "nt":
    from ._windows_security import WindowsDirectoryAnchor



_IDENTIFIER_BYTES: Final[int] = 32
_NAME_ATTEMPTS: Final[int] = 32
_OWNER_FILE_MODE: Final[int] = 0o600
_SLOT_MAGIC: Final[str] = "BONOBO-PENDING-1"
_SLOT_PREFIX: Final[str] = ".bonobo-pending-slot-"
_SLOT_SUFFIX: Final[str] = ".slot"
_ARTIFACT_PREFIX: Final[str] = ".bonobo-pending-artifact-"
_ARTIFACT_SUFFIX: Final[str] = ".psafe3"
_MAX_SLOT_BYTES: Final[int] = 1024



#### Expose only stable non-path metadata needed to select one pending artifact.
####
@dataclass(frozen=True, slots=True)
class SuspendedSession:
    identifier: str
    sha256: str
    source_sha256: str
    size: int



    #### Reject malformed or unbounded metadata before it can select storage.
    ####
    def __post_init__(self) -> None:
        _validate_digest(self.identifier, "pending identifier")
        _validate_digest(self.sha256, "pending artifact")
        _validate_digest(self.source_sha256, "pending source")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not 0 < self.size <= MAX_ENCRYPTED_FILE_BYTES
        ):
            raise ValueError("pending size must be within the encrypted-file bound")



#### Identify one injectable private pending-store transaction boundary.
####
class PendingStage(StrEnum):
    PREPARATION = "preparation"
    WRITE = "write"
    FILE_SYNC = "file-sync"
    AUTHENTICATION = "authentication"
    COMPARE = "compare"
    SLOT_PUBLICATION = "slot-publication"
    DIRECTORY_SYNC = "directory-sync"
    POST_PUBLICATION_VALIDATION = "post-publication-validation"
    CLEANUP = "cleanup"



#### Mark one deliberate test-only pending-store interruption.
####
class _InjectedPendingFaultError(RuntimeError):
    pass



#### Arm at most one deterministic pending-store failure for fault tests.
####
class PendingFaults:
    __slots__ = ("_lock", "_stage")



    #### Begin with no selected fault boundary.
    ####
    def __init__(self) -> None:
        self._lock = RLock()
        self._stage: PendingStage | None = None



    #### Configure one stage to fail on its next traversal.
    ####
    def raise_at(self, stage: PendingStage) -> None:
        if not isinstance(stage, PendingStage):
            raise TypeError("pending fault stage must use PendingStage")
        with self._lock:
            self._stage = stage



    #### Raise once at the configured boundary and then disarm it.
    ####
    def _hit(self, stage: PendingStage) -> None:
        with self._lock:
            if self._stage is stage:
                self._stage = None
                raise _InjectedPendingFaultError()



#### Retain every private value encoded in one stable source slot.
####
@dataclass(frozen=True, slots=True)
class _StoredPending:
    suspended: SuspendedSession
    source_baseline: FileBaseline



#### Transfer one verified anonymous encrypted snapshot and its source baseline.
####
@dataclass(frozen=True, slots=True)
class _OpenedPending:
    snapshot: EncryptedSnapshot
    source_baseline: FileBaseline



#### Preserve safe committed metadata when only obsolete cleanup failed.
####
class _CommittedPendingError(StorageError):
    __slots__ = ("suspended",)



    #### Carry path-free committed evidence for internal state reconciliation.
    ####
    def __init__(self, suspended: SuspendedSession) -> None:
        super().__init__(StorageReason.PUBLICATION_FAILED)
        self.suspended = suspended



#### Own retained slot and artifact descriptors during verification or cleanup.
####
@dataclass(slots=True)
class _LocatedPending:
    anchor: _PublicationAnchor
    slot_name: str
    slot_descriptor: int
    slot_identity: tuple[int, int]
    artifact_name: str
    artifact_descriptor: int
    artifact_identity: tuple[int, int]
    artifact_baseline: FileBaseline
    stored: _StoredPending



    #### Release every descriptor and the validated directory anchor.
    ####
    def close(self, *, close_anchor: bool = True) -> None:
        first_failure: BaseException | None = None
        for descriptor in (self.artifact_descriptor, self.slot_descriptor):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
        self.artifact_descriptor = -1
        self.slot_descriptor = -1
        if close_anchor:
            try:
                self.anchor.close()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
        if first_failure is not None:
            raise first_failure



PendingValidator = Callable[[EncryptedSnapshot], None]



#### Persist and resolve one authenticated pending revision per source locator.
####
class PendingSessionStore:
    __slots__ = ("_directory", "_faults", "_lock", "_random", "_snapshot_directory")



    #### Validate both private directories and retain only safe dependencies.
    ####
    def __init__(
        self,
        directory: Path,
        snapshot_directory: Path,
        *,
        random_source: RandomSource | None = None,
    ) -> None:
        selected_random = SystemRandomSource() if random_source is None else random_source
        if not isinstance(selected_random, RandomSource):
            raise TypeError("pending randomness must implement RandomSource")
        self._directory = _require_private_directory(directory)
        self._snapshot_directory = _require_private_directory(snapshot_directory)
        self._random = selected_random
        self._faults = PendingFaults()
        self._lock = RLock()



    #### Expose the deterministic stage seam used only by fault tests.
    ####
    @property
    def faults(self) -> PendingFaults:
        return self._faults



    #### Copy, authenticate, and atomically advertise one complete candidate.
    ####
    def publish(
        self,
        source: Path,
        candidate: EncryptedCandidate,
        source_baseline: FileBaseline,
        *,
        expected: SuspendedSession | None,
        validator: PendingValidator,
    ) -> SuspendedSession:
        if not isinstance(source, Path):
            raise TypeError("pending source must use Path")
        if not isinstance(candidate, EncryptedCandidate):
            raise TypeError("pending candidate must use EncryptedCandidate")
        if not isinstance(source_baseline, FileBaseline):
            raise TypeError("pending source baseline must use FileBaseline")
        if expected is not None:
            _validate_suspended(expected)
        if not callable(validator):
            raise TypeError("pending validator must be callable")
        with (
            self._lock,
            _source_identity_lock(self._snapshot_directory, source_baseline),
            _destination_lock(self._snapshot_directory, source),
        ):
            return self._publish_locked(source, candidate, source_baseline, expected, validator)



    #### Hold the source-keyed writer lock while proving no pending slot exists.
    ####
    @contextmanager
    def guard_open(self, source: Path) -> Iterator[None]:
        if not isinstance(source, Path):
            raise TypeError("pending source must use Path")
        try:
            source_baseline = _capture_regular_file(source)
            with (
                self._lock,
                _source_identity_lock(self._snapshot_directory, source_baseline),
                _destination_lock(self._snapshot_directory, source),
            ):
                if _capture_regular_file(source) != source_baseline:
                    raise ExternalModificationError()
                anchor: _PublicationAnchor | None = None
                try:
                    anchor = _open_private_anchor(self._directory)
                    slot_name = _slot_name(_vault_locator(source))
                    if self._source_has_pending_locked(anchor, slot_name, source_baseline):
                        raise StorageError(StorageReason.VERIFICATION_FAILED)
                finally:
                    if anchor is not None:
                        with suppress(BaseException):
                            anchor.close()
                yield
        except BaseException as error:
            _raise_closed_pending_error(error)



    #### Resolve one artifact into an anonymous bounded snapshot for authentication.
    ####
    def open(self, source: Path, suspended: SuspendedSession) -> _OpenedPending:
        if not isinstance(source, Path):
            raise TypeError("pending source must use Path")
        _validate_suspended(suspended)
        with self._lock, _destination_lock(self._snapshot_directory, source):
            located: _LocatedPending | None = None
            snapshot: EncryptedSnapshot | None = None
            try:
                located = self._find_locked(source, suspended)
                with os.fdopen(os.dup(located.artifact_descriptor), "rb", closefd=True) as artifact_source:
                    snapshot = EncryptedSnapshot.capture(
                        artifact_source,
                        self._snapshot_directory,
                        chunk_size=MAX_IO_CHUNK_BYTES,
                        max_bytes=MAX_ENCRYPTED_FILE_BYTES,
                    )
                if snapshot.size != suspended.size or snapshot.sha256 != suspended.sha256:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                slot_baseline = _capture_open_descriptor(located.slot_descriptor)
                if (
                    _capture_open_descriptor(located.artifact_descriptor) != located.artifact_baseline
                    or _capture_anchor_child(located.anchor, located.artifact_name)
                    != located.artifact_baseline
                    or _capture_anchor_child(located.anchor, located.slot_name) != slot_baseline
                ):
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                _validate_private_child(
                    self._directory,
                    located.anchor,
                    located.artifact_name,
                    located.artifact_descriptor,
                    located.artifact_identity,
                )
                _validate_private_child(
                    self._directory,
                    located.anchor,
                    located.slot_name,
                    located.slot_descriptor,
                    located.slot_identity,
                )
                result = _OpenedPending(snapshot, located.stored.source_baseline)
                snapshot = None
                return result
            except BaseException as error:
                _raise_closed_pending_error(error)
            finally:
                if snapshot is not None:
                    with suppress(BaseException):
                        snapshot.close()
                if located is not None:
                    with suppress(BaseException):
                        located.close()



    #### Remove only the selected unchanged slot and encrypted artifact.
    ####
    def discard(self, source: Path, suspended: SuspendedSession) -> None:
        if not isinstance(source, Path):
            raise TypeError("pending source must use Path")
        _validate_suspended(suspended)
        with self._lock, _destination_lock(self._snapshot_directory, source):
            located: _LocatedPending | None = None
            try:
                located = self._find_locked(source, suspended)
                self._discard_locked(located)
            except BaseException as error:
                _raise_closed_pending_error(error)



    #### Recheck that one selected slot and artifact remain exact and unambiguous.
    ####
    def verify(self, source: Path, suspended: SuspendedSession) -> None:
        if not isinstance(source, Path):
            raise TypeError("pending source must use Path")
        _validate_suspended(suspended)
        with self._lock, _destination_lock(self._snapshot_directory, source):
            located: _LocatedPending | None = None
            try:
                located = self._find_locked(source, suspended)
                slot_baseline = _capture_open_descriptor(located.slot_descriptor)
                if (
                    _capture_open_descriptor(located.artifact_descriptor) != located.artifact_baseline
                    or _capture_anchor_child(located.anchor, located.artifact_name)
                    != located.artifact_baseline
                    or _capture_anchor_child(located.anchor, located.slot_name) != slot_baseline
                ):
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                _validate_private_child(
                    self._directory,
                    located.anchor,
                    located.artifact_name,
                    located.artifact_descriptor,
                    located.artifact_identity,
                )
                _validate_private_child(
                    self._directory,
                    located.anchor,
                    located.slot_name,
                    located.slot_descriptor,
                    located.slot_identity,
                )
                located.close()
                located = None
            except BaseException as error:
                _raise_closed_pending_error(error)
            finally:
                if located is not None:
                    with suppress(BaseException):
                        located.close()



    #### Remove one selected pending state with an explicit artifact-delete commit point.
    ####
    def _discard_locked(self, located: _LocatedPending) -> None:
        tombstone = f".bonobo-pending-discard-{secrets.token_hex(16)}"
        moved = False
        artifact_removed = False
        failure: BaseException | None = None
        try:
            moved = located.anchor.publish_new_child(
                located.slot_descriptor,
                located.slot_identity,
                located.slot_name,
                tombstone,
            )
            if not moved:
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            located.anchor.synchronize()
            self._faults._hit(PendingStage.CLEANUP)
            artifact_removed = located.anchor.remove_if_same(
                located.artifact_descriptor,
                located.artifact_name,
                located.artifact_identity,
            )
            if not artifact_removed:
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            if not located.anchor.remove_if_same(
                located.slot_descriptor,
                tombstone,
                located.slot_identity,
            ):
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            located.anchor.synchronize()
        except BaseException as error:
            failure = error
            if moved and not artifact_removed:
                with suppress(BaseException):
                    located.anchor.publish_new_child(
                        located.slot_descriptor,
                        located.slot_identity,
                        tombstone,
                        located.slot_name,
                    )
                    located.anchor.synchronize()
        finally:
            try:
                located.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        if artifact_removed:
            return
        if failure is not None:
            raise failure
        raise StorageError(StorageReason.PUBLICATION_FAILED)



    #### Execute one complete candidate-to-slot transaction while serialized.
    ####
    def _publish_locked(
        self,
        source: Path,
        candidate: EncryptedCandidate,
        source_baseline: FileBaseline,
        expected: SuspendedSession | None,
        validator: PendingValidator,
    ) -> SuspendedSession:
        anchor: _PublicationAnchor | None = None
        previous: _LocatedPending | None = None
        candidate_baseline: FileBaseline | None = None
        artifact_descriptor = -1
        artifact_identity: tuple[int, int] | None = None
        temporary_name = ""
        artifact_name = ""
        artifact_published = False
        slot_descriptor = -1
        slot_identity: tuple[int, int] | None = None
        slot_temporary_name = ""
        slot_name = ""
        slot_published = False
        previous_slot_moved = False
        committed = False
        suspended: SuspendedSession | None = None
        failure: BaseException | None = None
        cleanup_failed = False
        authentication_snapshot: EncryptedSnapshot | None = None
        artifact_baseline: FileBaseline | None = None
        stored: _StoredPending | None = None
        preserve_new_artifact = False
        try:
            self._faults._hit(PendingStage.PREPARATION)
            if _capture_regular_file(source) != source_baseline:
                raise ExternalModificationError()
            candidate_baseline = _capture_regular_file(candidate.path)
            if candidate_baseline.sha256 != candidate.sha256:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            anchor = _open_private_anchor(self._directory)
            locator = _vault_locator(source)
            slot_name = _slot_name(locator)
            previous = self._publication_previous_locked(
                anchor,
                slot_name,
                source_baseline,
                expected,
            )
            identifier = self._new_identifier(anchor)
            artifact_name = _artifact_name(identifier)
            temporary_name = f".bonobo-pending-write-{secrets.token_hex(16)}"
            created = anchor.create_persistent(temporary_name)
            if created is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            artifact_descriptor, artifact_identity, cleanup_name = created
            if cleanup_name != temporary_name:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            _validate_private_child(
                self._directory,
                anchor,
                temporary_name,
                artifact_descriptor,
                artifact_identity,
            )
            self._faults._hit(PendingStage.WRITE)
            _copy_path_to_descriptor(candidate.path, artifact_descriptor)
            self._faults._hit(PendingStage.FILE_SYNC)
            os.fsync(artifact_descriptor)
            artifact_baseline = _capture_open_descriptor(artifact_descriptor)
            if artifact_baseline.sha256 != candidate.sha256 or artifact_baseline.size <= 0:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            if not anchor.private_child_is_safe(artifact_descriptor, artifact_identity):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            with os.fdopen(os.dup(artifact_descriptor), "rb", closefd=True) as artifact_source:
                authentication_snapshot = EncryptedSnapshot.capture(
                    artifact_source,
                    self._snapshot_directory,
                    chunk_size=MAX_IO_CHUNK_BYTES,
                    max_bytes=MAX_ENCRYPTED_FILE_BYTES,
                )
            if (
                authentication_snapshot.size != artifact_baseline.size
                or authentication_snapshot.sha256 != artifact_baseline.sha256
            ):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            self._faults._hit(PendingStage.AUTHENTICATION)
            validator(authentication_snapshot)
            authentication_snapshot = None
            self._faults._hit(PendingStage.COMPARE)
            _validate_private_child(
                self._directory,
                anchor,
                temporary_name,
                artifact_descriptor,
                artifact_identity,
            )
            if (
                _capture_open_descriptor(artifact_descriptor) != artifact_baseline
                or _capture_anchor_child(anchor, temporary_name) != artifact_baseline
            ):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            if not anchor.publish_new_child(
                artifact_descriptor,
                artifact_identity,
                temporary_name,
                artifact_name,
            ):
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            artifact_published = True
            suspended = SuspendedSession(
                identifier,
                artifact_baseline.sha256,
                source_baseline.sha256,
                artifact_baseline.size,
            )
            stored = _StoredPending(suspended, source_baseline)
            payload = _encode_slot(stored)
            slot_temporary_name = f".bonobo-pending-slot-write-{secrets.token_hex(16)}"
            slot_created = anchor.create_persistent(slot_temporary_name)
            if slot_created is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            slot_descriptor, slot_identity, slot_cleanup_name = slot_created
            if slot_cleanup_name != slot_temporary_name:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            _validate_private_child(
                self._directory,
                anchor,
                slot_temporary_name,
                slot_descriptor,
                slot_identity,
            )
            _write_descriptor_bytes(slot_descriptor, payload)
            os.fsync(slot_descriptor)
            if _capture_open_descriptor(slot_descriptor).size != len(payload):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            if _capture_regular_file(source) != source_baseline:
                raise ExternalModificationError()
            self._faults._hit(PendingStage.SLOT_PUBLICATION)
            if previous is not None:
                previous_slot_baseline = _capture_open_descriptor(previous.slot_descriptor)
                _validate_private_child(
                    self._directory,
                    previous.anchor,
                    previous.slot_name,
                    previous.slot_descriptor,
                    previous.slot_identity,
                )
                if _capture_anchor_child(anchor, slot_name) != previous_slot_baseline:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                previous_name = f".bonobo-pending-previous-slot-{secrets.token_hex(16)}"
                if not anchor.publish_new_child(
                    previous.slot_descriptor,
                    previous.slot_identity,
                    previous.slot_name,
                    previous_name,
                ):
                    raise StorageError(StorageReason.PUBLICATION_FAILED)
                previous.slot_name = previous_name
                previous_slot_moved = True
                anchor.synchronize()
            slot_published = anchor.publish_new_child(
                slot_descriptor,
                slot_identity,
                slot_temporary_name,
                slot_name,
            )
            if not slot_published:
                raise StorageError(StorageReason.PUBLICATION_FAILED)
            self._faults._hit(PendingStage.DIRECTORY_SYNC)
            anchor.synchronize()
            self._faults._hit(PendingStage.POST_PUBLICATION_VALIDATION)
            current = self._read_located(_open_private_anchor(self._directory), slot_name)
            if current is None:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            try:
                if current.stored != stored or current.artifact_baseline != artifact_baseline:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
            finally:
                current.close()
            committed = True
        except BaseException as error:
            failure = error
        finally:
            if authentication_snapshot is not None:
                with suppress(BaseException):
                    authentication_snapshot.close()
            if slot_published and not committed and anchor is not None and slot_identity is not None:
                restored = self._restore_previous_slot(anchor, slot_name, slot_descriptor, slot_identity, previous)
                if not restored:
                    committed = (
                        stored is not None
                        and artifact_baseline is not None
                        and self._visible_pending_matches(slot_name, stored, artifact_baseline)
                    )
                    preserve_new_artifact = not committed
            elif (
                previous_slot_moved
                and previous is not None
                and anchor is not None
            ):
                try:
                    restored = anchor.publish_new_child(
                        previous.slot_descriptor,
                        previous.slot_identity,
                        previous.slot_name,
                        slot_name,
                    )
                    if restored:
                        previous.slot_name = slot_name
                        previous_slot_moved = False
                        anchor.synchronize()
                    else:
                        preserve_new_artifact = True
                except BaseException:
                    preserve_new_artifact = True
            if (
                not committed
                and not preserve_new_artifact
                and anchor is not None
                and artifact_identity is not None
            ):
                cleanup_name = artifact_name if artifact_published else temporary_name
                with suppress(BaseException):
                    anchor.remove_if_same(artifact_descriptor, cleanup_name, artifact_identity)
            if not slot_published and anchor is not None and slot_identity is not None:
                with suppress(BaseException):
                    anchor.remove_if_same(slot_descriptor, slot_temporary_name, slot_identity)
            if committed and previous is not None:
                try:
                    self._faults._hit(PendingStage.CLEANUP)
                    artifact_removed = previous.anchor.remove_if_same(
                        previous.artifact_descriptor,
                        previous.artifact_name,
                        previous.artifact_identity,
                    )
                    slot_removed = previous.anchor.remove_if_same(
                        previous.slot_descriptor,
                        previous.slot_name,
                        previous.slot_identity,
                    )
                    previous.anchor.synchronize()
                    cleanup_failed = not artifact_removed or not slot_removed
                except BaseException:
                    cleanup_failed = True
            if candidate_baseline is not None:
                try:
                    self._faults._hit(PendingStage.CLEANUP)
                    candidate_removed = _remove_candidate_if_same(candidate.path, candidate_baseline)
                    cleanup_failed = not candidate_removed or cleanup_failed
                except BaseException:
                    cleanup_failed = True
            for descriptor in (slot_descriptor, artifact_descriptor):
                if descriptor >= 0:
                    with suppress(BaseException):
                        os.close(descriptor)
            if previous is not None:
                with suppress(BaseException):
                    previous.close(close_anchor=False)
            if anchor is not None:
                with suppress(BaseException):
                    anchor.close()
        if committed and suspended is not None:
            if cleanup_failed or failure is not None:
                raise _CommittedPendingError(suspended) from None
            return suspended
        if failure is not None:
            if not isinstance(failure, Exception):
                raise failure
            if isinstance(failure, (ExternalModificationError, StorageError)):
                raise failure from None
            if isinstance(failure, PasswordSafeError):
                raise StorageError(StorageReason.VERIFICATION_FAILED) from None
        raise StorageError(StorageReason.PUBLICATION_FAILED)



    #### Generate one fresh 256-bit identifier not already present as an artifact.
    ####
    def _new_identifier(self, anchor: _PublicationAnchor) -> str:
        for _attempt in range(_NAME_ATTEMPTS):
            entropy = self._random.bytes(_IDENTIFIER_BYTES)
            if not isinstance(entropy, bytes) or len(entropy) != _IDENTIFIER_BYTES:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            identifier = entropy.hex()
            opened = anchor.open_child(_artifact_name(identifier))
            if opened is None:
                return identifier
            os.close(opened[0])
        raise StorageError(StorageReason.PREPARATION_FAILED)



    #### Report any exact-path or same-file-identity pending slot after validation.
    ####
    def _source_has_pending_locked(
        self,
        anchor: _PublicationAnchor,
        expected_slot_name: str,
        source_baseline: FileBaseline,
    ) -> bool:
        for slot_name in _slot_names(self._directory, anchor):
            located = self._read_located(anchor, slot_name, close_anchor=False)
            if located is None:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            try:
                if slot_name == expected_slot_name or _same_source_identity(
                    located.stored.source_baseline,
                    source_baseline,
                ):
                    return True
            finally:
                _close_located_descriptors(located)
        return False



    #### Select the sole exact expected slot and reject every identity alias.
    ####
    def _publication_previous_locked(
        self,
        anchor: _PublicationAnchor,
        expected_slot_name: str,
        source_baseline: FileBaseline,
        expected: SuspendedSession | None,
    ) -> _LocatedPending | None:
        identity_match: _LocatedPending | None = None
        exact_slot_seen = False
        selected: _LocatedPending | None = None
        try:
            for slot_name in _slot_names(self._directory, anchor):
                located = self._read_located(anchor, slot_name, close_anchor=False)
                if located is None:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                exact_slot_seen = exact_slot_seen or slot_name == expected_slot_name
                if _same_source_identity(located.stored.source_baseline, source_baseline):
                    if identity_match is not None:
                        _close_located_descriptors(located)
                        raise StorageError(StorageReason.VERIFICATION_FAILED)
                    identity_match = located
                else:
                    _close_located_descriptors(located)
            if expected is None:
                if exact_slot_seen or identity_match is not None:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                return None
            if (
                identity_match is None
                or identity_match.slot_name != expected_slot_name
                or identity_match.stored.suspended != expected
            ):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            selected = identity_match
            identity_match = None
            return selected
        finally:
            if identity_match is not None:
                _close_located_descriptors(identity_match)



    #### Locate exactly one stable slot whose metadata matches the caller token.
    ####
    def _find_locked(self, source: Path, suspended: SuspendedSession) -> _LocatedPending:
        anchor = _open_private_anchor(self._directory)
        matches: list[_LocatedPending] = []
        transferred = False
        expected_slot_name = _slot_name(_vault_locator(source))
        try:
            for slot_name in _slot_names(self._directory, anchor):
                located = self._read_located(anchor, slot_name, close_anchor=False)
                if located is None:
                    raise StorageError(StorageReason.VERIFICATION_FAILED)
                if located.stored.suspended.identifier == suspended.identifier:
                    if slot_name != expected_slot_name or located.stored.suspended != suspended:
                        located.close()
                        raise StorageError(StorageReason.VERIFICATION_FAILED)
                    matches.append(located)
                else:
                    _close_located_descriptors(located)
            if len(matches) != 1:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            result = matches[0]
            transferred = True
            return result
        finally:
            if not transferred:
                for located in matches:
                    _close_located_descriptors(located)
                with suppress(BaseException):
                    anchor.close()



    #### Open and validate one exact stable slot plus its named artifact.
    ####
    def _read_located(
        self,
        anchor: _PublicationAnchor,
        slot_name: str,
        *,
        close_anchor: bool = True,
    ) -> _LocatedPending | None:
        slot_opened = anchor.open_child_for_replace(slot_name)
        if slot_opened is None:
            if (self._directory / slot_name).exists():
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            if close_anchor:
                anchor.close()
            return None
        slot_descriptor, slot_identity = slot_opened
        artifact_descriptor = -1
        try:
            _validate_private_child(
                self._directory,
                anchor,
                slot_name,
                slot_descriptor,
                slot_identity,
            )
            before = _capture_open_descriptor(slot_descriptor)
            if not 0 < before.size <= _MAX_SLOT_BYTES:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            payload = _read_descriptor_bytes(slot_descriptor, _MAX_SLOT_BYTES)
            if (
                _capture_open_descriptor(slot_descriptor) != before
                or _capture_anchor_child(anchor, slot_name) != before
            ):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            stored = _decode_slot(payload)
            artifact_name = _artifact_name(stored.suspended.identifier)
            artifact_opened = anchor.open_child_for_replace(artifact_name)
            if artifact_opened is None:
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            artifact_descriptor, artifact_identity = artifact_opened
            _validate_private_child(
                self._directory,
                anchor,
                artifact_name,
                artifact_descriptor,
                artifact_identity,
            )
            artifact_baseline = _capture_open_descriptor(artifact_descriptor)
            if (
                artifact_baseline.size != stored.suspended.size
                or artifact_baseline.sha256 != stored.suspended.sha256
                or _capture_anchor_child(anchor, artifact_name) != artifact_baseline
            ):
                raise StorageError(StorageReason.VERIFICATION_FAILED)
            return _LocatedPending(
                anchor,
                slot_name,
                slot_descriptor,
                slot_identity,
                artifact_name,
                artifact_descriptor,
                artifact_identity,
                artifact_baseline,
                stored,
            )
        except BaseException:
            if artifact_descriptor >= 0:
                with suppress(BaseException):
                    os.close(artifact_descriptor)
            with suppress(BaseException):
                os.close(slot_descriptor)
            if close_anchor:
                with suppress(BaseException):
                    anchor.close()
            raise



    #### Roll a failed slot replacement back to its prior valid association.
    ####
    def _restore_previous_slot(
        self,
        anchor: _PublicationAnchor,
        slot_name: str,
        slot_descriptor: int,
        slot_identity: tuple[int, int],
        previous: _LocatedPending | None,
    ) -> bool:
        rollback_name = f".bonobo-pending-rollback-{secrets.token_hex(16)}"
        try:
            if previous is None:
                restored = anchor.remove_if_same(slot_descriptor, slot_name, slot_identity)
                anchor.synchronize()
                return restored
            if (
                _capture_open_descriptor(previous.artifact_descriptor) != previous.artifact_baseline
                or _capture_anchor_child(anchor, previous.artifact_name) != previous.artifact_baseline
            ):
                return False
            _validate_private_child(
                self._directory,
                previous.anchor,
                previous.artifact_name,
                previous.artifact_descriptor,
                previous.artifact_identity,
            )
            previous_slot = _capture_open_descriptor(previous.slot_descriptor)
            if _capture_anchor_child(anchor, previous.slot_name) != previous_slot:
                return False
            _validate_private_child(
                self._directory,
                previous.anchor,
                previous.slot_name,
                previous.slot_descriptor,
                previous.slot_identity,
            )
            current_slot = _capture_open_descriptor(slot_descriptor)
            if _capture_anchor_child(anchor, slot_name) != current_slot:
                return False
            if not anchor.publish_new_child(
                slot_descriptor,
                slot_identity,
                slot_name,
                rollback_name,
            ):
                return False
            if not anchor.publish_new_child(
                previous.slot_descriptor,
                previous.slot_identity,
                previous.slot_name,
                slot_name,
            ):
                with suppress(BaseException):
                    anchor.publish_new_child(
                        slot_descriptor,
                        slot_identity,
                        rollback_name,
                        slot_name,
                    )
                    anchor.synchronize()
                return False
            previous.slot_name = slot_name
            anchor.synchronize()
            current = self._read_located(_open_private_anchor(self._directory), slot_name)
            if current is None:
                return False
            try:
                if current.stored != previous.stored or current.artifact_baseline != previous.artifact_baseline:
                    return False
            finally:
                current.close()
            with suppress(BaseException):
                anchor.remove_if_same(slot_descriptor, rollback_name, slot_identity)
                anchor.synchronize()
            return True
        except BaseException:
            return False



    #### Confirm that failed rollback still left the new exact state authoritative.
    ####
    def _visible_pending_matches(
        self,
        slot_name: str,
        stored: _StoredPending,
        artifact_baseline: FileBaseline,
    ) -> bool:
        current: _LocatedPending | None = None
        try:
            current = self._read_located(_open_private_anchor(self._directory), slot_name)
            return (
                current is not None
                and current.stored == stored
                and current.artifact_baseline == artifact_baseline
            )
        except BaseException:
            return False
        finally:
            if current is not None:
                with suppress(BaseException):
                    current.close()



#### Open one persistent anchor only after the directory passes private checks.
####
def _open_private_anchor(directory: Path) -> _PublicationAnchor:
    validation = _validate_private_directory(directory)
    if validation is None:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    validation.close()
    anchor: _PublicationAnchor | None = (
        WindowsDirectoryAnchor.open(directory)
        if os.name == "nt"
        else _PosixPublicationAnchor.open(directory)
    )
    if anchor is None or not anchor.stable():
        if anchor is not None:
            with suppress(BaseException):
                anchor.close()
        raise StorageError(StorageReason.PREPARATION_FAILED)
    return anchor



#### Validate owner-only regular-file state through the retained descriptor.
####
def _validate_private_child(
    directory: Path,
    anchor: _PublicationAnchor,
    name: str,
    descriptor: int,
    identity: tuple[int, int],
) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_ENCRYPTED_FILE_BYTES
        or not anchor.private_child_is_safe(descriptor, identity)
    ):
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    if os.name == "nt":
        return
    if stat.S_IMODE(metadata.st_mode) != _OWNER_FILE_MODE:
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    get_effective_user = getattr(os, "geteuid", None)
    if get_effective_user is not None and metadata.st_uid != get_effective_user():
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    if sys.platform == "darwin":
        _require_no_extended_acl(descriptor)



#### Serialize one closed slot record as strict bounded ASCII lines.
####
def _encode_slot(stored: _StoredPending) -> bytes:
    baseline = stored.source_baseline
    values = (
        _SLOT_MAGIC,
        stored.suspended.identifier,
        stored.suspended.sha256,
        str(stored.suspended.size),
        baseline.sha256,
        str(baseline.size),
        str(baseline.modified_ns),
        _optional_integer(baseline.device),
        _optional_integer(baseline.inode),
        _optional_integer(baseline.windows_file_id),
    )
    payload = ("\n".join(values) + "\n").encode("ascii")
    if len(payload) > _MAX_SLOT_BYTES:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    return payload



#### Parse one exact closed slot schema without retaining malformed text.
####
def _decode_slot(payload: bytes) -> _StoredPending:
    try:
        values = payload.decode("ascii").splitlines()
        if len(values) != 10 or values[0] != _SLOT_MAGIC:
            raise ValueError
        identifier = values[1]
        artifact_sha256 = values[2]
        artifact_size = _nonnegative_integer(values[3])
        source_sha256 = values[4]
        source_size = _nonnegative_integer(values[5])
        modified_ns = _nonnegative_integer(values[6])
        device = _decode_optional_integer(values[7])
        inode = _decode_optional_integer(values[8])
        windows_file_id = _decode_optional_integer(values[9])
        suspended = SuspendedSession(identifier, artifact_sha256, source_sha256, artifact_size)
        baseline = FileBaseline(source_size, source_sha256, modified_ns, device, inode, windows_file_id)
        return _StoredPending(suspended, baseline)
    except (UnicodeError, ValueError, TypeError):
        raise StorageError(StorageReason.VERIFICATION_FAILED) from None



#### Render one optional nonnegative identity without an ambiguous empty field.
####
def _optional_integer(value: int | None) -> str:
    return "-" if value is None else str(value)



#### Parse one strict decimal integer without signs, spaces, or boolean aliases.
####
def _nonnegative_integer(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError
    return int(value)



#### Parse one optional strict decimal file identity.
####
def _decode_optional_integer(value: str) -> int | None:
    return None if value == "-" else _nonnegative_integer(value)



#### Build the stable private slot name for one source locator.
####
def _slot_name(locator: str) -> str:
    _validate_digest(locator, "pending locator")
    return f"{_SLOT_PREFIX}{locator}{_SLOT_SUFFIX}"



#### Build the private artifact name from one validated random identifier.
####
def _artifact_name(identifier: str) -> str:
    _validate_digest(identifier, "pending identifier")
    return f"{_ARTIFACT_PREFIX}{identifier}{_ARTIFACT_SUFFIX}"



#### Enumerate only exact stable slot names while rejecting locator ambiguity.
####
def _slot_names(directory: Path, anchor: _PublicationAnchor) -> tuple[str, ...]:
    if not anchor.stable():
        raise StorageError(StorageReason.PREPARATION_FAILED)
    names: list[str] = []
    enumeration_failed = False
    try:
        for entry in os.scandir(directory):
            name = entry.name
            if not name.startswith(_SLOT_PREFIX) or not name.endswith(_SLOT_SUFFIX):
                continue
            locator = name[len(_SLOT_PREFIX): -len(_SLOT_SUFFIX)]
            try:
                _validate_digest(locator, "pending locator")
            except ValueError:
                raise StorageError(StorageReason.VERIFICATION_FAILED) from None
            names.append(name)
    except StorageError:
        raise
    except Exception:
        enumeration_failed = True
    if enumeration_failed:
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    if len(names) != len(set(names)) or not anchor.stable():
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    return tuple(sorted(names))



#### Validate the exact public selector type before private directory traversal.
####
def _validate_suspended(suspended: SuspendedSession) -> None:
    if not isinstance(suspended, SuspendedSession):
        raise TypeError("pending selector must use SuspendedSession")



#### Compare stable device/file identity without changing path-bound metadata.
####
def _same_source_identity(left: FileBaseline, right: FileBaseline) -> bool:
    left_file_id = left.windows_file_id if os.name == "nt" else left.inode
    right_file_id = right.windows_file_id if os.name == "nt" else right.inode
    if (
        left.device is None
        or right.device is None
        or left_file_id is None
        or right_file_id is None
    ):
        raise StorageError(StorageReason.VERIFICATION_FAILED)
    return (left.device, left_file_id) == (right.device, right_file_id)



#### Convert platform diagnostics into the closed pending-store error vocabulary.
####
def _raise_closed_pending_error(error: BaseException) -> Never:
    if not isinstance(error, Exception):
        raise error
    if isinstance(error, PasswordSafeError):
        raise error from None
    raise StorageError(StorageReason.VERIFICATION_FAILED) from None



#### Remove only the unchanged candidate captured before pending publication.
####
def _remove_candidate_if_same(path: Path, baseline: FileBaseline) -> bool:
    anchor: _PublicationAnchor | None = None
    descriptor = -1
    try:
        if _capture_regular_file(path) != baseline:
            return False
        anchor = _open_private_anchor(path.parent)
        opened = anchor.open_child_for_replace(path.name)
        if opened is None:
            return False
        descriptor, identity = opened
        if _capture_open_descriptor(descriptor) != baseline:
            return False
        return anchor.remove_if_same(descriptor, path.name, identity)
    except FileNotFoundError:
        return True
    except (OSError, StorageError):
        return False
    finally:
        if descriptor >= 0:
            with suppress(BaseException):
                os.close(descriptor)
        if anchor is not None:
            with suppress(BaseException):
                anchor.close()



#### Close only child descriptors when several locations share one anchor.
####
def _close_located_descriptors(located: _LocatedPending) -> None:
    for descriptor in (located.artifact_descriptor, located.slot_descriptor):
        if descriptor >= 0:
            with suppress(BaseException):
                os.close(descriptor)
    located.artifact_descriptor = -1
    located.slot_descriptor = -1
