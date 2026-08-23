"""Capture immutable encrypted files into private, bounded snapshot owners.

Snapshots copy source ciphertext into exclusively created owner-only artifacts in
a caller-supplied private directory.  They retain no source path and expose only
bounded offset reads before deterministic encrypted-artifact cleanup.
"""

import hashlib
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Final, NoReturn, Protocol, Self, SupportsIndex

from .constants import MAX_IO_CHUNK_BYTES
from .errors import StorageError, StorageReason



_SNAPSHOT_NAME_ATTEMPTS: Final[int] = 32
_OWNER_FILE_MODE: Final[int] = 0o600
_OWNER_DIRECTORY_MASK: Final[int] = 0o077



#### Describe the bounded binary-source operation used during capture.
####
class ReadableBinary(Protocol):



    #### Fill at most the supplied mutable buffer or report end of input.
    ####
    def readinto(self, buffer: bytearray) -> int | None:
        raise NotImplementedError



#### Report attempted access after an encrypted snapshot becomes terminal.
####
class SnapshotClosedError(RuntimeError):



    #### Initialize one fixed diagnostic that contains no file or source identity.
    ####
    def __init__(self) -> None:
        super().__init__("encrypted snapshot is closed")



#### Reject unsafe private-directory state without retaining platform diagnostics.
####
def _validate_private_directory(directory: Path) -> Path | None:
    try:
        absolute = directory.absolute()
        metadata = absolute.lstat()
        is_junction = getattr(os.path, "isjunction", None)
        if stat.S_ISLNK(metadata.st_mode) or (is_junction is not None and is_junction(absolute)):
            raise OSError
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError
        if os.name != "nt":
            if stat.S_IMODE(metadata.st_mode) & _OWNER_DIRECTORY_MASK:
                raise OSError
            get_effective_user = getattr(os, "geteuid", None)
            if get_effective_user is not None and metadata.st_uid != get_effective_user():
                raise OSError
        return absolute
    except Exception:
        return None



#### Create one unpredictable regular file exclusively inside a validated directory.
####
def _create_private_artifact(directory: Path) -> tuple[int, Path, tuple[int, int]] | None:
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(_SNAPSHOT_NAME_ATTEMPTS):
        path = directory / f"snapshot-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(path, flags, _OWNER_FILE_MODE)
        except FileExistsError:
            continue
        except Exception:
            return None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != _OWNER_FILE_MODE:
                raise OSError
            return descriptor, path, (metadata.st_dev, metadata.st_ino)
        except Exception:
            with suppress(BaseException):
                os.close(descriptor)
            with suppress(BaseException):
                path.unlink()
            return None
    return None



#### Write one bounded buffer completely despite permitted partial OS writes.
####
def _write_all(descriptor: int, data: memoryview[int], length: int) -> None:
    offset = 0
    while offset < length:
        written = os.write(descriptor, data[offset:length])
        if written <= 0:
            raise OSError
        offset += written



#### Copy and synchronize source bytes while discarding arbitrary source failures.
####
def _copy_and_synchronize(
    source: ReadableBinary,
    descriptor: int,
    buffer: bytearray,
    view: memoryview[int],
    chunk_size: int,
) -> tuple[int, str] | None:
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            count = source.readinto(buffer)
            if count is None:
                raise OSError
            if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= chunk_size:
                raise OSError
            if count == 0:
                break
            chunk = view[:count]
            digest.update(chunk)
            _write_all(descriptor, chunk, count)
            size += count
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != size:
            raise OSError
        os.lseek(descriptor, 0, os.SEEK_SET)
        return size, digest.hexdigest()
    except Exception:
        return None



#### Remove only the exact regular artifact originally created by this owner.
####
def _unlink_if_same(path: Path, identity: tuple[int, int]) -> None:
    metadata = path.lstat()
    if stat.S_ISREG(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity:
        path.unlink()



#### Own one synchronized immutable encrypted copy and its bounded reader handle.
####
#### The source stream remains caller-owned.  Closing releases the descriptor and
#### removes only the unchanged encrypted artifact created during capture.
####
class EncryptedSnapshot:
    __slots__ = ("_fd", "_identity", "_lock", "_path", "_sha256", "_size")

    _sha256: str
    _size: int



    #### Publish already synchronized snapshot state after successful capture.
    ####
    def __init__(self, descriptor: int, path: Path, identity: tuple[int, int], size: int, digest: str) -> None:
        if hasattr(self, "_fd"):
            raise TypeError("encrypted snapshot cannot be reinitialized")
        self._fd = descriptor
        self._path = path
        self._identity = identity
        self._lock = RLock()
        self._size = size
        self._sha256 = digest



    #### Return the immutable synchronized ciphertext byte count.
    ####
    @property
    def size(self) -> int:
        return self._size



    #### Return the immutable synchronized ciphertext SHA-256 identity.
    ####
    @property
    def sha256(self) -> str:
        return self._sha256



    #### Copy ciphertext in bounded chunks and synchronize it before publication.
    ####
    #### The caller supplies an existing private application directory.  Any source
    #### or platform failure is reduced to a safe path-free storage category.
    ####
    @classmethod
    def capture(
        cls,
        source: ReadableBinary,
        private_directory: Path,
        *,
        chunk_size: int = MAX_IO_CHUNK_BYTES,
    ) -> Self:
        _validate_chunk_size(chunk_size)
        directory = _validate_private_directory(private_directory)
        if directory is None:
            raise StorageError(StorageReason.PREPARATION_FAILED)
        descriptor = -1
        path: Path | None = None
        identity: tuple[int, int] | None = None
        published = False
        buffer = bytearray(chunk_size)
        view = memoryview(buffer)
        try:
            created = _create_private_artifact(directory)
            if created is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            descriptor, path, identity = created
            copied = _copy_and_synchronize(source, descriptor, buffer, view, chunk_size)
            if copied is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            size, digest = copied
            snapshot = cls(descriptor, path, identity, size, digest)
            published = True
            return snapshot
        finally:
            view.release()
            buffer[:] = bytes(len(buffer))
            if not published:
                if descriptor >= 0:
                    with suppress(BaseException):
                        os.close(descriptor)
                if path is not None and identity is not None:
                    with suppress(BaseException):
                        _unlink_if_same(path, identity)



    #### Report whether descriptor release has made this owner terminal.
    ####
    @property
    def closed(self) -> bool:
        return self._fd < 0



    #### Read one exact range no larger than the reviewed I/O ceiling.
    ####
    def read_at(self, offset: int, length: int) -> bytes:
        _validate_read_range(offset, length, self.size)
        with self._lock:
            descriptor = self._require_descriptor()
            try:
                os.lseek(descriptor, offset, os.SEEK_SET)
                output = bytearray(length)
                view = memoryview(output)
                read = 0
                try:
                    while read < length:
                        chunk = os.read(descriptor, length - read)
                        if not chunk:
                            raise OSError
                        view[read:read + len(chunk)] = chunk
                        read += len(chunk)
                    return bytes(output)
                finally:
                    view.release()
                    output[:] = bytes(len(output))
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise StorageError(StorageReason.VERIFICATION_FAILED) from None



    #### Yield one exact bounded range in caller-selected chunks and source order.
    ####
    def iter_chunks(self, offset: int, length: int, chunk_size: int) -> Iterator[memoryview[int]]:
        _validate_chunk_size(chunk_size)
        _validate_span(offset, length, self.size)
        position = offset
        remaining = length
        while remaining:
            requested = min(chunk_size, remaining)
            chunk = self.read_at(position, requested)
            yield memoryview(chunk)
            position += requested
            remaining -= requested



    #### Return the live descriptor or reject all use after deterministic cleanup.
    ####
    def _require_descriptor(self) -> int:
        if self._fd < 0:
            raise SnapshotClosedError()
        return self._fd



    #### Release and remove the encrypted artifact exactly once.
    ####
    def close(self) -> None:
        with self._lock:
            descriptor = self._fd
            if descriptor < 0:
                return
            self._fd = -1
            try:
                os.close(descriptor)
                _unlink_if_same(self._path, self._identity)
            except FileNotFoundError:
                return
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise StorageError(StorageReason.PREPARATION_FAILED) from None



    #### Enter only a live snapshot without changing its read position or lifetime.
    ####
    def __enter__(self) -> Self:
        self._require_descriptor()
        return self



    #### Close encrypted snapshot state after normal or exceptional context exit.
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



    #### Defensively release forgotten encrypted state without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Render only encrypted content identity and lifecycle metadata.
    ####
    def __repr__(self) -> str:
        return f"EncryptedSnapshot(size={self.size}, sha256={self.sha256!r}, closed={self.closed})"



    #### Reject shallow copies that would alias one descriptor and artifact owner.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("snapshot owner cannot be copied or serialized")



    #### Reject deep copies that would duplicate encrypted artifact ownership.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("snapshot owner cannot be copied or serialized")



    #### Reject direct state extraction from a live resource owner.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("snapshot owner cannot be copied or serialized")



    #### Reject fabricated state injection into a resource owner.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("snapshot owner cannot be copied or serialized")



    #### Reject legacy serialization reduction without exposing private paths.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("snapshot owner cannot be copied or serialized")



    #### Reject protocol-specific serialization reduction before state inspection.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("snapshot owner cannot be copied or serialized")



#### Validate caller chunk bounds before allocating or reading any data.
####
def _validate_chunk_size(chunk_size: int) -> None:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk size must be an integer")
    if not 0 < chunk_size <= MAX_IO_CHUNK_BYTES:
        raise ValueError("chunk size must be within the approved I/O bound")



#### Validate one bounded exact random-access request against snapshot size.
####
def _validate_read_range(offset: int, length: int, size: int) -> None:
    _validate_span(offset, length, size)
    if length > MAX_IO_CHUNK_BYTES:
        raise ValueError("snapshot reads must be bounded")



#### Validate a nonallocating integer span before calculating its end.
####
def _validate_span(offset: int, length: int, size: int) -> None:
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if offset < 0 or length < 0 or offset > size or length > size - offset:
        raise ValueError("snapshot range is outside captured ciphertext")
