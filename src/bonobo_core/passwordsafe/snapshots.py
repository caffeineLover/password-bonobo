"""Capture immutable encrypted files into private, bounded snapshot owners.

Snapshots copy source ciphertext into exclusively created owner-only artifacts in
a caller-supplied private directory.  They retain no source path and expose only
bounded offset reads before deterministic encrypted-artifact cleanup.
"""

import hashlib
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Final, NoReturn, Protocol, Self, SupportsIndex

from ._darwin_security import require_no_extended_acl as _require_no_extended_acl
from .constants import MAX_ENCRYPTED_FILE_BYTES, MAX_IO_CHUNK_BYTES
from .errors import ResourceLimitError, ResourceLimitReason, StorageError, StorageReason



if os.name == "nt":
    from ._windows_security import WindowsDirectoryAnchor, path_is_private



_SNAPSHOT_NAME_ATTEMPTS: Final[int] = 32
_OWNER_FILE_MODE: Final[int] = 0o600
_OWNER_DIRECTORY_MASK: Final[int] = 0o077
_O_TMPFILE: Final[int] = getattr(os, "O_TMPFILE", 0)
if sys.platform.startswith("linux"):
    _POSIX_FILE_STRATEGY: Final[str] = "linux-o-tmpfile"
elif sys.platform == "darwin":
    _POSIX_FILE_STRATEGY = "macos-unlinked"
else:
    _POSIX_FILE_STRATEGY = "unsupported"



#### Provide one deterministic no-op seam before fallback unlink.
####
def _before_posix_unlink() -> None:
    return None



#### Describe the bounded binary-source operation used during capture.
####
class ReadableBinary(Protocol):



    #### Fill at most the supplied mutable buffer or report end of input.
    ####
    def readinto(self, buffer: bytearray) -> int | None:
        raise NotImplementedError



#### Define the stable anchored operations retained through artifact cleanup.
####
class _DirectoryAnchor(Protocol):



    #### Create one exclusive child and return its descriptor and stable identity.
    ####
    def create(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        raise NotImplementedError



    #### Remove only the child whose stable identity still matches.
    ####
    def remove_if_same(self, descriptor: int, name: str, identity: tuple[int, int]) -> bool:
        raise NotImplementedError



    #### Release the retained validated directory handle.
    ####
    def close(self) -> None:
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
def _validate_private_directory(directory: Path) -> _DirectoryAnchor | None:
    if os.name == "nt":
        try:
            return WindowsDirectoryAnchor.open(directory)
        except Exception:
            return None
    descriptor = -1
    try:
        absolute = directory.absolute()
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise OSError
        metadata = absolute.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError
        if stat.S_IMODE(metadata.st_mode) & _OWNER_DIRECTORY_MASK:
            raise OSError
        get_effective_user = getattr(os, "geteuid", None)
        if get_effective_user is not None and metadata.st_uid != get_effective_user():
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute, flags)
        anchored = os.fstat(descriptor)
        if (anchored.st_dev, anchored.st_ino) != (metadata.st_dev, metadata.st_ino):
            os.close(descriptor)
            raise OSError
        return _PosixDirectoryAnchor(absolute, descriptor)
    except Exception:
        if descriptor >= 0:
            with suppress(BaseException):
                os.close(descriptor)
        return None



#### Hold a POSIX directory descriptor for relative create, verify, and unlink.
####
class _PosixDirectoryAnchor:
    __slots__ = ("_fd", "_identity", "_path")



    #### Retain one validated open directory descriptor and safe display-free path.
    ####
    def __init__(self, path: Path, descriptor: int) -> None:
        self._path = path
        self._fd = descriptor
        metadata = os.fstat(descriptor)
        self._identity = (metadata.st_dev, metadata.st_ino)



    #### Create one regular owner-only child relative to the held directory.
    ####
    def create(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        if not self._stable():
            return None
        common_flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        if _POSIX_FILE_STRATEGY == "linux-o-tmpfile":
            if not _O_TMPFILE:
                return None
            try:
                descriptor = os.open(".", common_flags | _O_TMPFILE, _OWNER_FILE_MODE, dir_fd=self._fd)
            except OSError:
                return None
            try:
                metadata = os.fstat(descriptor)
                identity = (metadata.st_dev, metadata.st_ino)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 0
                    or stat.S_IMODE(metadata.st_mode) != _OWNER_FILE_MODE
                    or not self._stable()
                ):
                    raise OSError
                return descriptor, identity, None
            except BaseException:
                with suppress(BaseException):
                    os.close(descriptor)
                raise
        if _POSIX_FILE_STRATEGY != "macos-unlinked":
            return None

        #### Ruling 5: same-UID namespace mutation is outside the threat scope;
        #### unlink the exclusive name immediately without a check-then-act read.
        _require_no_extended_acl(self._fd)
        flags = common_flags | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, _OWNER_FILE_MODE, dir_fd=self._fd)
        except Exception:
            return None
        linked = True
        try:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError
            if stat.S_IMODE(metadata.st_mode) != _OWNER_FILE_MODE:
                raise OSError
            if not self._stable():
                raise OSError
            _require_no_extended_acl(descriptor)
            _before_posix_unlink()
            os.unlink(name, dir_fd=self._fd)
            linked = False
            anonymous = os.fstat(descriptor)
            if (anonymous.st_dev, anonymous.st_ino) != identity or anonymous.st_nlink != 0:
                raise OSError
            return descriptor, identity, None
        except BaseException:
            if linked:
                with suppress(BaseException):
                    os.unlink(name, dir_fd=self._fd)
            with suppress(BaseException):
                os.close(descriptor)
            raise



    #### Confirm the already anonymous child still matches its retained fd.
    ####
    def remove_if_same(self, descriptor: int, _name: str, identity: tuple[int, int]) -> bool:
        opened = os.fstat(descriptor)
        return (
            stat.S_ISREG(opened.st_mode)
            and (opened.st_dev, opened.st_ino) == identity
            and opened.st_nlink == 0
        )



    #### Compare the directory name with the identity retained by the open fd.
    ####
    def _stable(self) -> bool:
        metadata = self._path.lstat()
        return not stat.S_ISLNK(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == self._identity



    #### Close the anchored descriptor exactly once.
    ####
    def close(self) -> None:
        descriptor = self._fd
        if descriptor >= 0:
            os.close(descriptor)
            self._fd = -1



#### Create one unpredictable regular file exclusively under a held anchor.
####
def _create_private_artifact(anchor: _DirectoryAnchor) -> tuple[int, str | None, tuple[int, int]] | None:
    for _attempt in range(_SNAPSHOT_NAME_ATTEMPTS):
        name = f"snapshot-{secrets.token_hex(16)}"
        try:
            created = anchor.create(name)
        except Exception:
            return None
        if created is not None:
            descriptor, identity, cleanup_name = created
            return descriptor, cleanup_name, identity
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
    max_bytes: int,
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
            if count > max_bytes - size:
                raise ResourceLimitError(ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES)
            chunk = view[:count]
            digest.update(chunk)
            _write_all(descriptor, chunk, count)
            size += count
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != size:
            raise OSError
        os.lseek(descriptor, 0, os.SEEK_SET)
        return size, digest.hexdigest()
    except ResourceLimitError:
        raise
    except Exception:
        return None



#### Remove only the exact regular artifact originally created by this owner.
####
def _unlink_if_same(
    anchor: _DirectoryAnchor,
    descriptor: int,
    name: str,
    identity: tuple[int, int],
) -> None:
    if not anchor.remove_if_same(descriptor, name, identity):
        raise OSError



#### Expose the native verifier solely for platform-specific security tests.
####
def _windows_path_is_private(path: Path) -> bool:
    if os.name != "nt":
        return False
    return path_is_private(path)



#### Own one synchronized immutable encrypted copy and its bounded reader handle.
####
#### The source stream remains caller-owned.  Closing releases the descriptor and
#### removes only the unchanged encrypted artifact created during capture.
####
class EncryptedSnapshot:
    __slots__ = (
        "__weakref__",
        "_anchor",
        "_anchor_closed",
        "_artifact_removed",
        "_cleanup_pending",
        "_fd",
        "_identity",
        "_lock",
        "_name",
        "_sha256",
        "_size",
    )

    _sha256: str
    _size: int



    #### Publish already synchronized snapshot state after successful capture.
    ####
    def __init__(
        self,
        descriptor: int,
        anchor: _DirectoryAnchor,
        name: str | None,
        identity: tuple[int, int],
        size: int,
        digest: str,
    ) -> None:
        if hasattr(self, "_fd"):
            raise TypeError("encrypted snapshot cannot be reinitialized")
        self._fd = descriptor
        self._anchor = anchor
        self._name = name
        self._identity = identity
        self._lock = RLock()
        self._cleanup_pending = True
        self._artifact_removed = name is None
        self._anchor_closed = False
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
        max_bytes: int = MAX_ENCRYPTED_FILE_BYTES,
    ) -> Self:
        _validate_chunk_size(chunk_size)
        _validate_max_bytes(max_bytes)
        anchor = _validate_private_directory(private_directory)
        if anchor is None:
            raise StorageError(StorageReason.PREPARATION_FAILED)
        descriptor = -1
        name: str | None = None
        identity: tuple[int, int] | None = None
        published = False
        buffer = bytearray(chunk_size)
        view = memoryview(buffer)
        try:
            created = _create_private_artifact(anchor)
            if created is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            descriptor, name, identity = created
            copied = _copy_and_synchronize(source, descriptor, buffer, view, chunk_size, max_bytes)
            if copied is None:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            size, digest = copied
            snapshot = cls(descriptor, anchor, name, identity, size, digest)
            published = True
            return snapshot
        finally:
            view.release()
            buffer[:] = bytes(len(buffer))
            if not published:
                if descriptor >= 0 and name is not None and identity is not None:
                    with suppress(BaseException):
                        _unlink_if_same(anchor, descriptor, name, identity)
                if descriptor >= 0:
                    with suppress(BaseException):
                        os.close(descriptor)
                with suppress(BaseException):
                    anchor.close()



    #### Report whether descriptor release has made this owner terminal.
    ####
    @property
    def closed(self) -> bool:
        return self._fd < 0 and not self._cleanup_pending



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
            if descriptor < 0 and not self._cleanup_pending:
                return
            failed = False
            try:
                if not self._artifact_removed:
                    if descriptor < 0 or self._name is None:
                        raise OSError
                    _unlink_if_same(self._anchor, descriptor, self._name, self._identity)
                    self._artifact_removed = True
                if self._fd >= 0:
                    os.close(descriptor)
                    self._fd = -1
                if not self._anchor_closed:
                    self._anchor.close()
                    self._anchor_closed = True
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                failed = True
            if failed:
                raise StorageError(StorageReason.PREPARATION_FAILED)
            self._cleanup_pending = False



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



#### Validate a capture ceiling before creating or reading any encrypted artifact.
####
def _validate_max_bytes(max_bytes: int) -> None:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("maximum snapshot bytes must be an integer")
    if not 0 < max_bytes <= MAX_ENCRYPTED_FILE_BYTES:
        raise ValueError("maximum snapshot bytes must be within the approved encrypted-file bound")



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
