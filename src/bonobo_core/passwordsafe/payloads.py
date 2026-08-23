"""Own bounded plaintext payloads and stream authenticated encrypted field spans.

Inline payloads adopt mutable buffers and wipe them.  Deferred payloads borrow an
immutable encrypted snapshot and authenticated content key, retain only copied CBC
metadata, and materialize no plaintext larger than a caller-approved chunk.
"""

import ctypes
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from threading import RLock
from types import TracebackType
from typing import NoReturn, Protocol, Self, SupportsIndex, runtime_checkable

from .constants import BLOCK_BYTES, FIELD_HEADER_BYTES, HMAC_BYTES, MAX_IO_CHUNK_BYTES
from .crypto import CbcDecryptor, TwofishBackend
from .secrets import SecretBuffer



_MAX_FIELD_PAYLOAD_BYTES = 0xFFFF_FFFF
_PY_BYTEARRAY_SIZE = ctypes.pythonapi.PyByteArray_Size
_PY_BYTEARRAY_SIZE.argtypes = [ctypes.py_object]
_PY_BYTEARRAY_SIZE.restype = ctypes.c_ssize_t
_PY_BYTEARRAY_AS_STRING = ctypes.pythonapi.PyByteArray_AsString
_PY_BYTEARRAY_AS_STRING.argtypes = [ctypes.py_object]
_PY_BYTEARRAY_AS_STRING.restype = ctypes.c_void_p



#### Return the CPython-owned size without invoking subclass Python methods.
####
def _mutable_buffer_size(buffer: bytearray) -> int:
    return int(_PY_BYTEARRAY_SIZE(buffer))



#### Wipe one adopted mutable buffer without dispatching to subclass methods.
####
def _wipe_mutable_buffer(buffer: bytearray) -> None:
    size = _mutable_buffer_size(buffer)
    if size > 0:
        address = _PY_BYTEARRAY_AS_STRING(buffer)
        if address is None:
            raise RuntimeError("mutable buffer address is unavailable")
        ctypes.memset(address, 0, size)



#### Report attempted access after one field payload becomes terminal.
####
class PayloadClosedError(RuntimeError):



    #### Initialize one fixed diagnostic without field identity or prior contents.
    ####
    def __init__(self) -> None:
        super().__init__("field payload is closed")



#### Describe the closable streaming surface shared by every raw field payload.
####
@runtime_checkable
class FieldPayload(Protocol):



    #### Return the exact declared plaintext byte length.
    ####
    @property
    def length(self) -> int:
        raise NotImplementedError



    #### Yield ordered read-only views no larger than the caller's approved bound.
    ####
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        raise NotImplementedError



    #### Acquire one independently closable lifetime without unbounded copying.
    ####
    def retain(self) -> FieldPayload:
        raise NotImplementedError



    #### Make this payload terminal without closing resources it only borrows.
    ####
    def close(self) -> None:
        raise NotImplementedError



#### Describe the exact bounded snapshot operations used by deferred payloads.
####
class SnapshotReader(Protocol):
    size: int



    #### Return one exact ciphertext range within the reviewed I/O ceiling.
    ####
    def read_at(self, offset: int, length: int) -> bytes:
        raise NotImplementedError



#### Reject generic duplication or serialization of a secret-bearing payload.
####
class _ExclusivePayloadOwner:
    __slots__ = ()



    #### Reject shallow copies that would alias mutable payload ownership.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("field payload cannot be copied or serialized")



    #### Reject deep copies that would duplicate secret-bearing payload state.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("field payload cannot be copied or serialized")



    #### Reject direct state extraction before mutable payload state is inspected.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("field payload cannot be copied or serialized")



    #### Reject fabricated state injection without mutating this owner.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("field payload cannot be copied or serialized")



    #### Reject legacy serialization reduction for secret-bearing payloads.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("field payload cannot be copied or serialized")



    #### Reject protocol-specific reduction before payload state is inspected.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("field payload cannot be copied or serialized")



#### Share one mutable inline buffer across explicitly retained payload leases.
####
#### The final lease release wipes the adopted bytearray under one lock.  Retain
#### operations never copy plaintext and cannot race the final deterministic wipe.
####
class _InlineStorage:
    __slots__ = ("_closing", "_data", "_leases", "_lock")



    #### Adopt one mutable buffer as the first live lease's shared storage.
    ####
    def __init__(self, data: bytearray) -> None:
        self._data = data
        self._leases = 1
        self._closing = False
        self._lock = RLock()



    #### Return the stable byte count without copying the shared buffer.
    ####
    @property
    def length(self) -> int:
        return _mutable_buffer_size(self._data)



    #### Add one lease only while at least one current lease keeps storage live.
    ####
    def retain(self) -> None:
        with self._lock:
            if self._leases == 0 or self._closing:
                raise PayloadClosedError()
            self._leases += 1



    #### Borrow one read-only view while the requesting lease remains live.
    ####
    def borrow(self) -> memoryview[int]:
        with self._lock:
            if self._leases == 0 or self._closing:
                raise PayloadClosedError()
            return memoryview(self._data).toreadonly()



    #### Release one lease and wipe the adopted storage after the final release.
    ####
    def release(self) -> None:
        with self._lock:
            if self._leases <= 0:
                return
            if self._leases > 1:
                self._leases -= 1
                return
            self._closing = True
            _wipe_mutable_buffer(self._data)
            self._leases = 0
            self._closing = False



#### Own one controlled mutable plaintext payload buffer.
####
#### Construction either adopts a caller bytearray or creates one explicit copy.
#### All yielded views borrow this storage and become unusable after close wipes it.
####
class InlinePayload(_ExclusivePayloadOwner):
    __slots__ = ("__weakref__", "_closed", "_closing", "_lock", "_storage")

    _closed: bool
    _storage: _InlineStorage



    #### Adopt storage already transferred through a checked ownership boundary.
    ####
    def __init__(self, data: bytearray) -> None:
        if not isinstance(data, bytearray):
            raise TypeError("inline payload ownership requires a bytearray")
        if hasattr(self, "_storage"):
            if data is not self._storage._data:
                _wipe_mutable_buffer(data)
            raise TypeError("inline payload cannot be reinitialized")
        self._storage = _InlineStorage(data)
        self._lock = RLock()
        self._closed = False
        self._closing = False



    #### Construct one new lease after its shared storage count is retained.
    ####
    @classmethod
    def _from_retained_storage(cls, storage: _InlineStorage) -> Self:
        instance = cls.__new__(cls)
        instance._storage = storage
        instance._lock = RLock()
        instance._closed = False
        instance._closing = False
        return instance



    #### Adopt a caller bytearray that the caller must no longer access.
    ####
    @classmethod
    def take_ownership(cls, data: bytearray) -> Self:
        return cls(data)



    #### Create one mutable owned copy from unavoidable immutable input bytes.
    ####
    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if not isinstance(data, bytes):
            raise TypeError("inline payload input must be bytes")
        return cls(bytearray(data))



    #### Return the exact retained plaintext length without revealing its contents.
    ####
    @property
    def length(self) -> int:
        return self._storage.length



    #### Report whether this owner has already wiped its mutable storage.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Yield read-only borrowed slices in exact payload order.
    ####
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        _validate_chunk_size(chunk_size)
        with self._lock:
            self._require_open()
            view = self._storage.borrow()
        try:
            for offset in range(0, len(view), chunk_size):
                self._require_open()
                yield view[offset:offset + chunk_size]
        finally:
            view.release()



    #### Acquire one new lease over the same bounded mutable plaintext storage.
    ####
    def retain(self) -> InlinePayload:
        with self._lock:
            self._require_open()
            self._storage.retain()
            return type(self)._from_retained_storage(self._storage)



    #### Reject access after deterministic wipe with one safe fixed error.
    ####
    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise PayloadClosedError()



    #### Wipe the exact adopted storage once and make iteration terminal.
    ####
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closing = True
            self._storage.release()
            self._closed = True
            self._closing = False



    #### Enter only an open inline owner without copying its payload.
    ####
    def __enter__(self) -> Self:
        self._require_open()
        return self



    #### Wipe inline plaintext on normal or exceptional context exit.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Defensively wipe forgotten inline plaintext without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



    #### Render only length and lifecycle metadata, never plaintext bytes.
    ####
    def __repr__(self) -> str:
        return f"InlinePayload(length={self.length}, closed={self.closed})"



#### Retain authenticated CBC metadata and borrowed cryptographic dependencies.
####
#### The key and backend stay owned by the authenticated session.  The immutable
#### metadata identifies exactly one complete padded PasswordSafe field frame.
####
@dataclass(frozen=True, slots=True)
class EncryptedSpan:
    backend: TwofishBackend = field(repr=False, compare=False)
    content_key: SecretBuffer = field(repr=False, compare=False)
    previous_block: bytes = field(repr=False)
    ciphertext_offset: int
    ciphertext_length: int
    frame_offset: int
    payload_length: int



    #### Validate frame arithmetic before a snapshot or backend can be touched.
    ####
    def __post_init__(self) -> None:
        _require_nonnegative_integer(self.ciphertext_offset, "ciphertext offset")
        _require_nonnegative_integer(self.ciphertext_length, "ciphertext length")
        _require_nonnegative_integer(self.frame_offset, "frame offset")
        _require_nonnegative_integer(self.payload_length, "payload length")
        if len(self.previous_block) != BLOCK_BYTES:
            raise ValueError("CBC starting state must be exactly one block")
        if self.frame_offset != FIELD_HEADER_BYTES:
            raise ValueError("field payload must begin after the five-byte frame header")
        if self.payload_length > _MAX_FIELD_PAYLOAD_BYTES:
            raise ValueError("declared payload length must fit uint32")
        framed_length = self.frame_offset + self.payload_length
        required_length = ((framed_length + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
        if (
            self.ciphertext_length == 0
            or self.ciphertext_length % BLOCK_BYTES
            or self.ciphertext_length != required_length
        ):
            raise ValueError("ciphertext span does not match the padded field frame")
        if len(self.content_key.borrow()) != HMAC_BYTES:
            raise ValueError("content key must be exactly 32 bytes")



    #### Reject shallow copies that would alias borrowed secret-bearing state.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("encrypted span cannot be copied or serialized")



    #### Reject deep copies that would duplicate borrowed secret-bearing state.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("encrypted span cannot be copied or serialized")



    #### Reject direct state extraction before secret-bearing references are read.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("encrypted span cannot be copied or serialized")



    #### Reject fabricated state injection without mutating authenticated metadata.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("encrypted span cannot be copied or serialized")



    #### Reject legacy serialization reduction for secret-bearing span metadata.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("encrypted span cannot be copied or serialized")



    #### Reject protocol-specific reduction before borrowed owners are inspected.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("encrypted span cannot be copied or serialized")



#### Stream one deferred field from authenticated encrypted snapshot bytes.
####
#### This owner copies and wipes only the CBC starting state.  It borrows the
#### snapshot, backend, and content key and never closes any of those dependencies.
####
class EncryptedSpanPayload(_ExclusivePayloadOwner):
    __slots__ = (
        "__weakref__",
        "_backend",
        "_ciphertext_length",
        "_ciphertext_offset",
        "_closed",
        "_closing",
        "_content_key",
        "_frame_offset",
        "_iterators",
        "_length",
        "_lock",
        "_previous",
        "_snapshot",
    )



    #### Validate the snapshot range and retain only copied or borrowed state.
    ####
    def __init__(self, snapshot: SnapshotReader, span: EncryptedSpan) -> None:
        if hasattr(self, "_snapshot"):
            raise TypeError("encrypted span payload cannot be reinitialized")
        if span.ciphertext_offset > snapshot.size or span.ciphertext_length > snapshot.size - span.ciphertext_offset:
            raise ValueError("encrypted field span is outside captured ciphertext")
        self._snapshot = snapshot
        self._backend = span.backend
        self._content_key = span.content_key
        self._previous = bytearray(span.previous_block)
        self._ciphertext_offset = span.ciphertext_offset
        self._ciphertext_length = span.ciphertext_length
        self._frame_offset = span.frame_offset
        self._length = span.payload_length
        self._lock = RLock()
        self._iterators: set[_EncryptedSpanIterator] = set()
        self._closed = False
        self._closing = False



    #### Return the declared payload length without decrypting any ciphertext.
    ####
    @property
    def length(self) -> int:
        return self._length



    #### Report whether this borrower has wiped its copied chaining state.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Decrypt sequential blocks and yield only declared payload bytes.
    ####
    #### Ciphertext reads are exactly one block, and the mutable output buffer never
    #### exceeds the caller chunk bound.  Resuming or closing the generator wipes
    #### each yielded buffer before more plaintext is produced.
    ####
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        _validate_chunk_size(chunk_size)
        with self._lock:
            self._require_open()
            iterator = _EncryptedSpanIterator(self, chunk_size)
            self._iterators.add(iterator)
            return iterator



    #### Decrypt sequential blocks for one registered managed iterator.
    ####
    def _stream_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        remaining = self._length
        frame_position = 0
        ciphertext_position = self._ciphertext_offset
        output = bytearray()
        try:
            with CbcDecryptor(self._backend, self._content_key, bytes(self._previous)) as decryptor:
                while remaining:
                    self._require_open()
                    ciphertext = self._snapshot.read_at(ciphertext_position, BLOCK_BYTES)
                    plaintext = bytearray(decryptor.transform(ciphertext))
                    try:
                        start = self._frame_offset if frame_position == 0 else 0
                        available = min(BLOCK_BYTES - start, remaining)
                        source_position = start
                        while available:
                            needed = chunk_size - len(output)
                            copied = min(needed, available)
                            output.extend(plaintext[source_position:source_position + copied])
                            source_position += copied
                            available -= copied
                            remaining -= copied
                            if len(output) == chunk_size:
                                yield from _yield_and_wipe(output)
                                self._require_open()
                                output = bytearray()
                    finally:
                        plaintext[:] = bytes(len(plaintext))
                    frame_position += BLOCK_BYTES
                    ciphertext_position += BLOCK_BYTES
            if output:
                yield from _yield_and_wipe(output)
                self._require_open()
                output = bytearray()
        finally:
            output[:] = bytes(len(output))



    #### Remove one exhausted or explicitly closed iterator from active ownership.
    ####
    def _release_iterator(self, iterator: _EncryptedSpanIterator) -> None:
        with self._lock:
            self._iterators.discard(iterator)



    #### Fork only copied CBC metadata while retaining borrowed upstream owners.
    ####
    def retain(self) -> EncryptedSpanPayload:
        with self._lock:
            self._require_open()
            span = EncryptedSpan(
                backend=self._backend,
                content_key=self._content_key,
                previous_block=bytes(self._previous),
                ciphertext_offset=self._ciphertext_offset,
                ciphertext_length=self._ciphertext_length,
                frame_offset=self._frame_offset,
                payload_length=self._length,
            )
            return type(self)(self._snapshot, span)



    #### Reject use after close without inspecting borrowed dependencies.
    ####
    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise PayloadClosedError()



    #### Wipe copied CBC state once without closing borrowed resources.
    ####
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closing = True
            self._previous[:] = bytes(len(self._previous))
            iterators = tuple(self._iterators)
        first_failure: BaseException | None = None
        for iterator in iterators:
            try:
                iterator._close_from_owner()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
        with self._lock:
            if not self._iterators:
                self._closed = True
                self._closing = False
        if first_failure is not None:
            raise first_failure



    #### Enter only a live deferred payload without opening cryptographic state yet.
    ####
    def __enter__(self) -> Self:
        self._require_open()
        return self



    #### Wipe copied metadata after normal or exceptional context exit.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Defensively wipe forgotten copied state without touching borrowed owners.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()
        with suppress(BaseException), self._lock:
            self._previous[:] = bytes(len(self._previous))
            self._closed = True
            self._closing = False
            self._iterators.clear()



    #### Render only safe length and lifecycle metadata.
    ####
    def __repr__(self) -> str:
        return f"EncryptedSpanPayload(length={self.length}, closed={self.closed})"



#### Coordinate one deferred generator with its owning payload's close operation.
####
#### Closing the payload closes every registered generator, which immediately wipes
#### its suspended mutable output and releases its keyed CBC context.
####
class _EncryptedSpanIterator:
    __slots__ = ("_closed", "_iterator", "_lock", "_owner")



    #### Register one not-yet-started bounded stream under an independent lock.
    ####
    def __init__(self, owner: EncryptedSpanPayload, chunk_size: int) -> None:
        self._owner = owner
        self._iterator = owner._stream_chunks(chunk_size)
        self._lock = RLock()
        self._closed = False



    #### Return this stateful iterator without creating a second stream.
    ####
    def __iter__(self) -> Self:
        return self



    #### Advance only while the owning payload remains open.
    ####
    def __next__(self) -> memoryview[int]:
        with self._lock:
            self._owner._require_open()
            if self._closed:
                raise StopIteration
            try:
                return next(self._iterator)
            except BaseException:
                self._finish()
                raise



    #### Close an abandoned consumer stream and wipe suspended plaintext now.
    ####
    def close(self) -> None:
        self._close_from_owner()



    #### Close this generator immediately because its owning payload is terminal.
    ####
    def _close_from_owner(self) -> None:
        with self._lock:
            if not self._closed:
                close = getattr(self._iterator, "close", None)
                if callable(close):
                    close()
                self._finish()



    #### Mark completion and release the owner's strong registration once.
    ####
    def _finish(self) -> None:
        if not self._closed:
            self._closed = True
            self._owner._release_iterator(self)



    #### Defensively close an abandoned iterator and wipe suspended plaintext.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self._close_from_owner()



#### Yield one read-only mutable buffer and wipe it when iteration resumes.
####
def _yield_and_wipe(buffer: bytearray) -> Iterator[memoryview[int]]:
    view = memoryview(buffer).toreadonly()
    try:
        yield view
    finally:
        view.release()
        buffer[:] = bytes(len(buffer))



#### Validate a caller chunk bound before accessing plaintext or ciphertext.
####
def _validate_chunk_size(chunk_size: int) -> None:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk size must be an integer")
    if not 0 < chunk_size <= MAX_IO_CHUNK_BYTES:
        raise ValueError("chunk size must be within the approved I/O bound")



#### Validate untrusted integer metadata before arithmetic or resource access.
####
def _require_nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} cannot be negative")
