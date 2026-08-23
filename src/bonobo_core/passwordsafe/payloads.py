"""Own bounded plaintext payloads and stream authenticated encrypted field spans.

Inline payloads adopt mutable buffers and wipe them.  Deferred payloads borrow an
immutable encrypted snapshot and authenticated content key, retain only copied CBC
metadata, and materialize no plaintext larger than a caller-approved chunk.
"""

from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from types import TracebackType
from typing import NoReturn, Protocol, Self, SupportsIndex, runtime_checkable

from .constants import BLOCK_BYTES, FIELD_HEADER_BYTES, HMAC_BYTES, MAX_IO_CHUNK_BYTES
from .crypto import CbcDecryptor, TwofishBackend
from .secrets import SecretBuffer



_MAX_FIELD_PAYLOAD_BYTES = 0xFFFF_FFFF



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



#### Own one controlled mutable plaintext payload buffer.
####
#### Construction either adopts a caller bytearray or creates one explicit copy.
#### All yielded views borrow this storage and become unusable after close wipes it.
####
class InlinePayload(_ExclusivePayloadOwner):
    __slots__ = ("_closed", "_data")

    _closed: bool
    _data: bytearray



    #### Adopt storage already transferred through a checked ownership boundary.
    ####
    def __init__(self, data: bytearray) -> None:
        if not isinstance(data, bytearray):
            raise TypeError("inline payload ownership requires a bytearray")
        if hasattr(self, "_data"):
            if data is not self._data:
                data[:] = bytes(len(data))
            raise TypeError("inline payload cannot be reinitialized")
        self._data = data
        self._closed = False



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
        return len(self._data)



    #### Report whether this owner has already wiped its mutable storage.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Yield read-only borrowed slices in exact payload order.
    ####
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview[int]]:
        _validate_chunk_size(chunk_size)
        self._require_open()
        view = memoryview(self._data).toreadonly()
        try:
            for offset in range(0, len(view), chunk_size):
                self._require_open()
                yield view[offset:offset + chunk_size]
        finally:
            view.release()



    #### Reject access after deterministic wipe with one safe fixed error.
    ####
    def _require_open(self) -> None:
        if self._closed:
            raise PayloadClosedError()



    #### Wipe the exact adopted storage once and make iteration terminal.
    ####
    def close(self) -> None:
        if not self._closed:
            self._data[:] = bytes(len(self._data))
            self._closed = True



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
        "_backend",
        "_ciphertext_length",
        "_ciphertext_offset",
        "_closed",
        "_content_key",
        "_frame_offset",
        "_length",
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
        self._closed = False



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
        self._require_open()
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
                                output = bytearray()
                    finally:
                        plaintext[:] = bytes(len(plaintext))
                    frame_position += BLOCK_BYTES
                    ciphertext_position += BLOCK_BYTES
            if output:
                yield from _yield_and_wipe(output)
                output = bytearray()
        finally:
            output[:] = bytes(len(output))



    #### Reject use after close without inspecting borrowed dependencies.
    ####
    def _require_open(self) -> None:
        if self._closed:
            raise PayloadClosedError()



    #### Wipe copied CBC state once without closing borrowed resources.
    ####
    def close(self) -> None:
        if not self._closed:
            self._previous[:] = bytes(len(self._previous))
            self._closed = True



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



    #### Render only safe length and lifecycle metadata.
    ####
    def __repr__(self) -> str:
        return f"EncryptedSpanPayload(length={self.length}, closed={self.closed})"



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
