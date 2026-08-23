"""Own mutable secret buffers and short-lived leases for PasswordSafe operations.

These classes deterministically wipe owned bytearrays when closed.  CPython cannot
guarantee physical zeroization of immutable temporary values or allocator copies.
"""

from types import TracebackType
from typing import Final, Self



MAX_SECRET_LEASE_BYTES: Final[int] = 1_048_576
_LEASE_CONSTRUCTION_TOKEN: Final[object] = object()



#### Validate a lease bound before reading or copying a source secret.
####
#### A caller can request a shorter lease but cannot turn this explicit access API
#### into an unbounded materialization path by supplying an oversized maximum.
####
def _validate_lease_bound(max_bytes: int) -> None:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 0 < max_bytes <= MAX_SECRET_LEASE_BYTES:
        raise ValueError("secret lease byte limit must be a positive approved integer")



#### Report attempted access after an owned secret's deterministic close.
####
#### This message intentionally contains no buffer length, field name, or prior
#### contents, so it remains safe in ordinary exception handling and repr output.
####
class SecretClosedError(RuntimeError):



    #### Initialize the fixed safe closed-secret diagnostic.
    ####
    def __init__(self) -> None:
        super().__init__("secret buffer is closed")



#### Own one mutable secret buffer and wipe it when its lifetime ends.
####
#### Ownership either adopts a caller bytearray or creates one controlled copy from
#### bytes.  Borrowers receive read-only views but must not retain them past close.
####
class SecretBuffer:
    __slots__ = ("_closed", "_data")



    #### Initialize a buffer whose mutable storage has already been transferred.
    ####
    #### Public constructors validate ownership boundaries.  This initializer stays
    #### narrow so closing always wipes the exact bytearray retained by the owner.
    ####
    def __init__(self, data: bytearray) -> None:
        self._data = data
        self._closed = False



    #### Adopt a caller bytearray without copying its mutable secret storage.
    ####
    #### The caller must stop using the bytearray after this transfer because close
    #### wipes it in place and later components rely on that ownership invariant.
    ####
    @classmethod
    def take_ownership(cls, data: bytearray) -> Self:
        if not isinstance(data, bytearray):
            raise TypeError("secret ownership requires a bytearray")
        return cls(data)



    #### Create one owned mutable copy from immutable secret bytes.
    ####
    #### This is the explicit boundary for API inputs that cannot be wiped by the
    #### caller.  Later operations should pass the resulting owner, not recreate it.
    ####
    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(bytearray(data))



    #### Borrow a read-only view while this owner remains open.
    ####
    #### The returned view shares storage with the owner; callers must consume it
    #### promptly and must not assume its bytes remain after the owner closes.
    ####
    def borrow(self) -> memoryview[int]:
        if self._closed:
            raise SecretClosedError()
        return memoryview(self._data).toreadonly()



    #### Report whether the owned mutable storage has already been wiped.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Wipe owned storage exactly once and mark it unavailable to future borrowers.
    ####
    #### Assigning a zero-filled byte sequence preserves the adopted bytearray
    #### identity, which lets callers verify the transfer and deterministic wipe.
    ####
    def close(self) -> None:
        if not self._closed:
            self._data[:] = b"\x00" * len(self._data)
            self._closed = True



    #### Enter this owner without transferring or copying its secret storage.
    ####
    def __enter__(self) -> Self:
        if self._closed:
            raise SecretClosedError()
        return self



    #### Wipe this owner when its context exits on success or failure.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Return only lifecycle metadata and never render secret bytes.
    ####
    def __repr__(self) -> str:
        return f"SecretBuffer(closed={self._closed})"



#### Provide a separately owned, short-lived secret view for explicit reveal APIs.
####
#### Leases copy only bounded material from another owner and expose the same
#### read-only borrowing and deterministic context lifetime without value equality.
####
class SecretLease:
    __slots__ = ("_secret",)



    #### Initialize a lease from a factory-created distinct mutable secret copy.
    ####
    #### The unforgeable module token keeps direct construction outside the public
    #### API, preventing callers from adopting shared or unbounded secret storage.
    ####
    def __init__(self, data: bytearray, *, _token: object) -> None:
        if _token is not _LEASE_CONSTRUCTION_TOKEN:
            raise TypeError("secret leases must be created through bounded factories")
        self._secret = SecretBuffer.take_ownership(data)



    #### Create a bounded lease with one controlled mutable copy from bytes.
    ####
    #### The explicit maximum prevents convenience reveal APIs from materializing a
    #### caller-selected amount of secret data outside the document resource policy.
    ####
    @classmethod
    def from_bytes(cls, data: bytes, *, max_bytes: int = 1_048_576) -> Self:
        _validate_lease_bound(max_bytes)
        if len(data) > max_bytes:
            raise ValueError("secret lease exceeds its byte limit")
        return cls(bytearray(data), _token=_LEASE_CONSTRUCTION_TOKEN)



    #### Copy bounded content from another open owner into this lease's storage.
    ####
    #### The source remains open and unchanged so callers can lease a reveal value
    #### without transferring session-owned key or field material to the caller.
    ####
    @classmethod
    def copy_of(cls, source: SecretBuffer, *, max_bytes: int = 1_048_576) -> Self:
        _validate_lease_bound(max_bytes)
        data = source.borrow()
        if len(data) > max_bytes:
            raise ValueError("secret lease exceeds its byte limit")
        return cls(bytearray(data), _token=_LEASE_CONSTRUCTION_TOKEN)



    #### Borrow the lease's read-only view while its short-lived access is active.
    ####
    def borrow(self) -> memoryview[int]:
        return self._secret.borrow()



    #### Report whether this lease's separate owned secret has been wiped.
    ####
    @property
    def closed(self) -> bool:
        return self._secret.closed



    #### Wipe the lease's separate storage without affecting its source owner.
    ####
    def close(self) -> None:
        self._secret.close()



    #### Enter this lease while retaining its explicit bounded lifetime.
    ####
    def __enter__(self) -> Self:
        if self.closed:
            raise SecretClosedError()
        return self



    #### Wipe the lease when its context exits on success or failure.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Return only lease lifecycle metadata and never render secret bytes.
    ####
    def __repr__(self) -> str:
        return f"SecretLease(closed={self.closed})"
