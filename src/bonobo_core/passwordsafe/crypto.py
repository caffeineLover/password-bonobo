"""Implement PasswordSafe cryptographic construction over fixed Twofish blocks.

The module owns mutable derived and vault keys, PasswordSafe stretching and key
wrapping, continuous CBC state, field-payload HMAC, and system randomness.  A
separate backend remains responsible for the native Twofish implementation.
CPython and OpenSSL expose no supported way to overwrite internal HMAC state;
terminal authentication releases that state promptly but cannot promise physical
zeroization of implementation-owned copies.
"""

import hashlib
import hmac
import secrets
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from types import TracebackType
from typing import NoReturn, Protocol, Self, SupportsIndex, runtime_checkable

from .constants import BLOCK_BYTES, HMAC_BYTES, SALT_BYTES, WRAPPED_KEY_BYTES, ResourceLimits
from .errors import ResourceLimitError, ResourceLimitReason
from .secrets import SecretBuffer, SecretClosedError



_DEFAULT_RESOURCE_LIMITS = ResourceLimits()



#### Describe one initialized Twofish key with an explicit native-resource lifetime.
####
#### Implementations transform exactly one block per call and must release owned
#### key state deterministically when close is invoked.
####
@runtime_checkable
class TwofishKey(Protocol):



    #### Encrypt exactly one 16-byte Twofish block.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError



    #### Decrypt exactly one 16-byte Twofish block.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError



    #### Release implementation-owned key state exactly once.
    ####
    def close(self) -> None:
        raise NotImplementedError



#### Describe the trusted fixed-algorithm backend used by PasswordSafe codecs.
####
#### Backends gate use through a known-answer self-test and scope each keyed native
#### handle to a context manager supplied with caller-owned mutable key material.
####
@runtime_checkable
class TwofishBackend(Protocol):



    #### Create one initialized key and close it at context exit.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        raise NotImplementedError



    #### Verify the backend against the fixed official Twofish known answer.
    ####
    def self_test(self) -> None:
        raise NotImplementedError



#### Prevent secret-bearing owners from being duplicated or reconstructed.
####
#### Exclusive mutable ownership cannot survive generic copying or object
#### serialization, so every supported protocol fails with one safe diagnostic.
####
class _ExclusiveCryptoOwner:
    __slots__ = ()



    #### Reject shallow copies that would alias exclusive secret-bearing state.
    ####
    def __copy__(self) -> NoReturn:
        raise TypeError("cryptographic owner cannot be copied or serialized")



    #### Reject deep copies that would duplicate exclusive secret-bearing state.
    ####
    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("cryptographic owner cannot be copied or serialized")



    #### Reject direct slot-state extraction before owner state is inspected.
    ####
    def __getstate__(self) -> NoReturn:
        raise TypeError("cryptographic owner cannot be copied or serialized")



    #### Reject direct fabricated-state injection without mutating this owner.
    ####
    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("cryptographic owner cannot be copied or serialized")



    #### Reject legacy reduction used by generic serialization protocols.
    ####
    def __reduce__(self) -> NoReturn:
        raise TypeError("cryptographic owner cannot be copied or serialized")



    #### Reject protocol-specific reduction before any owner state is inspected.
    ####
    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("cryptographic owner cannot be copied or serialized")



#### Own the mutable 256-bit passphrase-derived key used for envelope checks.
####
#### Construction adopts caller storage only when its exact PasswordSafe size is
#### valid.  A rejected transfer is wiped before the constructor raises.
####
class DerivedKey(_ExclusiveCryptoOwner, SecretBuffer):
    __slots__ = ()



    #### Adopt one exact derived-key buffer or wipe invalid transferred storage.
    ####
    def __init__(self, data: bytearray) -> None:
        if not isinstance(data, bytearray):
            raise TypeError("derived key ownership requires a bytearray")
        if hasattr(self, "_data"):
            if data is not self._data:
                data[:] = bytes(len(data))
            raise TypeError("derived key cannot be reinitialized")
        if len(data) != HMAC_BYTES:
            data[:] = bytes(len(data))
            raise ValueError("derived key must be exactly 32 bytes")
        super().__init__(data)



    #### Return only lifecycle metadata and never render derived-key bytes.
    ####
    def __repr__(self) -> str:
        return f"DerivedKey(closed={self.closed})"



#### Wipe a mutable transfer candidate while safely ignoring other runtime types.
####
def _wipe_transferred_bytearray(candidate: object) -> None:
    if isinstance(candidate, bytearray):
        candidate[:] = bytes(len(candidate))



#### Wipe distinct fresh transfer candidates while preserving adopted storage.
####
def _wipe_distinct_transferred_bytearrays(
    first: object,
    second: object,
    *,
    preserved: tuple[bytearray, ...] = (),
) -> None:
    if not any(first is owned for owned in preserved):
        _wipe_transferred_bytearray(first)
    if second is not first and not any(second is owned for owned in preserved):
        _wipe_transferred_bytearray(second)



#### Own independent content and HMAC keys under one session lifetime.
####
#### Both 256-bit mutable buffers transfer together.  Failed or partial
#### construction wipes every transferred bytearray so no orphan key remains.
####
class VaultKeys(_ExclusiveCryptoOwner):
    __slots__ = ("_content_key", "_hmac_key")

    _content_key: SecretBuffer
    _hmac_key: SecretBuffer



    #### Adopt two exact independent keys and establish their joint lifetime.
    ####
    def __init__(self, content_key: bytearray, hmac_key: bytearray) -> None:
        content_candidate: object = content_key
        hmac_candidate: object = hmac_key
        if hasattr(self, "_content_key") or hasattr(self, "_hmac_key"):
            preserved = tuple(
                owner._data
                for owner in (
                    getattr(self, "_content_key", None),
                    getattr(self, "_hmac_key", None),
                )
                if isinstance(owner, SecretBuffer)
            )
            _wipe_distinct_transferred_bytearrays(
                content_candidate,
                hmac_candidate,
                preserved=preserved,
            )
            raise TypeError("vault keys cannot be reinitialized")
        if content_candidate is hmac_candidate:
            _wipe_transferred_bytearray(content_candidate)
            raise TypeError("vault keys require distinct storage")
        if not isinstance(content_candidate, bytearray):
            _wipe_transferred_bytearray(hmac_candidate)
            raise TypeError("vault key ownership requires bytearrays")
        if not isinstance(hmac_candidate, bytearray):
            content_candidate[:] = bytes(len(content_candidate))
            raise TypeError("vault key ownership requires bytearrays")
        if len(content_candidate) != HMAC_BYTES or len(hmac_candidate) != HMAC_BYTES:
            content_candidate[:] = bytes(len(content_candidate))
            hmac_candidate[:] = bytes(len(hmac_candidate))
            raise ValueError("vault keys must be exactly 32 bytes")
        self._content_key = SecretBuffer.take_ownership(content_candidate)
        try:
            self._hmac_key = SecretBuffer.take_ownership(hmac_candidate)
        except BaseException:
            self._content_key.close()
            hmac_candidate[:] = bytes(len(hmac_candidate))
            raise



    #### Expose the content-key owner without permitting replacement of ownership.
    ####
    @property
    def content_key(self) -> SecretBuffer:
        return self._content_key



    #### Expose the HMAC-key owner without permitting replacement of ownership.
    ####
    @property
    def hmac_key(self) -> SecretBuffer:
        return self._hmac_key



    #### Report whether both independently owned keys have been wiped.
    ####
    @property
    def closed(self) -> bool:
        return self.content_key.closed and self.hmac_key.closed



    #### Wipe both keys exactly once while preserving their separate storage.
    ####
    def close(self) -> None:
        self.content_key.close()
        self.hmac_key.close()



    #### Enter the joint key owner only while both retained keys remain open.
    ####
    def __enter__(self) -> Self:
        self.content_key.borrow()
        self.hmac_key.borrow()
        return self



    #### Wipe both vault keys on successful or exceptional context exit.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Return only the joint lifecycle state and never include either key.
    ####
    def __repr__(self) -> str:
        return f"VaultKeys(closed={self.closed})"



#### Derive one PasswordSafe wrapping key within the caller's resource budget.
####
#### Iteration validity is decided before passphrase access or hashing.  The raw
#### passphrase remains caller-owned, while all mutable intermediate state is wiped
#### on success, validation failure after creation, and hash exceptions.
####
def stretch_passphrase(
    passphrase: SecretBuffer,
    salt: bytes,
    iterations: int,
    *,
    limits: ResourceLimits = _DEFAULT_RESOURCE_LIMITS,
) -> DerivedKey:
    if isinstance(iterations, bool) or not isinstance(iterations, int) or not 1 <= iterations <= limits.max_iterations:
        raise ResourceLimitError(ResourceLimitReason.MAX_ITERATIONS)
    if len(salt) != SALT_BYTES:
        raise ValueError("salt must be exactly 32 bytes")

    digest = hashlib.sha256(passphrase.borrow())
    digest.update(salt)
    stretched = bytearray(digest.digest())
    replacement: bytearray | None = None
    transferred = False
    try:
        replacement = bytearray(HMAC_BYTES)
        for _iteration in range(iterations):
            replacement[:] = hashlib.sha256(stretched).digest()
            stretched[:] = replacement
            replacement[:] = bytes(HMAC_BYTES)
        derived = DerivedKey(stretched)
        transferred = True
        return derived
    finally:
        if replacement is not None:
            replacement[:] = bytes(len(replacement))
        if not transferred:
            stretched[:] = bytes(len(stretched))



#### Encrypt K then L as exactly four ordered PasswordSafe ECB blocks.
####
#### The caller retains every key owner.  Mutable block and aggregate output
#### buffers are wiped on all paths after the intended immutable result is copied.
####
def wrap_vault_keys(backend: TwofishBackend, derived_key: DerivedKey, vault_keys: VaultKeys) -> bytes:
    wrapped = bytearray(WRAPPED_KEY_BYTES)
    try:
        with backend.key(derived_key) as cipher:
            output_offset = 0
            for key_owner in (vault_keys.content_key, vault_keys.hmac_key):
                source = key_owner.borrow()
                for source_offset in range(0, HMAC_BYTES, BLOCK_BYTES):
                    block = bytearray(source[source_offset:source_offset + BLOCK_BYTES])
                    try:
                        encrypted = cipher.encrypt_block(bytes(block))
                        if len(encrypted) != BLOCK_BYTES:
                            raise ValueError("backend returned an invalid block")
                        wrapped[output_offset:output_offset + BLOCK_BYTES] = encrypted
                        output_offset += BLOCK_BYTES
                    finally:
                        block[:] = bytes(len(block))
        return bytes(wrapped)
    finally:
        wrapped[:] = bytes(len(wrapped))



#### Decrypt exactly four wrapped blocks into independent K and L owners.
####
#### Malformed input is rejected before backend use.  Any backend or construction
#### failure wipes both partial mutable keys before it can escape.
####
def unwrap_vault_keys(backend: TwofishBackend, derived_key: DerivedKey, wrapped_keys: bytes) -> VaultKeys:
    if len(wrapped_keys) != WRAPPED_KEY_BYTES:
        raise ValueError("wrapped keys must be exactly 64 bytes")

    content_key = bytearray(HMAC_BYTES)
    hmac_key = bytearray(HMAC_BYTES)
    transferred = False
    try:
        with backend.key(derived_key) as cipher:
            for block_index in range(4):
                block_offset = block_index * BLOCK_BYTES
                decrypted = bytearray()
                try:
                    decrypted[:] = cipher.decrypt_block(wrapped_keys[block_offset:block_offset + BLOCK_BYTES])
                    if len(decrypted) != BLOCK_BYTES:
                        raise ValueError("backend returned an invalid block")
                    destination = content_key if block_index < 2 else hmac_key
                    destination_offset = (block_index % 2) * BLOCK_BYTES
                    destination[destination_offset:destination_offset + BLOCK_BYTES] = decrypted
                finally:
                    decrypted[:] = bytes(len(decrypted))
        keys = VaultKeys(content_key, hmac_key)
        transferred = True
        return keys
    finally:
        if not transferred:
            content_key[:] = bytes(len(content_key))
            hmac_key[:] = bytes(len(hmac_key))



#### Encrypt one continuous PasswordSafe CBC stream under a borrowed content key.
####
#### The object owns only the keyed backend context and mutable chaining block.
#### Invalid blocks leave state unchanged; backend faults close and wipe the owner.
####
class CbcEncryptor(_ExclusiveCryptoOwner):
    __slots__ = ("_closed", "_context", "_key", "_previous")



    #### Validate key and IV sizes before opening the keyed backend context.
    ####
    def __init__(self, backend: TwofishBackend, content_key: SecretBuffer, iv: bytes) -> None:
        if hasattr(self, "_context"):
            raise TypeError("CBC transformer cannot be reinitialized")
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be exactly 16 bytes")
        if len(content_key.borrow()) != HMAC_BYTES:
            raise ValueError("content key must be exactly 32 bytes")

        self._closed = True
        self._key: TwofishKey | None = None
        self._previous = bytearray(iv)
        try:
            self._context: AbstractContextManager[TwofishKey] = backend.key(content_key)
            self._key = self._context.__enter__()
            self._closed = False
        except BaseException:
            self._previous[:] = bytes(len(self._previous))
            raise



    #### Report whether backend and chaining state have reached terminal cleanup.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### XOR one plaintext block with the chain and encrypt it exactly once.
    ####
    def transform(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("CBC transformer is closed")
        if len(block) != BLOCK_BYTES:
            raise ValueError("CBC requires exactly one 16-byte block")

        mixed = bytearray(BLOCK_BYTES)
        try:
            for index in range(BLOCK_BYTES):
                mixed[index] = block[index] ^ self._previous[index]
            if self._key is None:
                raise RuntimeError("CBC transformer is closed")
            encrypted = self._key.encrypt_block(bytes(mixed))
            if len(encrypted) != BLOCK_BYTES:
                raise ValueError("backend returned an invalid block")
            self._previous[:] = encrypted
            return encrypted
        except BaseException:
            with suppress(BaseException):
                self.close()
            raise
        finally:
            mixed[:] = bytes(len(mixed))



    #### Close the keyed context once and wipe the last ciphertext chain block.
    ####
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._key = None
        self._previous[:] = bytes(len(self._previous))
        self._context.__exit__(None, None, None)



    #### Enter this live streaming owner without resetting its CBC chain.
    ####
    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("CBC transformer is closed")
        return self



    #### Close normally or preserve an active caller exception during cleanup.
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



    #### Defensively release forgotten keyed state without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



#### Decrypt one continuous PasswordSafe CBC stream under a borrowed content key.
####
#### Each ciphertext block is saved before decryption so it becomes the next chain
#### value.  The owner has the same terminal cleanup behavior as the encryptor.
####
class CbcDecryptor(_ExclusiveCryptoOwner):
    __slots__ = ("_closed", "_context", "_key", "_previous")



    #### Validate key and IV sizes before opening the keyed backend context.
    ####
    def __init__(self, backend: TwofishBackend, content_key: SecretBuffer, iv: bytes) -> None:
        if hasattr(self, "_context"):
            raise TypeError("CBC transformer cannot be reinitialized")
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be exactly 16 bytes")
        if len(content_key.borrow()) != HMAC_BYTES:
            raise ValueError("content key must be exactly 32 bytes")

        self._closed = True
        self._key: TwofishKey | None = None
        self._previous = bytearray(iv)
        try:
            self._context: AbstractContextManager[TwofishKey] = backend.key(content_key)
            self._key = self._context.__enter__()
            self._closed = False
        except BaseException:
            self._previous[:] = bytes(len(self._previous))
            raise



    #### Report whether backend and chaining state have reached terminal cleanup.
    ####
    @property
    def closed(self) -> bool:
        return self._closed



    #### Decrypt one ciphertext block before advancing to its saved chain value.
    ####
    def transform(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("CBC transformer is closed")
        if len(block) != BLOCK_BYTES:
            raise ValueError("CBC requires exactly one 16-byte block")

        current = bytearray(block)
        plaintext = bytearray()
        try:
            if self._key is None:
                raise RuntimeError("CBC transformer is closed")
            plaintext[:] = self._key.decrypt_block(bytes(current))
            if len(plaintext) != BLOCK_BYTES:
                raise ValueError("backend returned an invalid block")
            for index in range(BLOCK_BYTES):
                plaintext[index] ^= self._previous[index]
            self._previous[:] = current
            return bytes(plaintext)
        except BaseException:
            with suppress(BaseException):
                self.close()
            raise
        finally:
            current[:] = bytes(len(current))
            plaintext[:] = bytes(len(plaintext))



    #### Close the keyed context once and wipe the last ciphertext chain block.
    ####
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._key = None
        self._previous[:] = bytes(len(self._previous))
        self._context.__exit__(None, None, None)



    #### Enter this live streaming owner without resetting its CBC chain.
    ####
    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("CBC transformer is closed")
        return self



    #### Close normally or preserve an active caller exception during cleanup.
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



    #### Defensively release forgotten keyed state without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



#### Calculate PasswordSafe HMAC-SHA-256 over ordered declared field payloads.
####
#### Callers pass only payload bytes after parsing the length and type framing.
#### Digest is terminal and releases Python's unavoidable internal key-schedule
#### reference.  CPython and OpenSSL do not expose physical zeroization for it.
####
class FieldAuthenticator(_ExclusiveCryptoOwner):
    __slots__ = ("_hmac",)

    _hmac: hmac.HMAC | None



    #### Initialize ordered authentication from one borrowed exact 256-bit key.
    ####
    def __init__(self, hmac_key: SecretBuffer) -> None:
        if hasattr(self, "_hmac"):
            raise TypeError("field authenticator cannot be reinitialized")
        borrowed_key = hmac_key.borrow()
        if len(borrowed_key) != HMAC_BYTES:
            raise ValueError("HMAC key must be exactly 32 bytes")
        key_owner = borrowed_key.obj
        if not isinstance(key_owner, bytearray):
            raise TypeError("HMAC key must use mutable owned storage")
        self._hmac = hmac.new(key_owner, digestmod=hashlib.sha256)



    #### Report whether terminal digest or explicit cleanup released HMAC state.
    ####
    @property
    def closed(self) -> bool:
        return getattr(self, "_hmac", None) is None



    #### Return live HMAC state or raise the fixed closed-secret lifecycle error.
    ####
    def _require_hmac(self) -> hmac.HMAC:
        try:
            state = self._hmac
        except AttributeError:
            raise SecretClosedError() from None
        if state is None:
            raise SecretClosedError()
        return state



    #### Append one declared field-payload chunk in document traversal order.
    ####
    def update(self, payload: bytes) -> None:
        self._require_hmac().update(payload)



    #### Return the final authenticator and release internal HMAC state on all exits.
    ####
    def digest(self) -> bytes:
        state = self._require_hmac()
        try:
            return state.digest()
        finally:
            self.close()



    #### Release the internal HMAC reference once and make the owner terminal.
    ####
    def close(self) -> None:
        self._hmac = None



    #### Enter only a live one-pass authenticator without resetting its state.
    ####
    def __enter__(self) -> Self:
        self._require_hmac()
        return self



    #### Release internal HMAC state after successful or exceptional traversal.
    ####
    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()



    #### Defensively release forgotten HMAC state without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()



#### Obtain cryptographic bytes only from the operating-system random provider.
####
class SystemRandomSource:



    #### Return the requested byte count after rejecting unsafe length types.
    ####
    def bytes(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int):
            raise TypeError("length must be an integer")
        if length < 0:
            raise ValueError("length cannot be negative")
        return secrets.token_bytes(length)
