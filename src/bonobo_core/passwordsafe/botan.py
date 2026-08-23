"""Bind the narrow Botan FFI surface required for PasswordSafe Twofish blocks.

The adapter accepts no algorithm name from callers.  Opening verifies the pinned
FFI contract, requires Botan 3.13 or newer in major version 3, and runs an
independent known-answer gate before returning a usable backend.
"""

import ctypes
import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Final, Protocol, Self, cast

from .crypto import TwofishKey
from .errors import CryptoBackendError, CryptoBackendReason
from .secrets import SecretBuffer



BOTAN_FFI_API_VERSION: Final[int] = 20_260_811
_BOTAN_MAJOR_VERSION: Final[int] = 3
_BOTAN_MINIMUM_MINOR_VERSION: Final[int] = 13
_BACKEND_CONSTRUCTION_TOKEN: Final[object] = object()
_TWOFISH_NAME: Final[bytes] = b"Twofish"
_TWOFISH_BLOCK_BYTES: Final[int] = 16
_TWOFISH_ZERO_KEY: Final[bytes] = bytes(16)
_TWOFISH_ZERO_BLOCK: Final[bytes] = bytes(16)
_TWOFISH_ZERO_CIPHERTEXT: Final[bytes] = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")



#### Describe the mutable ctypes metadata and integer result shared by bound calls.
####
#### The dynamic native boundary cannot express each C signature statically, so
#### binding validates every symbol and assigns exact argument and result types.
####
class _BotanFunction(Protocol):
    argtypes: list[object] | None
    restype: object | None



    #### Invoke one already-bound Botan function through its checked ABI metadata.
    ####
    def __call__(self, *arguments: object) -> int:
        raise NotImplementedError



#### Describe exactly the Botan symbols retained after ABI binding.
####
class _BotanLibrary(Protocol):
    botan_ffi_supports_api: _BotanFunction
    botan_version_major: _BotanFunction
    botan_version_minor: _BotanFunction
    botan_version_patch: _BotanFunction
    botan_block_cipher_init: _BotanFunction
    botan_block_cipher_destroy: _BotanFunction
    botan_block_cipher_set_key: _BotanFunction
    botan_block_cipher_encrypt_blocks: _BotanFunction
    botan_block_cipher_decrypt_blocks: _BotanFunction



#### Load a caller-selected Botan binary while discarding unsafe loader details.
####
#### A failure returns no platform exception object, so a later typed error cannot
#### retain a path-bearing exception context through Python exception chaining.
####
def _load_library(library_path: Path) -> ctypes.CDLL | None:
    try:
        return ctypes.CDLL(os.fspath(library_path))
    except Exception:
        return None



#### Assign exact ctypes signatures to every retained Botan entry point.
####
def _bind_library(loaded_library: ctypes.CDLL) -> _BotanLibrary | None:
    try:
        library = cast(_BotanLibrary, loaded_library)
        byte_pointer = ctypes.POINTER(ctypes.c_uint8)
        library.botan_ffi_supports_api.argtypes = [ctypes.c_uint32]
        library.botan_ffi_supports_api.restype = ctypes.c_int
        for version_function in (
            library.botan_version_major,
            library.botan_version_minor,
            library.botan_version_patch,
        ):
            version_function.argtypes = []
            version_function.restype = ctypes.c_uint32
        library.botan_block_cipher_init.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p]
        library.botan_block_cipher_init.restype = ctypes.c_int
        library.botan_block_cipher_destroy.argtypes = [ctypes.c_void_p]
        library.botan_block_cipher_destroy.restype = ctypes.c_int
        library.botan_block_cipher_set_key.argtypes = [ctypes.c_void_p, byte_pointer, ctypes.c_size_t]
        library.botan_block_cipher_set_key.restype = ctypes.c_int
        block_arguments = [ctypes.c_void_p, byte_pointer, byte_pointer, ctypes.c_size_t]
        library.botan_block_cipher_encrypt_blocks.argtypes = block_arguments
        library.botan_block_cipher_encrypt_blocks.restype = ctypes.c_int
        library.botan_block_cipher_decrypt_blocks.argtypes = block_arguments
        library.botan_block_cipher_decrypt_blocks.restype = ctypes.c_int
        return library
    except Exception:
        return None



#### Invoke an FFI function without retaining arbitrary boundary diagnostics.
####
#### Real Botan calls return integers.  Dynamic-call failures become a missing
#### status so callers can map them into the same closed backend taxonomy.
####
def _call(function: _BotanFunction, *arguments: object) -> int | None:
    try:
        return function(*arguments)
    except Exception:
        return None



#### Own one Botan block-cipher handle initialized with fixed Twofish key material.
####
#### The native handle is destroyed on explicit close, context cleanup, construction
#### failure after allocation, and defensive finalization.  Finalization never raises.
####
class _BotanTwofishKey:
    __slots__ = ("_handle", "_library")



    #### Initialize and key one native handle without copying mutable key storage.
    ####
    def __init__(self, library: _BotanLibrary, key_material: SecretBuffer) -> None:
        borrowed_key = key_material.borrow()
        key_owner = borrowed_key.obj
        if not isinstance(key_owner, bytearray):
            raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)
        key_buffer_type = ctypes.c_uint8 * len(borrowed_key)
        key_buffer = key_buffer_type.from_buffer(key_owner)

        self._library = library
        self._handle = ctypes.c_void_p()
        initialization_status = _call(
            library.botan_block_cipher_init,
            ctypes.byref(self._handle),
            _TWOFISH_NAME,
        )
        if initialization_status != 0 or self._handle.value is None:
            self._release_after_failed_initialization()
            raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)

        key_status = _call(
            library.botan_block_cipher_set_key,
            self._handle,
            key_buffer,
            len(borrowed_key),
        )
        if key_status != 0:
            self._release_after_failed_initialization()
            raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)



    #### Release any partial handle created before construction can return an owner.
    ####
    def _release_after_failed_initialization(self) -> None:
        handle = self._handle
        self._handle = ctypes.c_void_p()
        if handle.value is not None and _call(self._library.botan_block_cipher_destroy, handle) != 0:
            raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)



    #### Encrypt exactly one block and wipe temporary ctypes input and output storage.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        return self._transform(block, self._library.botan_block_cipher_encrypt_blocks)



    #### Decrypt exactly one block and wipe temporary ctypes input and output storage.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self._transform(block, self._library.botan_block_cipher_decrypt_blocks)



    #### Apply one checked native block operation through the retained live handle.
    ####
    def _transform(self, block: bytes, operation: _BotanFunction) -> bytes:
        if len(block) != _TWOFISH_BLOCK_BYTES:
            raise ValueError("operation requires exactly one Twofish block")
        if self._handle.value is None:
            raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)

        buffer_type = ctypes.c_uint8 * _TWOFISH_BLOCK_BYTES
        input_buffer = buffer_type.from_buffer_copy(block)
        output_buffer = buffer_type()
        try:
            status = _call(operation, self._handle, input_buffer, output_buffer, 1)
            if status != 0:
                raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)
            return bytes(output_buffer)
        finally:
            ctypes.memset(ctypes.addressof(input_buffer), 0, _TWOFISH_BLOCK_BYTES)
            ctypes.memset(ctypes.addressof(output_buffer), 0, _TWOFISH_BLOCK_BYTES)



    #### Destroy the native handle once and surface a failed explicit release safely.
    ####
    def close(self) -> None:
        handle = self._handle
        self._handle = ctypes.c_void_p()
        if handle.value is None:
            return
        if _call(self._library.botan_block_cipher_destroy, handle) != 0:
            raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)



    #### Defensively release a forgotten native handle without raising at shutdown.
    ####
    def __del__(self) -> None:
        with suppress(Exception):
            self.close()



#### Provide a gated fixed-Twofish backend over one verified Botan library.
####
class BotanBackend:
    __slots__ = ("_library",)



    #### Retain one library only through the private validated factory boundary.
    ####
    #### The identity token prevents untyped callers from constructing a backend
    #### around an arbitrary library and reaching key operations without open().
    ####
    def __init__(self, library: _BotanLibrary, *, _token: object) -> None:
        if _token is not _BACKEND_CONSTRUCTION_TOKEN:
            raise TypeError("Botan backends must be created through open")
        self._library = library



    #### Load, bind, version-check, and self-test one Botan shared library.
    ####
    #### No backend escapes this factory until the independent Twofish vector passes.
    #### Loader and ABI details are reduced to safe closed error categories.
    ####
    @classmethod
    def open(cls, library_path: Path) -> Self:
        loaded_library = _load_library(library_path)
        if loaded_library is None:
            raise CryptoBackendError(CryptoBackendReason.UNAVAILABLE)
        library = _bind_library(loaded_library)
        if library is None:
            raise CryptoBackendError(CryptoBackendReason.INVALID_ABI)

        supported_api = _call(library.botan_ffi_supports_api, BOTAN_FFI_API_VERSION)
        major = _call(library.botan_version_major)
        minor = _call(library.botan_version_minor)
        patch = _call(library.botan_version_patch)
        if supported_api != 0 or major != _BOTAN_MAJOR_VERSION or minor is None or minor < _BOTAN_MINIMUM_MINOR_VERSION:
            raise CryptoBackendError(CryptoBackendReason.INVALID_ABI)
        if patch is None:
            raise CryptoBackendError(CryptoBackendReason.INVALID_ABI)

        backend = cls(library, _token=_BACKEND_CONSTRUCTION_TOKEN)
        backend.self_test()
        return backend



    #### Create one fixed Twofish handle and guarantee deterministic context cleanup.
    ####
    #### Cleanup failure is reported on normal exit.  During exceptional exit the
    #### original caller failure remains authoritative after cleanup is attempted.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key = _BotanTwofishKey(self._library, key_material)
        try:
            yield key
        except BaseException:
            with suppress(CryptoBackendError):
                key.close()
            raise
        else:
            key.close()



    #### Verify encryption and decryption against the official zero-key vector.
    ####
    def self_test(self) -> None:
        with SecretBuffer.from_bytes(_TWOFISH_ZERO_KEY) as key_material, self.key(key_material) as key:
            ciphertext = key.encrypt_block(_TWOFISH_ZERO_BLOCK)
            plaintext = key.decrypt_block(_TWOFISH_ZERO_CIPHERTEXT)
            if ciphertext != _TWOFISH_ZERO_CIPHERTEXT or plaintext != _TWOFISH_ZERO_BLOCK:
                raise CryptoBackendError(CryptoBackendReason.SELF_TEST_FAILED)
