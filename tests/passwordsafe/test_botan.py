"""Verify the fixed Botan Twofish adapter against its ABI and official vector.

The real-library test guards native integration.  Controlled fake libraries force
every status boundary without providing a fallback cipher to production code.
"""

import ctypes
import gc
import os
from collections.abc import Callable
from pathlib import Path
from typing import Final, cast

import pytest

from bonobo_core.passwordsafe.botan import BOTAN_FFI_API_VERSION, BotanBackend, _BotanLibrary, _BotanTwofishKey
from bonobo_core.passwordsafe.errors import CryptoBackendError, CryptoBackendReason
from bonobo_core.passwordsafe.secrets import SecretBuffer



TWOFISH_ZERO_KEY: Final[bytes] = bytes(16)
TWOFISH_ZERO_BLOCK: Final[bytes] = bytes(16)
TWOFISH_ZERO_CIPHERTEXT: Final[bytes] = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")
_REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_DEFAULT_BOTAN_LIBRARY: Final[Path] = _REPOSITORY_ROOT / "build" / "botan" / "bin" / "botan-3.dll"


_FakeCallback = Callable[[tuple[object, ...]], int]



#### Model one ctypes function with configurable behavior and inspectable ABI metadata.
####
class _FakeFunction:
    argtypes: list[object] | None
    restype: object | None
    calls: list[tuple[object, ...]]



    #### Initialize an unbound fake function around one narrowly typed callback.
    ####
    def __init__(self, callback: _FakeCallback) -> None:
        self.argtypes = None
        self.restype = None
        self.calls = []
        self._callback = callback



    #### Record each native-style call before returning its controlled status or value.
    ####
    def __call__(self, *arguments: object) -> int:
        self.calls.append(arguments)
        return self._callback(arguments)



#### Emulate only the exact Botan symbols consumed by the production adapter.
####
#### Successful block operations implement the independent official vector so the
#### fake can pass the opening gate unless a test deliberately forces one boundary.
####
class _FakeBotanLibrary:
    botan_ffi_supports_api: _FakeFunction
    botan_version_major: _FakeFunction
    botan_version_minor: _FakeFunction
    botan_version_patch: _FakeFunction
    botan_block_cipher_init: _FakeFunction
    botan_block_cipher_destroy: _FakeFunction
    botan_block_cipher_set_key: _FakeFunction
    botan_block_cipher_encrypt_blocks: _FakeFunction
    botan_block_cipher_decrypt_blocks: _FakeFunction
    algorithm_names: list[bytes]



    #### Initialize version values, per-symbol statuses, and the KAT behavior.
    ####
    def __init__(
        self,
        *,
        major: int = 3,
        minor: int = 13,
        patch: int = 0,
        statuses: dict[str, int] | None = None,
        valid_vector: bool = True,
    ) -> None:
        self._statuses = statuses or {}
        self._valid_vector = valid_vector
        self.algorithm_names = []
        self.botan_ffi_supports_api = _FakeFunction(
            lambda arguments: self._status("supports_api") if arguments == (BOTAN_FFI_API_VERSION,) else -1,
        )
        self.botan_version_major = _FakeFunction(lambda _arguments: major)
        self.botan_version_minor = _FakeFunction(lambda _arguments: minor)
        self.botan_version_patch = _FakeFunction(lambda _arguments: patch)
        self.botan_block_cipher_init = _FakeFunction(self._initialize)
        self.botan_block_cipher_destroy = _FakeFunction(lambda _arguments: self._status("destroy"))
        self.botan_block_cipher_set_key = _FakeFunction(self._set_key)
        self.botan_block_cipher_encrypt_blocks = _FakeFunction(self._encrypt)
        self.botan_block_cipher_decrypt_blocks = _FakeFunction(self._decrypt)



    #### Return one configured native status, defaulting to success.
    ####
    def _status(self, name: str) -> int:
        return self._statuses.get(name, 0)



    #### Initialize one non-null fake handle and retain the fixed algorithm name.
    ####
    def _initialize(self, arguments: tuple[object, ...]) -> int:
        status = self._status("init")
        self.algorithm_names.append(cast(bytes, arguments[1]))
        if status == 0:
            handle_pointer = ctypes.cast(cast(ctypes.c_void_p, arguments[0]), ctypes.POINTER(ctypes.c_void_p))
            handle_pointer.contents.value = 1
        return status



    #### Accept only the official zero key used by the enforced self-test.
    ####
    def _set_key(self, arguments: tuple[object, ...]) -> int:
        status = self._status("set_key")
        if status != 0:
            return status
        key_length = cast(int, arguments[2])
        key = ctypes.string_at(cast(ctypes.c_void_p, arguments[1]), key_length)
        return 0 if key == TWOFISH_ZERO_KEY else -1



    #### Emit the independent official ciphertext unless corruption is requested.
    ####
    def _encrypt(self, arguments: tuple[object, ...]) -> int:
        status = self._status("encrypt")
        if status != 0:
            return status
        output = TWOFISH_ZERO_CIPHERTEXT if self._valid_vector else bytes(16)
        ctypes.memmove(cast(ctypes.c_void_p, arguments[2]), output, len(output))
        return 0



    #### Emit the official vector's zero plaintext for the reverse KAT operation.
    ####
    def _decrypt(self, arguments: tuple[object, ...]) -> int:
        status = self._status("decrypt")
        if status != 0:
            return status
        ctypes.memmove(cast(ctypes.c_void_p, arguments[2]), TWOFISH_ZERO_BLOCK, len(TWOFISH_ZERO_BLOCK))
        return 0



#### Resolve the built host library while allowing a CI-provided explicit path.
####
@pytest.fixture
def botan_library() -> Path:
    configured = os.environ.get("BONOBO_BOTAN_LIBRARY")
    library = Path(configured) if configured is not None else _DEFAULT_BOTAN_LIBRARY
    if not library.is_file():
        pytest.skip("verified Botan host library is not available")
    return library



#### Replace ctypes loading with one controlled library at the native boundary.
####
def _install_fake_library(monkeypatch: pytest.MonkeyPatch, library: _FakeBotanLibrary) -> None:
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: cast(ctypes.CDLL, library))



#### Raise a controlled loader error without retaining a real system path.
####
def _reject_library_load(_path: object) -> ctypes.CDLL:
    raise OSError("fabricated loader detail")



#### Prove the installed Botan library implements the official Twofish vector.
####
def test_botan_twofish_known_answer(botan_library: Path) -> None:
    backend = BotanBackend.open(botan_library)
    backend.self_test()
    with SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material, backend.key(key_material) as key:
        assert key.encrypt_block(TWOFISH_ZERO_BLOCK) == TWOFISH_ZERO_CIPHERTEXT
        assert key.decrypt_block(TWOFISH_ZERO_CIPHERTEXT) == TWOFISH_ZERO_BLOCK



#### Bind each official C signature and pass only the fixed Twofish name.
####
def test_botan_binds_exact_ffi_signatures_and_fixed_algorithm(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)

    BotanBackend.open(Path("fabricated-botan-library"))

    byte_pointer = ctypes.POINTER(ctypes.c_uint8)
    assert library.botan_ffi_supports_api.argtypes == [ctypes.c_uint32]
    assert library.botan_ffi_supports_api.restype is ctypes.c_int
    for version_function in (
        library.botan_version_major,
        library.botan_version_minor,
        library.botan_version_patch,
    ):
        assert version_function.argtypes == []
        assert version_function.restype is ctypes.c_uint32
        assert len(version_function.calls) == 1
    assert library.botan_block_cipher_init.argtypes == [ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p]
    assert library.botan_block_cipher_destroy.argtypes == [ctypes.c_void_p]
    assert library.botan_block_cipher_set_key.argtypes == [ctypes.c_void_p, byte_pointer, ctypes.c_size_t]
    block_arguments = [ctypes.c_void_p, byte_pointer, byte_pointer, ctypes.c_size_t]
    assert library.botan_block_cipher_encrypt_blocks.argtypes == block_arguments
    assert library.botan_block_cipher_decrypt_blocks.argtypes == block_arguments
    for status_function in (
        library.botan_block_cipher_init,
        library.botan_block_cipher_destroy,
        library.botan_block_cipher_set_key,
        library.botan_block_cipher_encrypt_blocks,
        library.botan_block_cipher_decrypt_blocks,
    ):
        assert status_function.restype is ctypes.c_int
    assert library.botan_ffi_supports_api.calls == [(BOTAN_FFI_API_VERSION,)]
    assert library.algorithm_names == [b"Twofish"]



#### Reject libraries that cannot load without exposing loader diagnostics.
####
def test_botan_maps_loader_failure_to_safe_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "CDLL", _reject_library_load)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    assert caught.value.reason == CryptoBackendReason.UNAVAILABLE.value
    assert "fabricated" not in str(caught.value)
    assert caught.value.__context__ is None



#### Reject an unsupported ABI before any cipher handle is initialized.
####
def test_botan_rejects_unsupported_ffi_api(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary(statuses={"supports_api": -1})
    _install_fake_library(monkeypatch, library)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    assert caught.value.reason == CryptoBackendReason.INVALID_ABI.value
    assert library.botan_block_cipher_init.calls == []



#### Require major version 3 and at least minor version 13.
####
@pytest.mark.parametrize(("major", "minor"), [(2, 99), (3, 12), (4, 0)])
def test_botan_rejects_unapproved_versions(monkeypatch: pytest.MonkeyPatch, major: int, minor: int) -> None:
    library = _FakeBotanLibrary(major=major, minor=minor)
    _install_fake_library(monkeypatch, library)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    assert caught.value.reason == CryptoBackendReason.INVALID_ABI.value
    assert library.botan_block_cipher_init.calls == []



#### Map every nonzero Botan operation status into the closed backend failure.
####
@pytest.mark.parametrize("operation", ["init", "set_key", "encrypt", "decrypt", "destroy"])
def test_botan_rejects_nonzero_operation_status(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    library = _FakeBotanLibrary(statuses={operation: -1})
    _install_fake_library(monkeypatch, library)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    assert caught.value.reason == CryptoBackendReason.SELF_TEST_FAILED.value



#### Destroy an allocated handle when native key setup rejects the supplied key.
####
def test_botan_key_setup_failure_releases_initialized_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary(statuses={"set_key": -1})
    _install_fake_library(monkeypatch, library)

    with pytest.raises(CryptoBackendError):
        BotanBackend.open(Path("fabricated-botan-library"))

    assert len(library.botan_block_cipher_init.calls) == 1
    assert len(library.botan_block_cipher_destroy.calls) == 1



#### Refuse a loaded cipher whose output does not match the independent KAT.
####
def test_botan_open_enforces_known_answer_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary(valid_vector=False)
    _install_fake_library(monkeypatch, library)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    assert caught.value.reason == CryptoBackendReason.SELF_TEST_FAILED.value



#### Destroy native key handles when a consumer exits through an exception.
####
def test_botan_key_context_destroys_handle_on_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    backend = BotanBackend.open(Path("fabricated-botan-library"))
    destroys_after_self_test = len(library.botan_block_cipher_destroy.calls)

    with (
        SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material,
        pytest.raises(RuntimeError, match="synthetic failure"),
        backend.key(key_material),
    ):
        raise RuntimeError("synthetic failure")

    assert len(library.botan_block_cipher_destroy.calls) == destroys_after_self_test + 1



#### Defensively destroy a native handle whose explicit owner was forgotten.
####
def test_botan_key_finalizer_releases_forgotten_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    BotanBackend.open(Path("fabricated-botan-library"))
    destroys_after_self_test = len(library.botan_block_cipher_destroy.calls)

    with SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material:
        forgotten_key = _BotanTwofishKey(cast(_BotanLibrary, library), key_material)
        del forgotten_key
        gc.collect()

    assert len(library.botan_block_cipher_destroy.calls) == destroys_after_self_test + 1



#### Reject non-block input before invoking a native block operation.
####
def test_botan_key_requires_exactly_one_twofish_block(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    backend = BotanBackend.open(Path("fabricated-botan-library"))

    with SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material, backend.key(key_material) as key:
        encrypt_calls = len(library.botan_block_cipher_encrypt_blocks.calls)
        with pytest.raises(ValueError, match="exactly one Twofish block"):
            key.encrypt_block(bytes(15))

    assert len(library.botan_block_cipher_encrypt_blocks.calls) == encrypt_calls
