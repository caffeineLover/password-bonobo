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
    block_buffers: list[tuple[object, object]]
    key_addresses: list[int]



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
        raised_operations: set[str] | None = None,
    ) -> None:
        self._statuses = statuses or {}
        self._valid_vector = valid_vector
        self.raised_operations = raised_operations or set()
        self.algorithm_names = []
        self.block_buffers = []
        self.key_addresses = []
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
        key_pointer = ctypes.cast(cast(ctypes.c_void_p, arguments[1]), ctypes.c_void_p)
        if key_pointer.value is None:
            return -1
        self.key_addresses.append(key_pointer.value)
        key = ctypes.string_at(key_pointer, key_length)
        return 0 if key == TWOFISH_ZERO_KEY else -1



    #### Emit the independent official ciphertext unless corruption is requested.
    ####
    def _encrypt(self, arguments: tuple[object, ...]) -> int:
        self.block_buffers.append((arguments[1], arguments[2]))
        if "encrypt" in self.raised_operations:
            raise RuntimeError("fabricated encrypt call detail")
        status = self._status("encrypt")
        if status != 0:
            return status
        output = TWOFISH_ZERO_CIPHERTEXT if self._valid_vector else bytes(16)
        ctypes.memmove(cast(ctypes.c_void_p, arguments[2]), output, len(output))
        return 0



    #### Emit the official vector's zero plaintext for the reverse KAT operation.
    ####
    def _decrypt(self, arguments: tuple[object, ...]) -> int:
        self.block_buffers.append((arguments[1], arguments[2]))
        if "decrypt" in self.raised_operations:
            raise RuntimeError("fabricated decrypt call detail")
        status = self._status("decrypt")
        if status != 0:
            return status
        ctypes.memmove(cast(ctypes.c_void_p, arguments[2]), TWOFISH_ZERO_BLOCK, len(TWOFISH_ZERO_BLOCK))
        return 0



#### Raise arbitrary caller text while Python converts an otherwise valid path.
####
class _ExplodingPath(Path):



    #### Refuse path conversion through an exception outside ordinary OS failures.
    ####
    def __fspath__(self) -> str:
        raise RuntimeError("E:/fabricated/path/fabricated-platform-detail")



#### Raise arbitrary native detail when the adapter first reads a required symbol.
####
class _ExplodingSymbolLibrary:



    #### Model a hostile dynamic symbol resolver rather than an absent attribute.
    ####
    @property
    def botan_ffi_supports_api(self) -> _FakeFunction:
        raise RuntimeError("E:/fabricated/path/fabricated-symbol-detail")



#### Resolve either the required CI artifact or an optional local developer build.
####
def _resolve_botan_library(default_library: Path = _DEFAULT_BOTAN_LIBRARY) -> Path:
    configured = os.environ.get("BONOBO_TEST_BOTAN_LIBRARY")
    if configured is not None:
        library = Path(configured)
        if not library.is_file():
            pytest.fail("configured Botan test library is not available")
        return library
    if not default_library.is_file():
        pytest.skip("verified Botan host library is not available")
    return default_library



#### Supply the real native artifact selected by explicit qualification policy.
####
@pytest.fixture
def botan_library() -> Path:
    return _resolve_botan_library()



#### Use the approved CI library variable as a required qualification artifact.
####
def test_botan_fixture_uses_planned_ci_library(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ci_library = tmp_path / "botan-test-library"
    ci_library.write_bytes(b"fabricated native artifact")
    monkeypatch.setenv("BONOBO_TEST_BOTAN_LIBRARY", os.fspath(ci_library))

    assert _resolve_botan_library(tmp_path / "missing-local-library") == ci_library



#### Fail release qualification when its explicitly built native artifact is absent.
####
def test_botan_fixture_fails_for_missing_required_ci_library(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("BONOBO_TEST_BOTAN_LIBRARY", os.fspath(tmp_path / "missing-ci-library"))

    with pytest.raises(pytest.fail.Exception, match="configured Botan test library is not available"):
        _resolve_botan_library(tmp_path / "missing-local-library")



#### Skip only a local developer run that has no explicit qualification artifact.
####
def test_botan_fixture_skips_missing_optional_local_library(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BONOBO_TEST_BOTAN_LIBRARY", raising=False)

    with pytest.raises(pytest.skip.Exception, match="verified Botan host library is not available"):
        _resolve_botan_library(tmp_path / "missing-local-library")



#### Replace ctypes loading with one controlled library at the native boundary.
####
def _install_fake_library(monkeypatch: pytest.MonkeyPatch, library: _FakeBotanLibrary) -> None:
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: cast(ctypes.CDLL, library))



#### Raise a controlled loader error without retaining a real system path.
####
def _reject_library_load(_path: object) -> ctypes.CDLL:
    raise OSError("fabricated loader detail")



#### Raise an arbitrary loader exception outside the original narrow catch family.
####
def _raise_arbitrary_library_error(_path: object) -> ctypes.CDLL:
    raise RuntimeError("E:/fabricated/path/fabricated-loader-detail")



#### Assert that a native-boundary failure carries only the closed safe taxonomy.
####
def _assert_safe_backend_error(error: CryptoBackendError, reason: CryptoBackendReason) -> None:
    assert error.reason == reason.value
    assert str(error) == "cryptographic backend is unavailable"
    assert "fabricated" not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None



#### Assert and release the fake's short-lived references to native block buffers.
####
def _assert_last_block_buffers_zero(library: _FakeBotanLibrary) -> None:
    input_buffer, output_buffer = library.block_buffers[-1]
    try:
        assert ctypes.string_at(cast(ctypes.c_void_p, input_buffer), 16) == bytes(16)
        assert ctypes.string_at(cast(ctypes.c_void_p, output_buffer), 16) == bytes(16)
    finally:
        library.block_buffers.clear()



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



#### Prevent direct construction from bypassing the opening validation and KAT gate.
####
def test_botan_backend_requires_private_validated_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    unsafe_constructor = cast(Callable[..., BotanBackend], BotanBackend)

    with pytest.raises(TypeError):
        unsafe_constructor(cast(_BotanLibrary, library))
    with pytest.raises(TypeError):
        unsafe_constructor(cast(_BotanLibrary, library), _token=object())

    assert library.botan_block_cipher_init.calls == []



#### Reject libraries that cannot load without exposing loader diagnostics.
####
def test_botan_maps_loader_failure_to_safe_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "CDLL", _reject_library_load)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    assert caught.value.reason == CryptoBackendReason.UNAVAILABLE.value
    assert "fabricated" not in str(caught.value)
    assert caught.value.__context__ is None



#### Contain arbitrary exceptions raised while converting a type-valid path.
####
def test_botan_contains_arbitrary_path_conversion_exception() -> None:
    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(_ExplodingPath("fabricated-botan-library"))

    _assert_safe_backend_error(caught.value, CryptoBackendReason.UNAVAILABLE)



#### Contain arbitrary exceptions raised by the ctypes library loader.
####
def test_botan_contains_arbitrary_ctypes_loader_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "CDLL", _raise_arbitrary_library_error)

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    _assert_safe_backend_error(caught.value, CryptoBackendReason.UNAVAILABLE)



#### Contain arbitrary exceptions raised during required symbol resolution.
####
def test_botan_contains_arbitrary_symbol_access_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _ExplodingSymbolLibrary()
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: cast(ctypes.CDLL, library))

    with pytest.raises(CryptoBackendError) as caught:
        BotanBackend.open(Path("fabricated-botan-library"))

    _assert_safe_backend_error(caught.value, CryptoBackendReason.INVALID_ABI)



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



#### Pass the SecretBuffer owner's storage directly to Botan without a key copy.
####
def test_botan_set_key_pointer_aliases_secret_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    backend = BotanBackend.open(Path("fabricated-botan-library"))
    source_storage = bytearray(TWOFISH_ZERO_KEY)
    source_probe = (ctypes.c_uint8 * len(source_storage)).from_buffer(source_storage)
    source_address = ctypes.addressof(source_probe)
    del source_probe

    with SecretBuffer.take_ownership(source_storage) as key_material, backend.key(key_material):
        assert library.key_addresses[-1] == source_address

    assert source_storage == bytearray(len(source_storage))



#### Wipe temporary native block buffers after a successful operation.
####
def test_botan_wipes_block_buffers_after_success(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    backend = BotanBackend.open(Path("fabricated-botan-library"))
    library.block_buffers.clear()

    with SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material, backend.key(key_material) as key:
        key.encrypt_block(bytes(range(16)))

    _assert_last_block_buffers_zero(library)



#### Wipe temporary native block buffers after a nonzero operation status.
####
def test_botan_wipes_block_buffers_after_nonzero_status(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    backend = BotanBackend.open(Path("fabricated-botan-library"))
    library.block_buffers.clear()
    library._statuses["encrypt"] = -1

    with (
        SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material,
        backend.key(key_material) as key,
        pytest.raises(CryptoBackendError),
    ):
        key.encrypt_block(bytes(range(16)))

    _assert_last_block_buffers_zero(library)



#### Wipe temporary native block buffers when a dynamic call raises internally.
####
def test_botan_wipes_block_buffers_after_raised_call(monkeypatch: pytest.MonkeyPatch) -> None:
    library = _FakeBotanLibrary()
    _install_fake_library(monkeypatch, library)
    backend = BotanBackend.open(Path("fabricated-botan-library"))
    library.block_buffers.clear()
    library.raised_operations.add("encrypt")

    with (
        SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material,
        backend.key(key_material) as key,
        pytest.raises(CryptoBackendError),
    ):
        key.encrypt_block(bytes(range(16)))

    _assert_last_block_buffers_zero(library)



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
