"""Verify PasswordSafe stretching, wrapped keys, CBC, HMAC, and randomness.

The deterministic expectations come from official construction rules and
independent standard-library or .NET calculations, never product reader or
writer output.
"""

import copy
import hashlib
import hmac
import json
import pickle
import secrets
from builtins import bytearray as builtin_bytearray
from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Final, Protocol, SupportsIndex, cast, overload

import pytest
from helpers import DeterministicRandomSource, build_spec_vault

import bonobo_core.passwordsafe.crypto as crypto_module
from bonobo_core.passwordsafe.constants import ResourceLimits
from bonobo_core.passwordsafe.crypto import (
    CbcDecryptor,
    CbcEncryptor,
    DerivedKey,
    FieldAuthenticator,
    SystemRandomSource,
    TwofishBackend,
    TwofishKey,
    VaultKeys,
    stretch_passphrase,
    unwrap_vault_keys,
    wrap_vault_keys,
)
from bonobo_core.passwordsafe.errors import ResourceLimitError, ResourceLimitReason
from bonobo_core.passwordsafe.secrets import SecretBuffer, SecretClosedError



_VECTOR_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1] / "fixtures" / "synthetic" / "passwordsafe" / "crypto-vectors.json"
)



#### Model one reversible block transform with controllable fault boundaries.
####
class _FakeTwofishKey:
    closed: bool
    inputs: list[bytes]



    #### Retain one fixed mask and the optional operation that must fail.
    ####
    def __init__(
        self,
        mask: bytes,
        *,
        fail_on_call: int | None,
        short_on_call: int | None,
        transform_error: BaseException | None,
    ) -> None:
        self._mask = mask[:16]
        self._fail_on_call = fail_on_call
        self._short_on_call = short_on_call
        self._transform_error = transform_error
        self.closed = False
        self.inputs = []



    #### Apply the fake symmetric transform for an encryption operation.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        return self._transform(block)



    #### Apply the same fake symmetric transform for a decryption operation.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self._transform(block)



    #### Return one XOR-transformed block after enforcing configured faults.
    ####
    def _transform(self, block: bytes) -> bytes:
        self.inputs.append(block)
        call = len(self.inputs)
        if call == self._fail_on_call:
            if self._transform_error is None:
                raise RuntimeError("synthetic block failure")
            raise self._transform_error
        if call == self._short_on_call:
            return bytes(15)
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Record deterministic release of the fake keyed resource.
    ####
    def close(self) -> None:
        self.closed = True



#### Provide deterministic keyed contexts while retaining lifecycle evidence.
####
class _FakeTwofishBackend:
    keys: list[_FakeTwofishKey]
    key_materials: list[SecretBuffer]



    #### Configure optional operation, entry, and context-exit failures.
    ####
    def __init__(
        self,
        *,
        fail_on_call: int | None = None,
        short_on_call: int | None = None,
        fail_on_enter: bool = False,
        fail_on_exit: bool = False,
        transform_error: BaseException | None = None,
        exit_error: BaseException | None = None,
    ) -> None:
        self._fail_on_call = fail_on_call
        self._short_on_call = short_on_call
        self._fail_on_enter = fail_on_enter
        self._fail_on_exit = fail_on_exit
        self._transform_error = transform_error
        self._exit_error = exit_error
        self.keys = []
        self.key_materials = []



    #### Yield a fake key whose mask comes from the caller's real secret owner.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        self.key_materials.append(key_material)
        if self._fail_on_enter:
            raise RuntimeError("synthetic key entry failure")
        key = _FakeTwofishKey(
            bytes(key_material.borrow()),
            fail_on_call=self._fail_on_call,
            short_on_call=self._short_on_call,
            transform_error=self._transform_error,
        )
        self.keys.append(key)
        try:
            yield key
        finally:
            key.close()
            if self._fail_on_exit:
                if self._exit_error is None:
                    raise RuntimeError("synthetic key exit failure")
                raise self._exit_error



    #### Complete the fake gate without providing a production fallback cipher.
    ####
    def self_test(self) -> None:
        return None



#### Raise before returning any keyed context to test partial CBC construction.
####
class _ImmediateFailureBackend:



    #### Fail synchronously before a context manager can become caller-owned.
    ####
    def key(self, _key_material: SecretBuffer) -> AbstractContextManager[TwofishKey]:
        raise RuntimeError("synthetic immediate key failure")



    #### Complete the fake gate without providing any block cipher operation.
    ####
    def self_test(self) -> None:
        return None



#### Emulate the initial SHA-256 operation before a controlled loop failure.
####
class _InitialHash:



    #### Accept the salt supplied to the initial passphrase hash.
    ####
    def update(self, _data: bytes) -> None:
        return None



    #### Return one nonsecret fabricated digest for the loop's mutable state.
    ####
    def digest(self) -> bytes:
        return bytes(range(32))



#### Retain the loop buffer and fail so the test can inspect final zeroization.
####
class _FaultingHashFactory:
    retained: bytearray | None



    #### Begin without a retained mutable stretching buffer.
    ####
    def __init__(self) -> None:
        self.retained = None



    #### Return the initial hash once, then fail after retaining loop storage.
    ####
    def __call__(self, data: bytes | bytearray | memoryview[int] = b"") -> _InitialHash:
        if isinstance(data, bytearray):
            self.retained = data
            raise RuntimeError("synthetic hash failure")
        return _InitialHash()



#### Fail the second mutable allocation while retaining the first for wipe proof.
####
class _FaultingBytearrayFactory:
    retained: bytearray | None



    #### Begin without any allocated stretching storage.
    ####
    def __init__(self) -> None:
        self._calls = 0
        self.retained = None



    #### Allocate once, then raise before the replacement buffer can be created.
    ####
    def __call__(self, source: object = b"") -> bytearray:
        self._calls += 1
        if self._calls == 2:
            raise MemoryError("synthetic allocation failure")
        allocate = cast(Callable[[object], bytearray], builtin_bytearray)
        allocated = allocate(source)
        self.retained = allocated
        return allocated



#### Count full-buffer zeroization assignments without changing bytearray behavior.
####
class _WipeCountingBytearray(bytearray):
    wipe_count: int



    #### Initialize fabricated key storage with no observed wipe operation.
    ####
    def __init__(self, source: bytes) -> None:
        super().__init__(source)
        self.wipe_count = 0



    #### Describe indexed byte replacement for the bytearray overload contract.
    ####
    @overload
    def __setitem__(self, key: SupportsIndex, value: SupportsIndex, /) -> None: ...



    #### Describe slice replacement for the bytearray overload contract.
    ####
    @overload
    def __setitem__(
        self,
        key: slice[SupportsIndex | None],
        value: Iterable[SupportsIndex] | bytes,
        /,
    ) -> None: ...



    #### Record only exact full-buffer zero fills before applying the real write.
    ####
    def __setitem__(
        self,
        key: SupportsIndex | slice[SupportsIndex | None],
        value: SupportsIndex | Iterable[SupportsIndex] | bytes,
        /,
    ) -> None:
        if isinstance(key, slice):
            slice_value = cast(Iterable[SupportsIndex] | bytes, value)
            if key == slice(None, None, None) and isinstance(slice_value, bytes) and slice_value == bytes(len(self)):
                self.wipe_count += 1
            super().__setitem__(key, slice_value)
        else:
            super().__setitem__(key, cast(SupportsIndex, value))



#### Describe direct state hooks that exclusive owners must reject safely.
####
class _StateSerializationOwner(Protocol):



    #### Attempt direct state extraction without relying on pickle framing.
    ####
    def __getstate__(self) -> object:
        raise NotImplementedError



    #### Attempt direct fabricated-state injection without deserializing secrets.
    ####
    def __setstate__(self, state: object) -> None:
        raise NotImplementedError



#### Assert all generic duplication and serialization routes reject one owner safely.
####
def _assert_copy_and_serialization_rejected(owner: object) -> None:
    diagnostic = "^cryptographic owner cannot be copied or serialized$"
    with pytest.raises(TypeError, match=diagnostic):
        copy.copy(owner)
    with pytest.raises(TypeError, match=diagnostic):
        copy.deepcopy(owner)
    with pytest.raises(TypeError, match=diagnostic):
        pickle.dumps(owner)



#### Raise during terminal digest to verify authenticator cleanup on failure.
####
class _DigestFailureHmac:



    #### Accept payload updates before the configured digest failure.
    ####
    def update(self, _payload: bytes) -> None:
        return None



    #### Fail the terminal digest operation with fabricated safe test text.
    ####
    def digest(self) -> bytes:
        raise RuntimeError("synthetic HMAC digest failure")



#### Return one controlled HMAC substitute for a terminal-failure regression.
####
def _new_digest_failure_hmac(_key: object, *, digestmod: object) -> hmac.HMAC:
    del digestmod
    return cast(hmac.HMAC, _DigestFailureHmac())



#### Create all five live owner types plus their two caller-owned source keys.
####
def _make_crypto_owner_set() -> tuple[
    DerivedKey,
    VaultKeys,
    CbcEncryptor,
    CbcDecryptor,
    FieldAuthenticator,
    SecretBuffer,
    SecretBuffer,
]:
    content_source = SecretBuffer.from_bytes(bytes(32))
    hmac_source = SecretBuffer.from_bytes(b"k" * 32)
    return (
        DerivedKey(bytearray(range(32))),
        VaultKeys(bytearray(range(32)), bytearray(range(32, 64))),
        CbcEncryptor(_FakeTwofishBackend(), content_source, bytes(16)),
        CbcDecryptor(_FakeTwofishBackend(), content_source, bytes(16)),
        FieldAuthenticator(hmac_source),
        content_source,
        hmac_source,
    )



#### Fail if an invalid request crosses the system-randomness boundary.
####
def _fail_unexpected_random_request(_length: int) -> bytes:
    pytest.fail("invalid length reached the randomness provider")



#### Load the independently recorded vector and preserve all authority metadata.
####
def test_crypto_vector_fixture_records_exact_independent_inputs() -> None:
    document = cast(dict[str, object], json.loads(_VECTOR_PATH.read_text(encoding="utf-8")))
    vectors = cast(list[dict[str, object]], document["vectors"])

    assert vectors == [
        {
            "authority": (
                "Independently evaluated from the official PasswordSafe V3 SHA-256 key-stretch definition with "
                ".NET System.Security.Cryptography.SHA256; production code was not imported or executed."
            ),
            "expected_stretched_key_hex": (
                "5f6c18d1eb9bc8b0ea2b8fb5dd3720e02b57d8dd6b91ff0cc8ebb5b9a5bd45f8"
            ),
            "hash": "SHA-256",
            "iterations": 2,
            "name": "fabricated-master-input-one",
            "passphrase_hex": "666162726963617465642d6d61737465722d696e7075742d6f6e65",
            "salt_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        },
    ]



#### Match the binding independently calculated PasswordSafe stretch vector.
####
def test_stretch_passphrase_matches_vector() -> None:
    password = SecretBuffer.from_bytes(b"fabricated-master-input-one")
    result = stretch_passphrase(password, bytes(range(32)), 2)

    assert bytes(result.borrow()).hex() == "5f6c18d1eb9bc8b0ea2b8fb5dd3720e02b57d8dd6b91ff0cc8ebb5b9a5bd45f8"
    assert not password.closed
    result.close()
    password.close()



#### Reject iteration bounds before borrowing the passphrase or beginning work.
####
@pytest.mark.parametrize("iterations", [0, -1, 3, True, 1.5])
def test_stretch_passphrase_rejects_invalid_iterations_before_secret_access(iterations: object) -> None:
    password = SecretBuffer.from_bytes(b"fabricated-master-input")
    password.close()

    with pytest.raises(ResourceLimitError) as caught:
        stretch_passphrase(
            password,
            bytes(32),
            cast(int, iterations),
            limits=ResourceLimits(max_iterations=2),
        )

    assert caught.value.reason == ResourceLimitReason.MAX_ITERATIONS.value



#### Reject an invalid salt without consuming or closing caller-owned input.
####
def test_stretch_passphrase_requires_exact_salt_size() -> None:
    password = SecretBuffer.from_bytes(b"fabricated-master-input")

    with pytest.raises(ValueError, match="salt must be exactly 32 bytes"):
        stretch_passphrase(password, bytes(31), 1)

    assert not password.closed
    password.close()



#### Wipe the mutable stretching state when a hash operation raises mid-loop.
####
def test_stretch_passphrase_wipes_intermediate_after_hash_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    factory = _FaultingHashFactory()
    monkeypatch.setattr(hashlib, "sha256", factory)

    with SecretBuffer.from_bytes(b"fabricated-master-input") as password, pytest.raises(
        RuntimeError,
        match="synthetic hash failure",
    ):
        stretch_passphrase(password, bytes(32), 1)

    assert factory.retained == bytearray(32)



#### Wipe derived state when replacement-buffer allocation fails after hashing.
####
def test_stretch_passphrase_wipes_state_after_partial_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    factory = _FaultingBytearrayFactory()
    monkeypatch.setattr(crypto_module, "bytearray", factory, raising=False)

    with SecretBuffer.from_bytes(b"fabricated-master-input") as password, pytest.raises(
        MemoryError,
        match="synthetic allocation failure",
    ):
        stretch_passphrase(password, bytes(32), 1)

    assert factory.retained == bytearray(32)



#### Wipe invalid caller storage rather than leaving a rejected derived key live.
####
def test_derived_key_rejects_size_and_wipes_transferred_storage() -> None:
    storage = bytearray(b"fabricated-short-key")

    with pytest.raises(ValueError, match="derived key must be exactly 32 bytes"):
        DerivedKey(storage)

    assert storage == bytearray(len(storage))



#### Reject derived-key reinitialization and wipe the unaccepted transfer candidate.
####
def test_derived_key_reinitialization_preserves_existing_owned_storage() -> None:
    original_storage = bytearray(range(32))
    replacement_storage = bytearray(range(32, 64))
    derived = DerivedKey(original_storage)

    with pytest.raises(TypeError, match="derived key cannot be reinitialized"):
        DerivedKey.__init__(derived, replacement_storage)

    assert bytes(derived.borrow()) == bytes(range(32))
    assert replacement_storage == bytearray(32)
    derived.close()
    assert original_storage == bytearray(32)



#### Preserve owned derived storage while wiping only a fresh reinit candidate.
####
@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("candidate_kind", ["owned", "fresh"])
def test_derived_key_reinitialization_is_owned_storage_aware(
    closed: bool,
    candidate_kind: str,
) -> None:
    owned_storage = _WipeCountingBytearray(bytes(range(32)))
    fresh_storage = _WipeCountingBytearray(bytes(range(32, 64)))
    derived = DerivedKey(owned_storage)
    owner_identity = derived._data
    if closed:
        derived.close()
    candidate = owned_storage if candidate_kind == "owned" else fresh_storage

    with pytest.raises(TypeError, match="derived key cannot be reinitialized"):
        DerivedKey.__init__(derived, candidate)

    assert derived._data is owner_identity
    assert derived.closed is closed
    assert owned_storage == (bytearray(32) if closed else bytearray(range(32)))
    assert owned_storage.wipe_count == (1 if closed else 0)
    if candidate_kind == "fresh":
        assert fresh_storage == bytearray(32)
        assert fresh_storage.wipe_count == 1
    else:
        assert fresh_storage == bytearray(range(32, 64))
        assert fresh_storage.wipe_count == 0
    derived.close()



#### Reject one buffer transferred as both vault keys and wipe it exactly once.
####
def test_vault_keys_reject_shared_storage_before_any_owner_can_escape() -> None:
    shared_storage = _WipeCountingBytearray(bytes(range(32)))

    with pytest.raises(TypeError, match="vault keys require distinct storage"):
        VaultKeys(shared_storage, shared_storage)

    assert shared_storage == bytearray(32)
    assert shared_storage.wipe_count == 1



#### Wipe both transferred vault-key buffers when their joint lifetime closes.
####
def test_vault_keys_close_wipes_both_owned_keys() -> None:
    content_storage = bytearray(range(32))
    hmac_storage = bytearray(range(32, 64))
    keys = VaultKeys(content_storage, hmac_storage)
    content_view = keys.content_key.borrow()
    hmac_view = keys.hmac_key.borrow()

    keys.close()

    assert content_storage == bytearray(32)
    assert hmac_storage == bytearray(32)
    assert bytes(content_view) == bytes(32)
    assert bytes(hmac_view) == bytes(32)
    assert keys.closed



#### Wipe every transferred buffer when vault-key construction is only partial.
####
@pytest.mark.parametrize("invalid_content", [True, False])
def test_vault_keys_invalid_size_wipes_all_transferred_storage(invalid_content: bool) -> None:
    content_storage = bytearray(31 if invalid_content else 32)
    hmac_storage = bytearray(32 if invalid_content else 31)

    with pytest.raises(ValueError, match="vault keys must be exactly 32 bytes"):
        VaultKeys(content_storage, hmac_storage)

    assert content_storage == bytearray(len(content_storage))
    assert hmac_storage == bytearray(len(hmac_storage))



#### Reject joint-key reinitialization without orphaning either existing owner.
####
def test_vault_keys_reinitialization_wipes_candidates_and_preserves_existing_keys() -> None:
    original_content = bytearray(range(32))
    original_hmac = bytearray(range(32, 64))
    replacement_content = bytearray([0xA5] * 32)
    replacement_hmac = bytearray([0x5A] * 32)
    keys = VaultKeys(original_content, original_hmac)

    with pytest.raises(TypeError, match="vault keys cannot be reinitialized"):
        VaultKeys.__init__(keys, replacement_content, replacement_hmac)

    assert bytes(keys.content_key.borrow()) == bytes(range(32))
    assert bytes(keys.hmac_key.borrow()) == bytes(range(32, 64))
    assert replacement_content == bytearray(32)
    assert replacement_hmac == bytearray(32)
    keys.close()
    assert original_content == bytearray(32)
    assert original_hmac == bytearray(32)



#### Wipe one aliased replacement only once while preserving existing owners.
####
def test_vault_keys_reinitialization_wipes_shared_candidate_exactly_once() -> None:
    original_content = bytearray(range(32))
    original_hmac = bytearray(range(32, 64))
    shared_replacement = _WipeCountingBytearray(bytes([0xA5] * 32))
    keys = VaultKeys(original_content, original_hmac)

    with pytest.raises(TypeError, match="vault keys cannot be reinitialized"):
        VaultKeys.__init__(keys, shared_replacement, shared_replacement)

    assert bytes(keys.content_key.borrow()) == bytes(range(32))
    assert bytes(keys.hmac_key.borrow()) == bytes(range(32, 64))
    assert shared_replacement == bytearray(32)
    assert shared_replacement.wipe_count == 1
    keys.close()



#### Preserve current vault storage and wipe every distinct fresh candidate once.
####
@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize(
    ("content_candidate_name", "hmac_candidate_name"),
    [
        ("content", "hmac"),
        ("hmac", "content"),
        ("content", "content"),
        ("hmac", "hmac"),
        ("content", "fresh_a"),
        ("fresh_a", "content"),
        ("hmac", "fresh_a"),
        ("fresh_a", "hmac"),
        ("fresh_a", "fresh_a"),
        ("fresh_a", "fresh_b"),
    ],
)
def test_vault_keys_reinitialization_is_owned_storage_aware(
    closed: bool,
    content_candidate_name: str,
    hmac_candidate_name: str,
) -> None:
    content_storage = _WipeCountingBytearray(bytes(range(32)))
    hmac_storage = _WipeCountingBytearray(bytes(range(32, 64)))
    fresh_a = _WipeCountingBytearray(bytes(range(32)))
    fresh_b = _WipeCountingBytearray(bytes(range(32, 64)))
    keys = VaultKeys(content_storage, hmac_storage)
    content_owner = keys.content_key
    hmac_owner = keys.hmac_key
    if closed:
        keys.close()
    candidates = {
        "content": content_storage,
        "hmac": hmac_storage,
        "fresh_a": fresh_a,
        "fresh_b": fresh_b,
    }

    with pytest.raises(TypeError, match="vault keys cannot be reinitialized"):
        VaultKeys.__init__(
            keys,
            candidates[content_candidate_name],
            candidates[hmac_candidate_name],
        )

    assert keys.content_key is content_owner
    assert keys.hmac_key is hmac_owner
    assert keys.closed is closed
    assert content_storage == (bytearray(32) if closed else bytearray(range(32)))
    assert hmac_storage == (bytearray(32) if closed else bytearray(range(32, 64)))
    assert content_storage.wipe_count == (1 if closed else 0)
    assert hmac_storage.wipe_count == (1 if closed else 0)
    used_names = {content_candidate_name, hmac_candidate_name}
    for name, fresh_storage, initial in (
        ("fresh_a", fresh_a, bytearray(range(32))),
        ("fresh_b", fresh_b, bytearray(range(32, 64))),
    ):
        if name in used_names:
            assert fresh_storage == bytearray(32)
            assert fresh_storage.wipe_count == 1
        else:
            assert fresh_storage == initial
            assert fresh_storage.wipe_count == 0
    keys.close()



#### Prevent callers from replacing either key owner outside joint lifecycle control.
####
def test_vault_key_properties_are_read_only() -> None:
    keys = VaultKeys(bytearray(32), bytearray(32))
    replacement = SecretBuffer.from_bytes(bytes(32))

    with pytest.raises(AttributeError):
        # Runtime misuse must be rejected even though typed callers cannot assign this property.
        keys.content_key = replacement  # type: ignore[misc]
    with pytest.raises(AttributeError):
        # Runtime misuse must be rejected even though typed callers cannot assign this property.
        keys.hmac_key = replacement  # type: ignore[misc]

    assert keys.content_key is not replacement
    assert keys.hmac_key is not replacement
    replacement.close()
    keys.close()



#### Reject copying and serialization without invalidating any live crypto owner.
####
def test_crypto_owners_reject_copy_deepcopy_and_pickle_when_live_or_closed() -> None:
    derived = DerivedKey(bytearray(range(32)))
    vault_keys = VaultKeys(bytearray(range(32)), bytearray(range(32, 64)))
    content_key = SecretBuffer.from_bytes(bytes(32))
    hmac_key = SecretBuffer.from_bytes(b"k" * 32)
    encryptor = CbcEncryptor(_FakeTwofishBackend(), content_key, bytes(16))
    decryptor = CbcDecryptor(_FakeTwofishBackend(), content_key, bytes(16))
    authenticator = FieldAuthenticator(hmac_key)
    owners: tuple[object, ...] = (derived, vault_keys, encryptor, decryptor, authenticator)

    for owner in owners:
        _assert_copy_and_serialization_rejected(owner)

    assert bytes(derived.borrow()) == bytes(range(32))
    assert bytes(vault_keys.content_key.borrow()) == bytes(range(32))
    assert encryptor.transform(bytes(range(16))) == bytes(range(16))
    assert decryptor.transform(bytes(range(16))) == bytes(range(16))
    authenticator.update(b"first")
    authenticator.update(b"second")
    assert authenticator.digest().hex() == "135c55ecf0b3052079eefadd5670cf5601d91084db46147a63ae900749423429"

    derived.close()
    vault_keys.close()
    encryptor.close()
    decryptor.close()
    for owner in owners:
        _assert_copy_and_serialization_rejected(owner)

    content_key.close()
    hmac_key.close()



#### Reject direct live and closed state extraction or injection without mutation.
####
@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("hook_name", ["getstate", "setstate"])
def test_crypto_owners_reject_direct_state_hooks_without_mutation(
    closed: bool,
    hook_name: str,
) -> None:
    (
        derived,
        vault_keys,
        encryptor,
        decryptor,
        authenticator,
        content_source,
        hmac_source,
    ) = _make_crypto_owner_set()
    owners: tuple[object, ...] = (derived, vault_keys, encryptor, decryptor, authenticator)
    derived_storage = derived._data
    content_owner = vault_keys.content_key
    hmac_owner = vault_keys.hmac_key
    encrypt_context = encryptor._context
    decrypt_context = decryptor._context
    encrypt_chain = encryptor._previous
    decrypt_chain = decryptor._previous
    hmac_state = authenticator._hmac
    if closed:
        derived.close()
        vault_keys.close()
        encryptor.close()
        decryptor.close()
        authenticator.close()

    try:
        for owner in owners:
            state_owner = cast(_StateSerializationOwner, owner)
            with pytest.raises(TypeError, match=r"^cryptographic owner cannot be copied or serialized$"):
                if hook_name == "getstate":
                    state_owner.__getstate__()
                else:
                    state_owner.__setstate__({"fabricated": ("state", 1)})

        assert derived._data is derived_storage
        assert vault_keys.content_key is content_owner
        assert vault_keys.hmac_key is hmac_owner
        assert encryptor._context is encrypt_context
        assert decryptor._context is decrypt_context
        assert encryptor._previous is encrypt_chain
        assert decryptor._previous is decrypt_chain
        if closed:
            assert derived.closed
            assert vault_keys.closed
            assert encryptor.closed
            assert decryptor.closed
            assert authenticator.closed
            assert derived_storage == bytearray(32)
            assert encrypt_chain == bytearray(16)
            assert decrypt_chain == bytearray(16)
            assert authenticator._hmac is None
        else:
            assert bytes(derived.borrow()) == bytes(range(32))
            assert bytes(vault_keys.content_key.borrow()) == bytes(range(32))
            assert bytes(vault_keys.hmac_key.borrow()) == bytes(range(32, 64))
            assert encryptor.transform(bytes(range(16))) == bytes(range(16))
            assert decryptor.transform(bytes(range(16))) == bytes(range(16))
            assert authenticator._hmac is hmac_state
            authenticator.update(b"first")
            authenticator.update(b"second")
            assert authenticator.digest().hex() == (
                "135c55ecf0b3052079eefadd5670cf5601d91084db46147a63ae900749423429"
            )
    finally:
        derived.close()
        vault_keys.close()
        encryptor.close()
        decryptor.close()
        authenticator.close()
        content_source.close()
        hmac_source.close()



#### Wrap content then HMAC key halves as exactly four ordered ECB blocks.
####
def test_wrap_vault_keys_uses_exact_block_order_and_caller_owners() -> None:
    backend = _FakeTwofishBackend()
    derived = DerivedKey(bytearray([0xA5] * 32))
    keys = VaultKeys(bytearray(range(32)), bytearray(range(32, 64)))

    wrapped = wrap_vault_keys(backend, derived, keys)

    assert wrapped == bytes(value ^ 0xA5 for value in range(64))
    assert backend.key_materials == [derived]
    assert backend.keys[0].inputs == [
        bytes(range(16)),
        bytes(range(16, 32)),
        bytes(range(32, 48)),
        bytes(range(48, 64)),
    ]
    assert backend.keys[0].closed
    assert not derived.closed
    assert not keys.closed
    keys.close()
    derived.close()



#### Unwrap four ordered blocks into two independently owned 32-byte keys.
####
def test_unwrap_vault_keys_restores_independent_key_owners() -> None:
    backend = _FakeTwofishBackend()
    derived = DerivedKey(bytearray([0xA5] * 32))
    wrapped = bytes(value ^ 0xA5 for value in range(64))

    keys = unwrap_vault_keys(backend, derived, wrapped)

    assert bytes(keys.content_key.borrow()) == bytes(range(32))
    assert bytes(keys.hmac_key.borrow()) == bytes(range(32, 64))
    assert backend.keys[0].inputs == [
        wrapped[:16],
        wrapped[16:32],
        wrapped[32:48],
        wrapped[48:],
    ]
    assert backend.keys[0].closed
    keys.close()
    derived.close()



#### Reject a malformed wrapped-key region before opening a keyed backend context.
####
@pytest.mark.parametrize("length", [0, 63, 65])
def test_unwrap_vault_keys_rejects_nonexact_region_before_backend_use(length: int) -> None:
    backend = _FakeTwofishBackend()
    derived = DerivedKey(bytearray(32))

    with pytest.raises(ValueError, match="wrapped keys must be exactly 64 bytes"):
        unwrap_vault_keys(backend, derived, bytes(length))

    assert backend.key_materials == []
    derived.close()



#### Close backend state and retain caller ownership when wrapping raises midstream.
####
def test_wrap_vault_keys_closes_backend_on_transform_failure() -> None:
    backend = _FakeTwofishBackend(fail_on_call=3)
    derived = DerivedKey(bytearray(32))
    keys = VaultKeys(bytearray(32), bytearray(32))

    with pytest.raises(RuntimeError, match="synthetic block failure"):
        wrap_vault_keys(backend, derived, keys)

    assert backend.keys[0].closed
    assert not derived.closed
    assert not keys.closed
    keys.close()
    derived.close()



#### Publish no partial keys and close backend state after invalid decrypted output.
####
def test_unwrap_vault_keys_rejects_invalid_backend_block_and_closes_context() -> None:
    backend = _FakeTwofishBackend(short_on_call=2)
    derived = DerivedKey(bytearray(32))

    with pytest.raises(ValueError, match="backend returned an invalid block"):
        unwrap_vault_keys(backend, derived, bytes(64))

    assert backend.keys[0].closed
    assert not derived.closed
    derived.close()



#### Chain encryption through the previous ciphertext across separate block calls.
####
def test_cbc_encryptor_chains_continuously() -> None:
    backend = _FakeTwofishBackend()
    content_key = SecretBuffer.from_bytes(bytes(32))

    with CbcEncryptor(backend, content_key, bytes(range(16))) as encryptor:
        first = encryptor.transform(bytes(range(16, 32)))
        second = encryptor.transform(bytes(range(32, 48)))

    assert first == bytes.fromhex("10101010101010101010101010101010")
    assert second == bytes.fromhex("303132333435363738393a3b3c3d3e3f")
    assert backend.keys[0].inputs == [
        bytes.fromhex("10101010101010101010101010101010"),
        bytes.fromhex("303132333435363738393a3b3c3d3e3f"),
    ]
    assert backend.keys[0].closed
    assert not content_key.closed
    content_key.close()



#### Save ciphertext before decrypting so the next block uses the correct chain.
####
def test_cbc_decryptor_chains_continuously() -> None:
    backend = _FakeTwofishBackend()
    content_key = SecretBuffer.from_bytes(bytes(32))
    ciphertext = bytes.fromhex(
        "10101010101010101010101010101010"
        "303132333435363738393a3b3c3d3e3f"
    )

    with CbcDecryptor(backend, content_key, bytes(range(16))) as decryptor:
        first = decryptor.transform(ciphertext[:16])
        second = decryptor.transform(ciphertext[16:])

    assert first == bytes(range(16, 32))
    assert second == bytes(range(32, 48))
    assert backend.keys[0].inputs == [ciphertext[:16], ciphertext[16:]]
    assert backend.keys[0].closed
    content_key.close()



#### Reject non-block data without advancing state or invoking the backend.
####
@pytest.mark.parametrize("length", [0, 15, 17, 32])
def test_cbc_transform_accepts_only_one_block(length: int) -> None:
    backend = _FakeTwofishBackend()
    content_key = SecretBuffer.from_bytes(bytes(32))

    with CbcEncryptor(backend, content_key, bytes(16)) as encryptor:
        with pytest.raises(ValueError, match="exactly one 16-byte block"):
            encryptor.transform(bytes(length))
        assert backend.keys[0].inputs == []
        assert encryptor.transform(bytes(range(16))) == bytes(range(16))

    content_key.close()



#### Reject an invalid IV before opening any keyed backend resource.
####
def test_cbc_constructor_rejects_invalid_iv_before_backend_use() -> None:
    backend = _FakeTwofishBackend()
    content_key = SecretBuffer.from_bytes(bytes(32))

    with pytest.raises(ValueError, match="IV must be exactly 16 bytes"):
        CbcEncryptor(backend, content_key, bytes(15))

    assert backend.key_materials == []
    content_key.close()



#### Wipe copied CBC state when backend context creation fails synchronously.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
def test_cbc_partial_construction_wipes_iv(cbc_type: type[CbcEncryptor] | type[CbcDecryptor]) -> None:
    content_key = SecretBuffer.from_bytes(bytes(32))
    retained = cbc_type.__new__(cbc_type)
    initialize = cast(
        Callable[[object, TwofishBackend, SecretBuffer, bytes], None],
        cbc_type.__init__,
    )

    with pytest.raises(RuntimeError, match="synthetic immediate key failure"):
        initialize(retained, cast(TwofishBackend, _ImmediateFailureBackend()), content_key, bytes(range(16)))

    previous = retained._previous
    assert previous == bytearray(16)
    assert retained.closed
    content_key.close()



#### Reject CBC reinitialization without replacing or leaking its live key context.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
def test_cbc_reinitialization_preserves_live_context(cbc_type: type[CbcEncryptor] | type[CbcDecryptor]) -> None:
    original_backend = _FakeTwofishBackend()
    replacement_backend = _FakeTwofishBackend()
    content_key = SecretBuffer.from_bytes(bytes(32))
    transformer = cbc_type(original_backend, content_key, bytes(16))
    reinitialize = cast(
        Callable[[object, TwofishBackend, SecretBuffer, bytes], None],
        cbc_type.__init__,
    )

    with pytest.raises(TypeError, match="CBC transformer cannot be reinitialized"):
        reinitialize(transformer, replacement_backend, content_key, bytes(16))

    assert transformer.transform(bytes(range(16))) == bytes(range(16))
    assert replacement_backend.key_materials == []
    transformer.close()
    assert original_backend.keys[0].closed
    content_key.close()



#### Close and invalidate a CBC owner when its backend transform raises.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
def test_cbc_backend_failure_closes_owned_state(cbc_type: type[CbcEncryptor] | type[CbcDecryptor]) -> None:
    backend = _FakeTwofishBackend(fail_on_call=1)
    content_key = SecretBuffer.from_bytes(bytes(32))
    transformer = cbc_type(backend, content_key, bytes(16))

    with pytest.raises(RuntimeError, match="synthetic block failure"):
        transformer.transform(bytes(16))

    assert transformer.closed
    assert backend.keys[0].closed
    with pytest.raises(RuntimeError, match="CBC transformer is closed"):
        transformer.transform(bytes(16))
    content_key.close()



#### Preserve the primary transform failure across independent cleanup failures.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_type", [RuntimeError, SystemExit])
def test_cbc_transform_preserves_active_exception_across_cleanup(
    cbc_type: type[CbcEncryptor] | type[CbcDecryptor],
    primary_type: type[BaseException],
    cleanup_type: type[BaseException],
) -> None:
    primary = primary_type("synthetic primary transform failure")
    cleanup = cleanup_type("synthetic secondary cleanup failure")
    backend = _FakeTwofishBackend(
        fail_on_call=1,
        fail_on_exit=True,
        transform_error=primary,
        exit_error=cleanup,
    )
    content_key = SecretBuffer.from_bytes(bytes(32))
    transformer = cbc_type(backend, content_key, bytes(16))

    with pytest.raises(primary_type) as caught:
        transformer.transform(bytes(16))

    assert caught.value is primary
    assert transformer.closed
    assert backend.keys[0].closed
    content_key.close()



#### Preserve an active process-control exception during context cleanup.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
def test_cbc_context_exit_preserves_active_base_exception(
    cbc_type: type[CbcEncryptor] | type[CbcDecryptor],
) -> None:
    cleanup = SystemExit("synthetic context cleanup failure")
    backend = _FakeTwofishBackend(fail_on_exit=True, exit_error=cleanup)
    content_key = SecretBuffer.from_bytes(bytes(32))
    transformer = cbc_type(backend, content_key, bytes(16))
    primary = KeyboardInterrupt("synthetic active process-control exception")

    with pytest.raises(KeyboardInterrupt) as caught, transformer:
        raise primary

    assert caught.value is primary
    assert transformer.closed
    assert backend.keys[0].closed
    content_key.close()



#### Prevent defensive CBC finalization from surfacing cleanup BaseExceptions.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
def test_cbc_finalizer_suppresses_cleanup_base_exception(
    cbc_type: type[CbcEncryptor] | type[CbcDecryptor],
) -> None:
    backend = _FakeTwofishBackend(
        fail_on_exit=True,
        exit_error=KeyboardInterrupt("synthetic finalizer cleanup failure"),
    )
    content_key = SecretBuffer.from_bytes(bytes(32))
    transformer = cbc_type(backend, content_key, bytes(16))

    transformer.__del__()
    transformer.__del__()

    assert transformer.closed
    assert backend.keys[0].closed
    content_key.close()



#### Close a CBC owner terminally while surfacing caller-initiated failures.
####
@pytest.mark.parametrize("cbc_type", [CbcEncryptor, CbcDecryptor])
@pytest.mark.parametrize("cleanup_type", [RuntimeError, KeyboardInterrupt])
def test_cbc_explicit_close_surfaces_backend_exit_failure(
    cbc_type: type[CbcEncryptor] | type[CbcDecryptor],
    cleanup_type: type[BaseException],
) -> None:
    cleanup = cleanup_type("synthetic explicit cleanup failure")
    backend = _FakeTwofishBackend(fail_on_exit=True, exit_error=cleanup)
    content_key = SecretBuffer.from_bytes(bytes(32))
    transformer = cbc_type(backend, content_key, bytes(16))

    with pytest.raises(cleanup_type) as caught:
        transformer.close()

    assert caught.value is cleanup
    assert transformer.closed
    assert backend.keys[0].closed
    content_key.close()



#### Authenticate only declared payload bytes in their document order.
####
def test_field_authenticator_matches_independent_ordered_payload_hmac() -> None:
    hmac_key = SecretBuffer.from_bytes(b"k" * 32)
    authenticator = FieldAuthenticator(hmac_key)

    authenticator.update(b"first")
    authenticator.update(b"second")

    assert authenticator.digest().hex() == "135c55ecf0b3052079eefadd5670cf5601d91084db46147a63ae900749423429"
    assert authenticator.closed
    assert authenticator._hmac is None
    assert not hmac_key.closed
    hmac_key.close()



#### Make field ordering observable so reordered payloads cannot authenticate.
####
def test_field_authenticator_is_order_sensitive() -> None:
    key = SecretBuffer.from_bytes(bytes(range(32)))
    forward = FieldAuthenticator(key)
    reverse = FieldAuthenticator(key)

    forward.update(b"alpha")
    forward.update(b"beta")
    reverse.update(b"beta")
    reverse.update(b"alpha")

    assert forward.digest() != reverse.digest()
    key.close()



#### Retain an internal HMAC copy after source close, then terminate at digest.
####
def test_field_authenticator_digest_is_terminal_after_source_key_closes() -> None:
    key = SecretBuffer.from_bytes(b"k" * 32)
    authenticator = FieldAuthenticator(key)
    key.close()

    authenticator.update(b"first")
    authenticator.update(b"second")
    assert authenticator.digest().hex() == "135c55ecf0b3052079eefadd5670cf5601d91084db46147a63ae900749423429"
    assert authenticator.closed
    assert authenticator._hmac is None

    with pytest.raises(SecretClosedError, match="secret buffer is closed"):
        authenticator.digest()
    with pytest.raises(SecretClosedError, match="secret buffer is closed"):
        authenticator.update(b"third")
    with pytest.raises(SecretClosedError, match="secret buffer is closed"):
        authenticator.__enter__()
    _assert_copy_and_serialization_rejected(authenticator)



#### Make explicit authenticator close idempotent and terminal before digest.
####
def test_field_authenticator_explicit_close_is_idempotent() -> None:
    key = SecretBuffer.from_bytes(bytes(32))
    authenticator = FieldAuthenticator(key)

    authenticator.close()
    authenticator.close()

    assert authenticator.closed
    assert authenticator._hmac is None
    with pytest.raises(SecretClosedError, match="secret buffer is closed"):
        authenticator.update(b"payload")
    with pytest.raises(SecretClosedError, match="secret buffer is closed"):
        authenticator.digest()
    assert not key.closed
    key.close()



#### Close the authenticator while preserving an active context-body exception.
####
def test_field_authenticator_exceptional_context_exit_is_terminal() -> None:
    key = SecretBuffer.from_bytes(bytes(32))
    authenticator = FieldAuthenticator(key)
    primary = KeyboardInterrupt("synthetic process-control exit")

    with pytest.raises(KeyboardInterrupt) as caught, authenticator as entered:
        assert entered is authenticator
        entered.update(b"payload")
        raise primary

    assert caught.value is primary
    assert authenticator.closed
    assert authenticator._hmac is None
    key.close()



#### Close terminal HMAC state even when the digest implementation raises.
####
def test_field_authenticator_digest_failure_still_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hmac, "new", _new_digest_failure_hmac)
    key = SecretBuffer.from_bytes(bytes(32))
    authenticator = FieldAuthenticator(key)

    authenticator.update(b"payload")
    with pytest.raises(RuntimeError, match="synthetic HMAC digest failure"):
        authenticator.digest()

    assert authenticator.closed
    assert authenticator._hmac is None
    key.close()



#### Reject reinitialization without replacing a live authenticator's state.
####
def test_field_authenticator_reinitialization_preserves_original_state() -> None:
    original_key = SecretBuffer.from_bytes(b"k" * 32)
    replacement_key = SecretBuffer.from_bytes(b"r" * 32)
    authenticator = FieldAuthenticator(original_key)

    with pytest.raises(TypeError, match="field authenticator cannot be reinitialized"):
        FieldAuthenticator.__init__(authenticator, replacement_key)

    authenticator.update(b"first")
    authenticator.update(b"second")
    assert authenticator.digest().hex() == "135c55ecf0b3052079eefadd5670cf5601d91084db46147a63ae900749423429"
    assert not replacement_key.closed
    original_key.close()
    replacement_key.close()



#### Defensively finalize forgotten authenticator state without raising.
####
def test_field_authenticator_finalizer_is_idempotent_and_terminal() -> None:
    key = SecretBuffer.from_bytes(bytes(32))
    authenticator = FieldAuthenticator(key)

    authenticator.__del__()
    authenticator.__del__()

    assert authenticator.closed
    assert authenticator._hmac is None
    key.close()



#### Reject a malformed HMAC key while leaving caller ownership unchanged.
####
def test_field_authenticator_requires_exact_key_size() -> None:
    key = SecretBuffer.from_bytes(bytes(31))

    with pytest.raises(ValueError, match="HMAC key must be exactly 32 bytes"):
        FieldAuthenticator(key)

    assert not key.closed
    key.close()



#### Delegate valid random requests to the operating-system randomness boundary.
####
def test_system_random_source_returns_requested_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "token_bytes", lambda length: b"r" * length)

    assert SystemRandomSource().bytes(5) == b"rrrrr"
    assert SystemRandomSource().bytes(0) == b""



#### Reject negative lengths before invoking operating-system randomness.
####
def test_system_random_source_rejects_negative_length_before_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "token_bytes", _fail_unexpected_random_request)

    with pytest.raises(ValueError, match="length cannot be negative"):
        SystemRandomSource().bytes(-1)



#### Reject bool and noninteger lengths without platform-specific diagnostics.
####
@pytest.mark.parametrize("length", [True, 1.5, "1"])
def test_system_random_source_rejects_noninteger_length(length: object) -> None:
    with pytest.raises(TypeError, match="length must be an integer"):
        SystemRandomSource().bytes(cast(int, length))



#### Keep deterministic test randomness finite, ordered, and outside product code.
####
def test_deterministic_random_source_consumes_without_cycling() -> None:
    source = DeterministicRandomSource(b"abcdef")

    assert source.bytes(2) == b"ab"
    assert source.bytes(4) == b"cdef"
    with pytest.raises(ValueError, match="exhausted"):
        source.bytes(1)



#### Build identical fabricated vault bytes without product reader or writer code.
####
def test_build_spec_vault_is_deterministic_and_matches_fixed_envelope_layout() -> None:
    fields = ((0x00, b"\x11\x03"), (0xFF, b""))
    first = build_spec_vault(
        _FakeTwofishBackend(),
        b"fabricated-master-input",
        fields,
        salt=bytes(range(32)),
        iterations=2,
        content_key=bytes(32),
        hmac_key=b"h" * 32,
        iv=bytes(16),
        random_source=DeterministicRandomSource(bytes(range(64))),
    )
    second = build_spec_vault(
        _FakeTwofishBackend(),
        b"fabricated-master-input",
        fields,
        salt=bytes(range(32)),
        iterations=2,
        content_key=bytes(32),
        hmac_key=b"h" * 32,
        iv=bytes(16),
        random_source=DeterministicRandomSource(bytes(range(64))),
    )

    assert first == second
    assert first[:4] == b"PWS3"
    assert first[4:36] == bytes(range(32))
    assert first[36:40] == b"\x02\x00\x00\x00"
    assert first[-48:-32] == b"PWS3-EOFPWS3-EOF"
    assert len(first) == 232
