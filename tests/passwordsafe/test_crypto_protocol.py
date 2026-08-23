"""Verify the narrow Twofish protocols support deterministic key ownership.

The protocol boundary lets later format code use fixed block operations without
depending on Botan handles, algorithm selection, or native-library details.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from bonobo_core.passwordsafe.crypto import TwofishBackend, TwofishKey
from bonobo_core.passwordsafe.secrets import SecretBuffer



#### Provide one deterministic protocol test key with an observable close state.
####
class _ProtocolKey:
    closed: bool



    #### Initialize the test key as an open fixed-block transformer.
    ####
    def __init__(self) -> None:
        self.closed = False



    #### Transform one block so the protocol consumer can observe encryption.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        return block[::-1]



    #### Reverse the deterministic test transformation.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return block[::-1]



    #### Record deterministic release of the test key.
    ####
    def close(self) -> None:
        self.closed = True



#### Provide a structurally conforming backend without a native dependency.
####
class _ProtocolBackend:
    last_key: _ProtocolKey | None



    #### Initialize the backend without an active key owner.
    ####
    def __init__(self) -> None:
        self.last_key = None



    #### Yield one key and close it even when the consumer exits exceptionally.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key_material.borrow()
        key = _ProtocolKey()
        self.last_key = key
        try:
            yield key
        finally:
            key.close()



    #### Complete the fake backend gate without selecting an algorithm.
    ####
    def self_test(self) -> None:
        return None



#### Exercise only operations promised by the backend protocol.
####
def _round_trip(backend: TwofishBackend, block: bytes) -> bytes:
    backend.self_test()
    with SecretBuffer.from_bytes(bytes(16)) as key_material, backend.key(key_material) as key:
        return key.decrypt_block(key.encrypt_block(block))



#### Keep later crypto consumers independent of Botan-specific implementation state.
####
def test_twofish_backend_protocol_closes_keys_after_use() -> None:
    backend = _ProtocolBackend()
    block = bytes(range(16))

    assert _round_trip(backend, block) == block
    assert backend.last_key is not None
    assert backend.last_key.closed
    assert isinstance(backend, TwofishBackend)
    assert isinstance(backend.last_key, TwofishKey)
