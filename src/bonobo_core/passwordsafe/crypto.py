"""Define the fixed Twofish boundary consumed by PasswordSafe format code.

The protocols expose only single-block operations and deterministic key lifetimes.
Algorithm selection and native-library details remain adapter responsibilities.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol, runtime_checkable

from .secrets import SecretBuffer



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
