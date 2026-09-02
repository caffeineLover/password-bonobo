"""Build deterministic PasswordSafe test data without product codec dependencies.

The helpers implement only the small official envelope construction needed by
reader tests.  They never import product reader or writer code, and all inputs
are fabricated test values supplied explicitly by callers.
"""

import hashlib
import hmac
from collections.abc import Sequence

from bonobo_core.passwordsafe.crypto import TwofishBackend
from bonobo_core.passwordsafe.secrets import SecretBuffer



#### Supply deterministic bytes from one caller-owned synthetic byte stream.
####
#### Tests use this source for reproducible padding only.  Exhaustion fails
#### explicitly instead of cycling and accidentally hiding excess consumption.
####
class DeterministicRandomSource:
    __slots__ = ("_offset", "_stream")



    #### Retain the complete fabricated stream and begin at its first byte.
    ####
    def __init__(self, stream: bytes) -> None:
        self._stream = stream
        self._offset = 0



    #### Return the next requested bytes or reject an invalid or exhausted request.
    ####
    def bytes(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int):
            raise TypeError("length must be an integer")
        if length < 0:
            raise ValueError("length cannot be negative")
        end = self._offset + length
        if end > len(self._stream):
            raise ValueError("deterministic random source is exhausted")
        output = self._stream[self._offset:end]
        self._offset = end
        return output



#### Construct one encrypted synthetic V3 vault directly from official wire rules.
####
#### This test oracle intentionally duplicates the small construction algorithm
#### instead of calling product stretching, wrapping, CBC, HMAC, reader, or writer
#### code.  The supplied backend is the sole cipher primitive dependency.
####
def build_spec_vault(
    backend: TwofishBackend,
    passphrase: bytes,
    fields: Sequence[tuple[int, bytes]],
    *,
    salt: bytes,
    iterations: int,
    content_key: bytes,
    hmac_key: bytes,
    iv: bytes,
    random_source: DeterministicRandomSource,
) -> bytes:
    if len(salt) != 32:
        raise ValueError("salt must be exactly 32 bytes")
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
        raise ValueError("iterations must be a positive integer")
    if len(content_key) != 32 or len(hmac_key) != 32:
        raise ValueError("vault keys must be exactly 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")

    initial_hash = hashlib.sha256(passphrase)
    initial_hash.update(salt)
    derived = bytearray(initial_hash.digest())
    try:
        for _iteration in range(iterations):
            derived[:] = hashlib.sha256(derived).digest()

        wrapped_blocks: list[bytes] = []
        with SecretBuffer.from_bytes(bytes(derived)) as wrapping_key, backend.key(wrapping_key) as cipher:
            for vault_key in (content_key, hmac_key):
                wrapped_blocks.append(cipher.encrypt_block(vault_key[:16]))
                wrapped_blocks.append(cipher.encrypt_block(vault_key[16:]))

        authenticator = hmac.new(hmac_key, digestmod=hashlib.sha256)
        previous = bytearray(iv)
        encrypted_blocks: list[bytes] = []
        try:
            with SecretBuffer.from_bytes(content_key) as content_owner, backend.key(content_owner) as cipher:
                for field_type, payload in fields:
                    if not 0 <= field_type <= 0xFF:
                        raise ValueError("field type must fit one byte")
                    if len(payload) > 0xFFFF_FFFF:
                        raise ValueError("field payload length must fit uint32")
                    authenticator.update(payload)
                    field = len(payload).to_bytes(4, "little") + bytes((field_type,)) + payload
                    padding_length = (-len(field)) % 16
                    field += random_source.bytes(padding_length)
                    for offset in range(0, len(field), 16):
                        mixed = bytearray(16)
                        try:
                            block = field[offset:offset + 16]
                            for index in range(16):
                                mixed[index] = block[index] ^ previous[index]
                            encrypted = cipher.encrypt_block(bytes(mixed))
                            if len(encrypted) != 16:
                                raise ValueError("backend returned an invalid block")
                            encrypted_blocks.append(encrypted)
                            previous[:] = encrypted
                        finally:
                            mixed[:] = bytes(16)
        finally:
            previous[:] = bytes(16)

        password_check = hashlib.sha256(derived).digest()
        return b"".join(
            (
                b"PWS3",
                salt,
                iterations.to_bytes(4, "little"),
                password_check,
                *wrapped_blocks,
                iv,
                *encrypted_blocks,
                b"PWS3-EOFPWS3-EOF",
                authenticator.digest(),
            ),
        )
    finally:
        derived[:] = bytes(len(derived))
