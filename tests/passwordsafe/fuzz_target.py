"""Feed arbitrary encrypted bytes through the authenticated parser with bounded test-only resources."""

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from bonobo_core.passwordsafe.constants import ResourceLimits
from bonobo_core.passwordsafe.crypto import TwofishKey
from bonobo_core.passwordsafe.errors import PasswordSafeError
from bonobo_core.passwordsafe.reader import PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer



_WORKSPACE_ENVIRONMENT = "BONOBO_FUZZ_WORKSPACE"
_PASSPHRASE = b"fabricated-fuzz-passphrase"
_LIMITS = ResourceLimits(
    max_iterations=3,
    max_records=32,
    max_fields=256,
    max_inline_payload_bytes=4096,
    max_decoded_text_bytes=32_768,
    io_chunk_bytes=1024,
    max_encrypted_file_bytes=1_048_576,
)



#### Implement the deterministic reversible block transform used only by the parser fuzz target.
####
class _FuzzKey:
    __slots__ = ("_closed", "_mask")



    #### Retain one fabricated mask until the target backend closes this keyed context.
    ####
    def __init__(self, key_material: SecretBuffer) -> None:
        self._mask = bytes(key_material.borrow()[:16])
        self._closed = False



    #### Apply the deterministic transform to one complete synthetic cipher block.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("fuzz key is closed")
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Reverse the same synthetic transform without introducing another algorithm.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)



    #### Make this keyed context terminal after its one fuzz operation.
    ####
    def close(self) -> None:
        self._closed = True



#### Supply the deterministic target cipher through the production backend protocol.
####
class _FuzzBackend:



    #### Yield one scoped key and close it even when arbitrary input fails parsing.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key = _FuzzKey(key_material)
        try:
            yield key
        finally:
            key.close()



    #### Complete the test-only backend gate without claiming production suitability.
    ####
    def self_test(self) -> None:
        return None



#### Return the optional runner-owned root used to make leak checks deterministic.
####
def _workspace_root() -> Path | None:
    configured = os.environ.get(_WORKSPACE_ENVIRONMENT)
    return None if configured is None else Path(configured)



#### Parse one arbitrary encrypted input, accepting only success or the public typed failure taxonomy.
####
def fuzz_one_input(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("fuzz input must be bytes")
    with tempfile.TemporaryDirectory(prefix="password-bonobo-fuzz-", dir=_workspace_root()) as temporary_name:
        workspace = Path(temporary_name)
        private_directory = workspace / "private"
        private_directory.mkdir(mode=0o700)
        private_directory.chmod(0o700)
        source = workspace / "input.bin"
        source.write_bytes(data)
        reader = PasswordSafeReader(_FuzzBackend(), private_directory, limits=_LIMITS)
        try:
            with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
                opened = reader.open(source, passphrase)
        except PasswordSafeError:
            return
        opened.close()
