"""Prove attacker-declared PasswordSafe sizes fail before proportional Python allocation."""

import tempfile
import tracemalloc
from pathlib import Path
from typing import Final

import pytest
from hypothesis import HealthCheck, given, settings

from bonobo_core.passwordsafe.errors import MalformedVaultError
from bonobo_core.passwordsafe.reader import PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer
from tests.passwordsafe.helpers import DeterministicRandomSource, build_spec_vault
from tests.passwordsafe.strategies import oversized_uint32_field_lengths
from tests.passwordsafe.test_reader import _base_fields, _private_directory, _XorBackend



_PASSPHRASE: Final[bytes] = b"fabricated-reader-passphrase"
_SALT: Final[bytes] = bytes(range(32))
_CONTENT_KEY: Final[bytes] = bytes(range(32, 64))
_HMAC_KEY: Final[bytes] = bytes(range(64, 96))
_IV: Final[bytes] = bytes(range(16))
_MAXIMUM_PARSE_PEAK_BYTES: Final[int] = 2 * 1024 * 1024



#### Replace the first encrypted field header with one attacker-declared uint32 payload length.
####
def _vault_with_declared_length(backend: _XorBackend, declared_length: int) -> bytes:
    data = bytearray(
        build_spec_vault(
            backend,
            _PASSPHRASE,
            _base_fields(),
            salt=_SALT,
            iterations=3,
            content_key=_CONTENT_KEY,
            hmac_key=_HMAC_KEY,
            iv=_IV,
            random_source=DeterministicRandomSource(bytes(index % 251 for index in range(4096))),
        )
    )
    for index, (original, malicious) in enumerate(
        zip((2).to_bytes(4, "little"), declared_length.to_bytes(4, "little"), strict=True)
    ):
        data[152 + index] ^= original ^ malicious
    return bytes(data)



#### Reject every generated oversized field declaration without allocating storage proportional to its claim.
####
@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=(HealthCheck.function_scoped_fixture,),
)
@given(declared_length=oversized_uint32_field_lengths())
def test_declared_uint32_field_length_does_not_allocate(declared_length: int, tmp_path: Path) -> None:
    with tempfile.TemporaryDirectory(dir=tmp_path) as temporary_name:
        workspace = Path(temporary_name)
        backend = _XorBackend()
        malicious = _vault_with_declared_length(backend, declared_length)
        source = workspace / "malicious.psafe3"
        source.write_bytes(malicious)
        reader = PasswordSafeReader(backend, _private_directory(workspace))

        tracemalloc.start()
        try:
            with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase, pytest.raises(MalformedVaultError):
                reader.open(source, passphrase)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert peak < _MAXIMUM_PARSE_PEAK_BYTES
        assert not reader.has_quarantined_document
