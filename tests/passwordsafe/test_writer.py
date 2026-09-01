"""Verify authenticated candidate serialization and retained envelope policy.

The tests build source vaults with the independent format helper, then exercise
the product writer through its real reader and ordered document boundaries.
"""

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from helpers import DeterministicRandomSource, build_spec_vault

from bonobo_core.passwordsafe.constants import HeaderFieldType, RecordFieldType, ResourceLimits
from bonobo_core.passwordsafe.crypto import TwofishKey
from bonobo_core.passwordsafe.model import documents_equal_exact
from bonobo_core.passwordsafe.payloads import EncryptedSpanPayload
from bonobo_core.passwordsafe.reader import OpenedVault, PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.writer import PasswordSafeWriter



_PASSPHRASE: Final[bytes] = b"fabricated-writer-passphrase"
_SALT: Final[bytes] = bytes(range(32))
_CONTENT_KEY: Final[bytes] = bytes(range(32, 64))
_HMAC_KEY: Final[bytes] = bytes(range(64, 96))
_IV: Final[bytes] = bytes(range(16))
_UUID: Final[bytes] = bytes.fromhex("22222222222242228222222222222222")
_DEFAULT_LIMITS: Final[ResourceLimits] = ResourceLimits()



#### Implement one deterministic reversible block transform for codec tests.
####
class _XorKey:
    __slots__ = ("_closed", "_mask")



    #### Retain one fabricated mask for the lifetime of this test key.
    ####
    def __init__(self, key_material: SecretBuffer) -> None:
        self._mask = bytes(key_material.borrow()[:16])
        self._closed = False



    #### Apply the reversible fabricated transform to one exact block.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("test key is closed")
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Reverse the same fabricated block transform.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)



    #### Make this test key terminal at backend context exit.
    ####
    def close(self) -> None:
        self._closed = True



#### Supply the deterministic test cipher through the production protocol.
####
class _XorBackend:



    #### Yield one scoped key and close it after the codec operation.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key = _XorKey(key_material)
        try:
            yield key
        finally:
            key.close()



    #### Complete the fake backend gate without claiming production suitability.
    ####
    def self_test(self) -> None:
        return None



#### Create one owner-only directory accepted by snapshot and candidate writers.
####
def _private_directory(tmp_path: Path, name: str) -> Path:
    directory = tmp_path / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory



#### Return one valid ordered document with fabricated unknown fields.
####
def _base_fields() -> tuple[tuple[int, bytes], ...]:
    return (
        (HeaderFieldType.VERSION, bytes.fromhex("0203")),
        (0xE0, bytes.fromhex("01020304")),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _UUID),
        (RecordFieldType.TITLE, b"Alpha Portal"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.URL, b"https://alpha.example.invalid"),
        (0xE1, bytes.fromhex("05060708")),
        (RecordFieldType.END, b""),
    )



#### Open one independently constructed weak-iteration source vault.
####
def _opened_source(
    tmp_path: Path,
    backend: _XorBackend,
    *,
    fields: tuple[tuple[int, bytes], ...] | None = None,
    limits: ResourceLimits = _DEFAULT_LIMITS,
) -> tuple[PasswordSafeReader, OpenedVault, Path]:
    source = tmp_path / "fabricated-source.psafe3"
    source.write_bytes(
        build_spec_vault(
            backend,
            _PASSPHRASE,
            _base_fields() if fields is None else fields,
            salt=_SALT,
            iterations=3,
            content_key=_CONTENT_KEY,
            hmac_key=_HMAC_KEY,
            iv=_IV,
            random_source=DeterministicRandomSource(bytes(index % 251 for index in range(4096))),
        )
    )
    reader = PasswordSafeReader(backend, _private_directory(tmp_path, "snapshots"), limits=limits)
    opened = reader.open(source, SecretBuffer.from_bytes(_PASSPHRASE))
    return reader, opened, source



#### Serialize and reopen every raw byte without changing the source document.
####
def test_no_edit_round_trip_preserves_exact_document(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    source_before = source.read_bytes()
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "candidates"),
        random_source=DeterministicRandomSource(bytes(index % 239 for index in range(8192))),
    )

    candidate = writer.write(opened.document, opened.crypto_state)
    reopened = reader.reopen_candidate(candidate.path, opened.crypto_state)

    assert documents_equal_exact(opened.document, reopened.document)
    assert candidate.manifest == opened.manifest
    assert candidate.reopened_manifest == opened.manifest
    assert candidate.sha256 == hashlib.sha256(candidate.path.read_bytes()).hexdigest()
    assert source.read_bytes() == source_before
    reopened.close()
    opened.close()



#### Harden weak stretching while retaining the original salt and format level.
####
def test_weak_iteration_round_trip_uses_prepared_hardening(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "candidates"),
        random_source=DeterministicRandomSource(bytes(index % 233 for index in range(8192))),
    )

    candidate = writer.write(opened.document, opened.crypto_state)
    prefix = candidate.path.read_bytes()[:40]

    assert prefix[4:36] == _SALT
    assert int.from_bytes(prefix[36:40], "little") == 262_144
    assert candidate.manifest.version == opened.document.version
    opened.close()



#### Stream an authenticated deferred unknown field through candidate verification.
####
def test_deferred_payload_round_trip_stays_streamed(tmp_path: Path) -> None:
    backend = _XorBackend()
    large_unknown = bytes(index % 251 for index in range(257))
    fields = tuple(
        (type_code, large_unknown if type_code == 0xE1 else payload)
        for type_code, payload in _base_fields()
    )
    limits = ResourceLimits(max_inline_payload_bytes=32, io_chunk_bytes=16)
    reader, opened, _source = _opened_source(tmp_path, backend, fields=fields, limits=limits)
    deferred = opened.document.records[0].fields[4].payload
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "candidates"),
        random_source=DeterministicRandomSource(bytes(index % 211 for index in range(16384))),
        limits=limits,
    )

    candidate = writer.write(opened.document, opened.crypto_state)

    assert isinstance(deferred, EncryptedSpanPayload)
    assert candidate.manifest == opened.manifest
    opened.close()



#### Generate independent encrypted bytes for identical plaintext revisions.
####
def test_repeated_writes_use_fresh_envelope_material(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "candidates"),
        random_source=DeterministicRandomSource(bytes(index % 199 for index in range(16384))),
    )

    first = writer.write(opened.document, opened.crypto_state)
    second = writer.write(opened.document, opened.crypto_state)

    first_bytes = first.path.read_bytes()
    second_bytes = second.path.read_bytes()

    assert first_bytes != second_bytes
    assert first_bytes[72:104] != second_bytes[72:104]
    assert first_bytes[104:136] != second_bytes[104:136]
    assert first_bytes[136:152] != second_bytes[136:152]
    assert first.manifest == second.manifest == opened.manifest
    opened.close()



#### Generate a new salt and wrapping key for a fresh-passphrase candidate.
####
def test_fresh_passphrase_write_uses_new_envelope_material(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "fresh-candidates"),
        random_source=DeterministicRandomSource(
            _SALT + bytes((index + 97) % 197 for index in range(16384)),
        ),
    )
    passphrase = SecretBuffer.from_bytes(b"fabricated-replacement-passphrase")

    candidate = writer.write_new(opened.document, passphrase, excluded_salt=_SALT)
    prefix = candidate.path.read_bytes()[:40]
    reopened = reader.reopen_candidate_with_passphrase(
        candidate.path,
        passphrase,
        expected_salt=prefix[4:36],
        expected_iterations=262_144,
    )

    assert prefix[4:36] != _SALT
    assert int.from_bytes(prefix[36:40], "little") == 262_144
    assert documents_equal_exact(opened.document, reopened.document)
    reopened.close()
    passphrase.close()
    opened.close()
