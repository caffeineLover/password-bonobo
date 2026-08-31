"""Verify reader mutations fail closed without partial document publication.

All malformed vaults are independently constructed with valid cryptographic
envelopes unless a test explicitly targets that envelope or its stored HMAC.
"""

import io
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

import pytest
from helpers import DeterministicRandomSource, build_spec_vault

import bonobo_core.passwordsafe.reader as reader_module
from bonobo_core.passwordsafe.constants import HeaderFieldType, RecordFieldType, ResourceLimits
from bonobo_core.passwordsafe.crypto import DerivedKey, TwofishKey
from bonobo_core.passwordsafe.crypto import stretch_passphrase as production_stretch
from bonobo_core.passwordsafe.errors import (
    AuthenticationError,
    IntegrityError,
    MalformedVaultError,
    PasswordSafeError,
    ResourceLimitError,
    ResourceLimitReason,
    UnsupportedFormatError,
)
from bonobo_core.passwordsafe.payloads import FieldPayload
from bonobo_core.passwordsafe.reader import PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.snapshots import EncryptedSnapshot



_PASSPHRASE: Final[bytes] = b"fabricated-reader-passphrase"
_SALT: Final[bytes] = bytes(range(32))
_CONTENT_KEY: Final[bytes] = bytes(range(32, 64))
_HMAC_KEY: Final[bytes] = bytes(range(64, 96))
_IV: Final[bytes] = bytes(range(16))
_UUID: Final[bytes] = bytes.fromhex("22222222222242228222222222222222")



#### Apply the deterministic reversible block operation used by malformed fixtures.
####
class _XorKey:
    __slots__ = ("_mask",)



    #### Retain the first fabricated key block as a reversible mask.
    ####
    def __init__(self, key_material: SecretBuffer) -> None:
        self._mask = bytes(key_material.borrow()[:16])



    #### XOR one exact block with the retained fabricated mask.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Reverse the symmetric fabricated block operation.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)



    #### Release no native state because this test key owns none.
    ####
    def close(self) -> None:
        return None



#### Count keyed operations and optionally raise a process-control exception.
####
class _XorBackend:
    key_calls: int



    #### Configure an optional failure after a selected keyed-context call.
    ####
    def __init__(self, *, interrupt_on_call: int | None = None) -> None:
        self.key_calls = 0
        self._interrupt_on_call = interrupt_on_call



    #### Yield a deterministic key or simulate one BaseException boundary.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        self.key_calls += 1
        if self.key_calls == self._interrupt_on_call:
            raise KeyboardInterrupt
        yield _XorKey(key_material)



    #### Complete the test-only backend gate.
    ####
    def self_test(self) -> None:
        return None



#### Create one private snapshot directory under the test-owned root.
####
def _private_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory



#### Return one structurally valid header and mandatory record sequence.
####
def _base_fields() -> tuple[tuple[int, bytes], ...]:
    return (
        (HeaderFieldType.VERSION, bytes.fromhex("0203")),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _UUID),
        (RecordFieldType.TITLE, b"Alpha Portal"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.END, b""),
    )



#### Construct authenticated fixture bytes without calling product codec code.
####
def _vault_bytes(
    backend: _XorBackend,
    fields: tuple[tuple[int, bytes], ...],
    *,
    iterations: int = 3,
) -> bytes:
    return build_spec_vault(
        backend,
        _PASSPHRASE,
        fields,
        salt=_SALT,
        iterations=iterations,
        content_key=_CONTENT_KEY,
        hmac_key=_HMAC_KEY,
        iv=_IV,
        random_source=DeterministicRandomSource(bytes(index % 251 for index in range(8192))),
    )



#### Write one encrypted mutation for the public open boundary.
####
def _write_vault(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "sensitive-vault-name.psafe3"
    path.write_bytes(data)
    return path



#### Reject each authenticated mandatory-structure mutation without publication.
####
@pytest.mark.parametrize(
    "fields,error_type",
    [
        (((HeaderFieldType.END, b""),), MalformedVaultError),
        (((HeaderFieldType.VERSION, b"\x02"), (HeaderFieldType.END, b"")), MalformedVaultError),
        (((HeaderFieldType.VERSION, bytes.fromhex("0004")), (HeaderFieldType.END, b"")), UnsupportedFormatError),
        (
            ((0xE0, b"x"), (HeaderFieldType.VERSION, bytes.fromhex("0203")), (HeaderFieldType.END, b"")),
            MalformedVaultError,
        ),
        (((HeaderFieldType.VERSION, bytes.fromhex("0203")),), MalformedVaultError),
        (
            (
                (HeaderFieldType.VERSION, bytes.fromhex("0203")),
                (HeaderFieldType.END, b""),
                (RecordFieldType.UUID, _UUID),
                (RecordFieldType.TITLE, b"Alpha Portal"),
                (RecordFieldType.PASSWORD, b"fabricated-credential"),
            ),
            MalformedVaultError,
        ),
        (
            (
                (HeaderFieldType.VERSION, bytes.fromhex("0203")),
                (HeaderFieldType.END, b""),
                (RecordFieldType.TITLE, b"Alpha Portal"),
                (RecordFieldType.PASSWORD, b"fabricated-credential"),
                (RecordFieldType.END, b""),
            ),
            MalformedVaultError,
        ),
        (
            (
                (HeaderFieldType.VERSION, bytes.fromhex("0203")),
                (HeaderFieldType.END, b""),
                (RecordFieldType.UUID, bytes(16)),
                (RecordFieldType.TITLE, b"Alpha Portal"),
                (RecordFieldType.PASSWORD, b"fabricated-credential"),
                (RecordFieldType.END, b""),
            ),
            MalformedVaultError,
        ),
    ],
)
def test_authenticated_structure_mutations_fail_closed(
    tmp_path: Path,
    fields: tuple[tuple[int, bytes], ...],
    error_type: type[PasswordSafeError],
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with pytest.raises(error_type):
        reader.open(_write_vault(tmp_path, _vault_bytes(backend, fields)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert not reader.has_quarantined_document



#### Reject a wrong passphrase through only the closed authentication taxonomy.
####
def test_wrong_password_fails_without_secret_or_path_context(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    path = _write_vault(tmp_path, _vault_bytes(backend, _base_fields()))

    with pytest.raises(AuthenticationError) as caught:
        reader.open(path, SecretBuffer.from_bytes(b"fabricated-wrong-password"))

    assert caught.value.__context__ is None
    assert "wrong" not in str(caught.value)
    assert "sensitive-vault-name" not in str(caught.value)
    assert not reader.has_quarantined_document



#### Reject a changed stored HMAC only after the encrypted document is consumed.
####
def test_wrong_hmac_discards_quarantined_payloads(tmp_path: Path) -> None:
    backend = _XorBackend()
    data = bytearray(_vault_bytes(backend, _base_fields()))
    data[-1] ^= 1
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with pytest.raises(IntegrityError):
        reader.open(_write_vault(tmp_path, bytes(data)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert not reader.has_quarantined_document
    assert tuple((tmp_path / "private").iterdir()) == ()



#### Defer optional iteration hardening until stored-HMAC authentication succeeds.
####
def test_wrong_hmac_does_not_prepare_hardened_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    data = bytearray(_vault_bytes(backend, _base_fields()))
    data[-1] ^= 1
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    stretch_calls = 0



    #### Permit unlock derivation but reject any preauthentication hardening pass.
    ####
    def reject_early_hardening(
        passphrase: SecretBuffer,
        salt: bytes,
        iterations: int,
        *,
        limits: ResourceLimits,
    ) -> DerivedKey:
        nonlocal stretch_calls
        stretch_calls += 1
        if stretch_calls > 1:
            raise AssertionError("hardening ran before stored-HMAC validation")
        return production_stretch(passphrase, salt, iterations, limits=limits)



    monkeypatch.setattr(reader_module, "stretch_passphrase", reject_early_hardening)

    with pytest.raises(IntegrityError):
        reader.open(_write_vault(tmp_path, bytes(data)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert stretch_calls == 1
    assert not reader.has_quarantined_document



#### Validate fixed envelope and terminal boundaries before parsing field content.
####
@pytest.mark.parametrize("mutation", ["short", "tag", "eof", "trailing", "unaligned", "zero-encrypted"])
def test_envelope_boundary_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    backend = _XorBackend()
    original = _vault_bytes(backend, _base_fields())
    if mutation == "short":
        data = original[:151]
    elif mutation == "tag":
        data = b"NOPE" + original[4:]
    elif mutation == "eof":
        data = original[:-48] + b"X" * 16 + original[-32:]
    elif mutation == "trailing":
        data = original + bytes(16)
    elif mutation == "unaligned":
        data = original[:153] + original[168:]
    else:
        data = original[:152] + original[-48:]
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with pytest.raises(PasswordSafeError) as caught:
        reader.open(_write_vault(tmp_path, data), SecretBuffer.from_bytes(_PASSPHRASE))

    assert caught.value.__context__ is None
    assert not reader.has_quarantined_document



#### Reject an iteration budget before stretching or opening any keyed context.
####
def test_iteration_limit_is_checked_before_large_work(tmp_path: Path) -> None:
    backend = _XorBackend()
    data = bytearray(_vault_bytes(backend, _base_fields()))
    data[36:40] = (4).to_bytes(4, "little")
    backend.key_calls = 0
    limits = ResourceLimits(max_iterations=3)
    reader = PasswordSafeReader(backend, _private_directory(tmp_path), limits=limits)

    with pytest.raises(ResourceLimitError):
        reader.open(_write_vault(tmp_path, bytes(data)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert backend.key_calls == 0
    assert not reader.has_quarantined_document



#### Accept a public-open source exactly at the caller's encrypted-file boundary.
####
def test_public_open_accepts_exact_encrypted_file_budget(tmp_path: Path) -> None:
    backend = _XorBackend()
    data = _vault_bytes(backend, _base_fields())
    reader = PasswordSafeReader(
        backend,
        _private_directory(tmp_path),
        limits=ResourceLimits(max_encrypted_file_bytes=len(data)),
    )

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase, reader.open(
        _write_vault(tmp_path, data),
        passphrase,
    ) as opened:
        assert opened.source_snapshot.size == len(data)



#### Reject public-open input while capture crosses the encrypted-file budget.
####
def test_public_open_rejects_encrypted_file_over_budget_and_cleans_snapshot(tmp_path: Path) -> None:
    backend = _XorBackend()
    data = _vault_bytes(backend, _base_fields())
    backend.key_calls = 0
    directory = _private_directory(tmp_path)
    reader = PasswordSafeReader(
        backend,
        directory,
        limits=ResourceLimits(max_encrypted_file_bytes=len(data) - 1, io_chunk_bytes=17),
    )
    passphrase = SecretBuffer.from_bytes(_PASSPHRASE)

    with pytest.raises(ResourceLimitError) as caught:
        reader.open(_write_vault(tmp_path, data), passphrase)

    assert caught.value.reason == ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES
    assert caught.value.__context__ is None
    assert backend.key_calls == 0
    assert not passphrase.closed
    assert not reader.has_quarantined_document
    assert tuple(directory.iterdir()) == ()
    passphrase.close()



#### Reject an oversized caller snapshot before any reader crypto or parser read.
####
def test_open_snapshot_rejects_encrypted_file_over_budget_before_crypto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    data = _vault_bytes(backend, _base_fields())
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(data), directory)
    backend.key_calls = 0
    reader = PasswordSafeReader(
        backend,
        directory,
        limits=ResourceLimits(max_encrypted_file_bytes=len(data) - 1),
    )
    read_calls = 0
    original_read_at = EncryptedSnapshot.read_at



    #### Count any forbidden reader access while preserving real snapshot behavior.
    ####
    def count_read(snapshot_owner: EncryptedSnapshot, offset: int, length: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return original_read_at(snapshot_owner, offset, length)



    monkeypatch.setattr(EncryptedSnapshot, "read_at", count_read)

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase, pytest.raises(ResourceLimitError) as caught:
        reader.open_snapshot(snapshot, passphrase)

    assert caught.value.reason == ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES
    assert caught.value.__context__ is None
    assert backend.key_calls == 0
    assert read_calls == 0
    assert not snapshot.closed
    assert not reader.has_quarantined_document
    snapshot.close()



#### Reject uint32 field-length overrun before allocating declared payload storage.
####
def test_declared_uint32_length_overrun_fails_before_payload_allocation(tmp_path: Path) -> None:
    backend = _XorBackend()
    data = bytearray(_vault_bytes(backend, _base_fields()))
    original_length = (2).to_bytes(4, "little")
    malicious_length = (0xFFFF_FFFF).to_bytes(4, "little")
    for index, (original, malicious) in enumerate(zip(original_length, malicious_length, strict=True)):
        data[152 + index] ^= original ^ malicious
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with pytest.raises(MalformedVaultError):
        reader.open(_write_vault(tmp_path, bytes(data)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert not reader.has_quarantined_document



#### Reject authenticated field and record counts before publishing a document.
####
@pytest.mark.parametrize(
    "limits,fields",
    [
        (ResourceLimits(max_fields=5), _base_fields()),
        (
            ResourceLimits(max_records=1),
            (
                *_base_fields(),
                (RecordFieldType.UUID, _UUID),
                (RecordFieldType.TITLE, b"Second"),
                (RecordFieldType.PASSWORD, b"second-secret"),
                (RecordFieldType.END, b""),
            ),
        ),
    ],
)
def test_resource_counts_fail_closed(
    tmp_path: Path,
    limits: ResourceLimits,
    fields: tuple[tuple[int, bytes], ...],
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path), limits=limits)

    with pytest.raises(ResourceLimitError):
        reader.open(_write_vault(tmp_path, _vault_bytes(backend, fields)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert not reader.has_quarantined_document



#### Reject an extra record before reading or processing its first large field.
####
def test_record_limit_precedes_any_over_budget_record_payload_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    fields = (*_base_fields(), (0xE0, b"Z" * 262_144), (RecordFieldType.END, b""))
    data = _vault_bytes(backend, fields)
    reader = PasswordSafeReader(
        backend,
        _private_directory(tmp_path),
        limits=ResourceLimits(max_records=1),
    )
    read_offsets: list[int] = []
    original_read_at = EncryptedSnapshot.read_at



    #### Record real snapshot reads without changing their data or ownership effects.
    ####
    def record_read(snapshot: EncryptedSnapshot, offset: int, length: int) -> bytes:
        read_offsets.append(offset)
        return original_read_at(snapshot, offset, length)



    monkeypatch.setattr(EncryptedSnapshot, "read_at", record_read)

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase, pytest.raises(ResourceLimitError) as caught:
        reader.open(_write_vault(tmp_path, data), passphrase)

    assert caught.value.reason == ResourceLimitReason.MAX_RECORDS
    assert [offset for offset in read_offsets if 296 <= offset < len(data) - 48] == []
    assert not reader.has_quarantined_document
    assert tuple((tmp_path / "private").iterdir()) == ()



#### Leave an internal caller-owned snapshot live when authentication fails.
####
def test_open_snapshot_failure_retains_caller_snapshot(tmp_path: Path) -> None:
    backend = _XorBackend()
    snapshot = EncryptedSnapshot.capture(
        io.BytesIO(_vault_bytes(backend, _base_fields())),
        _private_directory(tmp_path),
    )
    reader = PasswordSafeReader(backend, tmp_path / "private")

    with pytest.raises(AuthenticationError):
        reader.open_snapshot(snapshot, SecretBuffer.from_bytes(b"fabricated-wrong-password"))

    assert not snapshot.closed
    assert not reader.has_quarantined_document
    snapshot.close()



#### Clean public-owned snapshots and partial owners across BaseException propagation.
####
def test_public_open_cleans_quarantine_on_base_exception(tmp_path: Path) -> None:
    builder = _XorBackend()
    data = _vault_bytes(builder, _base_fields())
    backend = _XorBackend(interrupt_on_call=2)
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    passphrase = SecretBuffer.from_bytes(_PASSPHRASE)

    with pytest.raises(KeyboardInterrupt):
        reader.open(_write_vault(tmp_path, data), passphrase)

    assert not passphrase.closed
    assert not reader.has_quarantined_document
    assert tuple((tmp_path / "private").iterdir()) == ()
    passphrase.close()



#### Close a just-created payload if private-builder insertion raises BaseException.
####
def test_builder_insertion_base_exception_closes_untransferred_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    captured: list[FieldPayload] = []



    #### Capture the untransferred owner, then interrupt before builder adoption.
    ####
    def interrupt_add(
        _builder: object,
        *,
        header: bool,
        record_ordinal: int,
        type_code: int,
        payload: FieldPayload,
    ) -> None:
        del header, record_ordinal, type_code
        captured.append(payload)
        raise KeyboardInterrupt



    monkeypatch.setattr(reader_module._QuarantinedBuilder, "add_field", interrupt_add)

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase, pytest.raises(KeyboardInterrupt):
        reader.open(_write_vault(tmp_path, _vault_bytes(backend, _base_fields())), passphrase)

    assert len(captured) == 1
    assert getattr(captured[0], "closed", False)
    assert not reader.has_quarantined_document
