"""Verify authenticated reader success, preservation, and owner lifetimes.

Every vault is built from fabricated data by the independent test helper.  The
tests never use a product writer or any external-client implementation material.
"""

import copy
import io
import json
import os
import pickle
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

import pytest

from bonobo_core.passwordsafe.botan import BotanBackend
from bonobo_core.passwordsafe.constants import HeaderFieldType, RecordFieldType, ResourceLimits
from bonobo_core.passwordsafe.crypto import TwofishKey, VaultKeys
from bonobo_core.passwordsafe.model import FieldClassification, PreservationWarningCode
from bonobo_core.passwordsafe.payloads import EncryptedSpanPayload, InlinePayload, PayloadClosedError
from bonobo_core.passwordsafe.reader import OpenedVault, PasswordSafeReader, VaultCryptoState
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.snapshots import EncryptedSnapshot, SnapshotClosedError
from tests.passwordsafe.helpers import DeterministicRandomSource, build_spec_vault



_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_VECTOR_PATH: Final[Path] = _ROOT / "tests" / "fixtures" / "synthetic" / "passwordsafe" / "reader-vectors.json"
_DEFAULT_BOTAN_LIBRARY: Final[Path] = _ROOT / "build" / "botan" / "bin" / "botan-3.dll"
_PASSPHRASE: Final[bytes] = b"fabricated-reader-passphrase"
_SALT: Final[bytes] = bytes(range(32))
_CONTENT_KEY: Final[bytes] = bytes(range(32, 64))
_HMAC_KEY: Final[bytes] = bytes(range(64, 96))
_IV: Final[bytes] = bytes(range(16))
_UUID: Final[bytes] = bytes.fromhex("22222222222242228222222222222222")
_UNKNOWN: Final[bytes] = bytes.fromhex("01020304")



#### Implement a deterministic reversible block transform for reader state-machine tests.
####
class _XorKey:
    __slots__ = ("_closed", "_mask")



    #### Retain one fabricated mask without providing a production cipher fallback.
    ####
    def __init__(self, key_material: SecretBuffer) -> None:
        self._mask = bytes(key_material.borrow()[:16])
        self._closed = False



    #### Apply the reversible fabricated block transform used by the test oracle.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("test key is closed")
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Reverse the same fabricated block transform.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)



    #### Mark the fabricated keyed context terminal.
    ####
    def close(self) -> None:
        self._closed = True



#### Supply the deterministic test-only cipher through the production protocol.
####
class _XorBackend:



    #### Yield one bounded test key and close it at context exit.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key = _XorKey(key_material)
        try:
            yield key
        finally:
            key.close()



    #### Complete the fake backend gate without representing production suitability.
    ####
    def self_test(self) -> None:
        return None



#### Create the owner-only directory required by encrypted snapshot capture.
####
def _private_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory



#### Return the exact valid field sequence described by the synthetic vector.
####
def _base_fields() -> tuple[tuple[int, bytes], ...]:
    return (
        (HeaderFieldType.VERSION, bytes.fromhex("0203")),
        (0xE0, _UNKNOWN),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _UUID),
        (RecordFieldType.TITLE, b"Alpha Portal"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.URL, b"https://alpha.example.invalid"),
        (0xE1, _UNKNOWN),
        (RecordFieldType.END, b""),
    )



#### Build one encrypted vault exclusively through the independent specification helper.
####
def _vault_bytes(
    backend: _XorBackend | BotanBackend,
    fields: tuple[tuple[int, bytes], ...],
    *,
    random_bytes: int = 4096,
) -> bytes:
    return build_spec_vault(
        backend,
        _PASSPHRASE,
        fields,
        salt=_SALT,
        iterations=3,
        content_key=_CONTENT_KEY,
        hmac_key=_HMAC_KEY,
        iv=_IV,
        random_source=DeterministicRandomSource(bytes(index % 251 for index in range(random_bytes))),
    )



#### Write one fabricated encrypted input for the public snapshot-owning boundary.
####
def _write_vault(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "fabricated.psafe3"
    path.write_bytes(data)
    return path



#### Open a valid synthetic vault and compare its complete redacted manifest.
####
def test_open_valid_synthetic_vault_matches_independent_manifest(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    path = _write_vault(tmp_path, _vault_bytes(backend, _base_fields()))
    expected = json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))["manifest"]

    passphrase = SecretBuffer.from_bytes(_PASSPHRASE)
    opened = reader.open(path, passphrase)

    manifest = opened.manifest
    assert manifest.version.value == 0x0302
    assert manifest.header_field_count == expected["header_field_count"]
    assert manifest.record_count == expected["record_count"]
    assert manifest.field_count == expected["field_count"]
    assert [
        {
            "section": entry.section,
            "record_ordinal": entry.record_ordinal,
            "field_ordinal": entry.field_ordinal,
            "type_code": entry.type_code,
            "length": entry.length,
            "sha256": entry.sha256,
        }
        for entry in manifest.entries
    ] == expected["entries"]
    assert not passphrase.closed
    assert not reader.has_quarantined_document
    opened.close()
    passphrase.close()



#### Preserve unknown fields, exact ordering, and warning coordinates after authentication.
####
def test_open_preserves_unknown_fields_and_order(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    opened = reader.open(
        _write_vault(tmp_path, _vault_bytes(backend, _base_fields())),
        SecretBuffer.from_bytes(_PASSPHRASE),
    )

    assert [field.type_code for field in opened.document.header_fields] == [0x00, 0xE0, 0xFF]
    assert [field.type_code for field in opened.document.records[0].fields] == [0x01, 0x03, 0x06, 0x0D, 0xE1, 0xFF]
    assert opened.document.header_fields[1].classification is FieldClassification.UNKNOWN
    assert opened.document.records[0].fields[4].classification is FieldClassification.UNKNOWN
    assert [(warning.code, warning.section, warning.field_ordinal) for warning in opened.document.warnings] == [
        (PreservationWarningCode.UNKNOWN_FIELD, "header", 1),
        (PreservationWarningCode.UNKNOWN_FIELD, "record", 4),
    ]
    opened.close()



#### Preserve duplicate and malformed optional fields with safe exact warnings.
####
def test_open_classifies_duplicate_and_malformed_optional_fields(tmp_path: Path) -> None:
    backend = _XorBackend()
    fields = (
        (HeaderFieldType.VERSION, bytes.fromhex("0203")),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _UUID),
        (RecordFieldType.TITLE, b"Alpha Portal"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.URL, b"https://alpha.example.invalid"),
        (RecordFieldType.URL, b"\xff"),
        (RecordFieldType.END, b""),
    )
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
        opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, fields)), passphrase)

    assert opened.document.records[0].fields[4].classification is FieldClassification.MALFORMED
    assert [warning.code for warning in opened.document.warnings] == [
        PreservationWarningCode.DUPLICATE_OPTIONAL_FIELD,
        PreservationWarningCode.MALFORMED_OPTIONAL_FIELD,
    ]
    opened.close()



#### Validate custom grammar without normalizing a legal empty value.
####
@pytest.mark.parametrize(
    ("encoded", "classification"),
    [
        (b"010004Name020000", FieldClassification.UNDERSTOOD),
        (b"010000020001v", FieldClassification.MALFORMED),
    ],
)
def test_open_preserves_custom_field_grammar_classification(
    tmp_path: Path,
    encoded: bytes,
    classification: FieldClassification,
) -> None:
    backend = _XorBackend()
    fields = (
        (HeaderFieldType.VERSION, bytes.fromhex("1103")),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _UUID),
        (RecordFieldType.TITLE, b"Alpha Portal"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.CUSTOM_TEXT_FIELD, encoded),
        (RecordFieldType.END, b""),
    )
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
        opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, fields)), passphrase)

    custom = opened.document.records[0].fields[3]
    assert custom.classification is classification
    assert b"".join(bytes(chunk) for chunk in custom.payload.iter_chunks(7)) == encoded
    opened.close()



#### Retain both authoritative TOTP start-time widths byte for byte.
####
@pytest.mark.parametrize("encoded", [bytes.fromhex("01020304"), bytes.fromhex("0102030405")])
def test_open_preserves_four_and_five_byte_totp_start_times(tmp_path: Path, encoded: bytes) -> None:
    backend = _XorBackend()
    fields = (
        (HeaderFieldType.VERSION, bytes.fromhex("0e03")),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _UUID),
        (RecordFieldType.TITLE, b"Alpha Portal"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.TOTP_START_TIME, encoded),
        (RecordFieldType.END, b""),
    )
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
        opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, fields)), passphrase)

    totp = opened.document.records[0].fields[3]
    assert b"".join(bytes(chunk) for chunk in totp.payload.iter_chunks(2)) == encoded
    opened.close()



#### Keep threshold-sized content inline and larger opaque content deferred.
####
def test_open_uses_authenticated_deferred_span_above_inline_limit(tmp_path: Path) -> None:
    backend = _XorBackend()
    opaque = bytes(index % 251 for index in range(65))
    fields = (*_base_fields()[:-1], (0xE2, opaque), (RecordFieldType.END, b""))
    limits = ResourceLimits(max_inline_payload_bytes=64, io_chunk_bytes=17)
    reader = PasswordSafeReader(backend, _private_directory(tmp_path), limits=limits)

    opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, fields)), SecretBuffer.from_bytes(_PASSPHRASE))

    assert isinstance(opened.document.records[0].fields[4].payload, InlinePayload)
    deferred = opened.document.records[0].fields[5].payload
    assert isinstance(deferred, EncryptedSpanPayload)
    assert b"".join(bytes(chunk) for chunk in deferred.iter_chunks(13)) == opaque
    opened.close()
    with pytest.raises((PayloadClosedError, SnapshotClosedError)):
        next(iter(deferred.iter_chunks(13)))



#### Exhaust payload cleanup before releasing borrowed keys and snapshot state.
####
def test_opened_close_is_exhaustive_after_one_payload_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
        opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, _base_fields())), passphrase)
    target = opened.document.header_fields[0].payload
    assert isinstance(target, InlinePayload)
    original_close = InlinePayload.close
    failed = False



    #### Raise once for one exact payload, then permit the aggregate retry to finish.
    ####
    def fail_once(payload: InlinePayload) -> None:
        nonlocal failed
        if payload is target and not failed:
            failed = True
            raise RuntimeError("synthetic cleanup failure")
        original_close(payload)



    monkeypatch.setattr(InlinePayload, "close", fail_once)

    with pytest.raises(RuntimeError, match="synthetic cleanup failure"):
        opened.close()

    assert opened.closed
    opened.close()



#### Preserve an active BaseException after aggregate cleanup reports a fault.
####
def test_opened_context_preserves_active_base_exception_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
        opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, _base_fields())), passphrase)
    target = opened.document.header_fields[0].payload
    assert isinstance(target, InlinePayload)
    original_close = InlinePayload.close
    failed = False



    #### Raise once so aggregate cleanup completes but reports a transient fault.
    ####
    def fail_once(payload: InlinePayload) -> None:
        nonlocal failed
        if payload is target and not failed:
            failed = True
            raise RuntimeError("synthetic cleanup failure")
        original_close(payload)



    monkeypatch.setattr(InlinePayload, "close", fail_once)

    with pytest.raises(KeyboardInterrupt), opened:
        raise KeyboardInterrupt

    assert opened.closed



#### Preserve an active BaseException after key-state cleanup reports a fault.
####
def test_crypto_state_context_preserves_active_base_exception_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
        opened = reader.open(_write_vault(tmp_path, _vault_bytes(backend, _base_fields())), passphrase)
    crypto_state = opened.crypto_state
    target = crypto_state.vault_keys
    original_close = VaultKeys.close
    failed = False



    #### Raise once so key cleanup completes but reports a transient fault.
    ####
    def fail_once(keys: VaultKeys) -> None:
        nonlocal failed
        if keys is target and not failed:
            failed = True
            original_close(keys)
            raise RuntimeError("synthetic cleanup failure")
        original_close(keys)



    monkeypatch.setattr(VaultKeys, "close", fail_once)

    with pytest.raises(KeyboardInterrupt), crypto_state:
        raise KeyboardInterrupt

    assert crypto_state.closed
    opened.close()
    assert opened.closed



#### Transfer a caller snapshot only after a successful internal authenticated open.
####
def test_open_snapshot_success_transfers_snapshot_to_opened_vault(tmp_path: Path) -> None:
    backend = _XorBackend()
    snapshot = EncryptedSnapshot.capture(
        io.BytesIO(_vault_bytes(backend, _base_fields())),
        _private_directory(tmp_path),
    )
    reader = PasswordSafeReader(backend, tmp_path / "private")

    opened = reader.open_snapshot(snapshot, SecretBuffer.from_bytes(_PASSPHRASE))

    assert opened.source_snapshot is snapshot
    opened.close()
    assert snapshot.closed



#### Make aggregate owners exclusive, nonserializable, and safe to represent.
####
@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_opened_and_crypto_owners_reject_copy_and_pickle(
    tmp_path: Path,
    operation: Callable[[object], object],
) -> None:
    backend = _XorBackend()
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    opened = reader.open(
        _write_vault(tmp_path, _vault_bytes(backend, _base_fields())),
        SecretBuffer.from_bytes(_PASSPHRASE),
    )

    with pytest.raises(TypeError):
        operation(opened)
    with pytest.raises(TypeError):
        operation(opened.crypto_state)
    assert "fabricated" not in repr(opened)
    assert "fabricated" not in repr(opened.crypto_state)
    opened.close()



#### Exercise the exact reader path against real Botan when qualification provides it.
####
def test_reader_uses_real_botan_when_configured(tmp_path: Path) -> None:
    configured = os.environ.get("BONOBO_TEST_BOTAN_LIBRARY")
    library = Path(configured) if configured is not None else _DEFAULT_BOTAN_LIBRARY
    if not library.is_file():
        pytest.skip("verified Botan host library is not available")
    backend = BotanBackend.open(library)
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))

    opened = reader.open(
        _write_vault(tmp_path, _vault_bytes(backend, _base_fields())),
        SecretBuffer.from_bytes(_PASSPHRASE),
    )

    assert opened.document.version.value == 0x0302
    opened.close()



#### Reopen a fresh-passphrase candidate only under its selected envelope policy.
####
def test_reopen_candidate_with_passphrase_checks_fresh_envelope(tmp_path: Path) -> None:
    backend = _XorBackend()
    source = _write_vault(tmp_path, _vault_bytes(backend, _base_fields()))
    reader = PasswordSafeReader(backend, _private_directory(tmp_path))
    passphrase = SecretBuffer.from_bytes(_PASSPHRASE)

    reopened = reader.reopen_candidate_with_passphrase(
        source,
        passphrase,
        expected_salt=_SALT,
        expected_iterations=3,
    )

    assert reopened.document.version.value == 0x0302
    reopened.close()
    passphrase.close()



#### Keep static type references to the ownership API under strict checking.
####
def _type_contract(opened: OpenedVault, state: VaultCryptoState) -> tuple[bool, bool]:
    return opened.closed, state.closed
