"""Verify independently authored PasswordSafe interoperability fixture evidence.

The tests enforce the exact synthetic fixture set, redacted ordered-manifest schema,
authority metadata, encrypted digests, and repository provenance coverage. Real
Botan authentication extracts only ordered redacted evidence and never exposes the
fabricated passphrase or typed field values.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from io import BytesIO, StringIO
from pathlib import Path
from typing import cast

import pytest
from helpers import DeterministicRandomSource, build_spec_vault
from tools.verify_passwordsafe_interop import (
    FieldTarget,
    InteropMismatchError,
    ManifestMetadata,
    compare_vaults,
    extract_ordered_manifest,
    render_manifest,
    run_cli,
)

from bonobo_core.passwordsafe.botan import BotanBackend
from bonobo_core.passwordsafe.constants import HeaderFieldType, RecordFieldType
from bonobo_core.passwordsafe.crypto import TwofishKey
from bonobo_core.passwordsafe.secrets import SecretBuffer



REPOSITORY_ROOT = Path(__file__).parents[2]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures" / "synthetic" / "passwordsafe"
LEDGER_PATH = REPOSITORY_ROOT / "docs" / "legal" / "dependency-asset-provenance-ledger.md"
REUSE_PATH = REPOSITORY_ROOT / "REUSE.toml"
TRANSACTION_PATH = FIXTURE_ROOT / "interop-transactions.json"
INTEROP_STEMS = frozenset(
    {
        "bonobo-0311",
        "passwordsafe-current",
        "gorilla-6728e85",
        "official-unknown-0302",
    }
)
EXPECTED_AUTHORITIES = {
    "bonobo-0311": ("Bonobo", "0.1.0", "0x0311", "bonobo-service"),
    "passwordsafe-current": ("Password Safe 3.72.1", "3.72.1", "0x0311", "password-safe-cli"),
    "gorilla-6728e85": (
        "Gorilla 6728e85",
        "6728e85c05ac25357b8f19f541487b9d26a97402",
        "0x0300",
        "gorilla-runtime",
    ),
    "official-unknown-0302": (
        "Independent PasswordSafe V3 fixture authority",
        "formatV3.txt",
        "0x0302",
        "independent-format-constructor",
    ),
}
EXPECTED_ENCRYPTED_HASHES = {
    "bonobo-0311": "97900c193c2b4a67e345519f4f50de1fb6af7d86951ae8c541981bb85f1ed0f0",
    "passwordsafe-current": "a5f856c99e70f801b4286f5f6f89c96c257b1a81ec1109fc80c1b2e3d24b8b47",
    "gorilla-6728e85": "3a7772a31398aa5edf88646b4254fe93b5116ab9e19073c0408287a2cc1853ad",
    "official-unknown-0302": "4e58f02225ad4782b33eebb3996644cdedb81b67eee65836759171d0c17ba3d3",
}
MANIFEST_SCHEMA = "password-bonobo-interoperability-manifest-v1"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
TYPE_HEX = re.compile(r"0x[0-9a-f]{2}")
ENTRY_KEYS = frozenset(
    {
        "section",
        "record_ordinal",
        "field_ordinal",
        "type",
        "length",
        "payload_sha256",
    }
)
MANIFEST_KEYS = frozenset(
    {
        "authority",
        "authority_version",
        "creation_method",
        "encrypted_sha256",
        "entries",
        "field_count",
        "fixture",
        "format_version",
        "header_field_count",
        "passphrase_input",
        "platform",
        "record_count",
        "schema",
        "tooling",
    }
)
TRANSACTION_KEYS = frozenset(
    {
        "backup_sha256",
        "client",
        "discarded_sequential_title_sha256",
        "exact_no_edit_result",
        "no_edit_sha256",
        "normalization",
        "normalized_baseline_sha256",
        "source_fixture",
        "source_sha256",
        "title_edit_sha256",
        "title_only_result",
    }
)
TRANSACTION_TOP_LEVEL_KEYS = frozenset(
    {"external_artifacts", "performed_on", "platform", "schema", "transactions"}
)
EXTERNAL_ARTIFACT_KEYS = frozenset(
    {
        "gorilla_commit",
        "password_safe_archive_sha256",
        "password_safe_version",
        "tclkit_sha256",
        "tclkit_version",
    }
)
EXPECTED_EXTERNAL_ARTIFACTS = {
    "gorilla_commit": "6728e85c05ac25357b8f19f541487b9d26a97402",
    "password_safe_archive_sha256": "2fe5c8e170ffc0c946d8d19b7b09680e965b15b5a8cfbb70d62d4faea1b74f9d",
    "password_safe_version": "3.72.1",
    "tclkit_sha256": "4008f8938ba60edaf9c7c72b1bd5330b4c60c3f4b10d9cd1ef25da0ac06333f1",
    "tclkit_version": "8.6.9",
}
EXPECTED_TRANSACTION_RELATIONSHIPS = {
    ("Bonobo 0.1.0", "gorilla-6728e85.psafe3"): EXPECTED_ENCRYPTED_HASHES["gorilla-6728e85"],
    ("Bonobo 0.1.0", "official-unknown-0302.psafe3"): EXPECTED_ENCRYPTED_HASHES["official-unknown-0302"],
    ("Bonobo 0.1.0", "passwordsafe-current.psafe3"): EXPECTED_ENCRYPTED_HASHES["passwordsafe-current"],
    ("Gorilla 6728e85", "bonobo-0311.psafe3"): EXPECTED_ENCRYPTED_HASHES["bonobo-0311"],
    ("Password Safe 3.72.1", "bonobo-0311.psafe3"): EXPECTED_ENCRYPTED_HASHES["bonobo-0311"],
}
REDACTED_LITERALS = (
    "fabricated-master-input-one",
    "fabricated-credential",
    "https://alpha.example.invalid",
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
)
_PASSPHRASE = b"fabricated-master-input-one"
_DATABASE_UUID = bytes.fromhex("11111111111141118111111111111111")
_RECORD_UUID = bytes.fromhex("22222222222242228222222222222222")
_UNKNOWN_HEADER = bytes.fromhex("f0e1d2c3")
_UNKNOWN_RECORD = bytes.fromhex("10213243")



#### Implement the deterministic reversible block operation used only by this tool test.
####
class _XorKey:
    __slots__ = ("_closed", "_mask")



    #### Retain a fabricated 16-byte mask from one test-owned key buffer.
    ####
    def __init__(self, key_material: SecretBuffer) -> None:
        self._closed = False
        self._mask = bytes(key_material.borrow()[:16])



    #### Apply the reversible test transform to one block.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        if self._closed:
            raise RuntimeError("test key is closed")
        return bytes(value ^ self._mask[index] for index, value in enumerate(block))



    #### Reverse the same fabricated transform.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)



    #### Make this fabricated key terminal.
    ####
    def close(self) -> None:
        self._closed = True



#### Supply test-only keys without representing a production cryptographic backend.
####
class _XorBackend:



    #### Yield and deterministically close one fabricated key.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key = _XorKey(key_material)
        try:
            yield key
        finally:
            key.close()



    #### Complete the reader's backend qualification hook for this isolated test.
    ####
    def self_test(self) -> None:
        return None



#### Return one exact standard-and-unknown synthetic field sequence.
####
def _interop_fields(
    *,
    title: bytes = b"Alpha Portal",
    unknown_record: bytes = _UNKNOWN_RECORD,
) -> tuple[tuple[int, bytes], ...]:
    return (
        (HeaderFieldType.VERSION, bytes.fromhex("0203")),
        (HeaderFieldType.UUID, _DATABASE_UUID),
        (0xE0, _UNKNOWN_HEADER),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, _RECORD_UUID),
        (RecordFieldType.TITLE, title),
        (RecordFieldType.USERNAME, b"fabricated-user"),
        (RecordFieldType.PASSWORD, b"fabricated-credential"),
        (RecordFieldType.URL, b"https://alpha.example.invalid"),
        (0xE1, unknown_record),
        (RecordFieldType.END, b""),
    )



#### Write one independently constructed deterministic test vault.
####
def _write_test_vault(path: Path, fields: tuple[tuple[int, bytes], ...]) -> None:
    backend = _XorBackend()
    path.write_bytes(
        build_spec_vault(
            backend,
            _PASSPHRASE,
            fields,
            salt=bytes(range(32)),
            iterations=3,
            content_key=bytes(range(32, 64)),
            hmac_key=bytes(range(64, 96)),
            iv=bytes(range(16)),
            random_source=DeterministicRandomSource(bytes(index % 251 for index in range(4096))),
        )
    )



#### Return the SHA-256 of one encrypted fixture without loading it all at once.
####
def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()



#### Load one JSON object and reject a non-object top-level manifest.
####
def _load_manifest(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return cast(dict[str, object], document)



#### Resolve the required real Botan library or skip only an optional local build.
####
def _botan_library_path() -> Path:
    configured = os.environ.get("BONOBO_TEST_BOTAN_LIBRARY")
    library = (
        Path(configured)
        if configured is not None
        else REPOSITORY_ROOT / "build" / "botan" / "bin" / "botan-3.dll"
    )
    if configured is not None and not library.is_file():
        pytest.fail("required BONOBO_TEST_BOTAN_LIBRARY does not exist")
    if os.environ.get("CI") and not library.is_file():
        pytest.fail("CI requires BONOBO_TEST_BOTAN_LIBRARY")
    if not library.is_file():
        pytest.skip("optional local Botan build is unavailable")
    return library



#### Return every path covered by the repository's aggregate REUSE annotation.
####
def _reuse_paths() -> frozenset[str]:
    document = tomllib.loads(REUSE_PATH.read_text(encoding="utf-8"))
    annotations = cast(list[dict[str, object]], document["annotations"])
    paths = {
        path
        for annotation in annotations
        for path in cast(list[str], annotation["path"])
    }
    return frozenset(paths)



#### Require the exact four encrypted fixtures and their same-stem manifests.
####
def test_every_interop_fixture_has_one_manifest() -> None:
    fixtures = {path.stem for path in FIXTURE_ROOT.glob("*.psafe3")}
    manifests = {
        path.name.removesuffix(".manifest.json")
        for path in FIXTURE_ROOT.glob("*.manifest.json")
    }

    assert fixtures == INTEROP_STEMS
    assert manifests == INTEROP_STEMS



#### Bind each fixture to its exact authority, format, construction method, and encrypted digest.
####
def test_every_interop_manifest_records_exact_authority_and_digest() -> None:
    for stem in sorted(INTEROP_STEMS):
        fixture = FIXTURE_ROOT / f"{stem}.psafe3"
        manifest_path = FIXTURE_ROOT / f"{stem}.manifest.json"
        if not fixture.exists() or not manifest_path.exists():
            continue
        manifest = _load_manifest(manifest_path)
        authority, authority_version, format_version, creation_method = EXPECTED_AUTHORITIES[stem]

        assert frozenset(manifest) == MANIFEST_KEYS
        assert manifest["schema"] == MANIFEST_SCHEMA
        assert manifest["fixture"] == fixture.name
        assert manifest["authority"] == authority
        assert manifest["authority_version"] == authority_version
        assert manifest["format_version"] == format_version
        assert manifest["creation_method"] == creation_method
        assert manifest["passphrase_input"] == "stdin"
        assert isinstance(manifest["platform"], str) and manifest["platform"]
        assert isinstance(manifest["tooling"], list) and manifest["tooling"]
        assert all(isinstance(item, str) and item for item in manifest["tooling"])
        assert manifest["encrypted_sha256"] == EXPECTED_ENCRYPTED_HASHES[stem]
        assert manifest["encrypted_sha256"] == _sha256_file(fixture)



#### Retain hash-only evidence for every manually executed cross-client transaction.
####
def test_interop_transactions_have_closed_redacted_schema() -> None:
    source = TRANSACTION_PATH.read_text(encoding="utf-8")
    document = json.loads(source)

    assert isinstance(document, dict)
    assert frozenset(document) == TRANSACTION_TOP_LEVEL_KEYS
    assert document["schema"] == "password-bonobo-interoperability-transactions-v1"
    assert document["performed_on"] == "2026-09-01"
    assert isinstance(document["platform"], str) and document["platform"]
    external_artifacts = document["external_artifacts"]
    assert isinstance(external_artifacts, dict)
    assert frozenset(external_artifacts) == EXTERNAL_ARTIFACT_KEYS
    assert external_artifacts == EXPECTED_EXTERNAL_ARTIFACTS
    transactions = document["transactions"]
    assert isinstance(transactions, list) and len(transactions) == 5
    relationships: dict[tuple[object, object], object] = {}
    for raw_transaction in transactions:
        assert isinstance(raw_transaction, dict)
        transaction = cast(dict[str, object], raw_transaction)
        assert frozenset(transaction) == TRANSACTION_KEYS
        assert transaction["exact_no_edit_result"] in {
            "match",
            "match from normalized baseline",
        }
        assert transaction["title_only_result"] in {
            "match",
            "match from normalized baseline",
            "match from paired normalized baseline",
        }
        for key in ("source_sha256", "no_edit_sha256", "title_edit_sha256"):
            value = transaction[key]
            assert isinstance(value, str) and SHA256_HEX.fullmatch(value)
        for key in ("normalized_baseline_sha256", "discarded_sequential_title_sha256"):
            value = transaction[key]
            assert value is None or (isinstance(value, str) and SHA256_HEX.fullmatch(value))
        backups = transaction["backup_sha256"]
        assert isinstance(backups, list)
        assert all(isinstance(value, str) and SHA256_HEX.fullmatch(value) for value in backups)
        relationship = (transaction["client"], transaction["source_fixture"])
        assert relationship not in relationships
        relationships[relationship] = transaction["source_sha256"]
    assert relationships == EXPECTED_TRANSACTION_RELATIONSHIPS
    assert not any(literal in source for literal in REDACTED_LITERALS)



#### Authenticate every checked-in fixture and regenerate its redacted semantic evidence.
####
def test_every_interop_fixture_authenticates_to_its_manifest(tmp_path: Path) -> None:
    backend = BotanBackend.open(_botan_library_path())
    for stem in sorted(INTEROP_STEMS):
        fixture = FIXTURE_ROOT / f"{stem}.psafe3"
        expected = _load_manifest(FIXTURE_ROOT / f"{stem}.manifest.json")
        extracted = extract_ordered_manifest(
            fixture,
            SecretBuffer.from_bytes(_PASSPHRASE),
            backend,
            tmp_path / stem,
        )

        assert extracted.encrypted_sha256 == EXPECTED_ENCRYPTED_HASHES[stem]
        assert f"0x{extracted.format_version:04x}" == expected["format_version"]
        assert extracted.header_field_count == expected["header_field_count"]
        assert extracted.record_count == expected["record_count"]
        assert extracted.field_count == expected["field_count"]
        assert [
            {
                "section": entry.section,
                "record_ordinal": entry.record_ordinal,
                "field_ordinal": entry.field_ordinal,
                "type": f"0x{entry.type_code:02x}",
                "length": entry.length,
                "payload_sha256": entry.sha256,
            }
            for entry in extracted.entries
        ] == expected["entries"]



#### Require ordered hash-only field evidence and reject embedded fabricated typed values.
####
def test_every_interop_manifest_redacts_typed_values() -> None:
    for stem in sorted(INTEROP_STEMS):
        manifest_path = FIXTURE_ROOT / f"{stem}.manifest.json"
        if not manifest_path.exists():
            continue
        source = manifest_path.read_text(encoding="utf-8")
        manifest = _load_manifest(manifest_path)
        entries = manifest["entries"]

        assert isinstance(entries, list) and entries
        for raw_entry in entries:
            assert isinstance(raw_entry, dict)
            entry = cast(dict[str, object], raw_entry)
            assert frozenset(entry) == ENTRY_KEYS
            assert entry["section"] in {"header", "record"}
            assert entry["record_ordinal"] is None or (
                isinstance(entry["record_ordinal"], int) and entry["record_ordinal"] >= 0
            )
            assert isinstance(entry["field_ordinal"], int) and entry["field_ordinal"] >= 0
            assert isinstance(entry["type"], str) and TYPE_HEX.fullmatch(entry["type"])
            assert isinstance(entry["length"], int) and entry["length"] >= 0
            assert isinstance(entry["payload_sha256"], str) and SHA256_HEX.fullmatch(entry["payload_sha256"])
        assert not any(literal in source for literal in REDACTED_LITERALS)



#### Require every present fixture and manifest to have ledger and REUSE provenance coverage.
####
def test_every_interop_artifact_has_repository_provenance() -> None:
    ledger = LEDGER_PATH.read_text(encoding="utf-8")
    reuse_paths = _reuse_paths()
    for stem in sorted(INTEROP_STEMS):
        for suffix in (".psafe3", ".manifest.json"):
            path = Path("tests/fixtures/synthetic/passwordsafe") / f"{stem}{suffix}"
            if not (REPOSITORY_ROOT / path).exists():
                continue
            posix_path = path.as_posix()

            assert f"|`{posix_path}`|" in ledger
            assert posix_path in reuse_paths
    transaction_path = TRANSACTION_PATH.relative_to(REPOSITORY_ROOT).as_posix()
    assert f"|`{transaction_path}`|" in ledger
    assert transaction_path in reuse_paths



#### Accept the exact independently exercised producer boundary for each fixture.
####
@pytest.mark.parametrize(
    "creation_method",
    [
        "bonobo-service",
        "password-safe-cli",
        "gorilla-runtime",
        "independent-format-constructor",
    ],
)
def test_manifest_metadata_accepts_exact_fixture_creation_methods(creation_method: str) -> None:
    metadata = ManifestMetadata(
        fixture="fabricated.psafe3",
        authority="Synthetic authority",
        authority_version="synthetic-version",
        platform="synthetic platform",
        tooling=("synthetic tool",),
        creation_method=creation_method,
    )

    assert metadata.creation_method == creation_method



#### Emit only ordered hashes and caller-supplied nonsensitive authority metadata.
####
def test_extract_ordered_manifest_redacts_all_typed_values(tmp_path: Path) -> None:
    vault = tmp_path / "fabricated.psafe3"
    private = tmp_path / "private"
    _write_test_vault(vault, _interop_fields())
    passphrase = SecretBuffer.from_bytes(_PASSPHRASE)

    extracted = extract_ordered_manifest(vault, passphrase, _XorBackend(), private)
    rendered = render_manifest(
        extracted,
        ManifestMetadata(
            fixture="official-unknown-0302.psafe3",
            authority="Independent PasswordSafe V3 fixture authority",
            authority_version="formatV3.txt",
            platform="synthetic test",
            tooling=("independent test constructor",),
            creation_method="independent-format-constructor",
        ),
    )
    document = json.loads(rendered)

    assert passphrase.closed
    assert document["format_version"] == "0x0302"
    assert [entry["type"] for entry in document["entries"]] == [
        "0x00",
        "0x01",
        "0xe0",
        "0xff",
        "0x01",
        "0x03",
        "0x04",
        "0x06",
        "0x0d",
        "0xe1",
        "0xff",
    ]
    assert not any(literal in rendered for literal in REDACTED_LITERALS)



#### Bind rendered ciphertext identity to the authenticated snapshot, not a replaced path.
####
def test_extract_manifest_hash_survives_post_authentication_path_replacement(tmp_path: Path) -> None:
    vault = tmp_path / "fabricated.psafe3"
    private = tmp_path / "private"
    _write_test_vault(vault, _interop_fields())
    authenticated_hash = _sha256_file(vault)

    extracted = extract_ordered_manifest(
        vault,
        SecretBuffer.from_bytes(_PASSPHRASE),
        _XorBackend(),
        private,
    )
    vault.write_bytes(b"replacement after authenticated snapshot")
    rendered = render_manifest(
        extracted,
        ManifestMetadata(
            fixture="fabricated.psafe3",
            authority="Synthetic authority",
            authority_version="synthetic-version",
            platform="synthetic platform",
            tooling=("synthetic tool",),
            creation_method="independent-format-constructor",
        ),
    )

    assert json.loads(rendered)["encrypted_sha256"] == authenticated_hash



#### Accept exactly one named title delta while comparing every other payload byte.
####
def test_compare_vaults_allows_only_explicit_title_delta(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.psafe3"
    renamed = tmp_path / "renamed.psafe3"
    wrong_unknown = tmp_path / "wrong-unknown.psafe3"
    private = tmp_path / "private"
    _write_test_vault(baseline, _interop_fields())
    _write_test_vault(renamed, _interop_fields(title=b"Alpha Portal Renamed"))
    _write_test_vault(wrong_unknown, _interop_fields(title=b"Alpha Portal Renamed", unknown_record=b"changed"))
    target = FieldTarget.record(0, RecordFieldType.TITLE)

    compare_vaults(
        baseline,
        renamed,
        SecretBuffer.from_bytes(_PASSPHRASE),
        _XorBackend(),
        private,
        target=target,
    )
    with pytest.raises(InteropMismatchError):
        compare_vaults(
            baseline,
            renamed,
            SecretBuffer.from_bytes(_PASSPHRASE),
            _XorBackend(),
            private,
        )
    with pytest.raises(InteropMismatchError):
        compare_vaults(
            baseline,
            wrong_unknown,
            SecretBuffer.from_bytes(_PASSPHRASE),
            _XorBackend(),
            private,
            target=target,
        )



#### Read the fabricated passphrase only from stdin and emit no typed value.
####
def test_extract_cli_uses_standard_input_and_redacted_output(tmp_path: Path) -> None:
    vault = tmp_path / "fabricated.psafe3"
    private = tmp_path / "private"
    _write_test_vault(vault, _interop_fields())
    stdout = StringIO()
    stderr = StringIO()

    status = run_cli(
        (
            "extract",
            str(vault),
            "--botan-library",
            str(tmp_path / "fabricated-botan.dll"),
            "--private-directory",
            str(private),
            "--fixture-name",
            "official-unknown-0302.psafe3",
            "--authority",
            "Independent PasswordSafe V3 fixture authority",
            "--authority-version",
            "formatV3.txt",
            "--platform",
            "synthetic test",
            "--tooling",
            "independent test constructor",
            "--creation-method",
            "independent-format-constructor",
        ),
        stdin=BytesIO(_PASSPHRASE + b"\n"),
        stdout=stdout,
        stderr=stderr,
        backend_loader=lambda _path: _XorBackend(),
    )

    assert status == 0
    assert stderr.getvalue() == ""
    assert json.loads(stdout.getvalue())["passphrase_input"] == "stdin"
    assert not any(literal in stdout.getvalue() for literal in REDACTED_LITERALS)
