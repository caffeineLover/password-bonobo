"""Extract and compare redacted PasswordSafe interoperability evidence.

The command authenticates only caller-selected synthetic vaults, reads the
fabricated passphrase exclusively from standard input, and emits ordered field
coordinates plus lengths and hashes.  Exact comparison streams every unchanged
payload byte and permits at most one explicitly named record-field delta.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, TextIO, cast

from bonobo_core.passwordsafe.botan import BotanBackend
from bonobo_core.passwordsafe.constants import MAX_IO_CHUNK_BYTES, RecordFieldType
from bonobo_core.passwordsafe.crypto import TwofishBackend
from bonobo_core.passwordsafe.errors import PasswordSafeError
from bonobo_core.passwordsafe.model import (
    ManifestEntry,
    RawField,
    SemanticManifest,
    VaultDocument,
    documents_equal_exact,
)
from bonobo_core.passwordsafe.payloads import FieldPayload
from bonobo_core.passwordsafe.reader import OpenedVault, PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.snapshots import EncryptedSnapshot



_SCHEMA: Final[str] = "password-bonobo-interoperability-manifest-v1"
_PASSPHRASE_INPUT_CHANNEL: Final[str] = "stdin"  # nosec B105
_MAX_STDIN_PASSPHRASE_BYTES: Final[int] = 1_048_576
_CREATION_METHODS: Final[frozenset[str]] = frozenset(
    {
        "bonobo-service",
        "password-safe-cli",
        "gorilla-runtime",
        "independent-format-constructor",
    }
)



#### Describe nonsensitive provenance supplied by the independent fixture producer.
####
@dataclass(frozen=True, slots=True)
class ManifestMetadata:
    fixture: str
    authority: str
    authority_version: str
    platform: str
    tooling: tuple[str, ...]
    creation_method: str



    #### Reject incomplete or unsupported provenance before emitting evidence.
    ####
    def __post_init__(self) -> None:
        for value in (self.fixture, self.authority, self.authority_version, self.platform):
            if not isinstance(value, str) or not value:
                raise ValueError("manifest provenance text must be nonempty")
        if not isinstance(self.tooling, tuple) or not self.tooling or any(
            not isinstance(item, str) or not item for item in self.tooling
        ):
            raise ValueError("manifest tooling must be a nonempty text tuple")
        if self.creation_method not in _CREATION_METHODS:
            raise ValueError("manifest creation method is unsupported")



#### Retain redacted ordered evidence after the authenticated vault owner closes.
####
@dataclass(frozen=True, slots=True)
class ExtractedManifest:
    format_version: int
    encrypted_sha256: str
    entries: tuple[ManifestEntry, ...]
    header_field_count: int
    record_count: int
    field_count: int



    #### Copy only immutable structural evidence from one authenticated manifest.
    ####
    @classmethod
    def from_semantic_manifest(
        cls,
        manifest: SemanticManifest,
        encrypted_sha256: str,
    ) -> ExtractedManifest:
        return cls(
            format_version=manifest.version.value,
            encrypted_sha256=encrypted_sha256,
            entries=manifest.entries,
            header_field_count=manifest.header_field_count,
            record_count=manifest.record_count,
            field_count=manifest.field_count,
        )



#### Identify the sole record field allowed to differ in a targeted comparison.
####
@dataclass(frozen=True, slots=True)
class FieldTarget:
    record_ordinal: int
    type_code: int



    #### Reject ambiguous or out-of-range target coordinates.
    ####
    def __post_init__(self) -> None:
        if isinstance(self.record_ordinal, bool) or not isinstance(self.record_ordinal, int):
            raise TypeError("target record ordinal must be an integer")
        if self.record_ordinal < 0:
            raise ValueError("target record ordinal cannot be negative")
        if isinstance(self.type_code, bool) or not isinstance(self.type_code, int):
            raise TypeError("target field type must be an integer")
        if not 0 <= self.type_code <= 0xFF:
            raise ValueError("target field type must fit one byte")



    #### Construct one record-scoped target from a typed or numeric field code.
    ####
    @classmethod
    def record(cls, record_ordinal: int, field_type: RecordFieldType | int) -> FieldTarget:
        return cls(record_ordinal, int(field_type))



#### Report a semantic comparison failure without paths, values, or record identity.
####
class InteropMismatchError(ValueError):



    #### Initialize the fixed safe comparison diagnostic.
    ####
    def __init__(self) -> None:
        super().__init__("interoperability manifests do not match the approved delta")



#### Authenticate one vault and retain only its immutable ordered redacted index.
####
#### The function consumes and closes the passphrase on every path.  The encrypted
#### snapshot and all decrypted payload owners close before the evidence escapes.
####
def extract_ordered_manifest(
    vault_path: Path,
    passphrase: SecretBuffer,
    backend: TwofishBackend,
    private_directory: Path,
) -> ExtractedManifest:
    opened: OpenedVault | None = None
    try:
        _prepare_private_directory(private_directory)
        reader = PasswordSafeReader(backend, private_directory)
        opened = reader.open(vault_path, passphrase)
        return ExtractedManifest.from_semantic_manifest(
            opened.manifest,
            _sha256_snapshot(opened.source_snapshot),
        )
    finally:
        if opened is not None:
            opened.close()
        passphrase.close()



#### Render a deterministic JSON manifest containing no decrypted typed values.
####
def render_manifest(
    manifest: ExtractedManifest,
    metadata: ManifestMetadata,
) -> str:
    document: dict[str, object] = {
        "schema": _SCHEMA,
        "fixture": metadata.fixture,
        "authority": metadata.authority,
        "authority_version": metadata.authority_version,
        "platform": metadata.platform,
        "tooling": list(metadata.tooling),
        "creation_method": metadata.creation_method,
        "passphrase_input": _PASSPHRASE_INPUT_CHANNEL,
        "format_version": f"0x{manifest.format_version:04x}",
        "encrypted_sha256": manifest.encrypted_sha256,
        "header_field_count": manifest.header_field_count,
        "record_count": manifest.record_count,
        "field_count": manifest.field_count,
        "entries": [_manifest_entry_document(entry) for entry in manifest.entries],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"



#### Authenticate two vaults and require exact equality outside one named field.
####
#### Omitting ``target`` requires complete exact document equality.  Supplying a
#### target requires that field to change and rejects ordering, metadata, warning,
#### version, or payload changes anywhere else.  Randomized envelopes are outside
#### the authenticated plaintext comparison by design.
####
def compare_vaults(
    baseline_path: Path,
    candidate_path: Path,
    passphrase: SecretBuffer,
    backend: TwofishBackend,
    private_directory: Path,
    *,
    target: FieldTarget | None = None,
) -> None:
    baseline: OpenedVault | None = None
    candidate: OpenedVault | None = None
    candidate_passphrase: SecretBuffer | None = None
    try:
        _prepare_private_directory(private_directory)
        candidate_passphrase = SecretBuffer.take_ownership(bytearray(passphrase.borrow()))
        reader = PasswordSafeReader(backend, private_directory)
        baseline = reader.open(baseline_path, passphrase)
        candidate = reader.open(candidate_path, candidate_passphrase)
        matches = (
            documents_equal_exact(baseline.document, candidate.document)
            if target is None
            else _documents_match_targeted_delta(baseline.document, candidate.document, target)
        )
        if not matches:
            raise InteropMismatchError()
    finally:
        if candidate is not None:
            candidate.close()
        if baseline is not None:
            baseline.close()
        if candidate_passphrase is not None:
            candidate_passphrase.close()
        passphrase.close()



#### Run the typed command boundary with injectable streams and backend loading.
####
def run_cli(
    argv: Sequence[str],
    *,
    stdin: BinaryIO,
    stdout: TextIO,
    stderr: TextIO,
    backend_loader: Callable[[Path], TwofishBackend] = BotanBackend.open,
) -> int:
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    try:
        backend = backend_loader(cast(Path, arguments.botan_library))
        passphrase = _read_standard_input_passphrase(stdin)
        command = cast(str, arguments.command)
        if command == "extract":
            manifest = extract_ordered_manifest(
                cast(Path, arguments.vault),
                passphrase,
                backend,
                cast(Path, arguments.private_directory),
            )
            metadata = ManifestMetadata(
                fixture=cast(str, arguments.fixture_name),
                authority=cast(str, arguments.authority),
                authority_version=cast(str, arguments.authority_version),
                platform=cast(str, arguments.platform),
                tooling=tuple(cast(list[str], arguments.tooling)),
                creation_method=cast(str, arguments.creation_method),
            )
            stdout.write(render_manifest(manifest, metadata))
            return 0

        target_text = cast(str | None, arguments.target_field)
        target = None if target_text is None else _parse_field_target(target_text)
        compare_vaults(
            cast(Path, arguments.baseline),
            cast(Path, arguments.candidate),
            passphrase,
            backend,
            cast(Path, arguments.private_directory),
            target=target,
        )
        stdout.write(json.dumps({"result": "match", "target_field": target_text}, sort_keys=True) + "\n")
        return 0
    except (InteropMismatchError, OSError, PasswordSafeError, TypeError, ValueError):
        stderr.write("interoperability verification failed\n")
        return 1



#### Parse process arguments and expose no passphrase option.
####
def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser("extract")
    extract.add_argument("vault", type=Path)
    _add_common_arguments(extract)
    extract.add_argument("--fixture-name", required=True)
    extract.add_argument("--authority", required=True)
    extract.add_argument("--authority-version", required=True)
    extract.add_argument("--platform", required=True)
    extract.add_argument("--tooling", action="append", required=True)
    extract.add_argument("--creation-method", choices=sorted(_CREATION_METHODS), required=True)

    compare = commands.add_parser("compare")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    _add_common_arguments(compare)
    compare.add_argument("--target-field")
    return parser



#### Add the nonsensitive native-library and private-snapshot arguments.
####
def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--botan-library", type=Path, required=True)
    parser.add_argument("--private-directory", type=Path, required=True)



#### Read one bounded fabricated passphrase line and transfer its mutable owner.
####
def _read_standard_input_passphrase(stream: BinaryIO) -> SecretBuffer:
    data = bytearray(stream.read(_MAX_STDIN_PASSPHRASE_BYTES + 1))
    try:
        if len(data) > _MAX_STDIN_PASSPHRASE_BYTES:
            raise ValueError("standard-input passphrase exceeds the tool limit")
        if data.endswith(b"\n"):
            del data[-1:]
        if data.endswith(b"\r"):
            del data[-1:]
        if not data or b"\n" in data or b"\r" in data:
            raise ValueError("standard input must contain exactly one nonempty passphrase line")
        owner = SecretBuffer.take_ownership(data)
        data = bytearray()
        return owner
    finally:
        data[:] = bytes(len(data))



#### Create the caller-selected private snapshot directory with owner-only intent.
####
def _prepare_private_directory(directory: Path) -> None:
    if not isinstance(directory, Path):
        raise TypeError("private directory must be a Path")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)



#### Convert one internal manifest entry into the stable hash-only JSON schema.
####
def _manifest_entry_document(entry: ManifestEntry) -> dict[str, object]:
    return {
        "section": entry.section,
        "record_ordinal": entry.record_ordinal,
        "field_ordinal": entry.field_ordinal,
        "type": f"0x{entry.type_code:02x}",
        "length": entry.length,
        "payload_sha256": entry.sha256,
    }



#### Hash the exact authenticated encrypted snapshot in bounded chunks.
####
def _sha256_snapshot(snapshot: EncryptedSnapshot) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < snapshot.size:
        amount = min(MAX_IO_CHUNK_BYTES, snapshot.size - offset)
        digest.update(snapshot.read_at(offset, amount))
        offset += amount
    return digest.hexdigest()



#### Parse the sole approved named edit coordinate.
####
def _parse_field_target(value: str) -> FieldTarget:
    parts = value.split(":")
    if len(parts) != 3 or parts[0] != "record" or parts[2] != "title" or not parts[1].isdigit():
        raise ValueError("target field must use record:N:title")
    return FieldTarget.record(int(parts[1]), RecordFieldType.TITLE)



#### Compare complete documents while allowing exactly one changed target payload.
####
def _documents_match_targeted_delta(
    baseline: VaultDocument,
    candidate: VaultDocument,
    target: FieldTarget,
) -> bool:
    if (
        baseline.version != candidate.version
        or baseline.warnings != candidate.warnings
        or len(baseline.header_fields) != len(candidate.header_fields)
        or len(baseline.records) != len(candidate.records)
        or not _field_sequences_equal(baseline.header_fields, candidate.header_fields)
        or target.record_ordinal >= len(baseline.records)
    ):
        return False

    target_changed = False
    for record_ordinal, (baseline_record, candidate_record) in enumerate(
        zip(baseline.records, candidate.records, strict=True)
    ):
        if baseline_record.ordinal != candidate_record.ordinal:
            return False
        if record_ordinal != target.record_ordinal:
            if not _field_sequences_equal(baseline_record.fields, candidate_record.fields):
                return False
            continue
        matches = tuple(
            index
            for index, field in enumerate(baseline_record.fields)
            if field.type_code == target.type_code
        )
        candidate_matches = tuple(
            index
            for index, field in enumerate(candidate_record.fields)
            if field.type_code == target.type_code
        )
        if len(matches) != 1 or candidate_matches != matches:
            return False
        equal_except_target, target_changed = _field_sequences_equal_except(
            baseline_record.fields,
            candidate_record.fields,
            matches[0],
        )
        if not equal_except_target:
            return False
    return target_changed



#### Compare one ordered field sequence exactly through bounded payload streams.
####
def _field_sequences_equal(
    baseline: tuple[RawField, ...],
    candidate: tuple[RawField, ...],
) -> bool:
    equal, target_changed = _field_sequences_equal_except(baseline, candidate, None)
    return equal and not target_changed



#### Compare field metadata and bytes while optionally allowing one payload delta.
####
def _field_sequences_equal_except(
    baseline: tuple[RawField, ...],
    candidate: tuple[RawField, ...],
    target_index: int | None,
) -> tuple[bool, bool]:
    if len(baseline) != len(candidate):
        return False, False
    target_changed = False
    for index, (baseline_field, candidate_field) in enumerate(zip(baseline, candidate, strict=True)):
        if (
            baseline_field.type_code != candidate_field.type_code
            or baseline_field.ordinal != candidate_field.ordinal
            or baseline_field.classification != candidate_field.classification
        ):
            return False, False
        if index == target_index:
            target_changed = (
                baseline_field.payload.length != candidate_field.payload.length
                or not _payloads_equal(baseline_field.payload, candidate_field.payload)
            )
            continue
        if (
            baseline_field.payload.length != candidate_field.payload.length
            or not _payloads_equal(baseline_field.payload, candidate_field.payload)
        ):
            return False, False
    return True, target_changed



#### Compare complete payload streams without assuming matching chunk boundaries.
####
def _payloads_equal(
    baseline: FieldPayload,
    candidate: FieldPayload,
    *,
    chunk_size: int = MAX_IO_CHUNK_BYTES,
) -> bool:
    if baseline.length != candidate.length:
        return False
    baseline_chunks = iter(baseline.iter_chunks(chunk_size))
    candidate_chunks = iter(candidate.iter_chunks(chunk_size))
    baseline_chunk = memoryview(b"")
    candidate_chunk = memoryview(b"")
    baseline_offset = 0
    candidate_offset = 0
    compared = 0
    while compared < baseline.length:
        if baseline_offset == len(baseline_chunk):
            baseline_chunk = _next_payload_chunk(baseline_chunks, chunk_size)
            baseline_offset = 0
        if candidate_offset == len(candidate_chunk):
            candidate_chunk = _next_payload_chunk(candidate_chunks, chunk_size)
            candidate_offset = 0
        if not baseline_chunk or not candidate_chunk:
            return False
        amount = min(
            len(baseline_chunk) - baseline_offset,
            len(candidate_chunk) - candidate_offset,
            baseline.length - compared,
        )
        if (
            baseline_chunk[baseline_offset:baseline_offset + amount]
            != candidate_chunk[candidate_offset:candidate_offset + amount]
        ):
            return False
        baseline_offset += amount
        candidate_offset += amount
        compared += amount
    if baseline_offset != len(baseline_chunk) or candidate_offset != len(candidate_chunk):
        return False
    return _iterator_exhausted(baseline_chunks) and _iterator_exhausted(candidate_chunks)



#### Return one valid bounded chunk or an empty sentinel at stream exhaustion.
####
def _next_payload_chunk(chunks: Iterator[memoryview[int]], chunk_size: int) -> memoryview[int]:
    try:
        chunk = next(chunks)
    except StopIteration:
        return memoryview(b"")
    if not 0 < len(chunk) <= chunk_size:
        return memoryview(b"")
    return chunk



#### Confirm that no payload bytes follow the declared stream length.
####
def _iterator_exhausted(chunks: Iterator[memoryview[int]]) -> bool:
    try:
        next(chunks)
    except StopIteration:
        return True
    return False



#### Bind real process streams to the testable command boundary.
####
def main(argv: Sequence[str] | None = None) -> int:
    selected_argv = tuple(sys.argv[1:]) if argv is None else argv
    return run_cli(
        selected_argv,
        stdin=sys.stdin.buffer,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )



# Return the command status without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
