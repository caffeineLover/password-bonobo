"""Verify that one intentional edit is the only semantic writer delta."""

from pathlib import Path

from helpers import DeterministicRandomSource
from test_writer import (
    _opened_source,
    _private_directory,
    _XorBackend,
)

from bonobo_core.passwordsafe.constants import RecordFieldType
from bonobo_core.passwordsafe.model import RawField, RawRecord, VaultDocument
from bonobo_core.passwordsafe.schema import encode_record_field
from bonobo_core.passwordsafe.writer import PasswordSafeWriter



#### Retain one document revision while replacing only its title payload.
####
def _replace_title(document: VaultDocument) -> VaultDocument:
    header = tuple(
        RawField(field.type_code, field.payload.retain(), field.ordinal, field.classification)
        for field in document.header_fields
    )
    records: list[RawRecord] = []
    try:
        for record in document.records:
            fields: list[RawField] = []
            for field in record.fields:
                replacement = (
                    encode_record_field(field, "Alpha Portal Renamed")
                    if field.type_code == RecordFieldType.TITLE
                    else RawField(field.type_code, field.payload.retain(), field.ordinal, field.classification)
                )
                fields.append(replacement)
            records.append(RawRecord.create(tuple(fields), ordinal=record.ordinal))
        return VaultDocument.create(document.version, header, tuple(records), warnings=document.warnings)
    except BaseException:
        for field in header:
            field.payload.close()
        for record in records:
            for field in record.fields:
                field.payload.close()
        raise



#### Change only the requested title coordinate in the ordered manifest.
####
def test_single_title_edit_changes_only_target_field(tmp_path: Path) -> None:
    backend = _XorBackend()
    reader, opened, _source = _opened_source(tmp_path, backend)
    revised = _replace_title(opened.document)
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "candidates"),
        random_source=DeterministicRandomSource(bytes(index % 229 for index in range(8192))),
    )

    candidate = writer.write(revised, opened.crypto_state)
    baseline = {(entry.section, entry.record_ordinal, entry.field_ordinal): entry for entry in opened.manifest.entries}
    changed = {
        (entry.section, entry.record_ordinal, entry.field_ordinal)
        for entry in candidate.manifest.entries
        if baseline[(entry.section, entry.record_ordinal, entry.field_ordinal)] != entry
    }

    assert changed == {("record", 0, 1)}
    revised.close()
    opened.close()
