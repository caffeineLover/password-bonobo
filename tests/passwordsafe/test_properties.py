"""Exercise generated lossless documents through authenticated reader, writer, and session boundaries."""

import tempfile
from pathlib import Path
from typing import Final

from helpers import DeterministicRandomSource, build_spec_vault
from hypothesis import HealthCheck, given, settings
from strategies import LosslessVaultCase, lossless_vault_cases
from test_writer import _private_directory, _XorBackend

from bonobo_core.passwordsafe.constants import ResourceLimits
from bonobo_core.passwordsafe.model import SemanticManifest, documents_equal_exact
from bonobo_core.passwordsafe.reader import PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.session import SetTextField, VaultSession
from bonobo_core.passwordsafe.writer import PasswordSafeWriter



_PASSPHRASE: Final[bytes] = b"fabricated-property-passphrase"
_SALT: Final[bytes] = bytes(range(32))
_CONTENT_KEY: Final[bytes] = bytes(range(32, 64))
_HMAC_KEY: Final[bytes] = bytes(range(64, 96))
_IV: Final[bytes] = bytes(range(16))
_RANDOM_BYTES: Final[bytes] = bytes(index % 251 for index in range(262_144))
_LIMITS: Final[ResourceLimits] = ResourceLimits(max_inline_payload_bytes=64, io_chunk_bytes=17)



#### Write one generated case through the independent official-format test oracle.
####
def _write_source(case: LosslessVaultCase, workspace: Path, backend: _XorBackend) -> Path:
    source = workspace / "generated.psafe3"
    source.write_bytes(
        build_spec_vault(
            backend,
            _PASSPHRASE,
            case.fields,
            salt=_SALT,
            iterations=3,
            content_key=_CONTENT_KEY,
            hmac_key=_HMAC_KEY,
            iv=_IV,
            random_source=DeterministicRandomSource(_RANDOM_BYTES),
        )
    )
    return source



#### Return the exact manifest coordinates changed by one generated targeted title edit.
####
def _changed_coordinates(baseline: SemanticManifest, revised: SemanticManifest) -> set[tuple[str, int | None, int]]:
    baseline_entries = {
        (entry.section, entry.record_ordinal, entry.field_ordinal): entry
        for entry in baseline.entries
    }
    return {
        (entry.section, entry.record_ordinal, entry.field_ordinal)
        for entry in revised.entries
        if baseline_entries[(entry.section, entry.record_ordinal, entry.field_ordinal)] != entry
    }



#### Preserve every generated field exactly and isolate one generated title mutation to its selected coordinate.
####
@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=(HealthCheck.function_scoped_fixture,),
)
@given(case=lossless_vault_cases())
def test_generated_document_round_trip_and_targeted_edit(case: LosslessVaultCase, tmp_path: Path) -> None:
    with tempfile.TemporaryDirectory(dir=tmp_path) as temporary_name:
        workspace = Path(temporary_name)
        backend = _XorBackend()
        reader = PasswordSafeReader(backend, _private_directory(workspace, "snapshots"), limits=_LIMITS)
        source = _write_source(case, workspace, backend)
        with SecretBuffer.from_bytes(_PASSPHRASE) as passphrase:
            opened = reader.open(source, passphrase)
        writer = PasswordSafeWriter(
            backend,
            reader,
            _private_directory(workspace, "candidates"),
            random_source=DeterministicRandomSource(_RANDOM_BYTES),
            limits=_LIMITS,
        )

        no_edit_candidate = writer.write(opened.document, opened.crypto_state)
        no_edit_reopened = reader.reopen_candidate(no_edit_candidate.path, opened.crypto_state)
        assert opened.document.version == case.version
        assert documents_equal_exact(opened.document, no_edit_reopened.document)
        assert no_edit_candidate.manifest == opened.manifest
        no_edit_reopened.close()

        session = VaultSession(opened)
        selected = session.records()[case.target_record_ordinal]
        changed = session.apply(
            selected.handle,
            selected.revision,
            (SetTextField(case.target_field_type, case.replacement_title),),
        )
        snapshot = session._prepare_save()
        edited_candidate = writer.write(snapshot, session._crypto_state_for_service)
        edited_reopened = reader.reopen_candidate(edited_candidate.path, session._crypto_state_for_service)

        assert changed.title == case.replacement_title
        assert _changed_coordinates(no_edit_candidate.manifest, edited_candidate.manifest) == {
            ("record", case.target_record_ordinal, case.target_field_ordinal),
        }
        assert documents_equal_exact(snapshot, edited_reopened.document)
        edited_reopened.close()
        session._abort_save()
        session.discard_and_lock()
