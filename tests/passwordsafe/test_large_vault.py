"""Prove large opaque attachments survive public saves with bounded Python memory and encrypted artifacts."""

import gc
import tracemalloc
from pathlib import Path
from typing import Final

from helpers import DeterministicRandomSource, build_spec_vault
from strategies import large_opaque_attachment
from test_writer import _private_directory, _XorBackend

from bonobo_core.passwordsafe.constants import HeaderFieldType, RecordFieldType, ResourceLimits
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.service import VaultService



_PASSPHRASE: Final[bytes] = b"fabricated-large-vault-passphrase"
_PLAINTEXT_FRAGMENT: Final[bytes] = b"fabricated-opaque-attachment-fragment-7f4c"
_LIMITS: Final[ResourceLimits] = ResourceLimits(
    max_iterations=3,
    max_records=8,
    max_fields=64,
    max_encrypted_file_bytes=4_194_304,
)
_PEAK_MEMORY_BOUND: Final[int] = (
    4 * _LIMITS.max_inline_payload_bytes
    + 8 * _LIMITS.io_chunk_bytes
)



#### Build one independently encrypted V3 source containing a deferred opaque attachment.
####
def _write_large_source(path: Path, backend: _XorBackend) -> None:
    attachment = large_opaque_attachment(_PLAINTEXT_FRAGMENT)
    fields = (
        (HeaderFieldType.VERSION, bytes.fromhex("0f03")),
        (HeaderFieldType.END, b""),
        (RecordFieldType.UUID, bytes.fromhex("22222222222242228222222222222222")),
        (RecordFieldType.TITLE, b"Large Fabricated Attachment"),
        (RecordFieldType.PASSWORD, b"fabricated-large-password"),
        (RecordFieldType.URL, b"https://large.example.invalid"),
        (RecordFieldType.ATTACHMENT_MEDIA_TYPE, b"application/octet-stream"),
        (RecordFieldType.ATTACHMENT_CONTENT, attachment),
        (RecordFieldType.END, b""),
    )
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



#### Keep open and no-edit save memory independent of attachment size and every private artifact encrypted.
####
def test_large_opaque_attachment_save_is_bounded_and_never_spooled_plaintext(tmp_path: Path) -> None:
    backend = _XorBackend()
    source = tmp_path / "large-fabricated.psafe3"
    _write_large_source(source, backend)
    working = _private_directory(tmp_path, "large-working")
    recovery = _private_directory(tmp_path, "large-recovery")
    service = VaultService(
        backend,
        working,
        recovery,
        random_source=DeterministicRandomSource(bytes(index % 239 for index in range(65_536))),
        limits=_LIMITS,
    )
    gc.collect()

    tracemalloc.start()
    try:
        session = service.open(source, SecretBuffer.from_bytes(_PASSPHRASE))
        open_current, open_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        service.save(session)
        save_current, save_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        session.lock()
        lock_current, lock_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    recovery_files = tuple(path for path in recovery.rglob("*") if path.is_file())
    assert recovery_files
    assert max(open_peak, save_peak, lock_peak) < _PEAK_MEMORY_BOUND, (
        (open_current, open_peak),
        (save_current, save_peak),
        (lock_current, lock_peak),
    )
    for directory in (working, recovery):
        for artifact in directory.rglob("*"):
            if artifact.is_file():
                assert _PLAINTEXT_FRAGMENT not in artifact.read_bytes()
