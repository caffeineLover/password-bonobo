"""Verify authenticated local publication and encrypted recovery behavior."""

import hashlib
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from bonobo_core.passwordsafe.model import documents_equal_exact
from bonobo_core.passwordsafe.reader import OpenedVault, PasswordSafeReader
from bonobo_core.passwordsafe.secrets import SecretBuffer
from bonobo_core.passwordsafe.snapshots import _windows_path_is_private
from bonobo_core.passwordsafe.storage import LocalVaultStore
from bonobo_core.passwordsafe.writer import EncryptedCandidate, PasswordSafeWriter
from tests.passwordsafe.helpers import DeterministicRandomSource
from tests.passwordsafe.test_writer import _PASSPHRASE, _opened_source, _private_directory, _XorBackend



#### Reopen copied ciphertext and compare it with the intended document revision.
####
@dataclass(slots=True)
class _CandidateValidator:
    reader: PasswordSafeReader
    opened: OpenedVault



    #### Authenticate and compare the exact candidate supplied by the store.
    ####
    def __call__(self, path: Path) -> None:
        reopened = self.reader.reopen_candidate(path, self.opened.crypto_state)
        try:
            if not documents_equal_exact(reopened.document, self.opened.document):
                raise ValueError("candidate document does not match")
        finally:
            reopened.close()



#### Authenticate historical ciphertext with explicit transient passphrase input.
####
@dataclass(slots=True)
class _RecoveryValidator:
    reader: PasswordSafeReader
    opened: OpenedVault



    #### Open and compare one recovery across its original iteration policy.
    ####
    def __call__(self, path: Path) -> None:
        passphrase = SecretBuffer.from_bytes(_PASSPHRASE)
        reopened = self.reader.open(path, passphrase)
        try:
            if not documents_equal_exact(reopened.document, self.opened.document):
                raise ValueError("recovery document does not match")
        finally:
            reopened.close()
            passphrase.close()



#### Retain one real writer candidate and every owner needed to validate it.
####
@dataclass(slots=True)
class _PublicationCase:
    source: Path
    candidate: EncryptedCandidate
    validator: _CandidateValidator
    recovery_validator: _RecoveryValidator



    #### Close the authenticated aggregate after a test completes.
    ####
    def close(self) -> None:
        self.validator.opened.close()



#### Build a real authenticated candidate without publishing the source path.
####
def _publication_case(tmp_path: Path) -> _PublicationCase:
    backend = _XorBackend()
    reader, opened, source = _opened_source(tmp_path, backend)
    writer = PasswordSafeWriter(
        backend,
        reader,
        _private_directory(tmp_path, "writer-candidates"),
        random_source=DeterministicRandomSource(bytes(index % 193 for index in range(8192))),
    )
    candidate = writer.write(opened.document, opened.crypto_state)
    return _PublicationCase(
        source,
        candidate,
        _CandidateValidator(reader, opened),
        _RecoveryValidator(reader, opened),
    )



#### Replace the destination only with the synchronized authenticated candidate.
####
def test_publish_replaces_source_and_removes_candidate(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    working = _private_directory(tmp_path, "store-working")
    recovery = _private_directory(tmp_path, "store-recovery")
    store = LocalVaultStore(working, recovery, validator=case.validator)
    baseline = store.capture(case.source)

    published = store.publish(case.source, case.candidate, baseline)

    assert published.sha256 == case.candidate.sha256
    assert hashlib.sha256(case.source.read_bytes()).hexdigest() == case.candidate.sha256
    assert not case.candidate.path.exists()
    assert not store.pending_candidates()
    if os.name == "nt":
        assert _windows_path_is_private(case.source)
    else:
        assert stat.S_IMODE(case.source.stat().st_mode) & 0o077 == 0
    case.close()



#### Retain the prior encrypted source as explicit path-free recovery metadata.
####
def test_publish_retains_one_encrypted_recovery_revision(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
        random_source=DeterministicRandomSource(bytes(index % 191 for index in range(256))),
    )
    baseline = store.capture(case.source)

    published = store.publish(case.source, case.candidate, baseline)
    recoveries = store.available_recovery(case.source)

    assert len(recoveries) == 1
    assert recoveries[0].sha256 == hashlib.sha256(original).hexdigest()
    assert recoveries[0].size == len(original)
    assert str(case.source) not in repr(recoveries[0])
    assert recoveries[0].identifier not in str(case.source)
    assert published.recovery == recoveries[0]
    case.close()



#### Expose recovery values as safe metadata without retaining a private path.
####
def test_recovery_revision_contains_only_path_free_metadata(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    store.publish(case.source, case.candidate, store.capture(case.source))
    recovery = store.available_recovery(case.source)[0]

    assert set(asdict(recovery)) == {"identifier", "created_ns", "size", "sha256"}
    case.close()



#### Restore a selected authenticated recovery through the same replace boundary.
####
def test_restore_republishes_selected_encrypted_revision(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
        random_source=DeterministicRandomSource(bytes(index % 181 for index in range(512))),
    )
    baseline = store.capture(case.source)
    store.publish(case.source, case.candidate, baseline)
    recovery = store.available_recovery(case.source)[0]
    published_baseline = store.capture(case.source)

    restored = store.restore(
        case.source,
        recovery,
        published_baseline,
        validator=case.recovery_validator,
    )

    assert case.source.read_bytes() == original
    assert restored.sha256 == hashlib.sha256(original).hexdigest()
    assert not store.pending_candidates()
    case.close()



#### Publish a complete candidate only when its destination is still absent.
####
def test_publish_new_creates_destination_without_recovery(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    destination = tmp_path / "fabricated-created.psafe3"
    store = LocalVaultStore(
        _private_directory(tmp_path, "new-store-working"),
        _private_directory(tmp_path, "new-store-recovery"),
        validator=case.validator,
    )

    published = store.publish_new(destination, case.candidate)

    assert published.path == destination
    assert published.sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert published.recovery is None
    assert not case.candidate.path.exists()
    assert not store.available_recovery(destination)
    case.close()
