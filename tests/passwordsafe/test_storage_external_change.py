"""Verify that local publication rejects stale or redirected destinations."""

import os
from pathlib import Path

import pytest

from bonobo_core.passwordsafe.errors import ExternalModificationError, StorageError
from bonobo_core.passwordsafe.storage import (
    FileBaseline,
    LocalVaultStore,
    _PosixPublicationAnchor,
    _PublicationAnchor,
    _RecoveryArtifact,
)
from tests.passwordsafe.test_snapshots import _create_windows_junction
from tests.passwordsafe.test_storage import _publication_case
from tests.passwordsafe.test_writer import _private_directory



#### Reject publication after another writer changes the captured destination.
####
def test_external_change_blocks_publication(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    baseline = store.capture(case.source)
    case.source.write_bytes(b"other encrypted bytes")

    with pytest.raises(ExternalModificationError):
        store.publish(case.source, case.candidate, baseline)

    assert case.source.read_bytes() == b"other encrypted bytes"
    assert not case.candidate.path.exists()
    assert not store.pending_candidates()
    case.close()



#### Recheck after recovery copying closes the final pre-replace race window.
####
def test_change_during_recovery_copy_blocks_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _publication_case(tmp_path)
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    baseline = store.capture(case.source)
    production_create = LocalVaultStore._create_recovery



    #### Preserve the real recovery copy, then simulate an uncooperative writer.
    ####
    def change_after_recovery(
        selected: LocalVaultStore,
        anchor: _PublicationAnchor,
        destination_name: str,
        captured: FileBaseline,
        locator: str,
    ) -> _RecoveryArtifact:
        recovery = production_create(selected, anchor, destination_name, captured, locator)
        case.source.write_bytes(b"changed during recovery")
        return recovery

    monkeypatch.setattr(LocalVaultStore, "_create_recovery", change_after_recovery)

    with pytest.raises(ExternalModificationError):
        store.publish(case.source, case.candidate, baseline)

    assert case.source.read_bytes() == b"changed during recovery"
    assert not case.candidate.path.exists()
    case.close()



#### Reject a staged pathname swapped after authentication but before replace.
####
def test_staged_candidate_swap_before_replace_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    baseline = store.capture(case.source)
    production_create = LocalVaultStore._create_recovery



    #### Preserve recovery, then replace the already authenticated staged name.
    ####
    def swap_staged_after_recovery(
        selected: LocalVaultStore,
        anchor: _PublicationAnchor,
        destination_name: str,
        captured: FileBaseline,
        locator: str,
    ) -> _RecoveryArtifact:
        recovery = production_create(selected, anchor, destination_name, captured, locator)
        staged = next(case.source.parent.glob(".bonobo-*.publish"))
        staged.unlink()
        staged.write_bytes(b"swapped after authentication")
        return recovery

    monkeypatch.setattr(LocalVaultStore, "_create_recovery", swap_staged_after_recovery)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, baseline)

    assert case.source.read_bytes() == original
    case.close()



#### Reject publication if the retained destination directory is redirected.
####
def test_destination_directory_retarget_before_replace_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _publication_case(tmp_path)
    destination_directory = tmp_path / "destination"
    destination_directory.mkdir()
    destination = destination_directory / "vault.psafe3"
    case.source.replace(destination)
    original = destination.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    baseline = store.capture(destination)
    production_create = LocalVaultStore._create_recovery
    moved_directory = tmp_path / "moved-destination"
    retargeted = False



    #### Retarget the caller pathname after recovery while the anchor stays open.
    ####
    def retarget_after_recovery(
        selected: LocalVaultStore,
        anchor: _PublicationAnchor,
        destination_name: str,
        captured: FileBaseline,
        locator: str,
    ) -> _RecoveryArtifact:
        nonlocal retargeted
        recovery = production_create(selected, anchor, destination_name, captured, locator)
        destination_directory.replace(moved_directory)
        destination_directory.mkdir()
        destination.write_bytes(original)
        retargeted = True
        return recovery

    monkeypatch.setattr(LocalVaultStore, "_create_recovery", retarget_after_recovery)

    with pytest.raises((ExternalModificationError, StorageError)) as caught:
        store.publish(destination, case.candidate, baseline)
    if not retargeted:
        case.close()
        pytest.skip("open destination directories cannot be renamed")

    assert isinstance(caught.value, ExternalModificationError)
    assert destination.read_bytes() == original
    assert (moved_directory / destination.name).read_bytes() == original
    case.close()



#### Reject a symbolic-link destination instead of replacing its target.
####
def test_symbolic_link_destination_is_rejected(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    target = tmp_path / "link-target.psafe3"
    target.write_bytes(case.source.read_bytes())
    link = tmp_path / "linked-source.psafe3"
    try:
        link.symlink_to(target)
    except OSError:
        case.close()
        pytest.skip("symbolic links are unavailable")
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )

    with pytest.raises(StorageError):
        store.capture(link)

    assert target.read_bytes() == case.source.read_bytes()
    case.candidate.path.unlink()
    case.close()



#### Reject a recovery directory reached through a symbolic-link component.
####
def test_symbolic_link_recovery_directory_is_rejected(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    real_recovery = _private_directory(tmp_path, "real-recovery")
    linked_recovery = tmp_path / "linked-recovery"
    try:
        linked_recovery.symlink_to(real_recovery, target_is_directory=True)
    except OSError:
        case.candidate.path.unlink()
        case.close()
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(StorageError):
        LocalVaultStore(
            _private_directory(tmp_path, "store-working"),
            linked_recovery,
            validator=case.validator,
        )

    assert not any(os.scandir(real_recovery))
    case.candidate.path.unlink()
    case.close()



#### Reject a non-privileged Windows junction in a captured file ancestry.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_capture_rejects_windows_junction_ancestor(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    target = tmp_path / "junction-target"
    target.mkdir()
    target_file = target / "vault.psafe3"
    target_file.write_bytes(case.source.read_bytes())
    junction = tmp_path / "junction-parent"
    _create_windows_junction(junction, target)
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )

    with pytest.raises(StorageError):
        store.capture(junction / target_file.name)

    assert target_file.read_bytes() == case.source.read_bytes()
    case.candidate.path.unlink()
    case.close()



#### Sanitize cleanup when validation removes the staged pathname unexpectedly.
####
def test_staged_removal_during_validation_returns_safe_typed_error(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()



    #### Remove the staged name and raise a path-bearing untrusted exception.
    ####
    def remove_and_reject(path: Path) -> None:
        path.unlink()
        raise ValueError(str(path))

    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=remove_and_reject,
    )

    with pytest.raises(StorageError) as captured:
        store.publish(case.source, case.candidate, store.capture(case.source))

    assert captured.value.__cause__ is None
    assert str(tmp_path) not in str(captured.value)
    assert case.source.read_bytes() == original
    case.close()



#### Reject a FIFO immediately instead of blocking while opening it for capture.
####
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO behavior")
def test_capture_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    case = _publication_case(tmp_path)
    fifo = tmp_path / "vault.fifo"
    make_fifo = vars(os).get("mkfifo")
    assert callable(make_fifo)
    make_fifo(fifo)
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )

    with pytest.raises(StorageError):
        store.capture(fifo)

    case.candidate.path.unlink()
    case.close()



#### Recheck the POSIX staged name inside the final replacement boundary.
####
@pytest.mark.skipif(os.name == "nt", reason="POSIX anchored replacement behavior")
def test_posix_swap_at_replace_boundary_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _publication_case(tmp_path)
    original = case.source.read_bytes()
    store = LocalVaultStore(
        _private_directory(tmp_path, "store-working"),
        _private_directory(tmp_path, "store-recovery"),
        validator=case.validator,
    )
    production_replace = _PosixPublicationAnchor.replace_child



    #### Swap the staged name at method entry before its final inode check.
    ####
    def swap_before_replace(
        anchor: _PosixPublicationAnchor,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        staged = anchor._path / source_name
        staged.unlink()
        staged.write_bytes(b"substituted at replace boundary")
        return production_replace(anchor, descriptor, identity, source_name, destination_name)

    monkeypatch.setattr(_PosixPublicationAnchor, "replace_child", swap_before_replace)

    with pytest.raises(StorageError):
        store.publish(case.source, case.candidate, store.capture(case.source))

    assert case.source.read_bytes() == original
    case.close()
