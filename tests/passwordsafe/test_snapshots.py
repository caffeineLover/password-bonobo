"""Verify encrypted snapshots are private, immutable, bounded file owners.

The tests use only fabricated ciphertext.  Source path text is deliberately
sensitive-looking so failures and representations prove they do not retain it.
"""

import copy
import io
import os
import pickle
import stat
from pathlib import Path
from typing import cast

import pytest

from bonobo_core.passwordsafe.snapshots import EncryptedSnapshot, SnapshotClosedError



#### Create one caller-owned private directory for snapshot artifacts.
####
def _private_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory



#### Raise one path-bearing platform error after capture has created its artifact.
####
class _FailingSource:



    #### Fail every bounded read with text that must not survive in error state.
    ####
    def readinto(self, _buffer: bytearray) -> int:
        raise OSError("C:/sensitive/vault-name.psafe3")



#### Capture fabricated ciphertext and expose only bounded exact offset reads.
####
def test_snapshot_capture_records_identity_and_bounded_reads(tmp_path: Path) -> None:
    ciphertext = bytes(range(256)) * 700
    directory = _private_directory(tmp_path)

    snapshot = EncryptedSnapshot.capture(io.BytesIO(ciphertext), directory, chunk_size=4096)

    assert snapshot.size == len(ciphertext)
    assert snapshot.sha256 == "5ae0db5b0a20d3b52286f7bd7cc9077915b9a1487d542debeedaa57bee73473c"
    assert snapshot.read_at(31, 97) == ciphertext[31:128]
    assert b"".join(bytes(chunk) for chunk in snapshot.iter_chunks(11, 9000, 1024)) == ciphertext[11:9011]
    assert "private" not in repr(snapshot)
    snapshot.close()



#### Prevent callers from mutating the synchronized encrypted content identity.
####
def test_snapshot_identity_metadata_is_immutable(tmp_path: Path) -> None:
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), _private_directory(tmp_path))

    # Deliberately cross the statically read-only boundary to verify runtime
    # enforcement for untyped callers.
    with pytest.raises(AttributeError):
        snapshot.size = 0  # type: ignore[misc]
    with pytest.raises(AttributeError):
        snapshot.sha256 = "0" * 64  # type: ignore[misc]

    snapshot.close()



#### Remove the exclusively created encrypted artifact on deterministic close.
####
def test_snapshot_close_is_idempotent_and_terminal(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert len(tuple(directory.iterdir())) == 1
    snapshot.close()
    snapshot.close()

    assert tuple(directory.iterdir()) == ()
    assert snapshot.closed
    with pytest.raises(SnapshotClosedError, match="encrypted snapshot is closed"):
        snapshot.read_at(0, 1)



#### Reject invalid ranges before any snapshot read can escape its fixed bounds.
####
@pytest.mark.parametrize(
    ("offset", "length"),
    [(-1, 1), (0, -1), (4, 1), (0, 65_537), (True, 1), (0, True)],
)
def test_snapshot_rejects_invalid_or_unbounded_reads(tmp_path: Path, offset: object, length: object) -> None:
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"abcd"), _private_directory(tmp_path))

    with pytest.raises((TypeError, ValueError)):
        snapshot.read_at(cast(int, offset), cast(int, length))

    snapshot.close()



#### Prevent generic duplication or serialization from aliasing a file owner.
####
def test_snapshot_rejects_copy_and_pickle(tmp_path: Path) -> None:
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), _private_directory(tmp_path))

    with pytest.raises(TypeError, match="snapshot owner cannot be copied or serialized"):
        copy.copy(snapshot)
    with pytest.raises(TypeError, match="snapshot owner cannot be copied or serialized"):
        copy.deepcopy(snapshot)
    with pytest.raises(TypeError, match="snapshot owner cannot be copied or serialized"):
        pickle.dumps(snapshot)

    snapshot.close()



#### Require private POSIX directory permissions before publishing an artifact.
####
@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not an ACL proof on Windows")
def test_snapshot_rejects_nonprivate_directory(tmp_path: Path) -> None:
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)

    with pytest.raises(Exception) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert "shared" not in str(caught.value)
    assert tuple(directory.iterdir()) == ()



#### Apply owner-only mode bits to the exclusively created artifact on POSIX.
####
@pytest.mark.skipif(os.name == "nt", reason="Windows owner-only behavior uses platform ACL semantics")
def test_snapshot_file_is_owner_only_while_open(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    artifact = next(directory.iterdir())

    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    snapshot.close()



#### Reject a symlink masquerading as the caller's private directory.
####
def test_snapshot_rejects_symlink_directory_where_supported(tmp_path: Path) -> None:
    target = _private_directory(tmp_path)
    link = tmp_path / "linked-private"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(Exception) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), link)

    assert "linked-private" not in str(caught.value)
    assert tuple(target.iterdir()) == ()



#### Suppress cleanup failures from defensive finalization while becoming terminal.
####
def test_snapshot_finalizer_is_idempotent(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    snapshot.__del__()
    snapshot.__del__()

    assert snapshot.closed
    assert tuple(directory.iterdir()) == ()



#### Remove partial artifacts and discard path-bearing exception context on failure.
####
def test_snapshot_capture_failure_cleans_up_without_retaining_source_error(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)

    with pytest.raises(Exception) as caught:
        EncryptedSnapshot.capture(_FailingSource(), directory)

    assert tuple(directory.iterdir()) == ()
    assert caught.value.__context__ is None
    assert "sensitive" not in repr(caught.value)
