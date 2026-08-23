"""Verify encrypted snapshots are private, immutable, bounded file owners.

The tests use only fabricated ciphertext.  Source path text is deliberately
sensitive-looking so failures and representations prove they do not retain it.
"""

import copy
import ctypes
import io
import os
import pickle
import stat
import struct
from ctypes import wintypes
from pathlib import Path
from typing import cast

import pytest

from bonobo_core.passwordsafe.errors import StorageError
from bonobo_core.passwordsafe.snapshots import (
    EncryptedSnapshot,
    SnapshotClosedError,
    _windows_path_is_private,
)



#### Create one caller-owned private directory for snapshot artifacts.
####
def _private_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory



#### Reject a deliberately inherited broad Windows DACL without path disclosure.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows DACL behavior")
def test_snapshot_rejects_permissive_windows_directory(tmp_path: Path) -> None:
    directory = tmp_path / "shared-windows"
    directory.mkdir(mode=0o777)

    assert not _windows_path_is_private(directory)
    with pytest.raises(StorageError) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert caught.value.__context__ is None
    assert "shared-windows" not in str(caught.value)
    assert tuple(directory.iterdir()) == ()



#### Create and verify an explicitly protected owner-only Windows artifact DACL.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows DACL behavior")
def test_snapshot_file_has_protected_owner_only_windows_dacl(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    assert _windows_path_is_private(directory)

    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    artifact = next(directory.iterdir())

    assert _windows_path_is_private(artifact)
    snapshot.close()



#### Raise one path-bearing platform error after capture has created its artifact.
####
class _FailingSource:



    #### Fail every bounded read with text that must not survive in error state.
    ####
    def readinto(self, _buffer: bytearray) -> int:
        raise OSError("C:/sensitive/vault-name.psafe3")



#### Create a Windows directory junction without requiring symlink privilege.
####
def _create_windows_junction(link: Path, target: Path) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    link.mkdir()
    handle = kernel32.CreateFileW(str(link), 0x40000000, 0, None, 3, 0x02200000, None)
    if ctypes.cast(handle, ctypes.c_void_p).value == ctypes.c_void_p(-1).value:
        raise OSError
    substitute = ("\\??\\" + str(target)).encode("utf-16le")
    printable = str(target).encode("utf-16le")
    path_buffer = substitute + b"\0\0" + printable + b"\0\0"
    reparse = struct.pack(
        "<LHHHHHH",
        0xA0000003,
        len(path_buffer) + 8,
        0,
        0,
        len(substitute),
        len(substitute) + 2,
        len(printable),
    ) + path_buffer
    buffer = ctypes.create_string_buffer(reparse)
    returned = wintypes.DWORD()
    try:
        if not kernel32.DeviceIoControl(
            handle,
            0x000900A4,
            buffer,
            len(reparse),
            None,
            0,
            ctypes.byref(returned),
            None,
        ):
            raise OSError
    finally:
        kernel32.CloseHandle(handle)



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

    with pytest.raises(StorageError) as caught:
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

    with pytest.raises(StorageError) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), link)

    assert "linked-private" not in str(caught.value)
    assert tuple(target.iterdir()) == ()



#### Reject a non-privileged Windows junction anywhere in directory ancestry.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_snapshot_rejects_windows_junction_ancestor(tmp_path: Path) -> None:
    target = tmp_path / "junction-target"
    target.mkdir(mode=0o700)
    private = target / "private"
    private.mkdir(mode=0o700)
    link = tmp_path / "junction-parent"
    _create_windows_junction(link, target)

    try:
        with pytest.raises(StorageError):
            EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), link / "private")
    finally:
        link.unlink()

    assert tuple(private.iterdir()) == ()



#### Reject a directory name swapped after anchor validation but before creation.
####
def test_snapshot_rejects_directory_swap_during_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _private_directory(tmp_path)
    moved = tmp_path / "moved-private"
    from bonobo_core.passwordsafe import snapshots

    original = snapshots._create_private_artifact



    #### Replace the validated pathname once, then exercise its retained anchor.
    ####
    def swap_then_create(anchor: snapshots._DirectoryAnchor) -> tuple[int, str, tuple[int, int]] | None:
        directory.replace(moved)
        directory.mkdir(mode=0o700)
        return original(anchor)

    monkeypatch.setattr(snapshots, "_create_private_artifact", swap_then_create)

    with pytest.raises(StorageError):
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert tuple(directory.iterdir()) == ()
    assert tuple(moved.iterdir()) == ()



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

    with pytest.raises(StorageError) as caught:
        EncryptedSnapshot.capture(_FailingSource(), directory)

    assert tuple(directory.iterdir()) == ()
    assert caught.value.__context__ is None
    assert "sensitive" not in repr(caught.value)



#### Keep cleanup retryable after one transient unlink failure.
####
def test_snapshot_close_retries_transient_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    from bonobo_core.passwordsafe import snapshots

    original = snapshots._unlink_if_same
    calls = 0



    #### Fail one anchored unlink before delegating every retry unchanged.
    ####
    def fail_once(anchor: snapshots._DirectoryAnchor, name: str, identity: tuple[int, int]) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("sensitive path diagnostic")
        original(anchor, name, identity)

    monkeypatch.setattr(snapshots, "_unlink_if_same", fail_once)

    with pytest.raises(StorageError) as caught:
        snapshot.close()
    assert caught.value.__context__ is None
    assert "sensitive" not in repr(caught.value)
    closed_after_failure = snapshot.closed
    assert not closed_after_failure

    snapshot.close()
    assert snapshot.closed
    assert tuple(directory.iterdir()) == ()



#### Never remove a different file substituted at the snapshot pathname.
####
def test_snapshot_close_preserves_substituted_target(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    artifact = next(directory.iterdir())
    moved = directory / "moved-artifact"
    artifact.replace(moved)
    artifact.write_bytes(b"substituted")

    snapshot.close()

    assert artifact.read_bytes() == b"substituted"
    moved.unlink()
    artifact.unlink()
