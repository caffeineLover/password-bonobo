"""Verify encrypted snapshots are private, immutable, bounded file owners.

The tests use only fabricated ciphertext.  Source path text is deliberately
sensitive-looking so failures and representations prove they do not retain it.
"""

import copy
import ctypes
import io
import os
import pickle
import secrets
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
    if os.name != "nt":
        pytest.skip("Windows RootDirectory-relative create interleaving")
    from bonobo_core.passwordsafe import _windows_security



    #### Replace the validated pathname once, then exercise its retained anchor.
    ####
    def swap_before_create() -> None:
        directory.replace(moved)
        directory.mkdir(mode=0o700)

    monkeypatch.setattr(_windows_security, "_before_relative_create", swap_before_create, raising=False)

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
    def fail_once(
        anchor: snapshots._DirectoryAnchor,
        descriptor: int,
        name: str,
        identity: tuple[int, int],
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("sensitive path diagnostic")
        original(anchor, descriptor, name, identity)

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



#### Delete through the verified handle after an exact pathname substitution.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows handle disposition interleaving")
def test_snapshot_close_deletes_owned_handle_and_preserves_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _windows_security

    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    artifact = next(directory.iterdir())
    moved = directory / "moved-artifact"
    swapped = False



    #### Substitute the public name after handle verification, before disposition.
    ####
    def substitute_before_delete() -> None:
        nonlocal swapped
        artifact.replace(moved)
        artifact.write_bytes(b"substituted")
        swapped = True

    monkeypatch.setattr(_windows_security, "_before_handle_delete", substitute_before_delete, raising=False)

    snapshot.close()

    assert swapped
    assert artifact.read_bytes() == b"substituted"
    assert not moved.exists()
    artifact.unlink()



#### Treat pointer-width all-ones as invalid and never pass it to CloseHandle.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows HANDLE ABI")
def test_windows_invalid_handle_value_is_never_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from bonobo_core.passwordsafe import _windows_security

    invalid = wintypes.HANDLE(ctypes.c_void_p(-1).value)
    close_calls = 0



    #### Record any forbidden CloseHandle call without invoking the kernel.
    ####
    def record_close(_handle: wintypes.HANDLE) -> bool:
        nonlocal close_calls
        close_calls += 1
        return True

    monkeypatch.setattr(_windows_security._KERNEL32, "CloseHandle", record_close)

    _windows_security._close_handle(invalid)

    assert close_calls == 0



#### Reject a CreateFileW invalid sentinel without forwarding it as a live handle.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows HANDLE ABI")
def test_windows_open_path_rejects_pointer_width_invalid_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    from bonobo_core.passwordsafe import _windows_security

    invalid = wintypes.HANDLE(ctypes.c_void_p(-1).value)
    close_calls = 0



    #### Return the native invalid sentinel for the one path-open boundary.
    ####
    def fail_open(*_arguments: object) -> wintypes.HANDLE:
        return invalid



    #### Record forbidden cleanup of a sentinel that never represented ownership.
    ####
    def record_close(_handle: wintypes.HANDLE) -> bool:
        nonlocal close_calls
        close_calls += 1
        return True

    monkeypatch.setattr(_windows_security._KERNEL32, "CreateFileW", fail_open)
    monkeypatch.setattr(_windows_security._KERNEL32, "CloseHandle", record_close)

    opened = _windows_security._open_path(Path("not-sensitive"), directory=False, access=0)

    assert opened is None
    assert close_calls == 0



#### Map failed NTSTATUS to no ownership and close only anomalous live outputs.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows NtCreateFile ABI")
@pytest.mark.parametrize(
    ("returned_handle", "expected_closes"),
    [(ctypes.c_void_p(-1).value, 0), (123, 1)],
)
def test_windows_nt_create_failure_cleans_only_live_handle(
    monkeypatch: pytest.MonkeyPatch,
    returned_handle: int | None,
    expected_closes: int,
) -> None:
    from bonobo_core.passwordsafe import _windows_security

    close_calls = 0



    #### Return a failing NTSTATUS after writing the selected output HANDLE.
    ####
    def fail_create(file_handle: object, *_arguments: object) -> int:
        output = ctypes.cast(cast(ctypes.c_void_p, file_handle), ctypes.POINTER(wintypes.HANDLE))
        output.contents.value = returned_handle
        return ctypes.c_long(0xC0000035).value



    #### Record cleanup only when the failed call anomalously returned ownership.
    ####
    def record_close(_handle: wintypes.HANDLE) -> bool:
        nonlocal close_calls
        close_calls += 1
        return True

    monkeypatch.setattr(_windows_security._NTDLL, "NtCreateFile", fail_create)
    monkeypatch.setattr(_windows_security._KERNEL32, "CloseHandle", record_close)

    created = _windows_security._nt_create_relative(
        wintypes.HANDLE(1),
        "snapshot-failure",
        wintypes.LPVOID(1),
    )

    assert created is None
    assert close_calls == expected_closes



#### Restore a POSIX substitution from quarantine without deleting either file.
####
@pytest.mark.skipif(os.name == "nt", reason="POSIX dir-fd quarantine behavior")
def test_snapshot_posix_quarantine_restores_interleaved_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    artifact = next(directory.iterdir())
    owned = directory / "owned-moved"
    swapped = False



    #### Swap the verified name immediately before its anchored quarantine rename.
    ####
    def substitute_before_quarantine() -> None:
        nonlocal swapped
        artifact.replace(owned)
        artifact.write_bytes(b"substituted")
        swapped = True

    monkeypatch.setattr(snapshots, "_before_posix_quarantine", substitute_before_quarantine)

    with pytest.raises(StorageError):
        snapshot.close()

    assert swapped
    assert artifact.read_bytes() == b"substituted"
    assert owned.read_bytes() == b"encrypted"
    monkeypatch.setattr(snapshots, "_before_posix_quarantine", lambda: None)
    artifact.unlink()
    owned.replace(artifact)
    snapshot.close()
    assert snapshot.closed



#### Retain a renamed POSIX quarantine identity across transient unlink failure.
####
def test_posix_anchor_retries_quarantine_unlink_after_rename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    identity = (7, 9)
    entries = {"artifact": identity}
    unlink_calls = 0



    #### Supply only regular-file metadata needed by the anchored state machine.
    ####
    class Metadata:
        st_mode = stat.S_IFREG | 0o600
        st_dev = identity[0]
        st_ino = identity[1]



    #### Resolve the in-memory child table or report the expected missing name.
    ####
    def fake_stat(name: str, **_arguments: object) -> Metadata:
        if name not in entries:
            raise FileNotFoundError
        return Metadata()



    #### Move one child name atomically within the fake anchored directory.
    ####
    def fake_rename(source: str, destination: str, **_arguments: object) -> None:
        entries[destination] = entries.pop(source)



    #### Fail the first quarantine unlink, then remove that exact retained name.
    ####
    def fake_unlink(name: str, **_arguments: object) -> None:
        nonlocal unlink_calls
        unlink_calls += 1
        if unlink_calls == 1:
            raise OSError("transient unlink failure")
        entries.pop(name)

    monkeypatch.setattr(os, "fstat", lambda _descriptor: Metadata())
    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(os, "rename", fake_rename)
    monkeypatch.setattr(os, "unlink", fake_unlink)
    monkeypatch.setattr(secrets, "token_hex", lambda _length: "fixed")
    anchor = snapshots._PosixDirectoryAnchor(Path("unused"), 99)

    with pytest.raises(OSError):
        anchor.remove_if_same(99, "artifact", identity)
    assert entries == {"quarantine-fixed": identity}

    assert anchor.remove_if_same(99, "artifact", identity)
    assert entries == {}



#### Keep a missing POSIX target pending until its exact identity is restored.
####
@pytest.mark.skipif(os.name == "nt", reason="POSIX dir-fd missing-target behavior")
def test_snapshot_posix_missing_target_remains_retryable(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    artifact = next(directory.iterdir())
    moved = directory / "owned-moved"
    artifact.replace(moved)

    with pytest.raises(StorageError):
        snapshot.close()

    assert not snapshot.closed
    assert moved.read_bytes() == b"encrypted"
    moved.replace(artifact)
    snapshot.close()
    assert tuple(directory.iterdir()) == ()
    assert snapshot.closed



#### Retry anchor release after artifact deletion without leaking its HANDLE.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows anchor HANDLE lifecycle")
def test_snapshot_close_retries_anchor_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _windows_security

    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    original = _windows_security.WindowsDirectoryAnchor.close
    close_calls = 0



    #### Fail before releasing the anchor once, then delegate the retry.
    ####
    def fail_once(anchor: _windows_security.WindowsDirectoryAnchor) -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise OSError("sensitive anchor diagnostic")
        original(anchor)

    monkeypatch.setattr(_windows_security.WindowsDirectoryAnchor, "close", fail_once)

    with pytest.raises(StorageError):
        snapshot.close()
    pending_after_failure = snapshot.closed
    assert not pending_after_failure

    snapshot.close()
    closed_after_retry = snapshot.closed
    assert closed_after_retry
    assert close_calls == 2
    assert tuple(directory.iterdir()) == ()



#### Retry a failed POSIX anchor close after the artifact is already gone.
####
@pytest.mark.skipif(os.name == "nt", reason="POSIX anchor descriptor lifecycle")
def test_snapshot_posix_retries_anchor_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    original = snapshots._PosixDirectoryAnchor.close
    close_calls = 0



    #### Fail before releasing the anchor once, then delegate the retry.
    ####
    def fail_once(anchor: snapshots._PosixDirectoryAnchor) -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise OSError("sensitive anchor diagnostic")
        original(anchor)

    monkeypatch.setattr(snapshots._PosixDirectoryAnchor, "close", fail_once)

    with pytest.raises(StorageError):
        snapshot.close()
    assert not snapshot.closed
    assert tuple(directory.iterdir()) == ()

    snapshot.close()
    assert close_calls == 2
    assert snapshot.closed
