"""Verify encrypted snapshots are private, immutable, bounded file owners.

The tests use only fabricated ciphertext.  Source path text is deliberately
sensitive-looking so failures and representations prove they do not retain it.
"""

import copy
import ctypes
import errno
import gc
import io
import os
import pickle
import stat
import struct
import sys
import weakref
from ctypes import wintypes
from pathlib import Path
from typing import Protocol, cast

import pytest

from bonobo_core.passwordsafe.errors import ResourceLimitError, ResourceLimitReason, StorageError, StorageReason
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



#### Delete every exclusively created child when post-create verification fails.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows owned-handle cleanup")
def test_windows_post_create_verifier_failure_leaks_no_retry_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _windows_security, snapshots

    directory = _private_directory(tmp_path)
    anchor = _windows_security.WindowsDirectoryAnchor.open(directory)
    assert anchor is not None
    verifier_calls = 0



    #### Fail only child privacy verification after the directory anchor is open.
    ####
    def fail_child_verifier(_handle: wintypes.HANDLE) -> bool:
        nonlocal verifier_calls
        verifier_calls += 1
        return False

    monkeypatch.setattr(snapshots, "_validate_private_directory", lambda _directory: anchor)
    monkeypatch.setattr(_windows_security, "_handle_is_private", fail_child_verifier)

    with pytest.raises(StorageError) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert verifier_calls == 32
    assert tuple(directory.iterdir()) == ()
    assert caught.value.__context__ is None



#### Keep disposition failure path-free while close-on-failure removes the child.
####
@pytest.mark.skipif(os.name != "nt", reason="Windows owned-handle cleanup")
@pytest.mark.parametrize("disposition_failure", [None, KeyboardInterrupt("disposition interrupted")])
def test_windows_post_create_disposition_failure_is_closed_and_leak_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition_failure: BaseException | None,
) -> None:
    from bonobo_core.passwordsafe import _windows_security, snapshots

    directory = _private_directory(tmp_path)
    anchor = _windows_security.WindowsDirectoryAnchor.open(directory)
    assert anchor is not None
    stable_calls = 0
    disposition_calls = 0



    #### Pass the pre-create stability check and fail the post-create check once.
    ####
    def fail_post_create_stability(_anchor: _windows_security.WindowsDirectoryAnchor) -> bool:
        nonlocal stable_calls
        stable_calls += 1
        return stable_calls == 1



    #### Refuse the explicit cleanup disposition so create-on-close is exercised.
    ####
    def fail_disposition(*_arguments: object) -> bool:
        nonlocal disposition_calls
        disposition_calls += 1
        if disposition_failure is not None:
            raise disposition_failure
        _windows_security._WINDOWS_CTYPES.set_last_error(5)
        return False

    monkeypatch.setattr(snapshots, "_validate_private_directory", lambda _directory: anchor)
    monkeypatch.setattr(_windows_security.WindowsDirectoryAnchor, "_stable", fail_post_create_stability)
    monkeypatch.setattr(_windows_security._KERNEL32, "SetFileInformationByHandle", fail_disposition)

    with pytest.raises(StorageError) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert disposition_calls == 1
    assert tuple(directory.iterdir()) == ()
    assert caught.value.__context__ is None
    assert "private" not in repr(caught.value)



#### Raise one path-bearing platform error after capture has created its artifact.
####
class _FailingSource:



    #### Fail every bounded read with text that must not survive in error state.
    ####
    def readinto(self, _buffer: bytearray) -> int:
        raise OSError("C:/sensitive/vault-name.psafe3")



#### Forge a typed resource failure with an explicitly path-bearing cause.
####
class _ForgedResourceFailureSource:



    #### Raise a closed public error that capture must still treat as untrusted.
    ####
    def readinto(self, _buffer: bytearray) -> int:
        try:
            raise OSError("C:/sensitive/forged-vault.psafe3")
        except OSError as source_error:
            raise ResourceLimitError(ResourceLimitReason.MAX_RECORDS) from source_error



#### Interrupt capture through the process-control BaseException boundary.
####
class _InterruptingSource:



    #### Raise one active control-flow exception instead of an ordinary source failure.
    ####
    def readinto(self, _buffer: bytearray) -> int:
        raise KeyboardInterrupt("capture interrupted")



#### Create a Windows directory junction without requiring symlink privilege.
####
def _create_windows_junction(link: Path, target: Path) -> None:
    from bonobo_core.passwordsafe import _windows_security

    kernel32 = _windows_security._WINDOWS_CTYPES.WinDLL("kernel32", use_last_error=True)
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



#### Enforce the encrypted-file byte boundary while streaming, before excess writes.
####
def test_snapshot_capture_enforces_streamed_byte_budget_and_cleans_artifact(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"123456789"), directory, chunk_size=4, max_bytes=9)

    assert snapshot.size == 9
    snapshot.close()

    with pytest.raises(ResourceLimitError) as caught:
        EncryptedSnapshot.capture(io.BytesIO(b"1234567890"), directory, chunk_size=4, max_bytes=9)

    assert caught.value.reason == ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES
    assert tuple(directory.iterdir()) == ()



#### Reject capture bounds that disable or exceed the reviewed outer ceiling.
####
@pytest.mark.parametrize("max_bytes", [0, -1, 4_296_015_873, True])
def test_snapshot_capture_rejects_invalid_byte_budget(tmp_path: Path, max_bytes: object) -> None:
    directory = _private_directory(tmp_path)

    with pytest.raises((TypeError, ValueError), match="maximum snapshot bytes"):
        EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory, max_bytes=cast(int, max_bytes))

    assert tuple(directory.iterdir()) == ()



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

    expected_entries = 1 if os.name == "nt" else 0
    assert len(tuple(directory.iterdir())) == expected_entries
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

    assert stat.S_IMODE(os.fstat(snapshot._fd).st_mode) == 0o600
    assert tuple(directory.iterdir()) == ()
    snapshot.close()



#### Keep POSIX snapshots anonymous for their entire readable lifetime.
####
@pytest.mark.skipif(os.name == "nt", reason="POSIX anonymous-file lifecycle")
def test_posix_snapshot_has_no_directory_entry_while_live(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)

    assert tuple(directory.iterdir()) == ()
    assert snapshot.read_at(0, 9) == b"encrypted"
    snapshot.close()
    assert tuple(directory.iterdir()) == ()



#### Fail closed on Linux when its only anonymous file primitive is unavailable.
####
def test_linux_anchor_never_falls_back_to_a_named_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    created_names: list[str] = []



    #### Supply only the already validated anchor identity.
    ####
    class Metadata:
        st_dev = 5
        st_ino = 6



    #### Record any forbidden attempt to create a visible fallback name.
    ####
    def fake_open(name: str, *_arguments: object, **_keywords: object) -> int:
        created_names.append(name)
        return 99

    monkeypatch.setattr(snapshots, "_POSIX_FILE_STRATEGY", "linux-o-tmpfile", raising=False)
    monkeypatch.setattr(snapshots, "_O_TMPFILE", 0)
    monkeypatch.setattr(os, "fstat", lambda _descriptor: Metadata())
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(snapshots._PosixDirectoryAnchor, "_stable", lambda _anchor: True)
    anchor = snapshots._PosixDirectoryAnchor(Path("unused"), 10)

    created = anchor.create("snapshot-fixed")

    assert created is None
    assert created_names == []



#### Describe the ctypes by-reference cell supplied to the fake entry function.
####
class _CtypesOutput(Protocol):
    _obj: object



#### Emulate the three descriptor-only Darwin ACL calls and their errno state.
####
class _FakeDarwinAclApi:



    #### Configure one ACL allocation, entry result, and optional injected failure.
    ####
    def __init__(
        self,
        *,
        acl: int | None = 0x1234,
        entry_result: int = -1,
        entry_errno: int = errno.EINVAL,
        entry_pointer: int | None = None,
        entry_error: BaseException | None = None,
        free_result: int = 0,
    ) -> None:
        self.acl = acl
        self.entry_result = entry_result
        self.entry_errno = entry_errno
        self.entry_pointer = entry_pointer
        self.entry_error = entry_error
        self.free_result = free_result
        self.get_calls: list[tuple[int, int]] = []
        self.entry_calls: list[tuple[int, int]] = []
        self.free_calls: list[int] = []



    #### Return one fake allocated ACL or the native null failure sentinel.
    ####
    def get_fd(self, descriptor: int, acl_type: int) -> int | None:
        self.get_calls.append((descriptor, acl_type))
        return self.acl



    #### Return one first-entry status after setting the captured native errno.
    ####
    def get_entry(self, acl: int, entry_id: int, _entry: _CtypesOutput) -> int:
        self.entry_calls.append((acl, entry_id))
        if self.entry_error is not None:
            raise self.entry_error
        if self.entry_pointer is not None:
            output = cast(ctypes.c_void_p, _entry._obj)
            output.value = self.entry_pointer
        ctypes.set_errno(self.entry_errno)
        return self.entry_result



    #### Record release of the exact allocated ACL working object.
    ####
    def free(self, acl: int) -> int:
        self.free_calls.append(acl)
        return self.free_result



#### Accept a descriptor only when its allocated extended ACL has no first entry.
####
def test_darwin_acl_helper_accepts_empty_acl_and_frees_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    api = _FakeDarwinAclApi()
    monkeypatch.setattr(_darwin_security, "_ACL_API", api)

    _darwin_security.require_no_extended_acl(41)

    assert api.get_calls == [(41, 0x100)]
    assert api.entry_calls == [(0x1234, 0)]
    assert api.free_calls == [0x1234]



#### Reject an allocated ACL containing even one entry and still free it once.
####
def test_darwin_acl_helper_rejects_any_entry_and_frees_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    api = _FakeDarwinAclApi(entry_result=0, entry_errno=0, entry_pointer=0x5678)
    monkeypatch.setattr(_darwin_security, "_ACL_API", api)

    with pytest.raises(StorageError) as caught:
        _darwin_security.require_no_extended_acl(42)

    assert caught.value.__context__ is None
    assert api.free_calls == [0x1234]



#### Fail closed when native ACL retrieval returns its null failure sentinel.
####
def test_darwin_acl_helper_rejects_acl_get_failure_without_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    api = _FakeDarwinAclApi(acl=None)
    monkeypatch.setattr(_darwin_security, "_ACL_API", api)

    with pytest.raises(StorageError) as caught:
        _darwin_security.require_no_extended_acl(43)

    assert caught.value.__context__ is None
    assert api.free_calls == []



#### Exhaust ACL release after either ordinary or control-flow entry failure.
####
@pytest.mark.parametrize("error", [RuntimeError("entry failure"), KeyboardInterrupt("entry failure")])
def test_darwin_acl_helper_frees_after_every_entry_exception(
    error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    api = _FakeDarwinAclApi(entry_error=error)
    monkeypatch.setattr(_darwin_security, "_ACL_API", api)

    with pytest.raises(StorageError) as caught:
        _darwin_security.require_no_extended_acl(44)

    assert caught.value.__context__ is None
    assert api.free_calls == [0x1234]



#### Fail closed on nonempty errno and anomalous ACL/free return statuses.
####
@pytest.mark.parametrize(
    ("entry_result", "entry_errno", "entry_pointer", "free_result"),
    [
        (-1, 0, None, 0),
        (-1, errno.EIO, None, 0),
        (1, errno.EINVAL, None, 0),
        (0, 0, None, 0),
        (-1, errno.EINVAL, None, -1),
    ],
)
def test_darwin_acl_helper_rejects_native_api_anomalies(
    entry_result: int,
    entry_errno: int,
    entry_pointer: int | None,
    free_result: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    api = _FakeDarwinAclApi(
        entry_result=entry_result,
        entry_errno=entry_errno,
        entry_pointer=entry_pointer,
        free_result=free_result,
    )
    monkeypatch.setattr(_darwin_security, "_ACL_API", api)

    with pytest.raises(StorageError) as caught:
        _darwin_security.require_no_extended_acl(45)

    assert caught.value.__context__ is None
    assert api.free_calls == [0x1234]



#### Reject a private-directory ACL before attempting any named child creation.
####
def test_macos_anchor_rejects_directory_extended_acl_before_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    created_names: list[str] = []



    #### Reject only the retained directory descriptor with one safe category.
    ####
    def reject_directory(descriptor: int) -> None:
        assert descriptor == 10
        raise StorageError(StorageReason.PREPARATION_FAILED)



    #### Record any forbidden named child creation attempt.
    ####
    def fake_open(name: str, *_arguments: object, **_keywords: object) -> int:
        created_names.append(name)
        return 99

    monkeypatch.setattr(snapshots, "_POSIX_FILE_STRATEGY", "macos-unlinked", raising=False)
    monkeypatch.setattr(snapshots, "_require_no_extended_acl", reject_directory, raising=False)
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(snapshots._PosixDirectoryAnchor, "_stable", lambda _anchor: True)
    anchor = snapshots._PosixDirectoryAnchor(Path("unused"), 10)

    with pytest.raises(StorageError) as caught:
        anchor.create("snapshot-fixed")

    assert caught.value.__context__ is None
    assert created_names == []



#### Unlink and close an exclusive child whose inherited extended ACL is nonempty.
####
def test_macos_anchor_rejects_child_extended_acl_without_leaking_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    entries = {"snapshot-fixed"}
    checked: list[int] = []
    closed: list[int] = []



    #### Supply stable regular-file metadata for the retained anchor and child.
    ####
    class Metadata:
        st_mode = stat.S_IFREG | 0o600
        st_dev = 7
        st_ino = 8
        st_nlink = 1



    #### Accept the directory ACL but reject the exclusively opened child ACL.
    ####
    def reject_child(descriptor: int) -> None:
        checked.append(descriptor)
        if descriptor == 99:
            raise StorageError(StorageReason.PREPARATION_FAILED)



    #### Remove only the still-exclusive child from the anchored namespace.
    ####
    def fake_unlink(name: str, **_arguments: object) -> None:
        entries.remove(name)

    monkeypatch.setattr(snapshots, "_POSIX_FILE_STRATEGY", "macos-unlinked", raising=False)
    monkeypatch.setattr(snapshots, "_require_no_extended_acl", reject_child, raising=False)
    monkeypatch.setattr(os, "fstat", lambda _descriptor: Metadata())
    monkeypatch.setattr(os, "open", lambda *_arguments, **_keywords: 99)
    monkeypatch.setattr(os, "unlink", fake_unlink)
    monkeypatch.setattr(os, "close", closed.append)
    monkeypatch.setattr(snapshots._PosixDirectoryAnchor, "_stable", lambda _anchor: True)
    anchor = snapshots._PosixDirectoryAnchor(Path("unused"), 10)

    with pytest.raises(StorageError) as caught:
        anchor.create("snapshot-fixed")

    assert caught.value.__context__ is None
    assert checked == [10, 99]
    assert entries == set()
    assert closed == [99]



#### Exercise the real Darwin directory-fd ACL API on an owner-only directory.
####
@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin extended ACL behavior")
def test_darwin_native_private_directory_has_no_extended_acl(tmp_path: Path) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    directory = _private_directory(tmp_path)
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _darwin_security.require_no_extended_acl(descriptor)
    finally:
        os.close(descriptor)



#### Exercise the real Darwin child-fd ACL API before unlinking its name.
####
@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin extended ACL behavior")
def test_darwin_native_private_child_has_no_extended_acl(tmp_path: Path) -> None:
    from bonobo_core.passwordsafe import _darwin_security

    directory = _private_directory(tmp_path)
    artifact = directory / "acl-check"
    descriptor = os.open(artifact, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _darwin_security.require_no_extended_acl(descriptor)
    finally:
        os.close(descriptor)
        artifact.unlink()



#### Immediately unlink a macOS child without a check-then-act pathname read.
####
def test_macos_anchor_returns_only_an_immediately_unlinked_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    anchor_identity = (5, 6)
    file_identity = (7, 8)
    unlinked = False



    #### Supply directory or file metadata with the current link count.
    ####
    class Metadata:



        #### Retain the requested identity and regular-file link state.
        ####
        def __init__(self, identity: tuple[int, int], *, links: int) -> None:
            self.st_mode = stat.S_IFREG | 0o600
            self.st_dev, self.st_ino = identity
            self.st_nlink = links



    #### Report the created fd as anonymous only after its anchored unlink.
    ####
    def fake_fstat(descriptor: int) -> Metadata:
        if descriptor == 10:
            return Metadata(anchor_identity, links=1)
        return Metadata(file_identity, links=0 if unlinked else 1)



    #### Remove the one exact fallback directory entry.
    ####
    def fake_unlink(name: str, **_arguments: object) -> None:
        nonlocal unlinked
        assert name == "snapshot-fixed"
        unlinked = True

    monkeypatch.setattr(snapshots, "_POSIX_FILE_STRATEGY", "macos-unlinked", raising=False)
    monkeypatch.setattr(snapshots, "_require_no_extended_acl", lambda _descriptor: None)
    monkeypatch.setattr(os, "fstat", fake_fstat)
    monkeypatch.setattr(os, "open", lambda *_arguments, **_keywords: 99)
    monkeypatch.setattr(
        os,
        "stat",
        lambda *_arguments, **_keywords: (_ for _ in ()).throw(AssertionError("check-then-act stat used")),
    )
    monkeypatch.setattr(os, "unlink", fake_unlink)
    monkeypatch.setattr(snapshots._PosixDirectoryAnchor, "_stable", lambda _anchor: True)
    anchor = snapshots._PosixDirectoryAnchor(Path("unused"), 10)

    created = anchor.create("snapshot-fixed")

    assert created == (99, file_identity, None)
    assert unlinked



#### Unlink a macOS child best-effort when post-create stability fails.
####
def test_macos_post_create_failure_leaves_no_directory_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bonobo_core.passwordsafe import snapshots

    anchor_identity = (5, 6)
    file_identity = (7, 8)
    entries = {"snapshot-fixed": file_identity}
    stable_calls = 0



    #### Supply the retained anchor or linked created-file metadata.
    ####
    class Metadata:



        #### Retain the selected identity and link count.
        ####
        def __init__(self, identity: tuple[int, int], *, links: int) -> None:
            self.st_mode = stat.S_IFREG | 0o600
            self.st_dev, self.st_ino = identity
            self.st_nlink = links



    #### Pass initial validation, then fail after exclusive creation.
    ####
    def fail_post_create(_anchor: snapshots._PosixDirectoryAnchor) -> bool:
        nonlocal stable_calls
        stable_calls += 1
        return stable_calls == 1



    #### Remove the exact exclusive child from the fake anchored namespace.
    ####
    def fake_unlink(name: str, **_arguments: object) -> None:
        entries.pop(name)

    monkeypatch.setattr(snapshots, "_POSIX_FILE_STRATEGY", "macos-unlinked", raising=False)
    monkeypatch.setattr(snapshots, "_require_no_extended_acl", lambda _descriptor: None)
    monkeypatch.setattr(
        os,
        "fstat",
        lambda descriptor: Metadata(anchor_identity if descriptor == 10 else file_identity, links=1),
    )
    monkeypatch.setattr(os, "open", lambda *_arguments, **_keywords: 99)
    monkeypatch.setattr(os, "unlink", fake_unlink)
    monkeypatch.setattr(snapshots._PosixDirectoryAnchor, "_stable", fail_post_create)
    anchor = snapshots._PosixDirectoryAnchor(Path("unused"), 10)

    with pytest.raises(OSError):
        anchor.create("snapshot-fixed")

    assert entries == {}



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



#### Release one forgotten snapshot through its actual automatic finalizer.
####
def test_snapshot_real_finalizer_releases_artifact(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    snapshot = EncryptedSnapshot.capture(io.BytesIO(b"encrypted"), directory)
    snapshot_reference = weakref.ref(snapshot)

    del snapshot
    gc.collect()

    assert snapshot_reference() is None
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



#### Contain forged typed source errors and discard every sensitive exception link.
####
def test_snapshot_capture_contains_forged_resource_error_and_cleans_artifact(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)

    with pytest.raises(StorageError) as caught:
        EncryptedSnapshot.capture(_ForgedResourceFailureSource(), directory)

    assert caught.value.reason == StorageReason.PREPARATION_FAILED
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "sensitive" not in str(caught.value)
    assert "sensitive" not in repr(caught.value)
    assert all("sensitive" not in repr(argument) for argument in caught.value.args)
    assert tuple(directory.iterdir()) == ()



#### Preserve active BaseException propagation while removing the partial artifact.
####
def test_snapshot_capture_propagates_source_base_exception_after_cleanup(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)

    with pytest.raises(KeyboardInterrupt, match="capture interrupted"):
        EncryptedSnapshot.capture(_InterruptingSource(), directory)

    assert tuple(directory.iterdir()) == ()



#### Keep cleanup retryable after one transient unlink failure.
####
def test_snapshot_close_retries_transient_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("POSIX anonymous snapshots have no cleanup pathname")
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
