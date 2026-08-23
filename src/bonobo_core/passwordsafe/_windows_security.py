"""Narrow native Windows security boundary for encrypted snapshot artifacts."""

import ctypes
import msvcrt
import os
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path
from typing import Final



_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

_TOKEN_QUERY: Final[int] = 0x0008
_TOKEN_USER: Final[int] = 1
_SE_FILE_OBJECT: Final[int] = 1
_OWNER_SECURITY_INFORMATION: Final[int] = 0x00000001
_DACL_SECURITY_INFORMATION: Final[int] = 0x00000004
_SE_DACL_PROTECTED: Final[int] = 0x1000
_ACCESS_ALLOWED_ACE_TYPE: Final[int] = 0
_INHERITED_ACE: Final[int] = 0x10
_ACL_SIZE_INFORMATION_CLASS: Final[int] = 2
_FILE_ALL_ACCESS: Final[int] = 0x001F01FF
_GENERIC_READ: Final[int] = 0x80000000
_GENERIC_WRITE: Final[int] = 0x40000000
_READ_CONTROL: Final[int] = 0x00020000
_FILE_READ_ATTRIBUTES: Final[int] = 0x00000080
_FILE_SHARE_READ: Final[int] = 0x00000001
_FILE_SHARE_WRITE: Final[int] = 0x00000002
_FILE_SHARE_DELETE: Final[int] = 0x00000004
_CREATE_NEW: Final[int] = 1
_OPEN_EXISTING: Final[int] = 3
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY: Final[int] = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT: Final[int] = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT: Final[int] = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS: Final[int] = 0x02000000
_INVALID_FILE_ATTRIBUTES: Final[int] = 0xFFFFFFFF
_INVALID_HANDLE_VALUE: Final[int] = -1



#### Mirror SECURITY_ATTRIBUTES at the single native object-creation boundary.
####
class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]



#### Mirror one token SID and its non-secret platform attribute flags.
####
class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]



#### Mirror TOKEN_USER for bounded current-token owner discovery.
####
class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]



#### Mirror aggregate ACL bounds before enumerating any ACE pointer.
####
class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]



#### Mirror the common ACE prefix used to reject inherited or non-allow entries.
####
class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", wintypes.WORD),
    ]



#### Mirror one access-allowed ACE and its variable-length SID starting address.
####
class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [("Header", _AceHeader), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]



#### Mirror stable volume and file-index identity plus reparse attributes.
####
class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]



_ADVAPI32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_ADVAPI32.OpenProcessToken.restype = wintypes.BOOL
_ADVAPI32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_ADVAPI32.GetTokenInformation.restype = wintypes.BOOL
_ADVAPI32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
_ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
_ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.DWORD),
]
_ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
_ADVAPI32.GetSecurityInfo.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
]
_ADVAPI32.GetSecurityInfo.restype = wintypes.DWORD
_ADVAPI32.GetSecurityDescriptorControl.argtypes = [
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.WORD),
    ctypes.POINTER(wintypes.DWORD),
]
_ADVAPI32.GetSecurityDescriptorControl.restype = wintypes.BOOL
_ADVAPI32.GetAclInformation.argtypes = [
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.c_int,
]
_ADVAPI32.GetAclInformation.restype = wintypes.BOOL
_ADVAPI32.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
_ADVAPI32.GetAce.restype = wintypes.BOOL
_KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
_KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
_KERNEL32.CloseHandle.restype = wintypes.BOOL
_KERNEL32.LocalFree.argtypes = [wintypes.HLOCAL]
_KERNEL32.LocalFree.restype = wintypes.HLOCAL
_KERNEL32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(_SecurityAttributes),
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_KERNEL32.CreateFileW.restype = wintypes.HANDLE
_KERNEL32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_KERNEL32.GetFileAttributesW.restype = wintypes.DWORD
_KERNEL32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)]
_KERNEL32.GetFileInformationByHandle.restype = wintypes.BOOL



#### Convert one opaque native handle without leaking its value to diagnostics.
####
def _handle_value(handle: wintypes.HANDLE) -> int:
    value = ctypes.cast(handle, ctypes.c_void_p).value
    return -1 if value is None else value



#### Close one valid native handle while ignoring best-effort cleanup status.
####
def _close_handle(handle: wintypes.HANDLE) -> None:
    if _handle_value(handle) != _INVALID_HANDLE_VALUE:
        _KERNEL32.CloseHandle(handle)



#### Copy the current token user SID and render it for exact ACL comparisons.
####
def _current_sid() -> tuple[ctypes.Array[ctypes.c_char], wintypes.LPVOID, str] | None:
    token = wintypes.HANDLE()
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        return None
    try:
        required = wintypes.DWORD()
        _ADVAPI32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(required))
        if required.value == 0:
            return None
        buffer = ctypes.create_string_buffer(required.value)
        if not _ADVAPI32.GetTokenInformation(
            token,
            _TOKEN_USER,
            buffer,
            required,
            ctypes.byref(required),
        ):
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents.User.Sid
        rendered = _sid_string(sid)
        if rendered is None:
            return None
        return buffer, sid, rendered
    finally:
        _close_handle(token)



#### Render one native SID through the locale-independent security API.
####
def _sid_string(sid: wintypes.LPVOID) -> str | None:
    output = wintypes.LPWSTR()
    if not _ADVAPI32.ConvertSidToStringSidW(sid, ctypes.byref(output)):
        return None
    try:
        return output.value
    finally:
        _KERNEL32.LocalFree(output)



#### Read one stable volume serial and 64-bit file index from an open handle.
####
def _file_identity(handle: wintypes.HANDLE) -> tuple[int, int] | None:
    information = _ByHandleFileInformation()
    if not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        return None
    index = (information.nFileIndexHigh << 32) | information.nFileIndexLow
    return information.dwVolumeSerialNumber, index



#### Require current ownership and a protected DACL containing no broad trustee.
####
def _handle_is_private(handle: wintypes.HANDLE) -> bool:
    current = _current_sid()
    if current is None:
        return False
    _buffer, _sid, current_sid = current
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    status = _ADVAPI32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0 or not descriptor.value or not owner.value or not dacl.value:
        return False
    try:
        if _sid_string(owner) != current_sid:
            return False
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not _ADVAPI32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            return False
        if not control.value & _SE_DACL_PROTECTED:
            return False
        information = _AclSizeInformation()
        if not _ADVAPI32.GetAclInformation(
            dacl,
            ctypes.byref(information),
            ctypes.sizeof(information),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            return False
        allowed_sids = {current_sid, "S-1-3-4", "S-1-5-18", "S-1-5-32-544"}
        owner_has_control = False
        for index in range(information.AceCount):
            ace_pointer = wintypes.LPVOID()
            if not _ADVAPI32.GetAce(dacl, index, ctypes.byref(ace_pointer)) or not ace_pointer.value:
                return False
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
            if ace.Header.AceType != _ACCESS_ALLOWED_ACE_TYPE or ace.Header.AceFlags & _INHERITED_ACE:
                return False
            sid_pointer = wintypes.LPVOID(ace_pointer.value + _AccessAllowedAce.SidStart.offset)
            ace_sid = _sid_string(sid_pointer)
            if ace_sid not in allowed_sids:
                return False
            if ace_sid in {current_sid, "S-1-3-4"} and ace.Mask & _FILE_ALL_ACCESS == _FILE_ALL_ACCESS:
                owner_has_control = True
        return owner_has_control
    finally:
        _KERNEL32.LocalFree(descriptor)



#### Open the object itself without traversing a final reparse-point target.
####
def _open_path(path: Path, *, directory: bool, access: int) -> wintypes.HANDLE | None:
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    handle = _KERNEL32.CreateFileW(
        str(path),
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    return None if _handle_value(handle) == _INVALID_HANDLE_VALUE else handle



#### Read fixed Windows attributes without retaining platform error text.
####
def _attributes(path: Path) -> int | None:
    attributes = int(_KERNEL32.GetFileAttributesW(str(path)))
    return None if attributes == _INVALID_FILE_ATTRIBUTES else attributes



#### Reject every reparse component in the absolute directory ancestry.
####
def _ancestry_is_plain_directory(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        attributes = _attributes(current)
        if attributes is None or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return False
    attributes = _attributes(path)
    return attributes is not None and bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)



#### Allocate a protected current-owner-only full-control security descriptor.
####
def _new_security_descriptor() -> wintypes.LPVOID | None:
    current = _current_sid()
    if current is None:
        return None
    _buffer, _sid, rendered = current
    descriptor = wintypes.LPVOID()
    length = wintypes.DWORD()
    sddl = f"O:{rendered}D:P(A;;FA;;;{rendered})"
    if not _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(descriptor),
        ctypes.byref(length),
    ):
        return None
    return descriptor



#### Hold a validated non-reparse directory handle and stable file identity.
####
class WindowsDirectoryAnchor:
    """Hold a validated non-reparse directory handle and stable file identity."""

    __slots__ = ("_handle", "_identity", "_path")



    #### Retain safe path addressing behind a validated open directory identity.
    ####
    def __init__(self, path: Path, handle: wintypes.HANDLE, identity: tuple[int, int]) -> None:
        self._path = path
        self._handle = handle
        self._identity = identity



    #### Validate ancestry, owner, protected DACL, and stable directory identity.
    ####
    @classmethod
    def open(cls, path: Path) -> WindowsDirectoryAnchor | None:
        handle: wintypes.HANDLE | None = None
        try:
            absolute = path.absolute()
            if not _ancestry_is_plain_directory(absolute):
                return None
            handle = _open_path(absolute, directory=True, access=_READ_CONTROL | _FILE_READ_ATTRIBUTES)
            if handle is None:
                return None
            identity = _file_identity(handle)
            if identity is None or not _handle_is_private(handle):
                return None
            anchor = cls(absolute, handle, identity)
            handle = None
            if not anchor._stable():
                anchor.close()
                return None
            return anchor
        except Exception:
            return None
        finally:
            if handle is not None:
                _close_handle(handle)



    #### Create one child with an explicit protected owner-only DACL and verify it.
    ####
    def create(self, name: str) -> tuple[int, tuple[int, int]] | None:
        if not self._stable() or Path(name).name != name:
            return None
        descriptor = _new_security_descriptor()
        if descriptor is None:
            return None
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        handle = wintypes.HANDLE()
        created_identity: tuple[int, int] | None = None
        transferred = False
        try:
            handle = _KERNEL32.CreateFileW(
                str(self._path / name),
                _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL,
                _FILE_SHARE_READ | _FILE_SHARE_DELETE,
                ctypes.byref(attributes),
                _CREATE_NEW,
                _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            if _handle_value(handle) == _INVALID_HANDLE_VALUE:
                return None
            identity = _file_identity(handle)
            created_identity = identity
            information = _ByHandleFileInformation()
            if (
                identity is None
                or not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
                or information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or not _handle_is_private(handle)
                or not self._stable()
            ):
                return None
            raw_handle = _handle_value(handle)
            file_descriptor = msvcrt.open_osfhandle(raw_handle, os.O_RDWR | os.O_BINARY)
            handle = wintypes.HANDLE(_INVALID_HANDLE_VALUE)
            transferred = True
            return file_descriptor, identity
        finally:
            _KERNEL32.LocalFree(descriptor)
            _close_handle(handle)
            if not transferred and created_identity is not None:
                with suppress(Exception):
                    self.remove_if_same(name, created_identity)



    #### Delete only an unchanged child under the still-stable directory identity.
    ####
    def remove_if_same(self, name: str, identity: tuple[int, int]) -> bool:
        if not self._stable():
            raise OSError
        path = self._path / name
        handle = _open_path(path, directory=False, access=_FILE_READ_ATTRIBUTES | _READ_CONTROL)
        if handle is None:
            return True
        try:
            if _file_identity(handle) != identity:
                return True
        finally:
            _close_handle(handle)
        path.unlink()
        return True



    #### Reopen the directory name and compare it with the retained handle identity.
    ####
    def _stable(self) -> bool:
        if not _ancestry_is_plain_directory(self._path):
            return False
        reopened = _open_path(self._path, directory=True, access=_FILE_READ_ATTRIBUTES)
        if reopened is None:
            return False
        try:
            return _file_identity(reopened) == self._identity
        finally:
            _close_handle(reopened)



    #### Release the retained directory handle exactly once.
    ####
    def close(self) -> None:
        handle = self._handle
        self._handle = wintypes.HANDLE(_INVALID_HANDLE_VALUE)
        _close_handle(handle)



#### Check a test path through the same handle-based DACL verifier.
####
def path_is_private(path: Path) -> bool:
    attributes = _attributes(path)
    if attributes is None:
        return False
    handle = _open_path(
        path,
        directory=bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
        access=_READ_CONTROL | _FILE_READ_ATTRIBUTES,
    )
    if handle is None:
        return False
    try:
        return _handle_is_private(handle)
    finally:
        _close_handle(handle)
