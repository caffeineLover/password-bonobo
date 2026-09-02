"""Narrow native Windows security boundary for encrypted snapshot artifacts."""

import ctypes
import msvcrt
import os
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from typing import Final, Protocol, cast



#### Describe the Windows-only ctypes members consumed by this native security boundary.
####
#### Typeshed deliberately omits these members on non-Windows hosts.  The explicit facade keeps this implementation
#### fully checked under every hosted profile while retaining the runtime module and WinDLL calling convention.
####
class _WindowsCtypesApi(Protocol):
    WinDLL: type[ctypes.CDLL]
    get_last_error: Callable[[], int]
    set_last_error: Callable[[int], None]



#### Describe the Windows descriptor conversion members consumed by retained native handles.
####
class _WindowsMsvcrtApi(Protocol):
    open_osfhandle: Callable[[int, int], int]
    get_osfhandle: Callable[[int], int]



#### Describe the Windows-only binary descriptor flag exposed by os.
####
class _WindowsOsApi(Protocol):
    O_BINARY: int



_WINDOWS_CTYPES = cast(_WindowsCtypesApi, ctypes)
_WINDOWS_MSVCRT = cast(_WindowsMsvcrtApi, msvcrt)
_WINDOWS_OS = cast(_WindowsOsApi, os)
_ADVAPI32 = _WINDOWS_CTYPES.WinDLL("advapi32", use_last_error=True)
_KERNEL32 = _WINDOWS_CTYPES.WinDLL("kernel32", use_last_error=True)
_NTDLL = _WINDOWS_CTYPES.WinDLL("ntdll")

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
_DELETE: Final[int] = 0x00010000
_READ_CONTROL: Final[int] = 0x00020000
_FILE_ADD_FILE: Final[int] = 0x00000002
_FILE_TRAVERSE: Final[int] = 0x00000020
_SYNCHRONIZE: Final[int] = 0x00100000
_FILE_READ_ATTRIBUTES: Final[int] = 0x00000080
_FILE_SHARE_READ: Final[int] = 0x00000001
_FILE_SHARE_WRITE: Final[int] = 0x00000002
_FILE_SHARE_DELETE: Final[int] = 0x00000004
_OPEN_EXISTING: Final[int] = 3
_FILE_CREATE: Final[int] = 2
_FILE_OPEN: Final[int] = 1
_FILE_SYNCHRONOUS_IO_NONALERT: Final[int] = 0x00000020
_FILE_NON_DIRECTORY_FILE: Final[int] = 0x00000040
_FILE_DELETE_ON_CLOSE: Final[int] = 0x00001000
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY: Final[int] = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT: Final[int] = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT: Final[int] = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS: Final[int] = 0x02000000
_INVALID_FILE_ATTRIBUTES: Final[int] = 0xFFFFFFFF
_FILE_DISPOSITION_INFO_CLASS: Final[int] = 4
_NT_FILE_RENAME_INFORMATION_CLASS: Final[int] = 10
_INVALID_HANDLE_VALUE: Final[int] = int(ctypes.c_void_p(-1).value or 0)
_ERROR_FILE_NOT_FOUND: Final[int] = 2
_ERROR_PATH_NOT_FOUND: Final[int] = 3



#### Provide one deterministic no-op seam immediately before relative creation.
####
def _before_relative_create() -> None:
    return None



#### Provide one deterministic no-op seam immediately before handle disposition.
####
def _before_handle_delete() -> None:
    return None



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



#### Mirror UNICODE_STRING while its caller-owned name buffer stays alive.
####
class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.WORD),
        ("MaximumLength", wintypes.WORD),
        ("Buffer", wintypes.LPWSTR),
    ]



#### Mirror OBJECT_ATTRIBUTES for one RootDirectory-relative child name.
####
class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]



#### Mirror the pointer-sized status union in IO_STATUS_BLOCK.
####
class _IoStatusValue(ctypes.Union):
    _fields_ = [("Status", ctypes.c_long), ("Pointer", wintypes.LPVOID)]



#### Mirror IO_STATUS_BLOCK output without interpreting filesystem details.
####
class _IoStatusBlock(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("value", _IoStatusValue), ("Information", ctypes.c_size_t)]



#### Mirror FILE_DISPOSITION_INFO for same-handle deletion marking.
####
class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]



#### Mirror the fixed prefix of variable-length FILE_RENAME_INFO.
####
class _FileRenameInfo(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.BOOLEAN),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
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
_KERNEL32.SetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
]
_KERNEL32.SetFileInformationByHandle.restype = wintypes.BOOL
_NTDLL.NtCreateFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    ctypes.POINTER(_ObjectAttributes),
    ctypes.POINTER(_IoStatusBlock),
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.LPVOID,
    wintypes.ULONG,
]
_NTDLL.NtCreateFile.restype = ctypes.c_long
_NTDLL.NtSetInformationFile.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_IoStatusBlock),
    wintypes.LPVOID,
    wintypes.ULONG,
    ctypes.c_int,
]
_NTDLL.NtSetInformationFile.restype = ctypes.c_long



#### Convert one opaque native handle without leaking its value to diagnostics.
####
def _handle_value(handle: wintypes.HANDLE) -> int:
    value = ctypes.cast(handle, ctypes.c_void_p).value
    return 0 if value is None else value



#### Recognize null and pointer-width all-ones without truncating the HANDLE ABI.
####
def _is_invalid_handle(handle: wintypes.HANDLE) -> bool:
    return _handle_value(handle) in (0, _INVALID_HANDLE_VALUE)



#### Close one valid native handle while ignoring best-effort cleanup status.
####
def _close_handle(handle: wintypes.HANDLE) -> bool:
    return _is_invalid_handle(handle) or bool(_KERNEL32.CloseHandle(handle))



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



#### Require private ownership and a protected DACL containing no broad trustee.
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
        if _sid_string(owner) not in {current_sid, "S-1-5-32-544"}:
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



#### Create one exclusive child relative to a retained directory HANDLE.
####
#### NTSTATUS never crosses this boundary: every negative result maps to no
#### ownership, with any anomalously returned live handle closed immediately.
####
def _nt_create_relative(
    root_directory: wintypes.HANDLE,
    name: str,
    security_descriptor: wintypes.LPVOID,
    *,
    delete_on_close: bool = True,
) -> wintypes.HANDLE | None:
    name_buffer = ctypes.create_unicode_buffer(name)
    name_length = len(name.encode("utf-16le"))
    unicode_name = _UnicodeString(name_length, name_length + 2, ctypes.cast(name_buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        root_directory,
        ctypes.pointer(unicode_name),
        0,
        security_descriptor,
        None,
    )
    io_status = _IoStatusBlock()
    handle = wintypes.HANDLE(_INVALID_HANDLE_VALUE)
    status = int(
        _NTDLL.NtCreateFile(
            ctypes.byref(handle),
            _GENERIC_READ | _GENERIC_WRITE | _DELETE | _READ_CONTROL | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            _FILE_SHARE_READ | _FILE_SHARE_DELETE,
            _FILE_CREATE,
            _FILE_SYNCHRONOUS_IO_NONALERT
            | _FILE_NON_DIRECTORY_FILE
            | (_FILE_DELETE_ON_CLOSE if delete_on_close else 0)
            | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
            0,
        )
    )
    if status < 0 or _is_invalid_handle(handle):
        _close_handle(handle)
        return None
    return handle



#### Open one existing non-reparse child relative to a retained directory handle.
####
def _nt_open_relative(
    root_directory: wintypes.HANDLE,
    name: str,
    access: int,
) -> wintypes.HANDLE | None:
    name_buffer = ctypes.create_unicode_buffer(name)
    name_length = len(name.encode("utf-16le"))
    unicode_name = _UnicodeString(name_length, name_length + 2, ctypes.cast(name_buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        root_directory,
        ctypes.pointer(unicode_name),
        0,
        None,
        None,
    )
    io_status = _IoStatusBlock()
    handle = wintypes.HANDLE(_INVALID_HANDLE_VALUE)
    status = int(
        _NTDLL.NtCreateFile(
            ctypes.byref(handle),
            access | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            _FILE_OPEN,
            _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_NON_DIRECTORY_FILE | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
            0,
        )
    )
    if status < 0 or _is_invalid_handle(handle):
        _close_handle(handle)
        return None
    return handle



#### Rename one retained file handle relative to one validated directory handle.
####
def _rename_handle_relative(
    handle: wintypes.HANDLE,
    root_directory: wintypes.HANDLE,
    name: str,
    *,
    replace: bool,
) -> bool:
    encoded = name.encode("utf-16le")
    size = _FileRenameInfo.FileName.offset + len(encoded)
    buffer = ctypes.create_string_buffer(size)
    information = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
    information.ReplaceIfExists = replace
    information.RootDirectory = root_directory
    information.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + _FileRenameInfo.FileName.offset, encoded, len(encoded))
    io_status = _IoStatusBlock()
    status = int(
        _NTDLL.NtSetInformationFile(
            handle,
            ctypes.byref(io_status),
            buffer,
            size,
            _NT_FILE_RENAME_INFORMATION_CLASS,
        )
    )
    return status >= 0



#### Verify and mark the exact still-open artifact handle for deletion.
####
def _set_handle_disposition(handle: wintypes.HANDLE, *, delete: bool) -> bool:
    disposition = _FileDispositionInfo(True)
    disposition.DeleteFile = delete
    return bool(
        _KERNEL32.SetFileInformationByHandle(
            handle,
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        )
    )



#### Verify and mark the exact still-open published artifact for deletion.
####
def _delete_handle_if_same(handle: wintypes.HANDLE, identity: tuple[int, int]) -> bool:
    information = _ByHandleFileInformation()
    if (
        _is_invalid_handle(handle)
        or _file_identity(handle) != identity
        or not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
        or information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or not _handle_is_private(handle)
    ):
        return False
    _before_handle_delete()
    if _file_identity(handle) != identity:
        return False
    return _set_handle_disposition(handle, delete=True)



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
        return cls._open_validated(path, require_private=True)



    #### Retain a non-reparse destination directory without requiring private ACLs.
    ####
    @classmethod
    def open_public(cls, path: Path) -> WindowsDirectoryAnchor | None:
        return cls._open_validated(path, require_private=False)



    #### Open one stable directory with optional current-owner-only ACL checks.
    ####
    @classmethod
    def _open_validated(
        cls,
        path: Path,
        *,
        require_private: bool,
    ) -> WindowsDirectoryAnchor | None:
        handle: wintypes.HANDLE | None = None
        try:
            absolute = path.absolute()
            if not _ancestry_is_plain_directory(absolute):
                return None
            handle = _open_path(
                absolute,
                directory=True,
                access=_READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_ADD_FILE | _FILE_TRAVERSE,
            )
            if handle is None:
                return None
            identity = _file_identity(handle)
            if identity is None or (require_private and not _handle_is_private(handle)):
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
    def create(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        return self._create_named(name, delete_on_close=True)



    #### Create one persistent protected child for later same-directory replacement.
    ####
    def create_persistent(self, name: str) -> tuple[int, tuple[int, int], str | None] | None:
        return self._create_named(name, delete_on_close=False)



    #### Open one existing regular non-reparse child relative to the retained handle.
    ####
    def open_child(self, name: str) -> tuple[int, tuple[int, int]] | None:
        return self._open_child_with_access(name, _GENERIC_READ)



    #### Open one regular child with delete access retained for atomic rename.
    ####
    def open_child_for_replace(self, name: str) -> tuple[int, tuple[int, int]] | None:
        return self._open_child_with_access(name, _GENERIC_READ | _DELETE)



    #### Validate privacy, identity, and plain-file state on the retained handle.
    ####
    def private_child_is_safe(self, descriptor: int, identity: tuple[int, int]) -> bool:
        handle = wintypes.HANDLE(_WINDOWS_MSVCRT.get_osfhandle(descriptor))
        information = _ByHandleFileInformation()
        return bool(
            self._stable()
            and _file_identity(handle) == identity
            and _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
            and not information.dwFileAttributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
            and _handle_is_private(handle)
        )



    #### Open and validate one child using the requested native access mask.
    ####
    def _open_child_with_access(self, name: str, access: int) -> tuple[int, tuple[int, int]] | None:
        if not self._stable() or Path(name).name != name:
            return None
        handle = _nt_open_relative(self._handle, name, access)
        if handle is None:
            return None
        try:
            identity = _file_identity(handle)
            information = _ByHandleFileInformation()
            if (
                identity is None
                or not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
                or information.dwFileAttributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
                or not self._stable()
            ):
                return None
            raw_handle = _handle_value(handle)
            descriptor = _WINDOWS_MSVCRT.open_osfhandle(raw_handle, os.O_RDONLY | _WINDOWS_OS.O_BINARY)
            handle = None
            return descriptor, identity
        finally:
            if handle is not None:
                _close_handle(handle)



    #### Atomically rename one retained child handle over a destination child name.
    ####
    def replace_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        if (
            not self._stable()
            or Path(source_name).name != source_name
            or Path(destination_name).name != destination_name
        ):
            return False
        handle = wintypes.HANDLE(_WINDOWS_MSVCRT.get_osfhandle(descriptor))
        information = _ByHandleFileInformation()
        if (
            _file_identity(handle) != identity
            or not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
            or information.dwFileAttributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
        ):
            return False
        return _rename_handle_relative(handle, self._handle, destination_name, replace=True) and self._stable()



    #### Atomically rename one complete child only when the destination is absent.
    ####
    def publish_new_child(
        self,
        descriptor: int,
        identity: tuple[int, int],
        source_name: str,
        destination_name: str,
    ) -> bool:
        if (
            not self._stable()
            or Path(source_name).name != source_name
            or Path(destination_name).name != destination_name
        ):
            return False
        handle = wintypes.HANDLE(_WINDOWS_MSVCRT.get_osfhandle(descriptor))
        information = _ByHandleFileInformation()
        if (
            _file_identity(handle) != identity
            or not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
            or information.dwFileAttributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
        ):
            return False
        return _rename_handle_relative(handle, self._handle, destination_name, replace=False) and self._stable()



    #### Report whether the retained directory still owns its original pathname.
    ####
    def stable(self) -> bool:
        return self._stable()



    #### Complete the cross-platform directory-sync seam where unsupported.
    ####
    def synchronize(self) -> None:
        return None



    #### Create and verify one child under the retained directory handle.
    ####
    def _create_named(
        self,
        name: str,
        *,
        delete_on_close: bool,
    ) -> tuple[int, tuple[int, int], str | None] | None:
        if not self._stable() or Path(name).name != name:
            return None
        descriptor = _new_security_descriptor()
        if descriptor is None:
            return None
        handle: wintypes.HANDLE | None = None
        try:
            _before_relative_create()
            handle = _nt_create_relative(
                self._handle,
                name,
                descriptor,
                delete_on_close=delete_on_close,
            )
            if handle is None:
                return None
            identity = _file_identity(handle)
            information = _ByHandleFileInformation()
            if (
                identity is None
                or not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
                or information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or not _handle_is_private(handle)
                or not self._stable()
            ):
                return None
            if not _set_handle_disposition(handle, delete=False):
                return None
            raw_handle = _handle_value(handle)
            file_descriptor = _WINDOWS_MSVCRT.open_osfhandle(raw_handle, os.O_RDWR | _WINDOWS_OS.O_BINARY)
            handle = None
            return file_descriptor, identity, name
        finally:
            _KERNEL32.LocalFree(descriptor)
            if handle is not None:
                try:
                    disposed = _set_handle_disposition(handle, delete=True)
                except BaseException:
                    disposed = False
                try:
                    closed = _close_handle(handle)
                except BaseException:
                    closed = False
                if not disposed or not closed:
                    raise OSError



    #### Delete only an unchanged child under the still-stable directory identity.
    ####
    def remove_if_same(self, descriptor: int, _name: str, identity: tuple[int, int]) -> bool:
        raw_handle = _WINDOWS_MSVCRT.get_osfhandle(descriptor)
        handle = wintypes.HANDLE(raw_handle)
        return _delete_handle_if_same(handle, identity)



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
        if _is_invalid_handle(handle):
            return
        if not _close_handle(handle):
            raise OSError
        self._handle = wintypes.HANDLE(_INVALID_HANDLE_VALUE)



#### Open one regular path without following a final or ancestral reparse point.
####
def open_regular_file(path: Path) -> int | None:
    handle: wintypes.HANDLE | None = None
    try:
        absolute = path.absolute()
        if not _ancestry_is_plain_directory(absolute.parent):
            return None
        handle = _KERNEL32.CreateFileW(
            str(absolute),
            _GENERIC_READ | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if _is_invalid_handle(handle):
            error = _WINDOWS_CTYPES.get_last_error()
            handle = None
            if error in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
                raise FileNotFoundError
            return None
        information = _ByHandleFileInformation()
        if (
            not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information))
            or information.dwFileAttributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
        ):
            return None
        raw_handle = _handle_value(handle)
        descriptor = _WINDOWS_MSVCRT.open_osfhandle(raw_handle, os.O_RDONLY | _WINDOWS_OS.O_BINARY)
        handle = None
        return descriptor
    finally:
        if handle is not None:
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
