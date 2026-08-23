"""Reject descriptor-backed Darwin objects carrying any extended ACL entry."""

import ctypes
import sys
from typing import Final, Protocol, cast

from .errors import StorageError, StorageReason



_ACL_TYPE_EXTENDED: Final[int] = 0x00000100
_ACL_FIRST_ENTRY: Final[int] = 0



#### Describe one dynamically loaded native call with an explicitly assigned ABI.
####
class _NativeFunction(Protocol):
    argtypes: list[object] | None
    restype: object



    #### Invoke one libc ACL function through its typed ctypes boundary.
    ####
    def __call__(self, *arguments: object) -> object:
        raise NotImplementedError



#### Describe the three descriptor-only ACL operations needed by the verifier.
####
class _AclApi(Protocol):



    #### Allocate the extended ACL working object for one open descriptor.
    ####
    def get_fd(self, descriptor: int, acl_type: int) -> int | None:
        raise NotImplementedError



    #### Retrieve only the requested entry from one allocated ACL object.
    ####
    def get_entry(self, acl: int, entry_id: int, entry: object) -> int:
        raise NotImplementedError



    #### Free one exact ACL working object allocated by the native library.
    ####
    def free(self, acl: int) -> int:
        raise NotImplementedError



#### Bind the documented Darwin libc ACL functions with pointer-width-safe types.
####
class _CtypesDarwinAclApi:
    __slots__ = ("_free", "_get_entry", "_get_fd")

    _free: _NativeFunction
    _get_entry: _NativeFunction
    _get_fd: _NativeFunction



    #### Load process libc and assign every argument and return type explicitly.
    ####
    def __init__(self) -> None:
        library = ctypes.CDLL(None, use_errno=True)
        self._get_fd = cast(_NativeFunction, library.acl_get_fd_np)
        self._get_fd.argtypes = [ctypes.c_int, ctypes.c_int]
        self._get_fd.restype = ctypes.c_void_p
        self._get_entry = cast(_NativeFunction, library.acl_get_entry)
        self._get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        self._get_entry.restype = ctypes.c_int
        self._free = cast(_NativeFunction, library.acl_free)
        self._free.argtypes = [ctypes.c_void_p]
        self._free.restype = ctypes.c_int



    #### Return the allocated pointer value or the native null failure sentinel.
    ####
    def get_fd(self, descriptor: int, acl_type: int) -> int | None:
        return cast(int | None, self._get_fd(descriptor, acl_type))



    #### Retrieve one entry through a caller-owned pointer-sized output cell.
    ####
    def get_entry(self, acl: int, entry_id: int, entry: object) -> int:
        return cast(int, self._get_entry(ctypes.c_void_p(acl), entry_id, entry))



    #### Free one exact pointer returned by acl_get_fd_np.
    ####
    def free(self, acl: int) -> int:
        return cast(int, self._free(ctypes.c_void_p(acl)))



#### Load Darwin ACL support only on the exact supported platform.
####
def _is_darwin() -> bool:
    return sys.platform == "darwin"



#### Construct the native ACL boundary only on Darwin and fail closed otherwise.
####
def _load_acl_api() -> _AclApi | None:
    if not _is_darwin():
        return None
    try:
        return _CtypesDarwinAclApi()
    except Exception:
        return None



_ACL_API: _AclApi | None = _load_acl_api()



#### Require one open descriptor to have a successfully read, empty extended ACL.
####
#### Every allocated acl_t is freed before the fixed safe failure is raised.
#### An empty Darwin ACL reports no first entry as -1 without setting errno.
####
def require_no_extended_acl(descriptor: int) -> None:
    api = _ACL_API
    if api is None:
        raise StorageError(StorageReason.PREPARATION_FAILED)
    acl = 0
    failed = False
    try:
        ctypes.set_errno(0)
        allocated = api.get_fd(descriptor, _ACL_TYPE_EXTENDED)
        if allocated is None or isinstance(allocated, bool) or allocated <= 0:
            failed = True
        else:
            acl = allocated
            entry = ctypes.c_void_p()
            ctypes.set_errno(0)
            status = api.get_entry(acl, _ACL_FIRST_ENTRY, ctypes.byref(entry))
            entry_errno = ctypes.get_errno()
            if status != -1 or entry_errno != 0:
                failed = True
    except BaseException:
        failed = True
    finally:
        if acl:
            try:
                if api.free(acl) != 0:
                    failed = True
            except BaseException:
                failed = True
    if failed:
        raise StorageError(StorageReason.PREPARATION_FAILED) from None
