"""Windows shims for the POSIX-only calls Orchestra uses (flock, killpg, directory fsync)."""
import os
import signal
import subprocess

LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN = 1, 2, 4, 8

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _k32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class _Overlapped(ctypes.Structure):
        _fields_ = [('Internal', ctypes.c_void_p), ('InternalHigh', ctypes.c_void_p),
                    ('Offset', wintypes.DWORD), ('OffsetHigh', wintypes.DWORD), ('hEvent', wintypes.HANDLE)]

    _k32.LockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                wintypes.DWORD, ctypes.POINTER(_Overlapped)]
    _k32.LockFileEx.restype = wintypes.BOOL
    _k32.UnlockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(_Overlapped)]
    _k32.UnlockFileEx.restype = wintypes.BOOL

    def flock(stream, op):
        """fcntl.flock over LockFileEx on byte 0; closing the file releases it, as on POSIX."""
        handle = msvcrt.get_osfhandle(stream.fileno())
        overlapped = _Overlapped()
        if op & LOCK_UN:
            _k32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped))
            return
        flags = (0x2 if op & LOCK_EX else 0) | (0x1 if op & LOCK_NB else 0)
        if not _k32.LockFileEx(handle, flags, 0, 1, 0, ctypes.byref(overlapped)):
            raise OSError(ctypes.get_last_error(), 'lock unavailable')

    def kill_tree(process):
        subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def fsync_dir(path):
        """Windows cannot open a directory for fsync; os.replace is already durable enough there."""
else:
    import fcntl as _fcntl

    def flock(stream, op):
        _fcntl.flock(stream, op)

    def kill_tree(process):
        os.killpg(process.pid, signal.SIGKILL)

    def fsync_dir(path):
        directory = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
