"""Platform-specific cleanup for trusted external command adapters."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any


class ProcessGroup:
    """Own a POSIX session or Windows kill-on-close job for one tool invocation.

    The executable is trusted local code, not a hostile-program sandbox. On
    Windows assignment follows process creation; on POSIX a child can explicitly
    leave its process group. Neither mechanism restricts filesystem or network.
    """

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self._job: Any = None
        self._kernel: Any = None
        if os.name == "nt":
            self._attach_windows_job()

    def _attach_windows_job(self) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL

        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise OSError("could not create Windows subprocess cleanup job")
        process_handle = None
        try:
            limits = ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise OSError("could not configure Windows subprocess cleanup job")
            # PROCESS_SET_QUOTA | PROCESS_TERMINATE; avoid private Popen handles.
            process_handle = kernel.OpenProcess(0x0100 | 0x0001, False, self.process.pid)
            if not process_handle or not kernel.AssignProcessToJobObject(job, process_handle):
                # A tiny command may already have exited before assignment.
                if self.process.poll() is None:
                    raise OSError("could not attach tool to Windows subprocess cleanup job")
        except BaseException:
            kernel.CloseHandle(job)
            raise
        finally:
            if process_handle:
                kernel.CloseHandle(process_handle)
        self._kernel, self._job = kernel, job

    def stop(self) -> None:
        """Terminate this invocation and its owned descendants; safe to repeat."""
        if self._job is not None:
            self._kernel.TerminateJobObject(self._job, 1)
            self._kernel.CloseHandle(self._job)
            self._job = None
        stop_process(self.process)


def stop_process(process: subprocess.Popen[bytes]) -> None:
    """Fallback cleanup, including a whole dedicated process group on POSIX."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
