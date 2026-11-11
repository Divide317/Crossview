"""crossview: Python control plane for libcrossview.

The C library does the observing (fast, close to the OS). Python loads it
through ctypes, asks for a scan, and receives the report as JSON.

Boundary rules (see include/libcrossview.h):
  * The library allocates, the library frees. Python never frees C memory
    with its own allocator; every C buffer goes back through cv_free().
  * Python mirrors exactly one struct (cv_config) and checks its size
    against the library at load time, so a layout drift fails loudly
    instead of corrupting memory.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

__all__ = ["CHECKS", "CrossviewError", "Library", "scan"]

ABI_VERSION = 0

CHECKS = {"processes": 1 << 0, "modules": 1 << 1, "ports": 1 << 2, "preload": 1 << 3}
PROTOS = {"tcp": 1 << 0, "tcp6": 1 << 1, "udp": 1 << 2, "udp6": 1 << 3}
F_SKIP_THREADS = 1 << 0
F_BIND_PROBE = 1 << 1

_STATUS = {0: "ok", -1: "invalid argument", -2: "out of memory", -3: "I/O error",
           -4: "permission denied", -5: "unsupported", -6: "internal error"}


class CrossviewError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"{_STATUS.get(status, status)}: {message}")
        self.status = status


# int (*cv_pid_probe_fn)(pid_t pid, void *user)
PID_PROBE_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int32, ctypes.c_void_p)


class CvConfig(ctypes.Structure):
    """Mirror of cv_config. Field order and types must match the header."""
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("proc_root", ctypes.c_char_p),
        ("sys_root", ctypes.c_char_p),
        ("etc_root", ctypes.c_char_p),
        ("pid_max", ctypes.c_int32),
        ("recheck_rounds", ctypes.c_uint32),
        ("recheck_delay_ms", ctypes.c_uint32),
        ("port_protos", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("pid_probe", PID_PROBE_FN),
        ("pid_probe_user", ctypes.c_void_p),
    ]


def _find_library() -> str:
    env = os.environ.get("CROSSVIEW_LIB")
    if env:
        return env
    here = Path(__file__).resolve()
    for cand in (here.parent / "libcrossview.so",
                 here.parents[2] / "build" / "libcrossview.so"):
        if cand.exists():
            return str(cand)
    found = ctypes.util.find_library("crossview")
    if found:
        return found
    raise FileNotFoundError("libcrossview.so not found: run `make` or set CROSSVIEW_LIB")


class Library:
    """Thin, typed wrapper over the FFI surface."""

    def __init__(self, path: str | None = None):
        self.path = path or _find_library()
        lib = ctypes.CDLL(self.path)
        self._lib = lib

        lib.cv_abi_version.restype = ctypes.c_int
        lib.cv_config_size.restype = ctypes.c_size_t
        lib.cv_version.restype = ctypes.c_char_p      # static string: safe as c_char_p
        lib.cv_config_init.argtypes = [ctypes.POINTER(CvConfig)]
        lib.cv_ctx_new.argtypes = [ctypes.POINTER(CvConfig), ctypes.POINTER(ctypes.c_void_p)]
        lib.cv_ctx_new.restype = ctypes.c_int
        lib.cv_ctx_free.argtypes = [ctypes.c_void_p]
        lib.cv_scan.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        lib.cv_scan.restype = ctypes.c_int
        # The JSON out-param is c_void_p, NOT c_char_p. ctypes would turn a
        # c_char_p into Python bytes and drop the pointer we must pass back
        # to cv_free(): a silent leak on every scan.
        lib.cv_report_to_json.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_size_t)]
        lib.cv_report_to_json.restype = ctypes.c_int
        lib.cv_report_free.argtypes = [ctypes.c_void_p]
        lib.cv_free.argtypes = [ctypes.c_void_p]
        lib.cv_last_error.argtypes = [ctypes.c_void_p]
        lib.cv_last_error.restype = ctypes.c_char_p   # borrowed static-lifetime-per-ctx string

        abi = lib.cv_abi_version()
        if abi != ABI_VERSION:
            raise ImportError(f"libcrossview ABI {abi}, bindings expect {ABI_VERSION}")
        if lib.cv_config_size() != ctypes.sizeof(CvConfig):
            raise ImportError(
                f"cv_config is {lib.cv_config_size()} bytes in C but {ctypes.sizeof(CvConfig)} "
                "in Python: header and bindings disagree"
            )

    @property
    def version(self) -> str:
        return self._lib.cv_version().decode()

    def scan(self, checks: Iterable[str] = CHECKS, *, proc_root: str | None = None,
             sys_root: str | None = None, etc_root: str | None = None,
             pid_max: int = 0, recheck_rounds: int | None = None,
             recheck_delay_ms: int | None = None, protos: Iterable[str] | None = None,
             bind_probe: bool = False, skip_threads: bool = True) -> dict[str, Any]:
        mask = 0
        for c in checks:
            if c not in CHECKS:
                raise ValueError(f"unknown check {c!r}; choose from {sorted(CHECKS)}")
            mask |= CHECKS[c]

        cfg = CvConfig()
        self._lib.cv_config_init(ctypes.byref(cfg))
        # Keep the encoded strings alive for the duration of the call; the
        # library copies them into the ctx, so they needn't outlive cv_ctx_new.
        keep = []
        for field, value in (("proc_root", proc_root), ("sys_root", sys_root), ("etc_root", etc_root)):
            if value is not None:
                b = value.encode()
                keep.append(b)
                setattr(cfg, field, b)
        cfg.pid_max = pid_max
        if recheck_rounds is not None:
            cfg.recheck_rounds = recheck_rounds
        if recheck_delay_ms is not None:
            cfg.recheck_delay_ms = recheck_delay_ms
        if protos is not None:
            cfg.port_protos = sum(PROTOS[p] for p in set(protos))
        cfg.flags = (F_SKIP_THREADS if skip_threads else 0) | (F_BIND_PROBE if bind_probe else 0)

        ctx = ctypes.c_void_p()
        self._check(self._lib.cv_ctx_new(ctypes.byref(cfg), ctypes.byref(ctx)), None)
        report = ctypes.c_void_p()
        try:
            self._check(self._lib.cv_scan(ctx, mask, ctypes.byref(report)), ctx)
            buf, n = ctypes.c_void_p(), ctypes.c_size_t()
            try:
                self._check(self._lib.cv_report_to_json(report, ctypes.byref(buf), ctypes.byref(n)), ctx)
                return json.loads(ctypes.string_at(buf, n.value))
            finally:
                self._lib.cv_free(buf)           # NULL-safe
        finally:
            self._lib.cv_report_free(report)     # NULL-safe
            self._lib.cv_ctx_free(ctx)

    def _check(self, status: int, ctx: ctypes.c_void_p | None) -> None:
        if status == 0:
            return
        msg = ""
        if ctx is not None and ctx.value:
            raw = self._lib.cv_last_error(ctx)
            msg = raw.decode(errors="replace") if raw else ""
        raise CrossviewError(status, msg or "libcrossview call failed")


_default: Library | None = None


def scan(checks: Iterable[str] = CHECKS, **kwargs: Any) -> dict[str, Any]:
    """Convenience: scan with a process-wide default Library."""
    global _default
    if _default is None:
        _default = Library()
    return _default.scan(checks, **kwargs)
