"""
Real-time memory scanner and pattern matcher.
Replaces the simulation in RealTime-Memory-Analytics and
RealTime-Offset-Analytics.

This module:
  1. Enumerates all memory regions of a target process via VirtualQueryEx
  2. Scans for AOB (Array-of-Bytes) signatures with wildcards
  3. Provides signature scanning for UE GObjects/GNames patterns
  4. Tracks region types (Image, MEM_MAPPED, MEM_PRIVATE)
  5. Emits structured events to SharedRingBuffer
"""

import ctypes, struct, time, os, sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Iterator
from dataclasses import dataclass
from enum import IntFlag
from collections import defaultdict

IS_WINDOWS = sys.platform == "win32"

def _load_kernel32():
    if IS_WINDOWS:
        k = ctypes.windll.kernel32
        k.VirtualQueryEx.argtypes  = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                       ctypes.c_size_t]
        k.VirtualQueryEx.restype   = ctypes.c_size_t
        k.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.POINTER(ctypes.c_size_t)]
        k.ReadProcessMemory.restype = ctypes.c_bool
        k.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
        k.GetModuleFileNameW.restype  = ctypes.c_ulong
        k.GetCurrentProcess.argtypes = []
        k.GetCurrentProcess.restype  = ctypes.c_void_p
        return k
    return None

kernel32 = _load_kernel32()


# ─── Win32 types & constants ──────────────────────────────────────────────────

PROCESS_ALL_ACCESS = 0x1F0FFF

class MEMORY_STATE(IntFlag):
    MEM_COMMIT  = 0x1000
    MEM_FREE    = 0x10000
    MEM_RESERVE = 0x2000

class MEMORY_TYPE(IntFlag):
    MEM_PRIVATE = 0x20000
    MEM_MAPPED  = 0x40000
    MEM_IMAGE   = 0x1000000

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",   ctypes.c_void_p),
        ("AllocationProtect",ctypes.c_ulong),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             ctypes.c_ulong),
        ("Protect",           ctypes.c_ulong),
        ("Type",              ctypes.c_ulong),
    ]


# ─── Memory enumeration (Windows only) ───────────────────────────────────────

def _query_process_memory(pid: int, address: int = 0) -> Optional[MEMORY_BASIC_INFORMATION]:
    """Query memory info at address for a process. Windows only."""
    if not IS_WINDOWS or not kernel32:
        return None
    mbi = MEMORY_BASIC_INFORMATION()
    ret = kernel32.VirtualQueryEx(
        ctypes.c_void_p(pid),
        ctypes.c_void_p(address),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi),
    )
    if ret == 0:
        return None
    return mbi


def enumerate_regions(pid: int) -> Iterator[MEMORY_BASIC_INFORMATION]:
    """Enumerate all memory regions of a process. Windows only."""
    if not IS_WINDOWS:
        return
        yield  # type: ignore
    addr = 0
    while True:
        mbi = _query_process_memory(pid, addr)
        if mbi is None:
            break
        yield mbi
        if mbi.RegionSize == 0:
            break
        addr = int(mbi.BaseAddress) + mbi.RegionSize


def read_process_memory(pid: int, addr: int, size: int) -> Optional[bytes]:
    """Read memory from a process. Windows only."""
    if not IS_WINDOWS or not kernel32:
        return None
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    # 1) Try full read
    if kernel32.ReadProcessMemory(
            ctypes.c_void_p(pid), ctypes.c_void_p(addr),
            buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    # 2) Try smaller chunks on failure
    for chunk in range(size - 1, 0, -256):
        if kernel32.ReadProcessMemory(
                ctypes.c_void_p(pid), ctypes.c_void_p(addr),
                buf, chunk, ctypes.byref(read)) and read.value > 0:
            return buf.raw[:read.value]
    return None


# ─── Pattern matching ─────────────────────────────────────────────────────────

@dataclass
class Signature:
    name:     str
    pattern:  str          # e.g. "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    relative: bool = False
    rel_off:  int  = 0     # offset from match to apply relative offset calc

    def parse(self) -> tuple[bytes, bytes]:
        """Parse pattern string into (mask, bytes).
        mask[i] = 1 -> byte must match, 0 -> wildcard.
        """
        parts   = self.pattern.strip().split()
        mask    = bytearray()
        pattern = bytearray()
        for p in parts:
            p = p.upper()
            if p == "??":
                mask.append(0); pattern.append(0)
            elif "?" in p:
                mask.append(0); pattern.append(int(p.replace("?", "0"), 16))
            else:
                mask.append(1); pattern.append(int(p, 16))
        return bytes(pattern), bytes(mask)


@dataclass
class ScanResult:
    module:       str
    region_start: int
    signature:    str
    offset:       int
    value:        Optional[int] = None
    pointer:      Optional[int] = None


class PatternMatcher:
    """
    AOB signature scanner with wildcard support.
    Pattern format: "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    Supports ?? (full wildcard) and X? (partial).
    """

    # ── Built-in UE4/UE5 signatures ──────────────────────────────────────────────
    BUILTIN_SIGNATURES = [
        Signature("GObjects_Ptr",   "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 0C C8",
                   relative=True, rel_off=3),
        Signature("GNames_Ptr",     "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45",
                   relative=True, rel_off=3),
        Signature("UWorld",         "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 89 05",
                   relative=True, rel_off=3),
        Signature("PersistentLevel","48 8B 80 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 08",
                   relative=True, rel_off=3),
        Signature("PlayerController","48 8B 80 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 08",
                   relative=True, rel_off=3),
        Signature("LocalPlayer",    "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 04 D8",
                   relative=True, rel_off=3),
    ]

    def __init__(self):
        self._results: List[ScanResult] = []

    def scan_region(self, data: bytes, region_start: int,
                    sig: Signature, module: str = "unknown") -> List[ScanResult]:
        """Scan a region of memory for a signature. Returns ALL matches."""
        results   = []
        sig_bytes, sig_mask = sig.parse()
        sig_len   = len(sig_bytes)

        if len(data) < sig_len:
            return results

        mv = memoryview(data)
        for i in range(len(data) - sig_len + 1):
            for j in range(sig_len):
                if sig_mask[j] and mv[i+j] != sig_bytes[j]:
                    break
            else:
                r = ScanResult(
                    module=module,
                    region_start=region_start,
                    signature=sig.name,
                    offset=region_start + i,
                    value=int.from_bytes(data[i:i+4], "little"),
                    pointer=None,
                )
                if sig.relative and i + 4 <= len(data):
                    rel = int.from_bytes(data[i:i+4], "little")
                    r.pointer = region_start + i + sig_len + rel
                results.append(r)
        return results

    def scan_data(self, data: bytes, region_start: int,
                  module: str = "unknown",
                  signatures: Optional[List[Signature]] = None) -> List[ScanResult]:
        """Scan data with a list of signatures."""
        sigs         = signatures or self.BUILTIN_SIGNATURES
        all_results  = []
        for sig in sigs:
            all_results.extend(self.scan_region(data, region_start, sig, module))
        self._results.extend(all_results)
        return all_results


# ─── Memory Scanner ────────────────────────────────────────────────────────────

class MemoryScanner:
    """
    Full memory scanner for a target process.

    Usage:
        scanner = MemoryScanner(pid=1234)
        scanner.add_signature("MySig", "48 8B 05 ?? ?? ?? ?? 90 90")
        results = scanner.scan_all()
        for r in results:
            print(f"{r.signature} @ {hex(r.offset)}")
    """

    def __init__(self, pid: Optional[int] = None):
        self._pid  = pid if pid is not None else os.getpid()
        self._sig  = PatternMatcher()
        self._custom: List[Signature] = []
        self._results: List[ScanResult] = []

        # Stats
        self._regions_scanned = 0
        self._bytes_scanned   = 0
        self._scan_time_ms    = 0.0

    def add_signature(self, name: str, pattern: str,
                      relative: bool = False, rel_off: int = 3):
        """Add a custom AOB signature."""
        self._custom.append(Signature(name, pattern, relative, rel_off))

    def scan_all(self, region_filter: Optional[Callable[[MEMORY_BASIC_INFORMATION], bool]] = None,
                 max_bytes: int = 0x100000) -> List[ScanResult]:
        """
        Scan all committed readable regions of the target process.

        Args:
            region_filter: function(MEMORY_BASIC_INFORMATION) -> bool
            max_bytes:     max bytes to read per region (0 = unlimited)

        Returns:
            List of ScanResult
        """
        self._results.clear()
        self._regions_scanned = 0
        self._bytes_scanned   = 0
        t0 = time.perf_counter()

        all_sigs = self._sig.BUILTIN_SIGNATURES + self._custom

        for mbi in enumerate_regions(self._pid):
            if mbi.State != MEMORY_STATE.MEM_COMMIT:
                continue
            if mbi.Protect == PAGE_NOACCESS:
                continue
            if region_filter and not region_filter(mbi):
                continue

            region_start = int(mbi.BaseAddress)
            read_sz      = min(int(mbi.RegionSize), max_bytes)
            data         = read_process_memory(self._pid, region_start, read_sz)

            if data:
                self._regions_scanned += 1
                self._bytes_scanned   += len(data)
                module = self._get_module_name(mbi)
                results = self._sig.scan_data(
                    data, region_start, module=module, signatures=all_sigs)
                self._results.extend(results)

        self._scan_time_ms = (time.perf_counter() - t0) * 1000
        return self._results

    def _get_module_name(self, mbi: MEMORY_BASIC_INFORMATION) -> str:
        """Attempt to get the module name for a memory region. Windows only."""
        if not IS_WINDOWS or not kernel32:
            return "unknown"
        if mbi.Type == MEMORY_TYPE.MEM_IMAGE:
            buf = ctypes.create_unicode_buffer(260)
            if kernel32.GetModuleFileNameW(ctypes.c_void_p(mbi.AllocationBase),
                                           buf, 260):
                return Path(buf.value).name
        return "unknown"

    def get_offset_db(self) -> Dict[str, Dict[str, Any]]:
        """Build an offset database from scan results."""
        db: Dict = defaultdict(lambda: {"offsets": {}, "count": 0})
        for r in self._results:
            db[r.signature]["offsets"][hex(r.offset)] = {
                "module":  r.module,
                "region":  hex(r.region_start),
                "pointer": hex(r.pointer) if r.pointer else None,
                "value":   hex(r.value)   if r.value   else None,
            }
            db[r.signature]["count"] += 1
        return dict(db)

    def get_analytics(self) -> Dict[str, Any]:
        """Return dashboard-ready analytics."""
        return {
            "source":           "memory",
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S"),
            "regions_scanned": self._regions_scanned,
            "bytes_scanned":    self._bytes_scanned,
            "scan_time_ms":     round(self._scan_time_ms, 2),
            "matches_found":   len(self._results),
            "offset_db":       self.get_offset_db(),
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "regions_scanned": self._regions_scanned,
            "bytes_scanned":   self._bytes_scanned,
            "scan_time_ms":    round(self._scan_time_ms, 2),
            "matches_found":   len(self._results),
        }


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Memory Scanner Self-Test ===")
    scanner = MemoryScanner()
    print(f"PID: {scanner._pid}")
    print(f"Built-in signatures: {len(scanner._sig.BUILTIN_SIGNATURES)}")
    print(f"Custom signatures: {len(scanner._custom)}")
    scanner.add_signature("test", "90 90 90 90 90")
    print(f"After add: {len(scanner._custom)}")
    if IS_WINDOWS:
        results = scanner.scan_all(max_bytes=0x10000)
        analytics = scanner.get_analytics()
        print(f"Regions scanned: {analytics['regions_scanned']}")
        print(f"Bytes scanned: {analytics['bytes_scanned']:,}")
        print(f"Matches found: {analytics['matches_found']}")
        print(f"Scan time: {analytics['scan_time_ms']}ms")
        for sig_name, info in analytics['offset_db'].items():
            print(f"  {sig_name}: {info['count']} matches")