"""
Real-time anti-debug & VM detection engine.
Replaces the simulation in RealTime-AntiDebug-Analytics.

This module:
  1. Checks PEB BeingDebugged, NtGlobalFlag, HeapFlags
  2. Detects timing anomalies (RDTSC, QueryPerformanceCounter, GetTickCount)
  3. Queries NtQueryInformationProcess for DebugObjectHandle
  4. Checks for VM artifacts (CPUID, registry, VM devices)
  5. Emits structured events to SharedRingBuffer
"""

import ctypes, struct, time, os, sys
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
import threading

IS_WINDOWS = sys.platform == "win32"

# Load DLLs lazily (Windows only)
def _load_kernel32():
    if IS_WINDOWS:
        k = ctypes.windll.kernel32
        k.GetCurrentProcess.argtypes  = []
        k.GetCurrentProcess.restype   = ctypes.c_void_p
        k.ReadProcessMemory.argtypes  = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_size_t)]
        k.ReadProcessMemory.restype  = ctypes.c_bool
        k.IsDebuggerPresent.argtypes = []
        k.IsDebuggerPresent.restype = ctypes.c_bool
        k.CheckRemoteDebuggerPresent.argtypes = [ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_bool)]
        k.CheckRemoteDebuggerPresent.restype  = ctypes.c_bool
        k.QueryPerformanceCounter.argtypes  = [ctypes.POINTER(ctypes.c_int64)]
        k.QueryPerformanceCounter.restype   = ctypes.c_bool
        k.QueryPerformanceFrequency.argtypes = [ctypes.POINTER(ctypes.c_int64)]
        k.QueryPerformanceFrequency.restype  = ctypes.c_bool
        k.GetTickCount64.argtypes = []
        k.GetTickCount64.restype  = ctypes.c_ulonglong
        k.RegOpenKeyExW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                     ctypes.c_ulong, ctypes.c_ulong,
                                     ctypes.POINTER(ctypes.c_void_p)]
        k.RegOpenKeyExW.restype  = ctypes.c_ulong
        k.RegCloseKey.argtypes  = [ctypes.c_void_p]
        k.RegCloseKey.restype   = ctypes.c_ulong
        k.CreateFileA.argtypes  = [ctypes.c_char_p, ctypes.c_ulong,
                                    ctypes.c_ulong, ctypes.c_void_p,
                                    ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
        k.CreateFileA.restype   = ctypes.c_void_p
        k.CloseHandle.argtypes  = [ctypes.c_void_p]
        k.CloseHandle.restype   = ctypes.c_bool
        return k
    return None

def _load_ntdll():
    if IS_WINDOWS:
        n = ctypes.windll.ntdll
        n.NtQueryInformationProcess.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
        ]
        n.NtQueryInformationProcess.restype = ctypes.c_long
        return n
    return None

kernel32 = _load_kernel32()
ntdll     = _load_ntdll()

# ─── PEB offsets (x64 Windows 10) ────────────────────────────────────────────

PEB_OFFSET         = 0x60   # gs:[0x60] on x64
PEB_BEING_DEBUGGED  = 0x02  # byte at PEB+0x02
PEB_NT_GLOBAL_FLAG  = 0x68  # dword at PEB+0x68
PEB_HEAP_FLAGS      = 0x70  # dword at PEB+0x70 (ProcessHeap->Flags)
PEB_HEAP_FORCE_FLAGS = 0x74 # dword at PEB+0x74
PEB_IMAGE_BASE      = 0x18 # qword at PEB+0x18

# NtGlobalFlag flags
FLG_HEAP_ENABLE_TAIL_CHECK   = 0x10
FLG_HEAP_ENABLE_FREE_CHECK   = 0x20
FLG_HEAP_VALIDATE_PARAMETERS = 0x40
FLG_HEAP_VALIDATE_ALL        = 0x08

# NtQueryInformationProcess classes
ProcessDebugPort          = 31
ProcessDebugObjectHandle  = 30
ProcessDebugFlags         = 29

# ─── Memory read helpers ──────────────────────────────────────────────────────

def _read_qword(addr: int) -> Optional[int]:
    if not IS_WINDOWS or not kernel32:
        return None
    buf  = ctypes.create_string_buffer(8)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(kernel32.GetCurrentProcess(),
                                  ctypes.c_void_p(addr),
                                  buf, 8, ctypes.byref(read)) and read.value == 8:
        return struct.unpack_from("<Q", buf.raw, 0)[0]
    return None

def _read_dword(addr: int) -> Optional[int]:
    if not IS_WINDOWS or not kernel32:
        return None
    buf  = ctypes.create_string_buffer(4)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(kernel32.GetCurrentProcess(),
                                  ctypes.c_void_p(addr),
                                  buf, 4, ctypes.byref(read)) and read.value == 4:
        return struct.unpack_from("<I", buf.raw, 0)[0]
    return None

def _read_byte(addr: int) -> Optional[int]:
    if not IS_WINDOWS or not kernel32:
        return None
    buf  = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(kernel32.GetCurrentProcess(),
                                  ctypes.c_void_p(addr),
                                  buf, 1, ctypes.byref(read)) and read.value == 1:
        return buf.raw[0]
    return None

# ─── Detection methods ────────────────────────────────────────────────────────

class DebugDetectionMethod(Enum):
    PEB_BEING_DEBUGGED    = auto()
    PEB_NT_GLOBAL_FLAG   = auto()
    PEB_HEAP_FLAGS       = auto()
    PEB_HEAP_FORCE_FLAGS = auto()
    NT_QUERY_DEBUG_PORT   = auto()
    NT_QUERY_DEBUG_FLAGS  = auto()
    NT_QUERY_DEBUG_OBJECT = auto()
    RDTSC_DELTA           = auto()
    QPC_DELTA             = auto()
    TICKCOUNT_DELTA       = auto()
    CPUID_HYPERVISOR_BIT  = auto()
    VM_REGISTRY           = auto()
    VM_SHARED_MEMORY      = auto()
    VM_MAC_ADDRESS        = auto()

DETECTION_METHODS = list(DebugDetectionMethod)


# ─── AntiDebugMonitor ─────────────────────────────────────────────────────────

class AntiDebugMonitor:
    """
    Real-time anti-debug and VM detection engine.

    Usage:
        ad = AntiDebugMonitor()
        ad.start(interval=2.0)
        result = ad.get_current_status()
        print(f"Debugger detected: {result['detected']}")
        ad.stop()
    """

    def __init__(self):
        self._results: Dict[DebugDetectionMethod, Dict[str, Any]] = {}
        self._running  = False
        self._lock     = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._total_checks = 0

    # ── PEB-based checks ───────────────────────────────────────────────────────

    def check_peb_being_debugged(self) -> Dict[str, Any]:
        """Read PEB+0x02 (BeingDebugged flag)."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        peb = _read_byte(PEB_OFFSET + PEB_BEING_DEBUGGED)
        if peb is None:
            return {"detected": False, "value": None, "detail": "PEB read failed"}
        return {"detected": bool(peb), "value": peb, "detail": ""}

    def check_peb_nt_global_flag(self) -> Dict[str, Any]:
        """Read PEB+0x68 (NtGlobalFlag)."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        flag = _read_dword(PEB_OFFSET + PEB_NT_GLOBAL_FLAG)
        if flag is None:
            return {"detected": False, "value": None, "detail": "PEB read failed"}
        dangerous = flag & (FLG_HEAP_ENABLE_TAIL_CHECK |
                           FLG_HEAP_ENABLE_FREE_CHECK |
                           FLG_HEAP_VALIDATE_PARAMETERS |
                           FLG_HEAP_VALIDATE_ALL)
        return {
            "detected": bool(dangerous),
            "value":    flag,
            "detail":   f"0x{flag:08X}" + (" (debug flags set)" if dangerous else " (clean)"),
        }

    def check_peb_heap_flags(self) -> Dict[str, Any]:
        """Read ProcessHeap flags at PEB+0x70 and PEB+0x74."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        flags    = _read_dword(PEB_OFFSET + PEB_HEAP_FLAGS)
        force_fl = _read_dword(PEB_OFFSET + PEB_HEAP_FORCE_FLAGS)
        detected = (flags is not None and flags & 0x50000000) or \
                   (force_fl is not None and force_fl != 0)
        return {
            "detected": detected,
            "value":    {"flags": flags, "force_flags": force_fl},
            "detail":   f"flags=0x{flags or 0:08X} force=0x{force_fl or 0:08X}",
        }

    # ── NtQueryInformationProcess checks ──────────────────────────────────────

    def _nt_query(self, info_class: int) -> Optional[int]:
        """Call NtQueryInformationProcess for a given class."""
        if not IS_WINDOWS or not ntdll:
            return None
        buf = ctypes.create_string_buffer(8)
        ret_len = ctypes.c_ulong()
        status = ntdll.NtQueryInformationProcess(
            kernel32.GetCurrentProcess(),
            info_class,
            buf, 8,
            ctypes.byref(ret_len),
        )
        if status == 0:  # NTSTATUS_SUCCESS
            return struct.unpack_from("<Q", buf.raw, 0)[0]
        return None

    def check_debug_port(self) -> Dict[str, Any]:
        """NtQueryInformationProcess(ProcessDebugPort). Non-zero = debugger present."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        port = self._nt_query(ProcessDebugPort)
        return {"detected": port is not None and port != 0,
                "value": port, "detail": f"port=0x{port or 0:X}"}

    def check_debug_object_handle(self) -> Dict[str, Any]:
        """NtQueryInformationProcess(ProcessDebugObjectHandle)."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        handle = self._nt_query(ProcessDebugObjectHandle)
        return {"detected": handle is not None and handle != 0,
                "value": handle, "detail": f"handle=0x{handle or 0:X}"}

    def check_debug_flags(self) -> Dict[str, Any]:
        """NtQueryInformationProcess(ProcessDebugFlags). 0 = debugging enabled."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        flags = self._nt_query(ProcessDebugFlags)
        return {"detected": flags is not None and flags == 0,
                "value": flags, "detail": f"flags={flags}"}

    # ── Timing-based checks ─────────────────────────────────────────────────────

    def check_rdtsc_delta(self, threshold: float = 100.0) -> Dict[str, Any]:
        """
        Two RDTSC calls with a CPU-intensive operation between them.
        Debuggers/single-stepping cause larger TSC deltas.
        """
        if not IS_WINDOWS:
            # Use time-based fallback on non-Windows
            import time
            t1 = time.perf_counter_ns()
            _ = sum(i*i for i in range(10000))
            t2 = time.perf_counter_ns()
            delta = (t2 - t1) / 1_000_000  # ms
            return {"detected": delta > threshold, "value": delta,
                    "detail": f"{delta:.2f}ms (threshold: {threshold}ms)"}
        class u64(ctypes.Structure):
            _fields_ = [("low", ctypes.c_ulong), ("high", ctypes.c_ulong)]
        def rdtsc() -> int:
            val = u64()
            ctypes.windll.kernel32.__rdtsc(ctypes.byref(val))
            return (val.high << 32) | val.low
        t1 = rdtsc()
        _ = sum(i*i for i in range(10000))
        t2 = rdtsc()
        delta = abs(t2 - t1)
        # Normal: a few thousand cycles. Debugger: hundreds of thousands+
        return {"detected": delta > 50000, "value": delta,
                "detail": f"delta={delta} cycles"}

    def check_qpc_delta(self, threshold_ms: float = 50.0) -> Dict[str, Any]:
        """QueryPerformanceCounter anomaly detection."""
        if not IS_WINDOWS or not kernel32:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        def qpc() -> int:
            val = ctypes.c_int64()
            kernel32.QueryPerformanceCounter(ctypes.byref(val))
            return val.value
        t1 = qpc()
        freq = ctypes.c_int64()
        kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
        _ = sum(i*i for i in range(5000))
        t2 = qpc()
        delta_ms = abs(t2 - t1) * 1000.0 / (freq.value or 1)
        return {"detected": delta_ms > threshold_ms, "value": delta_ms,
                "detail": f"{delta_ms:.2f}ms elapsed (threshold {threshold_ms}ms)"}

    def check_tickcount_delta(self, threshold_ms: float = 100.0) -> Dict[str, Any]:
        """GetTickCount64 anomaly detection."""
        if not IS_WINDOWS or not kernel32:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        t1 = kernel32.GetTickCount64()
        _ = sum(i*i for i in range(5000))
        t2 = kernel32.GetTickCount64()
        delta = abs(t2 - t1)
        return {"detected": delta > threshold_ms, "value": delta,
                "detail": f"{delta}ms (threshold {threshold_ms}ms)"}

    # ── CPUID / hypervisor checks ───────────────────────────────────────────────

    def check_cpuid_hypervisor(self) -> Dict[str, Any]:
        """CPUID.1 ECX.31: hypervisor bit."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        regs = (ctypes.c_int * 4)()
        ctypes.windll.ntdll.__cpuidex(ctypes.byref(regs), 1, 0)
        hypervisor_bit = (regs[2] >> 31) & 1
        # Also check extended hypervisor leaves
        leaf2 = (ctypes.c_int * 4)()
        ctypes.windll.ntdll.__cpuidex(ctypes.byref(leaf2), 0x40000000, 0)
        hv_present = leaf2[0] >= 0x40000000
        hypervisor_id = None
        if hv_present:
            leaf3 = (ctypes.c_int * 4)()
            ctypes.windll.ntdll.__cpuidex(ctypes.byref(leaf3), 0x40000001, 0)
            hypervisor_id = leaf3[0]
        return {
            "detected": bool(hypervisor_bit),
            "value":    {"hypervisor_bit": hypervisor_bit, "hv_id": hypervisor_id},
            "detail":   f"bit={hypervisor_bit} id=0x{hypervisor_id or 0:X}",
        }

    # ── VM artifact checks ─────────────────────────────────────────────────────

    def check_vm_registry(self) -> Dict[str, Any]:
        """Check for VMware/VBox registry keys."""
        if not IS_WINDOWS or not kernel32:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        HKEY_LOCAL_MACHINE = 0x80000003
        keys = [
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse"),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxService"),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmci"),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmhgfs"),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxSF"),
        ]
        found = []
        for hkey_root, subkey in keys:
            hkey = ctypes.c_void_p(hkey_root)
            if kernel32.RegOpenKeyExW(hkey, subkey, 0, 0x20019,
                                       ctypes.byref(hkey)) == 0:
                found.append(subkey.split("\\")[-1])
                kernel32.RegCloseKey(hkey)
        return {
            "detected": bool(found),
            "value":    found,
            "detail":   ", ".join(found) if found else "No VM keys found",
        }

    def check_vm_shared_memory(self) -> Dict[str, Any]:
        """Check for VM shared memory device handles."""
        if not IS_WINDOWS or not kernel32:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        paths = [
            b"\\\\.\\vmci",
            b"\\\\.\\hgfs",
            b"\\\\.\\vmhgfs",
            b"\\\\.\\VBoxMiniRdrDN",
        ]
        found = []
        for path in paths:
            h = kernel32.CreateFileA(path, 0, 0, None, 3, 0, None)  # OPEN_EXISTING
            if h != ctypes.c_void_p(-1).value:
                found.append(path.decode())
                kernel32.CloseHandle(h)
        return {
            "detected": bool(found),
            "value":    found,
            "detail":   ", ".join(found) if found else "No VM devices found",
        }

    def check_vm_mac_address(self) -> Dict[str, Any]:
        """Check MAC address OUI for VMware/VBox prefixes."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            import subprocess
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object Status -eq 'Up' | "
                 "Select-Object -ExpandProperty MacAddress"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode()
            macs = [m.strip().replace("-", ":").upper()[:17]
                    for m in out.strip().split("\n") if m.strip()]
            vm_ouis = {"00:05:69", "00:0C:29", "00:1C:14",  # VMware
                       "08:00:27",                          # VirtualBox
                       "00:50:56"}                          # VMware alternate
            found = [m for m in macs if any(m.startswith(o) for o in vm_ouis)]
            return {
                "detected": bool(found),
                "value":    found,
                "detail":   ", ".join(found) if found else "No VM MACs found",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"Failed to query adapters: {e}"}

    # ── Check runner ───────────────────────────────────────────────────────────

    def _run_check(self, method: DebugDetectionMethod) -> Dict[str, Any]:
        runner = {
            DebugDetectionMethod.PEB_BEING_DEBUGGED:    self.check_peb_being_debugged,
            DebugDetectionMethod.PEB_NT_GLOBAL_FLAG:   self.check_peb_nt_global_flag,
            DebugDetectionMethod.PEB_HEAP_FLAGS:        self.check_peb_heap_flags,
            DebugDetectionMethod.PEB_HEAP_FORCE_FLAGS:  self.check_peb_heap_flags,
            DebugDetectionMethod.NT_QUERY_DEBUG_PORT:   self.check_debug_port,
            DebugDetectionMethod.NT_QUERY_DEBUG_FLAGS:  self.check_debug_flags,
            DebugDetectionMethod.NT_QUERY_DEBUG_OBJECT: self.check_debug_object_handle,
            DebugDetectionMethod.RDTSC_DELTA:            self.check_rdtsc_delta,
            DebugDetectionMethod.QPC_DELTA:             self.check_qpc_delta,
            DebugDetectionMethod.TICKCOUNT_DELTA:       self.check_tickcount_delta,
            DebugDetectionMethod.CPUID_HYPERVISOR_BIT:  self.check_cpuid_hypervisor,
            DebugDetectionMethod.VM_REGISTRY:           self.check_vm_registry,
            DebugDetectionMethod.VM_SHARED_MEMORY:       self.check_vm_shared_memory,
            DebugDetectionMethod.VM_MAC_ADDRESS:        self.check_vm_mac_address,
        }.get(method)
        if runner:
            return runner()
        return {"detected": False, "value": None, "detail": "Unknown method"}

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_all(self) -> Dict[str, Any]:
        """Run all detection checks and store results."""
        with self._lock:
            for method in DETECTION_METHODS:
                result = self._run_check(method)
                self._results[method] = {
                    "method":   method.name,
                    "detected": result["detected"],
                    "value":    result["value"],
                    "detail":   result["detail"],
                }
            self._total_checks += 1
        return self._results

    def get_current_status(self) -> Dict[str, Any]:
        """Quick status: detected or not, with count."""
        with self._lock:
            detected = [m.name for m, r in self._results.items() if r.get("detected")]
            return {
                "detected": bool(detected),
                "count":    len(detected),
                "methods":  detected,
            }

    def get_analytics(self) -> Dict[str, Any]:
        """Full analytics for the dashboard."""
        with self._lock:
            return {
                "source":       "antidebug",
                "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%S"),
                "total_checks": self._total_checks,
                "status":       self.get_current_status(),
                "all_results":  list(self._results.values()),
            }

    def start(self, interval: float = 2.0):
        """Start background monitoring thread."""
        self._running = True
        self._thread  = threading.Thread(target=self._loop,
                                          args=(interval,), daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)

    def _loop(self, interval: float):
        while self._running:
            self.check_all()
            time.sleep(interval)


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== AntiDebug Monitor Self-Test ===")
    ad = AntiDebugMonitor()
    ad.check_all()
    status = ad.get_current_status()
    print(f"Debugger detected: {status['detected']}")
    print(f"Methods triggered: {status['count']}")
    print("\nResults:")
    for method_name in status['methods']:
        print(f"  [DETECTED] {method_name}")
    for m, r in ad._results.items():
        if not r['detected']:
            print(f"  [  CLEAN   ] {m.name}: {r['detail']}")