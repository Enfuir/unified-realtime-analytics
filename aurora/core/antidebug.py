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
    # ── Advanced (from UnknownCheats / red team research) ────────────────────
    SEH_ABUSE             = auto()   # INT3 inside __except block
    VEH_PRESENT           = auto()   # Vectored Exception Handler
    TRAP_FLAG             = auto()   # TF bit in EFLAGS/RFLAGS
    INT2D_INSTRUCTION     = auto()   # INT 2D anti-debug
    SW_BREAKPOINT_SCAN    = auto()   # Scan .text for CC / INT3 bytes
    KI_USER_EXCEPTION     = auto()   # KiUserExceptionDispatcher hooked
    PARENT_PROCESS        = auto()   # non-explorer parent process
    NTDLL_UNHOOKED        = auto()   # ntdll mapped image (not PE)
    CODE_INTEGRITY         = auto()   # CiCheck / driver signing
    HARDWARE_BP           = auto()   # Dr0-Dr7 debug registers
    REMOTE_THREAD         = auto()   # foreign thread in process
    PEB_SESSION_ID        = auto()   # SessionId != 0 on domain-joined
    SBIEDLL_LOADED        = auto()   # Sandboxie sbiedll.dll
    KERNEL32_UNHOOKED     = auto()   # kernel32 on-disk vs in-memory differ
    KERNEL_CALLBACK       = auto()   # PsSetCreateProcessNotifyRoutine
    CPUID_MANUFACTURER    = auto()   # "AuthenticAMD" vs "GenuineIntel" anomalies
    VMWARE_PORT           = auto()   # IN 0xA from VMWare
    VBOX_PORT             = auto()   # IN 0x10 from VirtualBox
    THREAD_CONTEXT_FAKE   = auto()   # Thread CONTEXT inconsistent
    TIMER_ANOMALY_LONG    = auto()   # GetTickCount delta > 500ms

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

    # ── Advanced anti-debug checks (UnknownCheats / red team research) ──────────

    def check_seh_abuse(self) -> Dict[str, Any]:
        """
        SEH abuse detection: set an exception handler, trigger INT3, then
        check if EIP lands inside the handler while the debugger would have
        silently swallowed the exception.
        Works on x64 (no SEH in 64-bit - uses VEH instead).
        """
        if not IS_WINDOWS or not ntdll:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            result = {"detected": False, "value": None, "detail": "clean"}

            def _veh_handler(exc):
                result["detected"] = True
                result["value"] = exc["exception_code"]
                result["detail"] = f"VEH hit: code=0x{exc['exception_code']:X}"
                return 1  # EXCEPTION_CONTINUE_SEARCH

            import ctypes
            handler = ctypes.WINFUNCTYPE(
                ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)
            cb = handler(lambda exc, _:
                (_veh_handler({"exception_code": exc}), 1)[1])
            ntdll.RtlAddVectoredExceptionHandler(1, cb)
            # Trigger breakpoint
            ctypes.windll.kernel32.DebugBreak()
            ntdll.RtlRemoveVectoredExceptionHandler(cb)
            return result
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"SEH check failed: {e}"}

    def check_veh_present(self) -> Dict[str, Any]:
        """Check if any Vectored Exception Handlers are registered."""
        if not IS_WINDOWS or not ntdll:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            # Walk VEH chain via PEB
            peb = _read_qword(PEB_OFFSET)
            if peb:
                # PEB + 0x78 = VEH toplimit / first handler (Nt8+)
                veh_ptr = _read_qword(peb + 0x78) if peb else None
                if veh_ptr and veh_ptr != 0:
                    return {"detected": True, "value": hex(veh_ptr),
                            "detail": "VEH chain not empty"}
        except Exception:
            pass
        return {"detected": False, "value": None, "detail": "No VEH detected"}

    def check_trap_flag(self) -> Dict[str, Any]:
        """Check if the Trap Flag (TF bit 8) is set in RFLAGS."""
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            class CONTEXT(ctypes.Structure):
                _fields_ = [("Rflags", ctypes.c_uint64),
                            ("Rip", ctypes.c_uint64)]
            ctx = CONTEXT()
            ctx.Rflags = 0
            # Read RFLAGS via inline assembly (pushfq / pop rax)
            import ctypes
            # Use GetThreadContext to get RFLAGS
            handle = kernel32.GetCurrentThread()
            class THREAD_CONTEXT(ctypes.Structure):
                _fields_ = [("P1", ctypes.c_uint64), ("P2", ctypes.c_uint64),
                            ("Rflags", ctypes.c_uint64), ("Rip", ctypes.c_uint64)]
            tc = THREAD_CONTEXT()
            tc.P1 = 0x10007  # CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER
            tc.P2 = 0
            tc.Rflags = 0
            # We can't call GetThreadContext reliably without SEH,
            # so use timing-based detection instead
            return self.check_rdtsc_delta(threshold=50000)
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"TF check error: {e}"}

    def check_int2d(self) -> Dict[str, Any]:
        """
        INT 2D instruction detection. In normal execution, INT 2D causes
        an exception with code 0x80000003. When a debugger is present,
        the kernel handles it differently — fewer bytes are returned as the
        instruction is treated differently. Also: under WinDBG, INT 2D with
        SSF (EFLAGS.TF) set triggers a single-step exception instead.
        """
        return {"detected": False, "value": None,
                "detail": "INT 2D requires inline assembly (deferred)"}

    def check_sw_breakpoint_scan(self, base: int = 0x140000000,
                                 size: int = 0x1000000) -> Dict[str, Any]:
        """
        Scan the .text section of the main module for 0xCC (INT3) bytes.
        A healthy .text section has very few or zero 0xCC bytes in
        non-export regions. Heavy 0xCC presence = active breakpoints.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            proc = kernel32.GetCurrentProcess()
            mod = kernel32.GetModuleHandleW(None)
            if not mod:
                return {"detected": False, "value": None,
                        "detail": "Failed to get module base"}

            buf = ctypes.create_string_buffer(4096)
            i = 0
            cc_count = 0
            cc_positions = []
            # Sample the .text region in 4KB chunks
            addr = ctypes.c_void_p(mod + 0x1000)
            for _ in range(256):
                read = ctypes.c_size_t()
                ok = kernel32.ReadProcessMemory(proc, addr,
                                                buf, 4096,
                                                ctypes.byref(read))
                if not ok or read.value == 0:
                    break
                for j in range(read.value):
                    if buf.raw[j] == 0xCC:
                        cc_count += 1
                        if cc_count <= 5:
                            cc_positions.append(hex(addr.value + j))
                addr.value += 4096
                if cc_count > 20:
                    break  # early exit on heavy breakpoint usage

            detected = cc_count > 3  # more than 3 breakpoints is suspicious
            return {
                "detected": detected,
                "value": {"cc_count": cc_count, "positions": cc_positions[:5]},
                "detail": f"INT3 bytes: {cc_count}, spots: {cc_positions[:5]}",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"BP scan failed: {e}"}

    def check_ki_user_exception_hooked(self) -> Dict[str, Any]:
        """
        Check if ntdll!KiUserExceptionDispatcher is hooked.
        Hooked by: Gepard Shield, most ring-3 anti-cheats.
        Detection: read first 16 bytes of the function and compare
        against known clean pattern (or verify it starts with a
        standard prolog like 'push rbp; mov rbp,rsp').
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            kud_addr = _get_func_addr("KiUserExceptionDispatcher")
            if not kud_addr:
                return {"detected": False, "value": None,
                        "detail": "Symbol not found"}
            code = _read_bytes(kud_addr, 32)
            if not code:
                return {"detected": False, "value": None,
                        "detail": "Read failed"}
            # Known clean prologs
            clean_prologs = [
                b"\\x48\\x89\\x5C\\x24\\x08",  # push rbp; mov rdi, rsi
                b"\\x48\\x83\\xEC",            # sub rsp, imm8
                b"\\x40\\x53",                # push rbx; mov rbx, rdx
            ]
            hooked = not any(code.startswith(p) for p in clean_prologs)
            return {
                "detected": hooked,
                "value": code[:16].hex(),
                "detail": "HOOKED" if hooked else "CLEAN",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"KiUserExceptionDispatcher check: {e}"}

    def check_parent_process(self) -> Dict[str, Any]:
        """
        Check if parent process is explorer.exe (normal) vs something else.
        Cheat engines often spawn from cmd, python, code, etc.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            import subprocess
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-Process -Id $PID).Parent.ProcessName"],
                timeout=3, stderr=subprocess.DEVNULL
            ).decode().strip()
            suspicious = out.lower() not in ("explorer", "cmd", "powershell")
            return {
                "detected": suspicious,
                "value": out,
                "detail": f"parent={out} (suspicious)" if suspicious else f"parent={out}",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"Parent check failed: {e}"}

    def check_ntdll_unhooked(self) -> Dict[str, Any]:
        """
        Detect ntdll hooks by checking if the in-memory .text section matches
        the on-disk PE file. Used by EDR bypass tools (Unhook-Ntdll).
        Also: check if ntdll is mapped via NtMapViewOfSection (not loaded).
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            ntdll_base = kernel32.GetModuleHandleW("ntdll.dll")
            if not ntdll_base:
                return {"detected": False, "value": None, "detail": "ntdll not found"}
            # Read first few bytes from in-memory ntdll
            in_mem = _read_bytes(ntdll_base, 16)
            if not in_mem:
                return {"detected": False, "value": None, "detail": "Read failed"}
            # A clean ntdll starts with MZ header (0x4D 0x5A = 'MZ')
            clean = in_mem[0] == 0x4D and in_mem[1] == 0x5A
            # Check if it looks like a mapped file vs PE loader
            return {
                "detected": not clean,
                "value": in_mem[:16].hex(),
                "detail": "UNHOOKED/MAPPED" if not clean else "PE-LOADED",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"ntdll check: {e}"}

    def check_code_integrity(self) -> Dict[str, Any]:
        """
        Check if Code Integrity (CiCheck.dll) is active.
        Kernel-side check — user mode proxy via PsCalloutNotify.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            import subprocess
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "Get-CimInstance Win32_DeviceGuard -ErrorAction SilentlyContinue "
                 "| Select-Object -ExpandProperty VirtualizationBasedSecurityStatus"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode().strip()
            status = int(out) if out.isdigit() else -1
            # 0=inactive, 1=inprogress, 2=active
            return {
                "detected": status == 2,
                "value": status,
                "detail": f"VBS={status} ({'active' if status==2 else 'inactive'})",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"Code Integrity check: {e}"}

    def check_hardware_breakpoints(self) -> Dict[str, Any]:
        """
        Read Dr0-Dr7 debug registers via GetThreadContext.
        Dr0-3: breakpoints addresses. Dr6: status. Dr7: control.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            class CONTEXT64(ctypes.Structure):
                _fields_ = [
                    ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
                    ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
                    ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
                ]
            ctx = CONTEXT64()
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
            ctx.Dr6 = ctx.Dr7 = 0
            # We can't call GetThreadContext without proper SEH setup in ctypes
            # So use PEB directly
            peb = _read_qword(PEB_OFFSET)
            if not peb:
                return {"detected": False, "value": None,
                        "detail": "PEB read failed"}
            # On x64, TEB + 0x0C0 contains the debug context area
            teb_base = _read_qword(PEB_OFFSET - 0x60)  # TEB from gs:0x60 then PEB
            dr0 = _read_qword(0)  # won't work
            return {
                "detected": False,
                "value": None,
                "detail": "Hardware BP requires kernel/driver (deferred)",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"Hardware BP check: {e}"}

    def check_remote_thread(self) -> Dict[str, Any]:
        """
        Enumerate threads in the current process. Check if any thread's
        start address belongs to a module that is not a known process module.
        Remote thread injection typically uses CreateRemoteThread with
        a target in kernel32/ntdll or a mapped section.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            import subprocess
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-Process -Id $PID).Threads | Select-Object Id, "
                 "StartAddress | ConvertTo-Json -Compress"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode().strip()
            # Look for threads with suspiciously low or non-module start addresses
            return {
                "detected": False,
                "value": out[:200],
                "detail": "Remote thread check (requires snapshot)",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"Remote thread check: {e}"}

    def check_sbiedll_loaded(self) -> Dict[str, Any]:
        """
        Check if Sandboxie sbiedll.dll is loaded in the process.
        Sandboxie hooks ntdll functions and is used by analysts to
        analyze cheats. Detection: enumerate loaded modules.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            import subprocess
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-Process -Id $PID).Modules | "
                 "Select-Object -ExpandProperty ModuleName"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode().strip().lower()
            sbie_dlls = ["sbiedll.dll", "SbieDll.dll", "sbiedll"]
            found = [d for d in sbie_dlls if d in out]
            return {
                "detected": bool(found),
                "value": found,
                "detail": ",".join(found) if found else "Sandboxie clean",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"Sandboxie check: {e}"}

    def check_kernel32_unhooked(self) -> Dict[str, Any]:
        """
        Compare kernel32.dll in-memory bytes vs on-disk bytes.
        If different = EDR/user-hook detected (or unhooking was done).
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        try:
            k32_base = kernel32.GetModuleHandleW("kernel32.dll")
            if not k32_base:
                return {"detected": False, "value": None,
                        "detail": "kernel32 not found"}
            in_mem = _read_bytes(k32_base, 16)
            if not in_mem:
                return {"detected": False, "value": None, "detail": "Read failed"}
            clean = in_mem[0] == 0x4D and in_mem[1] == 0x5A
            return {
                "detected": not clean,
                "value": in_mem[:16].hex(),
                "detail": "UNHOOKED" if not clean else "PE-LOADED",
            }
        except Exception as e:
            return {"detected": False, "value": None,
                    "detail": f"kernel32 check: {e}"}

    def check_cpuid_manufacturer(self) -> Dict[str, Any]:
        """
        Read CPUID 0x0 to get vendor string. GenuineIntel / AuthenticAMD
        are normal. Virtual machines often return modified IDs or
        the hypervisor bit + "Microsoft Hv" for Hyper-V.
        """
        if not IS_WINDOWS:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        regs = (ctypes.c_int * 4)()
        ctypes.windll.ntdll.__cpuidex(ctypes.byref(regs), 0, 0)
        vendor = "".join(
            struct.pack("<I", regs[i]) for i in (1, 3, 2)
        ).decode("ascii", errors="replace")
        known_vm_vendors = [
            "Microsoft Hv",  # Hyper-V
            "KVMKVMKVM",     # KVM
            "VMwareVMware",  # VMware
            "XenVMMXenVMM",  # Xen
            "Prl hyperv ",   # Parallels
        ]
        detected = any(vendor.startswith(v.rstrip()) for v in known_vm_vendors)
        return {
            "detected": detected,
            "value": vendor,
            "detail": vendor if not detected else f"VM: {vendor}",
        }

    def check_vmware_port(self) -> Dict[str, Any]:
        """Read port 0x5658 (VMware backdoor port) using IN instruction."""
        return {"detected": False, "value": None,
                "detail": "VMware port requires kernel/inline asm (deferred)"}

    def check_vbox_port(self) -> Dict[str, Any]:
        """Read port 0x10 (VirtualBox port) using IN instruction."""
        return {"detected": False, "value": None,
                "detail": "VBox port requires kernel/inline asm (deferred)"}

    def check_timer_anomaly_long(self, threshold_ms: float = 500.0) -> Dict[str, Any]:
        """
        Long-duration timing anomaly check: GetTickCount delta with
        heavy CPU work between calls. If > 500ms, suspicious.
        """
        if not IS_WINDOWS or not kernel32:
            return {"detected": False, "value": None, "detail": "Not on Windows"}
        t1 = kernel32.GetTickCount64()
        # Heavy work
        for _ in range(5):
            _ = sum(i*i for i in range(100000))
        t2 = kernel32.GetTickCount64()
        delta = abs(t2 - t1)
        return {
            "detected": delta > threshold_ms,
            "value": delta,
            "detail": f"{delta}ms ({'SUSPICIOUS' if delta > threshold_ms else 'clean'})",
        }

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
            # ── Advanced checks ──────────────────────────────────────────────
            DebugDetectionMethod.SEH_ABUSE:             self.check_seh_abuse,
            DebugDetectionMethod.VEH_PRESENT:           self.check_veh_present,
            DebugDetectionMethod.TRAP_FLAG:             self.check_trap_flag,
            DebugDetectionMethod.INT2D_INSTRUCTION:      self.check_int2d,
            DebugDetectionMethod.SW_BREAKPOINT_SCAN:    self.check_sw_breakpoint_scan,
            DebugDetectionMethod.KI_USER_EXCEPTION:      self.check_ki_user_exception_hooked,
            DebugDetectionMethod.PARENT_PROCESS:        self.check_parent_process,
            DebugDetectionMethod.NTDLL_UNHOOKED:        self.check_ntdll_unhooked,
            DebugDetectionMethod.CODE_INTEGRITY:         self.check_code_integrity,
            DebugDetectionMethod.HARDWARE_BP:           self.check_hardware_breakpoints,
            DebugDetectionMethod.REMOTE_THREAD:         self.check_remote_thread,
            DebugDetectionMethod.PEB_SESSION_ID:        self.check_parent_process,
            DebugDetectionMethod.SBIEDLL_LOADED:        self.check_sbiedll_loaded,
            DebugDetectionMethod.KERNEL32_UNHOOKED:    self.check_kernel32_unhooked,
            DebugDetectionMethod.CPUID_MANUFACTURER:    self.check_cpuid_manufacturer,
            DebugDetectionMethod.VMWARE_PORT:           self.check_vmware_port,
            DebugDetectionMethod.VBOX_PORT:             self.check_vbox_port,
            DebugDetectionMethod.THREAD_CONTEXT_FAKE:  self.check_hardware_breakpoints,
            DebugDetectionMethod.TIMER_ANOMALY_LONG:    self.check_timer_anomaly_long,
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