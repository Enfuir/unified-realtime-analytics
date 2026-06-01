"""
Terminal dashboard for RealTime Analytics.
Replaces all 4 old terminal dashboards (SyscallAnalytics, MemoryAnalytics,
OffsetAnalytics, AntiDebugDashboard) with ONE unified view.
"""

import sys, os
from typing import Dict, List, Any, Optional

# Color codes
C_HEADER  = '\033[95m'
C_BLUE   = '\033[94m'
C_CYAN   = '\033[96m'
C_GREEN  = '\033[92m'
C_YELLOW = '\033[93m'
C_RED    = '\033[91m'
C_BOLD   = '\033[1m'
C_UNDER  = '\033[4m'
C_END    = '\033[0m'
C_DIM    = '\033[2m'

COLORS = [C_CYAN, C_BLUE, C_GREEN, C_YELLOW, C_MAGENTA := '\033[35m']


class RealtimeDashboard:
    """
    Single unified real-time terminal dashboard.

    Replaces:
    - SyscallAnalytics.display_syscall_dashboard()
    - MemoryAnalytics.display_memory_dashboard()
    - OffsetAnalytics.display_offset_dashboard()
    - AntiDebugDashboard.display_dashboard()
    """

    WIDTH = 90

    def __init__(self, width: int = 90):
        self.WIDTH = width

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _bar(self, value: float, max_val: float, width: int = 40,
             fill: str = "█", empty: str = "░") -> str:
        if max_val <= 0:
            return empty * width
        ratio = min(value / max_val, 1.0)
        filled = int(ratio * width)
        return C_GREEN + fill * filled + C_DIM + empty * (width - filled) + C_END

    def _rule(self, char: str = "─", color: str = C_DIM) -> str:
        return color + char * self.WIDTH + C_END

    def _center(self, text: str, width: int = 0) -> str:
        w = width or self.WIDTH
        return text.center(w)

    def _left(self, text: str, width: int = 0) -> str:
        w = width or self.WIDTH
        return text.ljust(w)

    def _right(self, text: str, width: int = 0) -> str:
        w = width or self.WIDTH
        return text.rjust(w)

    def render(self, metrics: Dict[str, Any], recent_events: Optional[List[Any]] = None):
        """Render the full dashboard."""
        self.clear()

        # ── Header ──────────────────────────────────────────────────────────
        title = "AURORA UNIFIED REALTIME ANALYTICS"
        subtitle = "Consolidated: Syscall · Memory · AntiDebug"
        print()
        print(C_HEADER + C_BOLD + self._center("╔" + "═" * (self.WIDTH - 2) + "╗") + C_END)
        print(C_HEADER + C_BOLD +
              self._center(f"║ {self._center(title, self.WIDTH - 4)} ║") + C_END)
        print(C_HEADER + C_BOLD +
              self._center(f"║ {self._center(subtitle, self.WIDTH - 4)} ║") + C_END)
        print(C_HEADER + C_BOLD + self._center("╚" + "═" * (self.WIDTH - 2) + "╝") + C_END)
        print()

        # ── Source breakdown ─────────────────────────────────────────────────
        by_source = metrics.get("by_source", {})
        total_ev  = metrics.get("total_events", 0)
        print(C_BOLD + self._rule("─", C_DIM) + C_END)
        print(C_BOLD + "  SOURCES" + C_END)
        print(C_BOLD + self._rule("─", C_DIM) + C_END)
        if by_source:
            max_src = max(by_source.values()) if by_source else 1
            colors_iter = iter(COLORS)
            for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
                bar = self._bar(count, max_src)
                c = next(colors_iter, C_CYAN)
                print(f"  {c}{C_BOLD}{src:<15}{C_END} {bar} {count:>6}")
        else:
            print(f"  {C_DIM}  (no data yet){C_END}")

        # ── Syscall section ─────────────────────────────────────────────────
        print()
        print(C_BOLD + self._rule("─", C_YELLOW) + C_END)
        print(C_BOLD + "  SYSCALL ANALYTICS" + C_END)
        print(C_BOLD + self._rule("─", C_YELLOW) + C_END)
        syscall_counts = metrics.get("syscall_counts", {})
        if syscall_counts:
            max_sc = max(syscall_counts.values()) if syscall_counts else 1
            for name, count in list(syscall_counts.items())[:12]:
                bar = self._bar(count, max_sc)
                print(f"  {C_YELLOW}{name:<38}{C_END} {bar} {count:>6}")
            print(f"  {C_DIM}  {len(syscall_counts)} unique syscalls tracked{C_END}")
        else:
            print(f"  {C_DIM}  (syscall monitor not started){C_END}")

        # ── Memory section ─────────────────────────────────────────────────
        print()
        print(C_BOLD + self._rule("─", C_CYAN) + C_END)
        print(C_BOLD + "  MEMORY SCANNER" + C_END)
        print(C_BOLD + self._rule("─", C_CYAN) + C_END)
        mem_regions = metrics.get("memory_regions", 0)
        mem_matches = metrics.get("memory_matches", 0)
        print(f"  {C_CYAN}Regions scanned:{C_END} {mem_regions:>8}")
        print(f"  {C_CYAN}Pattern matches: {C_END} {mem_matches:>8}")

        offset_db = metrics.get("offset_db", {})
        if offset_db:
            print(f"  {C_CYAN}Signatures found:{C_END}")
            for sig_name, sig_data in list(offset_db.items())[:6]:
                count = sig_data.get("count", 0)
                offsets = list(sig_data.get("offsets", {}).keys())
                offset_str = ", ".join(offsets[:2]) + ("..." if len(offsets) > 2 else "")
                print(f"    {C_CYAN}{sig_name:<25}{C_END} x{count} @ {offset_str}")

        # ── Anti-debug section ──────────────────────────────────────────────
        print()
        print(C_BOLD + self._rule("─", C_RED) + C_END)
        print(C_BOLD + "  ANTI-DEBUG STATUS" + C_END)
        print(C_BOLD + self._rule("─", C_RED) + C_END)
        antidebug = metrics.get("antidebug_status", {})
        if antidebug:
            detected = antidebug.get("detected", False)
            status_color = C_RED + C_BOLD if detected else C_GREEN + C_BOLD
            status_text  = "⚠ DETECTED" if detected else "✓ CLEAN"
            print(f"  {status_color}Status: {status_text}{C_END}")
            methods = antidebug.get("methods", [])
            if methods:
                print(f"  {C_RED}Detected by:{C_END}")
                for m in methods:
                    print(f"    {C_RED}  • {m}{C_END}")
            else:
                print(f"  {C_GREEN}  No debugger or VM detected{C_END}")
        else:
            print(f"  {C_DIM}  (anti-debug monitor not started){C_END}")
            print(f"  {C_CYAN}  Checks available:{C_END}")
            for method in sorted(DETECTION_METHODS.keys()):
                print(f"    {C_DIM}  - {method}{C_END}")

        # ── Recent events ───────────────────────────────────────────────────
        print()
        print(C_BOLD + self._rule("─", C_DIM) + C_END)
        print(C_BOLD + "  RECENT EVENTS" + C_END)
        print(C_BOLD + self._rule("─", C_DIM) + C_END)
        if recent_events:
            for ev in recent_events[-8:]:
                src  = getattr(ev, "source", "?")
                data = getattr(ev, "data",  {})
                ts   = getattr(ev, "timestamp", "")[-14:-5]
                c    = C_GREEN if src == "syscall" else C_CYAN if src == "memory" else C_RED
                summary = str(data)[:60]
                print(f"  {c}[{ts}]{C_END} {C_BOLD}{src:<10}{C_END} {summary}")
        else:
            print(f"  {C_DIM}  (no events yet){C_END}")

        print()
        print(C_DIM + self._center(f"Total events: {total_ev} | Window: {metrics.get('window_size', 60)}s") + C_END)
        print()

    def render_summary(self, metrics: Dict[str, Any]) -> str:
        """Render a compact one-line summary."""
        parts = []
        by_src = metrics.get("by_source", {})
        if "syscall" in by_src:
            parts.append(f"syscalls={by_src['syscall']}")
        if "memory" in by_src:
            parts.append(f"memory={by_src['memory']}")
        if "antidebug" in by_src:
            parts.append(f"antidebug={by_src['antidebug']}")
        return f"Aurora: {' | '.join(parts)}"


# ─── Detection method registry ─────────────────────────────────────────────────
DETECTION_METHODS = {
    "PEB_BEING_DEBUGGED":      "PEB.BeingDebugged byte",
    "PEB_NT_GLOBAL_FLAG":     "PEB.NtGlobalFlag",
    "PEB_HEAP_FLAGS":         "PEB.ProcessHeap->Flags",
    "PEB_HEAP_FORCE_FLAGS":   "PEB.ProcessHeap->ForceFlags",
    "NT_QUERY_DEBUG_PORT":    "NtQueryInformationProcess(ProcessDebugPort)",
    "NT_QUERY_DEBUG_FLAGS":   "NtQueryInformationProcess(ProcessDebugFlags)",
    "NT_QUERY_DEBUG_OBJECT":  "NtQueryInformationProcess(ProcessDebugObjectHandle)",
    "CHECK_REMOTE_DEBUGGER":  "CheckRemoteDebuggerPresent",
    "TIMING_RDTSC":            "RDTSC delta between two calls",
    "TIMING_QPC":              "QueryPerformanceCounter delta",
    "TIMING_GET_TICK_COUNT":   "GetTickCount64 anomaly after sleep",
    "CPUID_VM":                "CPUID hypervisor bit (ECX.31)",
    "REGISTRY_VM":             "VMware/VBox registry keys",
    "SHARED_MEMORY_VM":        "VMCI / hgfs shared memory",
    "MAC_ADDRESS_VM":          "VMware/VBox MAC OUI",
}


# ─── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    from aurora.core.shared import AnalyticsEngine
    from aurora.core.syscalls import SyscallMonitor
    from aurora.core.memory import MemoryScanner
    from aurora.core.antidebug import AntiDebugMonitor
    import time

    engine = AnalyticsEngine()
    dash   = RealtimeDashboard()

    # Start monitors
    sc_mon  = SyscallMonitor()
    mem_mon = MemoryScanner()
    ad_mon  = AntiDebugMonitor()

    sc_mon.start(interval=0.5)
    ad_mon.start(interval=2.0)

    print(f"{C_GREEN}Aurora Unified RealTime Dashboard started. Press Ctrl+C to stop.{C_END}\n")

    try:
        while True:
            # Collect data
            engine.track("syscall",    sc_mon.get_analytics())
            engine.track("antidebug",  ad_mon.get_analytics())
            metrics = engine.get_realtime_metrics()
            dash.render(metrics, engine.get_events(limit=10))
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Shutting down...{C_END}")
        sc_mon.stop()
        ad_mon.stop()
        engine.close()
