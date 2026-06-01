#!/usr/bin/env python3
"""Aurora package CLI entry point."""
from aurora.core.dashboard import RealtimeDashboard
from aurora.core.shared   import AnalyticsEngine
from aurora.core.syscalls import SyscallMonitor
from aurora.core.memory   import MemoryScanner
from aurora.core.antidebug import AntiDebugMonitor
import time, sys

C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_END = '\033[0m'

def main():
    print(f"{C_GREEN}Starting Aurora RealTime Analytics...{C_END}\n")

    engine = AnalyticsEngine()
    dash   = RealtimeDashboard()
    sc_mon = SyscallMonitor()
    ad_mon = AntiDebugMonitor()

    sc_mon.start(interval=0.5)
    ad_mon.start(interval=2.0)

    print(f"{C_GREEN}Aurora Unified RealTime Dashboard{C_YELLOW}")
    print(f"  Syscalls:  enabled (SSN discovery + tracking)")
    print(f"  Memory:    enabled (AOB pattern scanner)")
    print(f"  AntiDebug: enabled ({len(__import__('aurora.core.antidebug', fromlist=['DETECTION_METHODS']).DETECTION_METHODS)} detection methods)")
    print(f"{C_YELLOW}Press Ctrl+C to stop.{C_END}\n")

    try:
        while True:
            engine.track("syscall",   sc_mon.get_analytics())
            engine.track("antidebug", ad_mon.get_analytics())
            metrics = engine.get_realtime_metrics()
            dash.render(metrics, engine.get_events(limit=10))
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Shutting down...{C_END}")
        sc_mon.stop()
        ad_mon.stop()
        engine.close()

if __name__ == "__main__":
    main()
