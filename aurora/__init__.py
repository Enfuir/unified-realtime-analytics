# Unified RealTime Analytics Engine
# A single consolidated engine replacing 5 separate simulation repos:
#   - RealTime-Syscall-Analytics
#   - RealTime-Memory-Analytics
#   - RealTime-Offset-Analytics
#   - RealTime-AntiDebug-Analytics
#   - aurora-realtime-analytics
#
# Modules:
#   core.syscalls  - Real syscall hooking via SSN trampolines
#   core.memory    - Memory region enumeration + AOB pattern scanning
#   core.antidebug - PEB/ timing/ DebugObject detection
#   core.dashboard - Real-time terminal dashboard (ASCII)
#   core.shared    - Shared data ring buffer (mmap for cross-process)
#   server         - Flask web dashboard with WebSocket polling
#   web/           - Chart.js frontend

from .core.syscalls    import SyscallMonitor, SYSCTL
from .core.memory      import MemoryScanner,  PatternMatcher
from .core.antidebug   import AntiDebugMonitor, DETECTION_METHODS
from .core.dashboard   import RealtimeDashboard
from .core.shared      import SharedRingBuffer, AnalyticsEngine

__all__ = [
    "SyscallMonitor", "SYSCTL",
    "MemoryScanner",  "PatternMatcher",
    "AntiDebugMonitor", "DETECTION_METHODS",
    "RealtimeDashboard",
    "SharedRingBuffer",
    "AnalyticsEngine",
]

__version__ = "1.0.0"