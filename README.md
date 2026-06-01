# Aurora Unified RealTime Analytics

**Consolidated from 5 separate simulation repos into 1 real implementation.**

## Origins

This project replaces and unifies:
| Old Repo | Status |
|---|---|
| `RealTime-Syscall-Analytics` | Replaced by `aurora/core/syscalls.py` |
| `RealTime-Memory-Analytics` | Replaced by `aurora/core/memory.py` |
| `RealTime-Offset-Analytics` | Merged into `aurora/core/memory.py` (offset DB) |
| `RealTime-AntiDebug-Analytics` | Replaced by `aurora/core/antidebug.py` |
| `aurora-realtime-analytics` | Replaced by `aurora/core/shared.py` + `server.py` + `web/` |

## Architecture

```
aurora/
├── core/
│   ├── shared.py     — SharedRingBuffer (mmap) + AnalyticsEngine
│   ├── syscalls.py   — Real syscall SSN resolver + monitor
│   ├── memory.py     — Memory scanner + AOB pattern matcher
│   ├── antidebug.py  — Anti-debug + VM detection engine
│   └── dashboard.py  — Unified terminal dashboard
├── __init__.py       — Package root with all exports
└── __main__.py       — CLI entry point

server.py             — Flask web server (API + dashboard)
web/index.html        — Chart.js web dashboard
requirements.txt
```

## Features

### Syscall Monitor (`aurora/core/syscalls.py`)
- **SSN Resolution**: Reads ntdll syscall stubs to extract real Service System Numbers
- **Trampoline Hooks**: SSN patching via `VirtualProtect` + `FlushInstructionCache`
- **Live Stats**: Call frequency, timing, error counts per syscall
- **Built-in SSN table**: 25+ well-known syscall numbers (Windows 10 1909–22H2 x64)

### Memory Scanner (`aurora/core/memory.py`)
- **`VirtualQueryEx` enumeration**: All MEM_COMMIT regions with protection flags
- **AOB Pattern Matching**: Wildcard support (`??` / partial bytes)
- **Built-in UE4/UE5 signatures**: GObjects, GNames, UWorld, PersistentLevel, PlayerController, LocalPlayer
- **Offset DB**: Persistent record of all matched offsets with pointers

### Anti-Debug Monitor (`aurora/core/antidebug.py`)
| Check | Method |
|---|---|
| PEB BeingDebugged | Direct PEB offset read |
| NtGlobalFlag | PEB+0x68 |
| Heap Flags | PEB+0x70/0x74 |
| Debug Port | `NtQueryInformationProcess(ProcessDebugPort)` |
| Debug Object Handle | `NtQueryInformationProcess(ProcessDebugObjectHandle)` |
| Debug Flags | `NtQueryInformationProcess(ProcessDebugFlags)` |
| RDTSC Delta | TSC difference between two calls |
| QPC Anomaly | `QueryPerformanceCounter` delta |
| CPUID Hypervisor Bit | ECX.31 of CPUID leaf 1 |
| VM Registry Keys | VBox/VMware registry presence |
| VM Shared Memory | \\.\vmci, \\.\hgfs handles |
| VM MAC Address | OUI check for VMware/VBox |

### Shared Ring Buffer (`aurora/core/shared.py`)
- **mmap-backed**: `/dev/shm/aurora_analytics` (10MB default)
- **Multi-writer safe**: CAS on head pointer
- **Shared between monitors and Flask server** (cross-process)

### Dashboards
- **Terminal**: `python -m aurora` — ASCII art dashboard replacing 4 old ones
- **Web**: `python server.py` → http://localhost:5000 — Chart.js + Flask

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run terminal dashboard
python -m aurora

# Run web dashboard
python server.py
# Open http://localhost:5000
```

## Requirements

```
flask
flask-cors
psutil
```

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/dashboard` | Unified metrics + all source data |
| `GET /api/syscalls` | Full syscall analytics |
| `GET /api/syscalls/top` | Top 20 syscalls by call count |
| `GET /api/syscalls/table` | Complete SSN table |
| `GET /api/memory` | Memory scanner analytics |
| `POST /api/memory/scan` | Trigger new scan |
| `GET /api/memory/offsets` | Offset database |
| `GET /api/antidebug` | Anti-debug analytics |
| `GET /api/antidebug/status` | Current debug/VM status |
| `GET /api/antidebug/checks` | Run all checks on demand |
| `GET /api/events` | Server-Sent Events stream |

## Extending

Add custom AOB signatures:
```python
from aurora.core.memory import MemoryScanner

scanner = MemoryScanner(pid=1234)
scanner.add_signature("MyGame_GName", "48 8B 05 ?? ?? ?? ?? C3", relative=True)
results = scanner.scan_all()
```

Hook additional syscalls:
```python
from aurora.core.syscalls import SyscallMonitor

mon = SyscallMonitor()
ssn = mon.get_ssn("ntreadvirtualmemory")
# ssn == 0x3F (on Windows 10 22H2 x64)
```
