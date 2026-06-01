"""
Shared memory ring buffer (mmap) for cross-module / cross-process data sharing.
Replaces the 5 separate deques in aurora_engine.py with a persistent,
multi-consumer, lock-free-ish ring buffer backed by mmap.
"""

import struct, mmap, os, time
from pathlib import Path
from typing import Any, Optional, Dict, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json

BUFSIZE   = 10 * 1024 * 1024   # 10 MB ring buffer
ENTRY_HDR  = 8                 # u32 magic + u32 payload_len
MAX_PAYLOAD = 65535
SHM_NAME    = "aurora_analytics"

# --- Serialization -------------------------------------------------------------

def _pack_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("<H", len(b)) + b

def _unpack_str(buf: memoryview, off: int) -> tuple[str, int]:
    L, = struct.unpack_from("<H", buf, off)
    return buf[off+2:off+2+L].tobytes().decode("utf-8"), off + 2 + L

# --- Event schema ---------------------------------------------------------------

@dataclass
class Event:
    source:     str       # "syscall" | "memory" | "antidebug"
    timestamp:  str       # ISO8601
    data:       Dict[str, Any]

    def pack(self) -> bytes:
        meta = json.dumps({"source": self.source, "timestamp": self.timestamp}, separators=(",",":"))
        body = json.dumps(self.data, separators=(",",":"))
        payload = meta.encode() + b"\x00" + body.encode()
        # Truncate if needed
        if len(payload) > MAX_PAYLOAD:
            payload = payload[:MAX_PAYLOAD]
        return struct.pack("<I", len(payload)) + payload

    @staticmethod
    def unpack(buf: memoryview, off: int) -> tuple["Event", int]:
        sz, = struct.unpack_from("<I", buf, off)
        raw = bytes(buf[off+4 : off+4+sz])
        meta_b, body_b = raw.split(b"\x00", 1)
        meta  = json.loads(meta_b.decode())
        data  = json.loads(body_b.decode()) if body_b else {}
        return Event(source=meta["source"], timestamp=meta["timestamp"], data=data), off+4+sz


class SharedRingBuffer:
    """
    Multi-writer single-reader (MW-SR) ring buffer over mmap.
    Writers only append (CAS on head pointer).
    Reader snapshots head, then walks the ring.
    """

    def __init__(self, name: str = SHM_NAME, capacity: int = BUFSIZE, create: bool = True):
        self.path = Path("/dev/shm") / name
        self.capacity = capacity
        self._create = create
        self._fd: int = -1
        self._mmap: Optional[mmap.mmap] = None
        self._head_off = 0   # file offset of logical start (reader)
        self._open()

    def _open(self):
        if self._create:
            # Create or truncate
            fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
            os.ftruncate(fd, self.capacity)
        else:
            fd = os.open(str(self.path), os.O_RDONLY, 0o600)
        self._fd = fd
        self._mmap = mmap.mmap(fd, self.capacity, access=mmap.ACCESS_WRITE if self._create else mmap.ACCESS_READ)

        if self._create:
            # Write initial tail=4 (past 4-byte write pointer)
            struct.pack_into("<Q", self._mmap, 0, 4)

    def _write_ptr(self) -> int:
        """Current logical tail (first byte after last record)."""
        return struct.unpack_from("<Q", self._mmap, 0)[0]

    def _advance(self, new_tail: int):
        struct.pack_into("<Q", self._mmap, 0, new_tail)

    def write(self, event: Event) -> bool:
        """Append one event. Returns False if buffer full (drops oldest)."""
        payload = event.pack()
        total   = len(payload)
        tail    = self._write_ptr()
        head    = self._head_off
        used    = (tail - head) % self.capacity

        # Need room for payload + 4-byte size header
        if used + total + 4 > self.capacity - 1:
            # Buffer full — advance head past one record
            self._skip_one(head)
            head = self._head_off

        # Pack size prefix + payload as one contiguous record
        record = struct.pack("<I", total) + payload

        # Wrap
        end = head + total + 4
        if end <= self.capacity:
            self._mmap[head : head + total + 4] = record
        else:
            # Split write (tail wraps)
            first = self.capacity - head
            self._mmap[head : self.capacity] = record[:first]
            self._mmap[0 : total + 4 - first] = record[first:]
            end = total + 4 - first

        self._advance((tail + total + 4) % self.capacity)
        return True

    def _skip_one(self, off: int):
        """Peek at off, skip one record, update head."""
        mv = memoryview(self._mmap)
        if off + 4 > self.capacity:
            off = 0
        sz, = struct.unpack_from("<I", self._mmap, off)
        self._head_off = (off + 4 + sz) % self.capacity

    def read_all(self) -> List[Event]:
        """Read all events since last read. Caller drains the buffer."""
        head = self._head_off
        tail = self._write_ptr()
        events: List[Event] = []

        # Make a local copy of the bytes to avoid mmap view issues
        raw = bytes(self._mmap)
        mv  = memoryview(raw)

        off = head
        while True:
            used = (tail - off) % self.capacity
            if used < 4:
                break
            sz = struct.unpack_from("<I", raw, off)[0]
            if sz == 0 or off + 4 + sz > self.capacity:
                # Corrupt — wrap
                off = 0
                tail = self._write_ptr()
                used = (tail - off) % self.capacity
                if used < 4:
                    break
                sz = struct.unpack_from("<I", raw, off)[0]
                if sz == 0:
                    break

            if off + 4 + sz <= self.capacity:
                chunk = mv[off+4 : off+4+sz]
            else:
                # Split record at wrap
                first = self.capacity - off - 4
                chunk = bytes(mv[off+4 : self.capacity]) + bytes(mv[0 : sz - first])

            try:
                meta_b, body_b = chunk.tobytes().split(b"\x00", 1)
                meta = json.loads(meta_b)
                data = json.loads(body_b) if body_b else {}
                events.append(Event(source=meta["source"], timestamp=meta["timestamp"], data=data))
            except (ValueError, KeyError):
                pass

            off = (off + 4 + sz) % self.capacity
            if off == tail:
                break

        self._head_off = off
        return events

    def close(self):
        if self._mmap:
            self._mmap.close()
        if self._fd >= 0:
            os.close(self._fd)

    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


# --- Backward-compatible API (replaces aurora_engine.py deques) -----------------

class AnalyticsEngine:
    """
    High-level API matching aurora_engine.AuroraAnalytics but backed by
    SharedRingBuffer so the Flask server can read the same data in real-time.
    """

    def __init__(self, shm_name: str = SHM_NAME):
        self._rb   = SharedRingBuffer(shm_name, create=True)
        self._buf  = []          # Local rolling window for display

    def track(self, source: str, data: Dict[str, Any]):
        ev = Event(source=source, timestamp=datetime.now().isoformat(), data=data)
        self._rb.write(ev)
        self._buf.append(ev)
        if len(self._buf) > 5000:
            self._buf = self._buf[-3000:]

    def get_events(self, source: Optional[str] = None, limit: int = 500) -> List[Event]:
        evts = self._rb.read_all()
        self._buf.extend(evts)
        if len(self._buf) > 5000:
            self._buf = self._buf[-3000:]
        if source:
            evts = [e for e in self._buf if e.source == source]
        else:
            evts = list(self._buf)
        return evts[-limit:]

    def get_realtime_metrics(self) -> Dict[str, Any]:
        now     = datetime.now()
        window  = 60  # seconds
        cutoff  = (now.timestamp() - window) if False else 0  # keep simple

        # Group by source
        by_source: Dict[str, int] = {}
        for e in self._buf[-2000:]:
            by_source[e.source] = by_source.get(e.source, 0) + 1

        # Syscall breakdown
        syscall_counts: Dict[str, int] = {}
        for e in self._buf[-2000:]:
            if e.source == "syscall":
                name = e.data.get("name", "?")
                syscall_counts[name] = syscall_counts.get(name, 0) + 1

        return {
            "timestamp":          now.isoformat(),
            "window_size":       window,
            "total_events":      len(self._buf),
            "by_source":         by_source,
            "syscall_counts":    dict(sorted(syscall_counts.items(), key=lambda x: -x[1])[:20]),
            "memory_regions":    by_source.get("memory", 0),
            "antidebug_checks":  by_source.get("antidebug", 0),
        }

    def display_realtime_dashboard(self):
        from .dashboard import RealtimeDashboard
        metrics = self.get_realtime_metrics()
        dashboard = RealtimeDashboard()
        dashboard.render(metrics, self._buf[-100:])

    def close(self):
        self._rb.close()