#!/usr/bin/env python3
"""
Aurora RealTime Analytics — Flask Web Server
Serves the dashboard UI and exposes REST API endpoints for:
  - /api/dashboard   — unified metrics + all source data
  - /api/syscalls    — syscall stats + SSN table
  - /api/memory      — memory scanner results + offset DB
  - /api/antidebug   — anti-debug status + detection results
  - /api/events      — raw event stream (SSE)
"""

from flask import Flask, jsonify, send_file, Response
from flask_cors import CORS
import threading, time, sys, os

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aurora import (
    SyscallMonitor, MemoryScanner, AntiDebugMonitor,
    AnalyticsEngine, RealtimeDashboard,
)
from aurora.core.shared import SharedRingBuffer

app = Flask(__name__, static_folder="../web", static_url_path="")
CORS(app)

# ── Shared engine (writer: monitors write here; server reads here) ───────────────
_engine = AnalyticsEngine()

_sc_mon  = SyscallMonitor()
_mem_mon = MemoryScanner()
_ad_mon  = AntiDebugMonitor()

_running = False
_thread: threading.Thread = None


def _collect_loop(interval: float = 0.5):
    """Background thread: run all monitors and push events to the ring buffer."""
    t_last_mem = 0
    t_last_ad  = 0
    while _running:
        # Syscall analytics
        try:
            sc_analytics = _sc_mon.get_analytics()
            _engine.track("syscall", sc_analytics)
        except Exception as e:
            pass

        # Memory scan every 10s
        t_now = time.time()
        if t_now - t_last_mem >= 10:
            t_last_mem = t_now
            try:
                _mem_mon.scan_all()
                _engine.track("memory", _mem_mon.get_analytics())
            except Exception as e:
                pass

        # Anti-debug check every 2s
        if t_now - t_last_ad >= 2:
            t_last_ad = t_now
            try:
                _ad_mon.check_all()
                _engine.track("antidebug", _ad_mon.get_analytics())
            except Exception:
                pass

        time.sleep(interval)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file("../web/index.html")


@app.route("/api/dashboard")
def api_dashboard():
    """Unified dashboard payload."""
    return jsonify({
        "metrics":   _engine.get_realtime_metrics(),
        "syscalls":  _sc_mon.get_analytics(),
        "memory":    _mem_mon.get_analytics(),
        "antidebug": _ad_mon.get_analytics(),
        "ssn_table": _sc_mon.get_ssn_table(),
    })


@app.route("/api/syscalls")
def api_syscalls():
    return jsonify(_sc_mon.get_analytics())


@app.route("/api/syscalls/top")
def api_syscalls_top():
    top = _sc_mon.get_top_syscalls(20)
    return jsonify({
        "top": [
            {"name": n, "ssn": hex(s.ssn), "count": s.call_count,
             "avg_us": round(s.avg_us, 4), "errors": s.errors}
            for n, s in top
        ]
    })


@app.route("/api/syscalls/table")
def api_ssn_table():
    return jsonify(_sc_mon.get_ssn_table())


@app.route("/api/memory")
def api_memory():
    return jsonify(_mem_mon.get_analytics())


@app.route("/api/memory/scan", methods=["POST"])
def api_memory_scan():
    """Trigger a new memory scan."""
    try:
        _mem_mon.scan_all()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(_mem_mon.get_analytics())


@app.route("/api/memory/offsets")
def api_offsets():
    return jsonify(_mem_mon.get_offset_db())


@app.route("/api/antidebug")
def api_antidebug():
    return jsonify(_ad_mon.get_analytics())


@app.route("/api/antidebug/status")
def api_antidebug_status():
    return jsonify(_ad_mon.get_current_status())


@app.route("/api/antidebug/checks")
def api_antidebug_checks():
    """Run all checks on demand."""
    _ad_mon.check_all()
    return jsonify(_ad_mon.get_analytics())


@app.route("/api/events")
def api_events():
    """Server-Sent Events stream of raw events."""
    def generate():
        last_idx = 0
        while True:
            events = _engine.get_events(limit=50)
            new_events = events[last_idx:]
            last_idx = len(events)
            for ev in new_events:
                import json
                yield f"data: {json.dumps({'source': ev.source, 'data': ev.data})}\n\n"
            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/metrics")
def api_metrics():
    return jsonify(_engine.get_realtime_metrics())


# ── Startup / Shutdown ────────────────────────────────────────────────────────

def start(background: bool = True):
    global _running, _thread

    # Start Flask in background
    if background:
        import threading
        t = threading.Thread(target=lambda: app.run(
            host="0.0.0.0", port=5000, debug=False, use_reloader=False),
                             daemon=True)
        t.start()
        _running = True
        _thread = threading.Thread(target=_collect_loop, daemon=True)
        _thread.start()
        print("Aurora server running at http://localhost:5000")
    else:
        _running = True
        _thread = threading.Thread(target=_collect_loop, daemon=True)
        _thread.start()
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    start(background=False)
