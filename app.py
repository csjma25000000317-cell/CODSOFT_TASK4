
from flask import Flask, render_template, jsonify, request
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
import csv
import io

from detector import IntrusionDetector
from config import APP_NAME, APP_VERSION, PORT, LOG_DIR, REPORT_DIR

app = Flask(__name__)
detector = IntrusionDetector()
events = []
event_lock = Lock()

Path(LOG_DIR).mkdir(exist_ok=True)
Path(REPORT_DIR).mkdir(exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html", app_name=APP_NAME)


@app.route("/api/status")
def status():
    with event_lock:
        total = len(events)
        protocols = {}
        for event in events:
            proto = event["protocol"]
            protocols[proto] = protocols.get(proto, 0) + 1

    return jsonify({
        "app": APP_NAME,
        "version": APP_VERSION,
        "status": "ready",
        "monitoring": False,
        "total_events": total,
        "total_alerts": len(detector.get_alerts()),
        "protocols": protocols,
    })


@app.route("/api/events")
def get_events():
    with event_lock:
        return jsonify(list(reversed(events[-200:])))


@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(reversed(detector.get_alerts()[-200:])))


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}

    src_ip = str(data.get("src_ip", "")).strip()
    dst_ip = str(data.get("dst_ip", "")).strip()
    protocol = str(data.get("protocol", "TCP")).upper()

    if not src_ip or not dst_ip:
        return jsonify({"error": "Source and destination IP are required"}), 400

    if protocol not in {"TCP", "UDP", "ICMP"}:
        return jsonify({"error": "Unsupported protocol"}), 400

    try:
        dst_port = int(data.get("dst_port", 0))
    except (ValueError, TypeError):
        return jsonify({"error": "Destination port must be a number"}), 400

    if not 0 <= dst_port <= 65535:
        return jsonify({"error": "Port must be between 0 and 65535"}), 400

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "dst_port": dst_port,
        "source": "manual-test",
    }

    alert = detector.analyze_event(event)

    with event_lock:
        events.append(event)
        if len(events) > 1000:
            del events[:-1000]

    return jsonify({
        "message": "Event analyzed",
        "event": event,
        "alert": alert,
    })


@app.route("/api/export")
def export_events():
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["timestamp", "src_ip", "dst_ip",
                    "protocol", "dst_port", "source"]
    )
    writer.writeheader()

    with event_lock:
        writer.writerows(events)

    return (
        output.getvalue(),
        200,
        {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": "attachment; filename=sentinel-events.csv",
        },
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
