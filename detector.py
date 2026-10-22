
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock


class IntrusionDetector:
    """Detect suspicious patterns in network events."""

    def __init__(self, port_scan_threshold=10, window_seconds=60):
        self.port_scan_threshold = port_scan_threshold
        self.window_seconds = window_seconds
        self._connections = defaultdict(deque)
        self._alerts = []
        self._lock = Lock()

    def analyze_event(self, event):
        """Analyze a normalized network event and return any alert."""
        src_ip = str(event.get("src_ip", "unknown"))
        dst_ip = str(event.get("dst_ip", "unknown"))
        protocol = str(event.get("protocol", "UNKNOWN")).upper()

        try:
            dst_port = int(event.get("dst_port", 0))
        except (ValueError, TypeError):
            dst_port = 0

        if not (0 <= dst_port <= 65535):
            return None

        now = datetime.now(timezone.utc).timestamp()
        alert = None

        with self._lock:
            history = self._connections[src_ip]

            while history and now - history[0][0] > self.window_seconds:
                history.popleft()

            if dst_port > 0:
                history.append((now, dst_port))

            unique_ports = len({port for _, port in history})

            if unique_ports >= self.port_scan_threshold:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "HIGH",
                    "type": "Possible Port Scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "dst_port": dst_port,
                    "description": (
                        f"{unique_ports} unique destination ports "
                        f"observed from {src_ip} within "
                        f"{self.window_seconds} seconds."
                    ),
                }

                self._alerts.append(alert)

        return alert

    def get_alerts(self):
        """Return a copy of recorded alerts."""
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self):
        """Clear stored alerts."""
        with self._lock:
            self._alerts.clear()
