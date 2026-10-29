"""Tail Windows Defender Firewall logs and make triage alerts from repeated events."""
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from backend.db import add_alert
from backend.firewall import settings
from backend.risk import risk_score, risk_band

class LiveFirewallMonitor:
    # Common remote services worth reviewing when repeated connections are allowed.
    WATCH_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5900}

    def __init__(self):
        self.thread = None
        self.running = False
        self.offset = 0
        self.fields = []
        self.file_key = None
        self.initialized = False
        self.attempts = defaultdict(deque)
        self.last_alert = {}

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True, name="windows-firewall-monitor")
        self.thread.start()

    def _loop(self):
        while self.running:
            try:
                self.read_new_lines()
            except Exception as exc:
                print("Live firewall monitor:", exc)
            time.sleep(1.5)

    def read_new_lines(self):
        path = Path(os.path.expandvars(settings()["log_path"]))
        if not path.is_file():
            return
        stat = path.stat()
        key = (str(path.resolve()), stat.st_ino)
        if not self.initialized:
            # Read the column header, then begin at the end so old entries aren't replayed.
            with path.open("r", encoding="utf-8", errors="replace") as log:
                for line in log:
                    if line.startswith("#Fields:"):
                        self.fields = line[len("#Fields:"):].split()
                        break
            self.file_key = key
            self.offset = stat.st_size
            self.initialized = True
            return
        if key != self.file_key or stat.st_size < self.offset:
            self.file_key = key
            self.offset = 0
            self.fields = []
        with path.open("r", encoding="utf-8", errors="replace") as log:
            log.seek(self.offset)
            for line in log:
                self.process_line(line)
            self.offset = log.tell()

    def process_line(self, line):
        line = line.strip()
        if not line:
            return None
        if line.startswith("#Fields:"):
            self.fields = line[len("#Fields:"):].split()
            return None
        if line.startswith("#") or not self.fields:
            return None
        values = line.split()
        if len(values) < len(self.fields):
            return None
        row = dict(zip(self.fields, values))
        action = row.get("action", "").upper()
        direction = row.get("path", "").upper()
        if action not in {"ALLOW", "DROP"}:
            return None
        try:
            local_port = int(row.get("dst-port", "0"))
            remote_port = int(row.get("src-port", "0"))
            if direction == "SEND":
                remote_ip, local_ip = row.get("dst-ip", ""), row.get("src-ip", "")
                alert_src_port, alert_dst_port = local_port, remote_port
            else:  # RECEIVE or older log without a path value
                remote_ip, local_ip = row.get("src-ip", ""), row.get("dst-ip", "")
                alert_src_port, alert_dst_port = remote_port, local_port
            service_port = local_port
            remote_port_int = int(remote_port)
        except ValueError:
            return None
        from backend.firewall import validate_remote_ip
        try:
            remote_ip = validate_remote_ip(remote_ip)
        except ValueError:
            return None

        now = time.time()
        key = (remote_ip, service_port)
        bucket = self.attempts[key]
        bucket.append(now)
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        # A suspicious service needs three allowed contacts; other ports need five.
        threshold = 3 if service_port in self.WATCH_PORTS else 5
        if action == "ALLOW" and len(bucket) < threshold:
            return None
        if action == "DROP" and len(bucket) < 3:
            return None
        if now - self.last_alert.get(key, 0) < 300:
            return None
        self.last_alert[key] = now

        attack = "Blocked Firewall Traffic" if action == "DROP" else "Repeated Connection Attempts"
        confidence = min(.98, .65 + .06 * len(bucket))
        anomaly = min(.98, .60 + .07 * len(bucket))
        score = risk_score(confidence, attack, anomaly)
        created_status = "Contained" if action == "DROP" else "New"
        return add_alert({
            "src_ip": remote_ip, "dst_ip": local_ip,
            "src_port": alert_src_port, "dst_port": alert_dst_port,
            "protocol": {"6":"TCP", "17":"UDP", "1":"ICMP", "58":"ICMPV6"}.get(row.get("protocol", ""), row.get("protocol", "unknown").upper()),
            "attack_type": attack, "confidence": confidence, "anomaly_score": anomaly,
            "risk_score": score, "risk_band": risk_band(score), "status": created_status,
            "source": "windows-firewall-log",
            "source_detail": f"Observed {action} {direction or 'firewall'} traffic from real firewall logs; {len(bucket)} attempts in 60 seconds",
            "top_features": [
                {"name": "Firewall action", "contribution": 1.0 if action == "DROP" else .85},
                {"name": "Remote service port", "contribution": .8 if service_port in self.WATCH_PORTS else .45},
                {"name": "Attempts in last minute", "contribution": min(1.0, len(bucket) / 10)},
                {"name": "Direction", "contribution": .35},
            ],
        })

live_monitor = LiveFirewallMonitor()
