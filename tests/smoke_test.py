"""Train a tiny model and check the full API over a local HTTP server."""
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ["PYTHONPATH"] = str(ROOT)
env = os.environ.copy()
env["SOC_SAMPLE_PER_CLASS"] = "300"
env.pop("LLM_API_KEY", None)

if os.getenv("SOC_SKIP_TRAIN") != "1":
    print("Training a small model for the smoke check...", flush=True)
    model_path = ROOT / "ml" / "model.joblib"
    metrics_path = ROOT / "ml" / "metrics.json"
    saved_model = model_path.read_bytes() if model_path.exists() else None
    saved_metrics = metrics_path.read_bytes() if metrics_path.exists() else None
    try:
        subprocess.run([sys.executable, "ml/train.py"], env=env, check=True)
    finally:
        # Keep a user's normal trained model and metrics intact after the tiny test run.
        if saved_model is not None:
            model_path.write_bytes(saved_model)
        if saved_metrics is not None:
            metrics_path.write_bytes(saved_metrics)

from backend import db
from backend.live_monitor import LiveFirewallMonitor

server_env = os.environ.copy()
server_env.pop("LLM_API_KEY", None)
server_env["SOC_MODE"] = "simulation"
server_env["ENABLE_REAL_BLOCKING"] = "false"
server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8765"],
    cwd=ROOT, env=server_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
base = "http://127.0.0.1:8765"
try:
    for _ in range(60):
        try:
            if requests.get(base + "/login.html", timeout=1).status_code == 200:
                break
        except requests.RequestException:
            time.sleep(.5)
    else:
        raise RuntimeError("Local API server did not start")

    db.init_db()
    with db.connect() as conn:
        conn.execute("DELETE FROM history_events")
        conn.execute("DELETE FROM explanations")
        conn.execute("DELETE FROM alerts")
    seed_id = db.add_alert({
        "src_ip": "10.1.2.3", "dst_ip": "192.168.1.5", "src_port": 51515, "dst_port": 443,
        "protocol": "TCP", "attack_type": "DoS", "confidence": .91, "anomaly_score": .88,
        "risk_score": 84, "risk_band": "Critical",
        "top_features": [{"name": "Flow Packets/s", "contribution": .8}],
    })
    monitor = LiveFirewallMonitor()
    monitor.fields = "date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path".split()
    live_line = "2026-10-30 10:00:00 ALLOW 6 8.8.8.8 192.168.1.10 50000 3389 60 - - - - - - - RECEIVE"
    live_id = None
    for _ in range(3):
        live_id = monitor.process_line(live_line)
    assert live_id and db.get_alert(live_id)["source"] == "windows-firewall-log"

    print("Checking login and dashboard...", flush=True)
    login = requests.post(base + "/login", json={"username": "analyst", "password": "analyst123"}, timeout=10)
    assert login.status_code == 200, login.text
    headers = {"Authorization": "Bearer " + login.json()["token"]}
    config = requests.get(base + "/config", headers=headers, timeout=10)
    assert config.status_code == 200 and config.json()["mode"] == "simulation", config.text
    assert requests.get(base + "/", headers=headers, timeout=10).status_code == 200
    assert requests.get(base + "/alerts", headers=headers, timeout=10).status_code == 200
    assert requests.get(base + "/alerts?risk_band=Critical", headers=headers, timeout=10).status_code == 200
    print("Checking alert details, statistics, and simulated burst...", flush=True)
    assert requests.get(base + f"/alerts/{seed_id}", headers=headers, timeout=10).status_code == 200
    assert requests.get(base + "/stats", headers=headers, timeout=10).status_code == 200
    burst = requests.post(base + "/simulate/burst", headers=headers,
                          json={"attack_type": "DoS", "n": 1}, timeout=20)
    assert burst.status_code == 200, burst.text
    print("Checking response action, explanation, and history...", flush=True)
    action = requests.post(base + f"/alerts/{seed_id}/action", headers=headers,
                           json={"action": "investigate", "note": "smoke"}, timeout=10)
    assert action.status_code == 200 and action.json()["status"] == "Investigating", action.text
    safe_action = requests.post(base + f"/alerts/{live_id}/action", headers=headers,
                                json={"action": "block_ip"}, timeout=10)
    assert safe_action.status_code == 200 and "simulated" in safe_action.json()["history"][-1]["details"], safe_action.text
    explanation = requests.post(base + f"/alerts/{seed_id}/explain", headers=headers, timeout=15)
    assert explanation.status_code == 200 and explanation.json()["text"], explanation.text
    detail = requests.get(base + f"/alerts/{seed_id}", headers=headers, timeout=10).json()
    assert len(detail["history"]) >= 3 and detail["explanation"], detail
    print("Smoke check passed: training, server startup, login, dashboard, alert filters/details, burst, live-log parser, simulated block, action, explanation, history, and stats.")
finally:
    server.terminate()
    server.wait(timeout=10)
