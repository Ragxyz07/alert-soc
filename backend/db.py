"""SQLite storage. Connections are short-lived so the simulator thread is safe."""
from pathlib import Path
import json, sqlite3
from datetime import datetime, timezone
from backend.auth import hash_password

DB_PATH = Path(__file__).resolve().parent / "soc.db"
STATUSES = ["New", "Investigating", "Contained", "False Positive", "Escalated", "Closed"]

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def connect():
    db = sqlite3.connect(DB_PATH, timeout=15); db.row_factory = sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); return db

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
          src_port INTEGER, dst_port INTEGER, protocol TEXT, attack_type TEXT, confidence REAL, anomaly_score REAL,
          risk_score INTEGER, risk_band TEXT, status TEXT DEFAULT 'New', assigned_to TEXT, top_features_json TEXT,
          source TEXT DEFAULT 'simulation');
        CREATE TABLE IF NOT EXISTS history_events(id INTEGER PRIMARY KEY, alert_id INTEGER REFERENCES alerts(id), action TEXT,
          performed_by TEXT, details TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS explanations(alert_id INTEGER PRIMARY KEY REFERENCES alerts(id), text TEXT, source TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT);
        """)
        alert_columns = {row[1] for row in db.execute("PRAGMA table_info(alerts)")}
        if "source" not in alert_columns:
            db.execute("ALTER TABLE alerts ADD COLUMN source TEXT DEFAULT 'simulation'")
        for username, password, role in [("analyst", "analyst123", "analyst"), ("admin", "admin123", "admin")]:
            db.execute("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES(?,?,?)", (username, hash_password(password), role))

def add_alert(alert):
    with connect() as db:
        cur = db.execute("""INSERT INTO alerts(created_at,src_ip,dst_ip,src_port,dst_port,protocol,attack_type,confidence,
          anomaly_score,risk_score,risk_band,status,assigned_to,top_features_json,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (now(), alert.get("src_ip"), alert.get("dst_ip"), alert.get("src_port"), alert.get("dst_port"), alert.get("protocol"),
           alert["attack_type"], alert["confidence"], alert["anomaly_score"], alert["risk_score"], alert["risk_band"], alert.get("status", "New"), None,
           json.dumps(alert.get("top_features", [])), alert.get("source", "simulation")))
        aid = cur.lastrowid
        source = alert.get("source", "simulation")
        detail = alert.get("source_detail", f"Detected {alert['attack_type']} traffic (simulated)")
        add_history(aid, "detected", source, detail, db=db)
        return aid

def add_history(alert_id, action, user, details, db=None):
    if db is not None:
        db.execute("INSERT INTO history_events(alert_id,action,performed_by,details,created_at) VALUES(?,?,?,?,?)", (alert_id, action, user, details, now()))
    else:
        with connect() as conn: add_history(alert_id, action, user, details, conn)

def rows(sql, params=()):
    with connect() as db: return [dict(r) for r in db.execute(sql, params).fetchall()]

def get_alert(aid):
    alert = rows("SELECT * FROM alerts WHERE id=?", (aid,))
    if not alert: return None
    a=alert[0]; a["top_features"] = json.loads(a.pop("top_features_json") or "[]")
    a["history"] = rows("SELECT * FROM history_events WHERE alert_id=? ORDER BY id", (aid,))
    e=rows("SELECT text,source,created_at FROM explanations WHERE alert_id=?", (aid,)); a["explanation"] = e[0] if e else None
    return a
