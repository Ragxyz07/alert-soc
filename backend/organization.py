"""Self-contained fictional manufacturing network for safe SOC demonstrations."""
from backend import db
from backend.risk import risk_band, risk_score

ORGANIZATION = {
    "name": "Northstar Manufacturing",
    "sector": "Industrial manufacturing",
    "environment": "Fictional training network",
    "boundary": "All addresses and events are synthetic. No devices are contacted.",
    "assets": [
        {"id": "NS-DC-01", "name": "Identity server", "ip": "10.42.10.10", "zone": "Corporate", "criticality": "Critical"},
        {"id": "NS-ERP-01", "name": "ERP web gateway", "ip": "10.42.20.20", "zone": "Business apps", "criticality": "High"},
        {"id": "NS-HMI-07", "name": "Production HMI", "ip": "10.42.30.7", "zone": "OT production", "criticality": "Critical"},
        {"id": "NS-FS-02", "name": "Engineering file server", "ip": "10.42.40.12", "zone": "Engineering", "criticality": "High"},
        {"id": "NS-SOC-WS-04", "name": "SOC analyst workstation", "ip": "10.42.50.44", "zone": "Security operations", "criticality": "Medium"},
    ],
}

SCENARIOS = {
    "port_scan": {
        "label": "External port scan",
        "attack": "PortScan",
        "source": "198.51.100.27",
        "asset": "NS-FS-02",
        "port": 445,
        "protocol": "TCP",
        "confidence": .97,
        "anomaly": .94,
        "events": [
            ("Connection probe", 22, "Blocked", "SSH service probe"),
            ("Connection probe", 139, "Blocked", "NetBIOS service probe"),
            ("Connection probe", 445, "Observed", "SMB service probe"),
            ("Connection probe", 3389, "Blocked", "Remote desktop service probe"),
            ("Connection probe", 1433, "Blocked", "Database service probe"),
        ],
        "summary": "Five service probes were detected against the engineering file server.",
    },
    "credential_attack": {
        "label": "Repeated sign-in failures",
        "attack": "BruteForce",
        "source": "203.0.113.53",
        "asset": "NS-DC-01",
        "port": 3389,
        "protocol": "TCP",
        "confidence": .95,
        "anomaly": .91,
        "events": [
            ("Authentication failure", 3389, "Denied", f"RDP sign-in attempt {index + 1} of 6")
            for index in range(6)
        ],
        "summary": "Six failed remote sign-in attempts were detected against the identity server.",
    },
    "ot_probe": {
        "label": "OT protocol probe",
        "attack": "PortScan",
        "source": "192.0.2.81",
        "asset": "NS-HMI-07",
        "port": 502,
        "protocol": "TCP",
        "confidence": .92,
        "anomaly": .89,
        "events": [
            ("Industrial protocol probe", 502, "Observed", f"Modbus service discovery {index + 1} of 4")
            for index in range(4)
        ],
        "summary": "Repeated Modbus discovery probes were detected at the production HMI boundary.",
    },
    "web_flood": {
        "label": "ERP web traffic surge",
        "attack": "DoS",
        "source": "198.51.100.73",
        "asset": "NS-ERP-01",
        "port": 443,
        "protocol": "TCP",
        "confidence": .93,
        "anomaly": .96,
        "events": [
            ("Request rate spike", 443, "Rate limited", f"Synthetic request burst {index + 1} of 8")
            for index in range(8)
        ],
        "summary": "A synthetic request-rate surge was detected at the ERP web gateway.",
    },
}

ASSET_BY_ID = {asset["id"]: asset for asset in ORGANIZATION["assets"]}


def run_drill(scenario_id: str):
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        raise ValueError("Choose one of the available organization drills")
    asset = ASSET_BY_ID[scenario["asset"]]
    score = risk_score(scenario["confidence"], scenario["attack"], scenario["anomaly"])
    alert = {
        "src_ip": scenario["source"], "dst_ip": asset["ip"],
        "src_port": 53000, "dst_port": scenario["port"],
        "protocol": scenario["protocol"], "attack_type": scenario["attack"],
        "confidence": scenario["confidence"], "anomaly_score": scenario["anomaly"],
        "risk_score": score, "risk_band": risk_band(score),
        "source": "organization-simulation",
        "source_detail": f"Synthetic {scenario['label'].lower()} drill in Northstar Manufacturing demo network.",
        "top_features": [
            {"name": "Scenario", "contribution": 1.0},
            {"name": "Target asset criticality", "contribution": .88 if asset["criticality"] == "Critical" else .72},
            {"name": "Correlated security events", "contribution": min(1.0, len(scenario["events"]) / 8)},
            {"name": "Observed service port", "contribution": .68},
        ],
    }
    alert_id = db.add_alert(alert)
    events = []
    for event_type, port, outcome, details in scenario["events"]:
        events.append({
            "event_type": event_type,
            "severity": alert["risk_band"],
            "source_ip": scenario["source"],
            "destination_ip": asset["ip"],
            "destination_port": port,
            "asset_id": asset["id"],
            "outcome": outcome,
            "details": details,
            "alert_id": alert_id,
        })
    db.add_security_events(events)
    return {"alert_id": alert_id, "created_events": len(events), "scenario": scenario["label"], "summary": scenario["summary"]}


def recent_events(limit=40):
    events = db.rows(
        "SELECT id,created_at,event_type,severity,source_ip,destination_ip,destination_port,asset_id,outcome,details,alert_id "
        "FROM security_events ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 100)),)
    )
    return events
