"""Simple risk score for analyst triage."""
SEVERITY = {"BENIGN": 0.15, "WebAttack": 0.65, "PortScan": 0.58,
            "BruteForce": 0.82, "DoS": 0.9, "Repeated Connection Attempts": 0.72,
            "Blocked Firewall Traffic": 0.68}

def risk_score(confidence, attack_type, anomaly_score):
    """Combine confidence, class severity, and normalized anomaly (each 0..1)."""
    anomaly = max(0.0, min(1.0, float(anomaly_score)))
    confidence = max(0.0, min(1.0, float(confidence)))
    severity = SEVERITY.get(attack_type, 0.65)
    score = 100 * (0.35 * confidence + 0.40 * severity + 0.25 * anomaly)
    return round(max(0, min(100, score)))

def risk_band(score):
    return "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low"
