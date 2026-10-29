# Sentinel SOC Triage Demo

A student-sized security operations demo showing the flow **Detect → Classify → Dashboard → Act → Track**. It uses CIC-IDS2017 network-flow rows, a Random Forest for attack classification, an Isolation Forest trained on BENIGN flows, SQLite for cases and history, and a plain HTML/CSS/JavaScript dashboard.

## Architecture

```text
CIC-IDS2017 CSVs
      │
      ├── ml/train.py ── Random Forest + BENIGN Isolation Forest
      │                         │
      └──────────────── backend/simulator.py (replay / burst)
                                │
                       risk score → SQLite
                                │
        browser ← FastAPI (login, alerts, action, explain, stats)
                                │
                   history timeline + dashboard
```

## Setup

Use Python 3.10 or newer. Keep the supplied CSV files under `data/` (the provided `data/MachineLearningCSV/MachineLearningCVE/` works).

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python ml/train.py
```

On Windows PowerShell, start with `.\run.bat` from the project folder (the `.` prefix tells PowerShell to run the script in the current folder). In Command Prompt, use `run.bat`; on macOS/Linux, run `sh run.sh`. The server listens on http://127.0.0.1:8000. Open `/login.html` if the dashboard does not redirect automatically. The first server start creates `backend/soc.db` and seeds the demo users.

Optional LLM explanations: copy `.env.example` to `.env`, set `LLM_API_KEY`, and adjust `LLM_MODEL` and `LLM_BASE_URL` for an OpenAI-compatible chat-completions provider. Explanations are generated only after clicking the button. If the key is absent or the provider is unavailable, a local explanation template is used.

## Demo accounts

- Analyst: `analyst` / `analyst123`
- Admin: `admin` / `admin123`

These are demo credentials. Change them before any use beyond a local classroom demonstration.

## Five-minute demo

1. Sign in as `analyst` and point out the risk summary, charts, filters, and live dataset replay.
2. Click **Simulate attack**, choose `DoS`, and show the new alert at the top of the queue.
3. Open the case. Explain the classifier confidence, anomaly signal, risk band, and top contributing flow features.
4. Click **Explain this alert**. The no-key fallback still gives a junior analyst next steps; with a configured provider the on-demand explanation is cached.
5. Add a short note and choose **Investigate** or **Block IP**. Confirm the dialog, then show the changed status and timeline entry. Emphasize that the action is logged only and never touches a firewall or host.

## Model and risk details

The trainer prints the actual CSV headers and source label counts. It merges CIC labels into BENIGN, DoS (including DDoS), PortScan, BruteForce (Patator and web brute force), and WebAttack (web XSS and SQL injection). Unsupported labels such as Bot and Infiltration are left out. Each source CSV contributes a bounded class sample; invalid/infinite rows, duplicates, and constant features are removed. Metrics include accuracy, per-class precision/recall/F1, support, and a confusion matrix in `ml/metrics.json`.

Risk is a weighted demo score: 35% classifier confidence, 40% attack severity, and 25% normalized anomaly. Bands are Critical (80+), High (60–79), Medium (40–59), and Low (under 40). It is a triage aid, not a production security decision.

## Optional live Windows mode

The default remains dataset simulation. To use events from this Windows PC, configure Windows Defender Firewall logging first. In an elevated PowerShell window, enable allowed and dropped connection logs:

```powershell
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging droppedconnections enable
```

Windows documents the default file as `%windir%\system32\logfiles\firewall\pfirewall.log`; logging must be enabled for events to appear. See Microsoft's [firewall logging guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging).

Copy `.env.example` to `.env`, then enable live monitoring:

```dotenv
SOC_MODE=live
WINDOWS_FIREWALL_LOG=C:\Windows\System32\LogFiles\Firewall\pfirewall.log
ENABLE_REAL_BLOCKING=true
```

Restart `run.bat` from an Administrator PowerShell window and sign in with `admin` / `admin123` for firewall rule controls. Live mode tails new firewall log entries, groups repeated contacts by remote IP and service port, and raises heuristic alerts after repeated allowed/blocked events. Windows firewall logs don't contain the CIC flow features, so live alerts use these transparent repeat-count signals instead of the trained Random Forest. The monitor skips old entries present when it starts.

For a live alert, **Block IP** asks for confirmation and then adds inbound and outbound Windows Defender Firewall rules for that single remote address. It applies to all matching traffic on this PC. **Remove firewall block** removes the rules created for that alert. The app refuses real blocking when running in dataset mode, when the alert isn't from the live log, for special-purpose addresses, or when Windows rejects the operation. The server process needs administrator rights; keep `ENABLE_REAL_BLOCKING=false` to use read-only live monitoring. Microsoft documents the [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) command and its `-RemoteAddress` behavior.

Returning to the default demo only requires removing `SOC_MODE=live` or setting it to `simulation`, then restarting the server. The app never enables Windows logging or adds a firewall rule without your explicit setup and button confirmation.

## Smoke check

Run `python tests/smoke_test.py`. It trains a smaller model from the local dataset, then checks login, alert listing/filtering, case details, simulated burst, action, explanation, history, static dashboard, and statistics through the API test client.

## Limitations

- This is a classroom demo using a lab dataset, not live enterprise telemetry.
- IP addresses are generated for display; the flow dataset does not provide the real endpoints used here.
- Response actions only change SQLite status and history. They never block network traffic, isolate machines, or call a security appliance.
- Classifier quality on a dataset split does not guarantee performance on new environments; CIC labels are merged and rare categories are omitted.
- LLM output can be wrong. It is optional, advisory, limited to explanation, and never controls scores, status, or response actions.
- Tokens are in memory and expire when the process restarts; this is not production authentication.
