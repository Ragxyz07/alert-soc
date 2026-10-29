"""Opt-in Windows Firewall controls for analyst-confirmed single-IP blocks."""
import ipaddress
import os
import subprocess
import socket
from functools import lru_cache

@lru_cache(maxsize=1)
def _local_ips():
    try:
        return {item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None)}
    except OSError:
        return set()

def settings():
    mode = os.getenv("SOC_MODE", "simulation").strip().lower()
    if mode not in {"simulation", "live"}:
        mode = "simulation"
    path = os.getenv("WINDOWS_FIREWALL_LOG", r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
    return {
        "mode": mode,
        "real_blocking_enabled": os.getenv("ENABLE_REAL_BLOCKING", "false").strip().lower() == "true",
        "live_log_configured": mode == "live" and os.path.isfile(os.path.expandvars(path)),
        "log_path": os.path.expandvars(path),
    }

def validate_remote_ip(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("The alert does not contain one valid IP address") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local or address.is_reserved:
        raise ValueError("Refusing to block a special-purpose IP address")
    # Avoid accidentally blocking the computer running this demo.
    if str(address) in _local_ips():
        raise ValueError("Refusing to block this computer's own IP address")
    return str(address)

def _powershell(script):
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Windows Firewall command timed out") from exc
    if result.returncode:
        reason = (result.stderr or result.stdout or "Windows Firewall rejected the rule").strip()
        raise RuntimeError(reason[-500:])

def block_ip(value, alert_id):
    if os.name != "nt":
        raise RuntimeError("Real blocking is available only on Windows")
    address = validate_remote_ip(value)
    group = f"SOC Triage Alert {int(alert_id)}"
    safe_group = group.replace("'", "''")
    safe_address = address.replace("'", "''")
    # Both directions stop the selected remote address from sending to or receiving from this PC.
    script = f"""
$ErrorActionPreference = 'Stop'
$group = '{safe_group}'
$address = '{safe_address}'
if (Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue) {{ exit 0 }}
try {{
  New-NetFirewallRule -DisplayName ($group + ' inbound') -Group $group -Direction Inbound -Action Block -RemoteAddress $address -Profile Any | Out-Null
  New-NetFirewallRule -DisplayName ($group + ' outbound') -Group $group -Direction Outbound -Action Block -RemoteAddress $address -Profile Any | Out-Null
}} catch {{
  Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Write-Error $_
  exit 1
}}
"""
    _powershell(script)
    return group

def unblock_ip(alert_id):
    if os.name != "nt":
        raise RuntimeError("Real blocking is available only on Windows")
    group = f"SOC Triage Alert {int(alert_id)}"
    _powershell(f"Get-NetFirewallRule -Group '{group}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
    return group
