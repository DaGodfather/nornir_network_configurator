# src/actions/audit_ntp.py
# Python 3.6+ / Nornir 2.5

"""
Audit NTP configuration/status and return a per-host row for your summary table.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<captured CLI text>)

Behavior:
1) Choose a concise, platform-aware config grep for NTP.
2) If the grep returns nothing, fall back to an operational command
   (e.g., 'show ntp associations' / 'show ntp peers') to provide useful context.
3) Put the captured text into `info`. If still empty, set status=FAIL.
"""

from utils.cisco_commands import *
from utils.juniper_commands import *
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command

# --------------------------- Platform helpers ---------------------------

def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos")


def _pick_ntp_config_cmd(platform):
    """
    Return a concise config-focused command that lists NTP peers/servers.
    """
    if _is_juniper(platform):
        # Only NTP stanza, easy to read/log.
        return "show configuration system ntp | display set"
    if _is_cisco(platform):
        # Anchor at line start to avoid noise.
        return "show run | i ^ntp server|^ntp peer|^ntp pool"
    # Fallback: generic Cisco-ish grep
    return "show run | i ntp server|ntp peer|ntp pool"


def _pick_ntp_operational_fallback(platform):
    """
    If config grep turns up empty, try an operational command so we still return
    something informative (status/associations).
    """
    if _is_juniper(platform):
        # Junos operational NTP
        return "show ntp associations"
    if _is_cisco(platform):
        # IOS/NX-OS—one of these usually works; Netmiko will run the string as-is.
        # We try 'associations' first; 'peers' is common on NX-OS.
        # Note: we execute only ONE fallback; pick the most universal for your fleet.
        return "show ntp associations"
    # Fallback, try the most common
    return "show ntp associations"


def _extract_text(nr_result):
    """
    Nornir may give a MultiResult; Netmiko returns a Result.
    Return plain text either way.
    """
    out = getattr(nr_result, "result", None)
    if isinstance(out, str):
        return out
    try:
        return nr_result[0].result
    except Exception:
        return ""


# ------------------------------- Action --------------------------------

def run(task: Task, pm=None) -> Result:
    """
    Entry point required by app_main.py.
    Executes an NTP audit and returns a row dict in Result.result.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname

    # 1) Try concise config grep
    cfg_cmd = _pick_ntp_config_cmd(platform)
    r1 = task.run(task=netmiko_send_command, command_string=cfg_cmd, name="NTP config grep")
    text = (_extract_text(r1) or "").strip()

    # 2) If empty, try an operational fallback for visibility
    if not text:
        op_cmd = _pick_ntp_operational_fallback(platform)
        r2 = task.run(task=netmiko_send_command, command_string=op_cmd, name="NTP operational")
        text = (_extract_text(r2) or "").strip()

    # 3) Decide status & build the row
    status = "OK" if text else "FAIL"
    info_text = text if text else "No NTP lines returned"

    # Progress UI (if pm is a real manager in your setup)
    if pm is not None:
        try:
            pm.advance(host=host)
            pm.update(host=host, description="Completed")
        except Exception:
            pass
    
    """
    This section is for reporting and requires to send back a dictionary. The following format must be returned

    Example:
    rows = [
    {"device": "edge1", "ip": "192.0.2.11", "platform": "cisco_ios", "model": "ISR4431", "status": "OK", "info": "NTP present"},
    {"device": "jnp-qfx1", "ip": "192.0.2.21", "platform": "juniper_junos", "model": "QFX5120", "status": "FAIL", "info": "No ntp server"},
    ]
    """

    # Build your row
    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),  # keep if you populate it elsewhere
        "status": status,
        "info": info_text,
    }

    return Result(host=task.host, changed=False, result=row)
