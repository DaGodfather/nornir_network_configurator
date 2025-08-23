# src/actions/audit_ntp.py
# Python 3.6+ / Nornir 2.5

from utils.cisco_commands import *
from utils.juniper_commands import *
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command


def _is_juniper(platform: str) -> bool:
    if not platform:
        return False
    p = platform.lower()
    return p in ("junos", "juniper")


def _is_cisco(platform: str) -> bool:
    if not platform:
        return False
    p = platform.lower()
    # Treat common Cisco platforms as “Cisco” for this audit
    return p.startswith("ios") or p in ("ios", "iosxe", "iosxr", "nxos", "cisco")


def run(task: Task, pm) -> Result:
    """
    Audit NTP configuration.
      - Cisco:   'show run | i ntp server'
      - Juniper: 'show configuration | display json'
    Returns the device's raw CLI output as the Result.result string.
    """
    host = task.host.name
    platform = (task.host.platform or "").lower()

    # Progress: set row text, then run, then advance
    pm.update(host=host, description="Auditing NTP")

    if _is_juniper(platform):
        cmd = "show configuration | display json"  # full keyword is safest
    elif _is_cisco(platform):
        cmd = "show run | i ntp server"
    else:
        # Fallback: default to Cisco syntax (common in many shops)
        cmd = "show run | i ntp server"

    # Execute command
    r = task.run(task=netmiko_send_command, command_string=cmd, name=f"{host}: {cmd}")

    # Nornir returns a Result; in rare cases a MultiResult—handle both safely
    out = getattr(r, "result", None)
    if out is None and hasattr(r, "__getitem__"):
        try:
            out = r[0].result
        except Exception:
            out = ""

    pm.advance(host=host)
    pm.update(host=host, description="Completed")

    return Result(host=task.host, changed=False, result=out or "")
