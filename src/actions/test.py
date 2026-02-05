# src/actions/audit_ntp.py
# Python 3.6+ / Nornir 2.5

import time
from src.utils.cisco_commands import *
from src.utils.juniper_commands import *
from nornir.core.task import Task, Result

# Prefer Nornir 2.x builtin task path; fallback to nornir_netmiko if you installed it
try:
    from nornir.plugins.tasks.networking import netmiko_send_command
except Exception:  # pragma: no cover
    from nornir_netmiko.tasks import netmiko_send_command


def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


def _is_cisco(platform):
    p = (platform or "").lower()
    # accept common labels + Netmiko device_types
    return (
        p.startswith("ios")
        or p in ("ios", "iosxe", "iosxr", "nxos", "cisco", "cisco_ios", "cisco_xr", "cisco_nxos")
    )


def _extract_output(run_result) -> str:
    """Handle both Result and MultiResult."""
    if hasattr(run_result, "result") and run_result.result is not None:
        return run_result.result
    try:
        return run_result[0].result
    except Exception:
        return ""


def run(task: Task, pm) -> Result:
    """
    Audit NTP config:
      - Cisco:   'show run | i ntp server'
      - Juniper: 'show configuration | display json'
    Returns raw CLI output as Result.result.
    """

    host = task.host.name
    platform = (task.host.platform or "").lower()

    if _is_juniper(platform):
        cmd = "show configuration | display json"
    else:  # default Cisco-style (covers Cisco + unknowns)
        cmd = "show run | i ntp server"

    failed = False
    out = ""

    try:
        time.sleep(5)
        #print(f"Testing host: {host} with IP: {task.host.hostname}, \twith command: {cmd}")
        
        # res = task.run(task=netmiko_send_command, command_string=cmd, name="{}: {}".format(host, cmd))
        #out = _extract_output(res)
    except Exception as e:
        failed = True
        out = "Command '{}' failed: {}".format(cmd, e)

    """
    This section is for reporting and requires to send back a dictionary. The following format must be returned

    Example:
    rows = [
    {"device": "edge1", "ip": "192.0.2.11", "platform": "cisco_ios", "model": "ISR4431", "status": "OK", "info": "NTP present"},
    {"device": "jnp-qfx1", "ip": "192.0.2.21", "platform": "juniper_junos", "model": "QFX5120", "status": "FAIL", "info": "No ntp server"},
    ]
    """

    out = {"device": host, "ip": task.host.hostname, "platform": task.host.platform, "model": "N/A", "status": "OK", "info": "This was a test"}

    return Result(host=task.host, changed=True, failed=failed, result=out)




