
# src/actions/audit_vty_access_list.py
# Python 3.6+ / Nornir 2.5

"""
Audit Cisco VTY 'access-class in' configuration and return a per-host row.

Conforms to app_main.py's expectations:
- Defines `run(task, pm=None) -> Result`
- Returns Result.result as a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<acl list text>)

Design:
- Uses a modular fetch function `fetch_vty_acl_info(task)` so other scripts
  can import it to reuse the parsing logic for updates.
- Primary command: `show run | i access-class`
- Parses ACL names only when direction is `in` (IPv4 or IPv6).

Examples of matched lines:
    access-class MGMT-VTY in
    ipv6 access-class V6-MGMT in
    access-class EDGE-IN in vrf-also
"""

import re
from typing import List, Tuple
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command

# --------------------------- Platform helpers ---------------------------

def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")

def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos")

# --------------------------- Command helpers ---------------------------

def _extract_text(nr_result) -> str:
    """Return plain text from a Nornir/Netmiko result or MultiResult."""
    out = getattr(nr_result, "result", None)
    if isinstance(out, str):
        return out
    try:
        return nr_result[0].result
    except Exception:
        return ""

def _send_show(task: Task, command: str, name: str = None) -> str:
    """Wrapper around netmiko_send_command for reuse/import elsewhere."""
    r = task.run(task=netmiko_send_command, command_string=command, name=name or command)
    return (_extract_text(r) or "").strip()

# ---------------------------- Core logic --------------------------------

_ACL_IN_REGEX = re.compile(r"^\s*(?:ipv6\s+)?access-class\s+(\S+)\s+in\b", re.IGNORECASE)

def fetch_vty_acl_info(task: Task) -> Tuple[str, List[str]]:
    """
    Run the show command and parse ACL names for 'access-class ... in'.
    Returns (raw_text, acl_names).
    """
    platform = task.host.platform
    if not _is_cisco(platform):
        # Not applicable for Junos; return empty so caller can decide status text
        return ("", [])

    raw = _send_show(task, "show run | i access-class", name="VTY access-class grep")

    acls: List[str] = []
    if raw:
        # Support multi-line output (one match per line typically)
        for line in raw.splitlines():
            m = _ACL_IN_REGEX.search(line)
            if m:
                acl = m.group(1)
                if acl not in acls:
                    acls.append(acl)
    return (raw, acls)

# ------------------------------- Action ---------------------------------

def run(task: Task, pm=None) -> Result:
    """Entry point: audit VTY access-class 'in' ACLs and return a row dict."""
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname

    raw, acls = fetch_vty_acl_info(task)

    if _is_cisco(platform):
        if acls:
            status = "OK"
            info_text = ", ".join(acls)  # place the list of ACL names in the info field
        else:
            status = "FAIL"
            info_text = "No 'access-class in' found"
    else:
        # Junos/others: not applicable; mark OK with guidance
        status = "OK"
        info_text = "Not applicable (Junos uses firewall filters / system services)"

    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),
        "status": status,
        "info": info_text,  # shows ACL names or explanatory text
    }
    return Result(host=task.host, changed=False, result=row)
