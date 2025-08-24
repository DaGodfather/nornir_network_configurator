# transport_discovery.py
"""
Transport discovery & caching for Nornir 2.x (Python 3.6+).

Usage (in your main script):
    from nornir import InitNornir
    from transport_discovery import bootstrap_transport

    nr = InitNornir(config_file="config.yaml")
    # Stage A: apply cached choices + discover for unknowns (probe once/host)
    discovery_result = bootstrap_transport(nr, cache_path="transport_cache.json")

    # Stage B: run your real tasks; connection options are already set
    # result = nr.run(task=your_task, ...)

What it does:
- Probes TCP/22 (SSH) and TCP/23 (Telnet) for each host's management IP.
- Chooses SSH if both are open; otherwise chooses whichever is open.
- Sets `host.connection_options["netmiko"]` with the proper port and Netmiko device_type.
- Adds `host["mgmt_transport"]`, `host["device_type"]`, and `host["port"]` for visibility.
- Saves decisions to a JSON cache so future runs skip probing for known hosts.

Notes:
- Designed for Cisco IOS/NX-OS (SSH + Telnet). Junos is SSH-only.
- Extend `platform_to_netmiko_types()` to cover more platforms.
"""

import json
import os
import socket
from typing import Dict, Any, Optional, Tuple

from nornir.core.task import Task, Result
from nornir.core.inventory import ConnectionOptions

# Default on-disk cache file (JSON). Change per-project if desired.
CACHE_PATH = "transport_cache.json"


# --------------------------- Low-level helpers ---------------------------

def is_port_open(host: str, port: int, timeout: float = 0.7) -> bool:
    """
    Return True if TCP `port` is reachable on `host` within `timeout` seconds.
    Lightweight probe to avoid long Netmiko timeouts.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def platform_to_netmiko_types(platform: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Map an inventory platform string to (ssh_device_type, telnet_device_type).
    - Returns (ssh_type, telnet_type or None).
    - Add/extend mappings as needed for your environment.

    Known good values:
      Cisco IOS:   ("cisco_ios", "cisco_ios_telnet")
      Cisco NX-OS: ("cisco_nxos", "cisco_nxos_telnet")
      Juniper:     ("juniper", None)   # Netmiko is SSH-only for Junos

    Unknown platforms default to Cisco IOS behavior.
    """
    p = (platform or "").lower()
    if p in ("cisco_ios", "ios", "ios-xe", "iosxe"):
        return ("cisco_ios", "cisco_ios_telnet")
    if p in ("cisco_nxos", "nxos"):
        return ("cisco_nxos", "cisco_nxos_telnet")
    if p in ("juniper", "junos"):
        return ("juniper", None)  # no Telnet fallback for Junos via Netmiko

    # Default: treat like Cisco IOS
    return ("cisco_ios", "cisco_ios_telnet")


def apply_conn(host_or_task: Any, device_type: str, port: int) -> None:
    """
    Apply Netmiko connection options to a Host (or Task.host).
    This overrides connection settings in-memory for the current Nornir run.
    """
    host = getattr(host_or_task, "host", host_or_task)
    # Close any open Netmiko session before changing options
    try:
        host.close_connection("netmiko")
    except Exception:
        pass

    host.connection_options["netmiko"] = ConnectionOptions(
        port=port,
        extras={"device_type": device_type},
    )


def load_cache(path: str = CACHE_PATH) -> Dict[str, Dict[str, Any]]:
    """
    Load the JSON cache from disk.
    Returns {} if the file does not exist.
    """
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_cache(mapping: Dict[str, Dict[str, Any]], path: str = CACHE_PATH) -> None:
    """
    Persist the discovery mapping to disk as JSON.
    """
    with open(path, "w") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)


# ---------------------- Pre-stage inventory operations ----------------------

def apply_cache_to_inventory(nr: Any, cache_path: str = CACHE_PATH) -> None:
    """
    Apply cached transport decisions to the in-memory inventory.
    - Sets connection options and convenience fields for hosts found in the cache.
    """
    cache = load_cache(cache_path)
    for host in nr.inventory.hosts.values():
        rec = cache.get(host.name)
        if not rec:
            continue
        apply_conn(host, rec["device_type"], int(rec["port"]))
        host["mgmt_transport"] = rec.get("transport")
        host["device_type"] = rec.get("device_type")
        host["port"] = int(rec["port"])


def discover_and_set(task: Task, prefer_ssh_when_both_open: bool = True, probe_timeout: float = 0.7) -> Result:
    """
    Nornir Task: probe a host, choose transport, and set connection options on the host.

    Behavior:
      1) If host already has 'mgmt_transport' (from cache), exits quickly.
      2) Probes TCP/22 and (if supported) TCP/23.
      3) Picks SSH if both are open and `prefer_ssh_when_both_open` is True.
      4) Applies the chosen port & device_type to host.connection_options["netmiko"].
      5) Stores metadata on the host: 'mgmt_transport', 'device_type', 'port'.

    Returns:
      Result.result dict with:
        {"transport": "ssh"|"telnet", "device_type": str, "port": int, "probed": {"22": bool, "23": bool}}
      On failure: Result.failed=True and an "error" string.
    """
    # Fast exit if applied from cache
    if task.host.get("mgmt_transport"):
        return Result(
            host=task.host,
            result={"cached": True, "transport": task.host["mgmt_transport"], "port": task.host.get("port")}
        )

    ip = str(task.host.hostname)
    ssh_type, telnet_type = platform_to_netmiko_types(task.host.platform)

    ssh_open = is_port_open(ip, 22, timeout=probe_timeout)
    tel_open = bool(telnet_type) and is_port_open(ip, 23, timeout=probe_timeout)

    if not (ssh_open or tel_open):
        return Result(
            host=task.host,
            failed=True,
            result={"error": "No open management ports detected (22/23).",
                    "probed": {"22": ssh_open, "23": tel_open}}
        )

    # Decide transport
    if ssh_open and tel_open and prefer_ssh_when_both_open:
        transport, device_type, port = "ssh", ssh_type, 22
    elif ssh_open:
        transport, device_type, port = "ssh", ssh_type, 22
    else:
        transport, device_type, port = "telnet", telnet_type, 23  # tel_open must be True here

    # Apply to this host for the remainder of the run
    apply_conn(task, device_type, port)
    task.host["mgmt_transport"] = transport
    task.host["device_type"] = device_type
    task.host["port"] = port

    return Result(
        host=task.host,
        result={"transport": transport, "device_type": device_type, "port": port,
                "probed": {"22": ssh_open, "23": tel_open}}
    )


def persist_discovery(nr_result: Dict[str, Any], cache_path: str = CACHE_PATH) -> None:
    """
    Merge a Nornir aggregated result from `discover_and_set` into the JSON cache on disk.
    Only successful discoveries (not failed, not cached-only) are written.
    """
    cache = load_cache(cache_path)
    for host, multi_result in nr_result.items():
        r = multi_result[0]
        if r.failed:
            continue
        data = r.result or {}
        if data.get("cached"):
            # Already persisted previously
            continue
        if {"transport", "device_type", "port"} <= set(data.keys()):
            cache[host] = {
                "transport": data["transport"],
                "device_type": data["device_type"],
                "port": int(data["port"]),
            }
    save_cache(cache, cache_path)


def bootstrap_transport(nr: Any,
                        cache_path: str = CACHE_PATH,
                        prefer_ssh_when_both_open: bool = True,
                        probe_timeout: float = 0.7) -> Dict[str, Any]:
    """
    One-call convenience to:
      1) Apply cached transport choices to inventory (fast path),
      2) Discover for unknown hosts (probe once),
      3) Persist new discoveries to cache.

    Returns the Nornir result from the discovery task (so you can log/inspect it).
    """
    # Stage 1: apply cached choices (no network I/O)
    apply_cache_to_inventory(nr, cache_path=cache_path)

    # Stage 2: discover for any hosts not in cache (one short probe per host)
    disc = nr.run(
        name="Transport discovery (SSH/Telnet probe)",
        task=discover_and_set,
        prefer_ssh_when_both_open=prefer_ssh_when_both_open,
        probe_timeout=probe_timeout,
    )

    # Stage 3: persist any newly-discovered transports
    persist_discovery(disc, cache_path=cache_path)
    return disc