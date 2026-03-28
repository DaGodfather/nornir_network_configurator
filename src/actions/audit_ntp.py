# src/actions/audit_ntp.py
# Python 3.6+ / Nornir 2.5

"""
Audit NTP configuration against playbook/ntp.txt.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<details>)

Behavior:
1) Load expected NTP servers from playbooks/ntp.txt
2) Query device for configured NTP servers
3) Compare configured servers against expected servers
4) Return status and detailed info about compliance
"""

import logging
import re
import time
from typing import List, Set
from pathlib import Path
from src.utils.csv_sanitizer import sanitize_for_csv, sanitize_error_message
from src.utils.enable_mode import _try_password_only_telnet
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command
from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

# Initialize logger
logger = logging.getLogger(__name__)

# --------------------------- Platform helpers ---------------------------

def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


# --------------------------- Playbook loading ---------------------------

def _load_ntp_playbook(playbook_path: str = "playbooks/ntp.txt") -> List[str]:
    """
    Load NTP server IPs from playbook file.
    Returns list of IP addresses (one per line), skipping comments and empty lines.
    """
    ntp_servers = []
    try:
        with open(playbook_path, "r") as f:
            for line in f:
                # Skip comments and empty lines
                if not line or line.strip().startswith('#'):
                    continue
                stripped = line.strip()
                if stripped:
                    ntp_servers.append(stripped)

        logger.info(f"Loaded playbook: {len(ntp_servers)} NTP server(s)")
    except FileNotFoundError:
        logger.warning(f"Playbook file not found: {playbook_path}")
    except Exception as e:
        logger.error(f"Failed to load playbook: {str(e)}")

    return ntp_servers


# --------------------------- Device parsing ---------------------------

def _parse_cisco_ntp_servers(output: str) -> Set[str]:
    """
    Parse Cisco 'show run | include ntp server' output.

    Example output:
    ntp server 10.1.1.100
    ntp server 10.1.1.101 prefer
    ntp server 172.16.0.10

    Returns set of IP addresses.
    """
    servers = set()
    for line in output.splitlines():
        line = line.strip()
        # Match 'ntp server <IP>' with optional trailing arguments
        match = re.match(r'^ntp server\s+(\S+)', line, re.IGNORECASE)
        if match:
            servers.add(match.group(1))
    return servers


def _parse_juniper_ntp_servers(output: str) -> Set[str]:
    """
    Parse Juniper 'show configuration system ntp | display set' output.

    Example output:
    set system ntp server 10.1.1.100
    set system ntp server 10.1.1.101 prefer
    set system ntp server 172.16.0.10

    Returns set of IP addresses.
    """
    servers = set()
    for line in output.splitlines():
        line = line.strip()
        # Match 'set system ntp server <IP>' with optional trailing arguments
        match = re.match(r'^set system ntp server\s+(\S+)', line, re.IGNORECASE)
        if match:
            servers.add(match.group(1))
    return servers


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
    Audits NTP configuration against playbook and returns a row dict in Result.result.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname
    status = "FAIL"
    info_text = ""

    # Log connection details
    conn_opts = task.host.connection_options.get("netmiko")
    if conn_opts:
        device_type = conn_opts.extras.get("device_type", "unknown")
        port = conn_opts.port or "default"
        has_secret = "secret" in conn_opts.extras
        logger.info(f"[{host}] Starting NTP audit for {ip} (platform: {platform}, device_type: {device_type}, port: {port}, enable_secret_configured: {has_secret})")
    else:
        logger.info(f"[{host}] Starting NTP audit for {ip} (platform: {platform})")

    try:
        # Step 1: Load expected NTP servers from playbook
        expected_servers = _load_ntp_playbook()
        if not expected_servers:
            logger.warning(f"[{host}] No NTP servers defined in playbook")
            status = "FAIL"
            info_text = "No NTP servers defined in playbook - create playbooks/ntp.txt"
            raise Exception("Playbook empty or missing")

        expected_set = set(expected_servers)
        logger.info(f"[{host}] Expected NTP servers: {expected_set}")

        # Step 2: Enter enable mode for Cisco devices
        enable_secret = task.host.data.get("enable_secret")
        if _is_cisco(platform) and enable_secret:
            logger.info(f"[{host}] Entering enable mode...")
            enable_success = False

            _pw_only_switched = False  # only probe password-only telnet once
            for attempt in range(2):  # Try twice
                try:
                    conn = task.host.get_connection("netmiko", task.nornir.config)
                    conn.secret = enable_secret  # sync secret in case connection was initialized with stale value
                    if not conn.check_enable_mode():
                        conn.enable()
                        logger.info(f"[{host}] Successfully entered enable mode (attempt {attempt + 1})")
                    else:
                        logger.info(f"[{host}] Already in enable mode (attempt {attempt + 1})")
                    enable_success = True
                    break

                except Exception as e:
                    error_str = str(e)
                    logger.warning(f"[{host}] Enable mode attempt {attempt + 1} failed: {error_str}")

                    _is_telnet_auth_failure = (
                        "telnet connection closed" in error_str.lower()
                        or "login failed" in error_str.lower()
                    )
                    if (
                        _is_telnet_auth_failure
                        and enable_secret
                        and not _pw_only_switched
                    ):
                        conn_opts_pw = task.host.connection_options.get("netmiko")
                        curr_dt_pw = (
                            conn_opts_pw.extras.get("device_type", "") if conn_opts_pw else ""
                        )
                        if "telnet" in curr_dt_pw.lower():
                            _tport = (
                                int(conn_opts_pw.port)
                                if conn_opts_pw and conn_opts_pw.port
                                else 23
                            )
                            logger.info(
                                f"[{host}] Telnet auth failure — likely password-only auth. "
                                f"Probing with enable_secret via raw telnetlib..."
                            )
                            _pw_ok, _pw_msg = _try_password_only_telnet(
                                host, task.host.hostname or "", _tport, enable_secret
                            )
                            if _pw_ok:
                                task.host.password = enable_secret
                                _pw_only_switched = True
                                logger.info(
                                    f"[{host}] Password-only telnet succeeded — "
                                    f"host.password updated to enable_secret, retrying..."
                                )
                                try:
                                    task.host.close_connection("netmiko")
                                except Exception:
                                    pass
                                continue
                            else:
                                logger.warning(
                                    f"[{host}] Password-only telnet probe also failed: {_pw_msg}"
                                )

                    if attempt == 0:  # First attempt failed (non-password-only path)
                        logger.info(f"[{host}] Waiting 15 seconds before retry...")
                        try:
                            task.host.close_connection("netmiko")
                        except Exception:
                            pass
                        time.sleep(15)
                    else:  # Second attempt failed
                        error_msg = f"Enable mode failed after 2 attempts: {error_str}"
                        logger.error(f"[{host}] {error_msg}")
                        status = "FAIL"
                        info_text = f"Enable mode failed - check enable password. Error: {error_str}"
                        raise Exception(error_msg)

            if not enable_success:
                raise Exception("Enable mode failed after retry")

        # Step 3: Query device for NTP configuration
        if _is_juniper(platform):
            cmd = "show configuration system ntp | display set"
        elif _is_cisco(platform):
            cmd = "show run | include ntp server"
        else:
            cmd = "show run | include ntp"

        logger.info(f"[{host}] Querying NTP configuration: {cmd}")

        r = task.run(
            task=netmiko_send_command,
            command_string=cmd,
            name="Query NTP config",
            delay_factor=3,
            max_loops=500,
        )

        output = (_extract_text(r) or "").strip()
        logger.info(f"[{host}] NTP config output:\n{output}")

        # Step 4: Parse configured servers
        if _is_juniper(platform):
            configured_servers = _parse_juniper_ntp_servers(output)
        elif _is_cisco(platform):
            configured_servers = _parse_cisco_ntp_servers(output)
        else:
            configured_servers = _parse_cisco_ntp_servers(output)  # Default to Cisco parsing

        logger.info(f"[{host}] Configured NTP servers: {configured_servers}")

        # Step 5: Compare configured vs expected
        missing = expected_set - configured_servers
        extra = configured_servers - expected_set

        if not configured_servers:
            status = "FAIL"
            info_text = f"No NTP servers configured. Expected: {', '.join(sorted(expected_set))}"
        elif missing and not extra:
            status = "FAIL"
            info_text = f"Missing NTP servers: {', '.join(sorted(missing))}. Configured: {', '.join(sorted(configured_servers))}"
        elif extra and not missing:
            status = "FAIL"
            info_text = f"Extra NTP servers found: {', '.join(sorted(extra))}. Expected: {', '.join(sorted(expected_set))}"
        elif missing and extra:
            status = "FAIL"
            info_text = f"Mismatch - Missing: {', '.join(sorted(missing))}; Extra: {', '.join(sorted(extra))}"
        else:
            status = "OK"
            info_text = f"All NTP servers configured correctly: {', '.join(sorted(configured_servers))}"

        logger.info(f"[{host}] Audit complete - Status: {status}")

    except NetmikoAuthenticationException as e:
        logger.error(f"[{host}] Authentication failed: {str(e)}")
        status = "FAIL"
        info_text = "Authentication failed - check credentials"

    except NetmikoTimeoutException as e:
        logger.error(f"[{host}] Connection timeout: {str(e)}")
        status = "FAIL"
        info_text = "Connection timeout - device unreachable"

    except Exception as e:
        logger.error(f"[{host}] Unexpected error: {str(e)}", exc_info=True)
        if not info_text:  # Don't override existing error messages
            status = "FAIL"
            info_text = f"Audit failed - {sanitize_error_message(e)}"

    finally:
        # Always close the connection to prevent hung sessions
        try:
            logger.debug(f"[{host}] Closing netmiko connection...")
            task.host.close_connection("netmiko")
            logger.debug(f"[{host}] Connection closed successfully")
        except Exception as e:
            logger.warning(f"[{host}] Error closing connection: {str(e)}")

    # Sanitize info_text for CSV compatibility
    info_text_sanitized = sanitize_for_csv(info_text, max_length=500)

    # Build the result row
    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),
        "status": status,
        "info": info_text_sanitized,
    }

    return Result(host=task.host, changed=False, result=row)
