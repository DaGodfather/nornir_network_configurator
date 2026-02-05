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

import logging
import time
from src.utils.cisco_commands import *
from src.utils.juniper_commands import *
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
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos","cisco_ios_telnet")


def _pick_ntp_config_cmd(platform):
    """
    Return a concise config-focused command that lists NTP peers/servers.
    """
    if _is_juniper(platform):
        # Only NTP stanza, easy to read/log.
        return "show configuration system ntp | display set"
    if _is_cisco(platform):
        # Use 'include' without regex anchors for maximum compatibility
        # This will match any line containing 'ntp server', 'ntp peer', or 'ntp pool'
        return "show run | include ntp server"
    # Fallback: generic Cisco-ish grep
    return "show run | include ntp"


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
        # Explicitly enter enable mode for Cisco devices if enable secret is configured
        enable_secret = task.host.data.get("enable_secret")
        if _is_cisco(platform) and enable_secret:
            logger.info(f"[{host}] Entering enable mode...")
            enable_success = False

            for attempt in range(2):  # Try twice
                try:
                    # Get the netmiko connection and enter enable mode
                    conn = task.host.get_connection("netmiko", task.nornir.config)
                    if not conn.check_enable_mode():
                        conn.enable()
                        logger.info(f"[{host}] Successfully entered enable mode (attempt {attempt + 1})")
                    else:
                        logger.info(f"[{host}] Already in enable mode (attempt {attempt + 1})")
                    enable_success = True
                    break  # Success, exit retry loop

                except Exception as e:
                    if attempt == 0:  # First attempt failed
                        logger.warning(f"[{host}] Enable mode attempt 1 failed: {str(e)}")
                        logger.info(f"[{host}] Waiting 10 seconds before retry...")
                        time.sleep(15)
                    else:  # Second attempt failed
                        # Enable mode failure is FATAL for Cisco - we need privileged exec for 'show run'
                        error_msg = f"Enable mode failed after 2 attempts: {str(e)}"
                        logger.error(f"[{host}] {error_msg}")
                        status = "FAIL"
                        info_text = f"Enable mode failed - check enable password. Error: {str(e)}"
                        raise Exception(error_msg)  # This will jump to the outer except block

            if not enable_success:
                raise Exception("Enable mode failed after retry")

        # 1) Try concise config grep
        cfg_cmd = _pick_ntp_config_cmd(platform)
        logger.info(f"[{host}] Sending command: {cfg_cmd}")

        r1 = task.run(
            task=netmiko_send_command,
            command_string=cfg_cmd,
            name="NTP config grep",
            delay_factor=2,
            max_loops=500
        )
        logger.info(f"[{host}] output from command: {cfg_cmd}: \n{r1}")
        text = (_extract_text(r1) or "").strip()

        logger.debug(f"[{host}] Command output ({len(text)} chars):\n{text}")

        # 2) If empty, try an operational fallback for visibility
        if not text:
            op_cmd = _pick_ntp_operational_fallback(platform)
            logger.info(f"[{host}] Config grep empty, trying operational command: {op_cmd}")

            r2 = task.run(
                task=netmiko_send_command,
                command_string=op_cmd,
                name="NTP operational",
                delay_factor=2,
                max_loops=500
            )
            text = (_extract_text(r2) or "").strip()

            logger.debug(f"[{host}] Operational command output ({len(text)} chars):\n{text}")

        # 3) Decide status & build the row
        status = "OK" if text else "FAIL"
        info_text = text if text else "No NTP lines returned"

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
        status = "FAIL"
        info_text = f"Error: {str(e)}"

    finally:
        # Always close the connection to prevent hung sessions
        try:
            logger.debug(f"[{host}] Closing netmiko connection...")
            task.host.close_connection("netmiko")
            logger.debug(f"[{host}] Connection closed successfully")
        except Exception as e:
            logger.warning(f"[{host}] Error closing connection: {str(e)}")

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
