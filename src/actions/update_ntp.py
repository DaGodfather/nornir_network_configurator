# src/actions/update_ntp.py
# Python 3.6+ / Nornir 2.5

"""
Update NTP server configuration based on playbooks/ntp.txt.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<details>)

Behavior:
1) Load expected NTP servers from playbooks/ntp.txt
2) Query device for currently configured NTP servers
3) Compare and determine what changes are needed
4) Remove old NTP servers not in playbook
5) Add new NTP servers from playbook
6) Verify configuration and save
"""

import logging
import re
import time
from typing import List, Set
from pathlib import Path
from src.utils.csv_sanitizer import sanitize_for_csv, sanitize_error_message
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config
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
    Updates NTP configuration based on playbook and returns a row dict in Result.result.
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
        logger.info(f"[{host}] Starting NTP update for {ip} (platform: {platform}, device_type: {device_type}, port: {port}, enable_secret_configured: {has_secret})")
    else:
        logger.info(f"[{host}] Starting NTP update for {ip} (platform: {platform})")

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

            for attempt in range(2):  # Try twice
                try:
                    conn = task.host.get_connection("netmiko", task.nornir.config)
                    if not conn.check_enable_mode():
                        conn.enable()
                        logger.info(f"[{host}] Successfully entered enable mode (attempt {attempt + 1})")
                    else:
                        logger.info(f"[{host}] Already in enable mode (attempt {attempt + 1})")
                    enable_success = True
                    break

                except Exception as e:
                    if attempt == 0:  # First attempt failed
                        logger.warning(f"[{host}] Enable mode attempt 1 failed: {str(e)}")
                        logger.info(f"[{host}] Waiting 15 seconds before retry...")
                        time.sleep(15)
                    else:  # Second attempt failed
                        error_msg = f"Enable mode failed after 2 attempts: {str(e)}"
                        logger.error(f"[{host}] {error_msg}")
                        status = "FAIL"
                        info_text = f"Enable mode failed - check enable password. Error: {str(e)}"
                        raise Exception(error_msg)

            if not enable_success:
                raise Exception("Enable mode failed after retry")

        # Step 3: Query current NTP configuration
        if _is_juniper(platform):
            query_cmd = "show configuration system ntp | display set"
        elif _is_cisco(platform):
            query_cmd = "show run | include ntp server"
        else:
            query_cmd = "show run | include ntp"

        logger.info(f"[{host}] Querying current NTP configuration...")
        r1 = task.run(
            task=netmiko_send_command,
            command_string=query_cmd,
            name="Query NTP config",
            delay_factor=3,
            max_loops=500,
        )

        current_output = (_extract_text(r1) or "").strip()
        logger.info(f"[{host}] Current NTP config:\n{current_output}")

        # Step 4: Parse currently configured servers
        if _is_juniper(platform):
            current_servers = _parse_juniper_ntp_servers(current_output)
        elif _is_cisco(platform):
            current_servers = _parse_cisco_ntp_servers(current_output)
        else:
            current_servers = _parse_cisco_ntp_servers(current_output)

        logger.info(f"[{host}] Current NTP servers: {current_servers}")

        # Step 5: Determine changes needed
        to_remove = current_servers - expected_set
        to_add = expected_set - current_servers

        logger.info(f"[{host}] Servers to remove: {to_remove}")
        logger.info(f"[{host}] Servers to add: {to_add}")

        # Check if already compliant
        if not to_remove and not to_add:
            logger.info(f"[{host}] NTP configuration already matches playbook")
            status = "OK"
            info_text = f"NTP already configured correctly: {', '.join(sorted(expected_set))}"
        else:
            # Step 6: Apply configuration changes
            logger.info(f"[{host}] Applying NTP configuration changes...")

            config_commands = []

            # Build removal commands
            if to_remove:
                if _is_juniper(platform):
                    for server in sorted(to_remove):
                        config_commands.append(f"delete system ntp server {server}")
                elif _is_cisco(platform):
                    for server in sorted(to_remove):
                        config_commands.append(f"no ntp server {server}")

            # Build addition commands
            if to_add:
                if _is_juniper(platform):
                    for server in sorted(to_add):
                        config_commands.append(f"set system ntp server {server}")
                elif _is_cisco(platform):
                    for server in sorted(to_add):
                        config_commands.append(f"ntp server {server}")

            logger.info(f"[{host}] Configuration commands:\n" + "\n".join(config_commands))

            # Apply configuration
            task.run(
                task=netmiko_send_config,
                config_commands=config_commands,
                name="Apply NTP config",
            )

            # Step 7: Verify configuration
            logger.info(f"[{host}] Verifying NTP configuration...")
            r2 = task.run(
                task=netmiko_send_command,
                command_string=query_cmd,
                name="Verify NTP config",
                delay_factor=3,
                max_loops=500,
            )

            verify_output = (_extract_text(r2) or "").strip()
            logger.info(f"[{host}] Verification output:\n{verify_output}")

            # Parse verification output
            if _is_juniper(platform):
                verify_servers = _parse_juniper_ntp_servers(verify_output)
            elif _is_cisco(platform):
                verify_servers = _parse_cisco_ntp_servers(verify_output)
            else:
                verify_servers = _parse_cisco_ntp_servers(verify_output)

            logger.info(f"[{host}] Verified NTP servers: {verify_servers}")

            # Check if verification matches expected
            if verify_servers == expected_set:
                logger.info(f"[{host}] Verification successful - configuration matches playbook")

                # Step 8: Save configuration
                logger.info(f"[{host}] Saving configuration...")

                if _is_juniper(platform):
                    save_cmd = "commit and-quit"
                    task.run(
                        task=netmiko_send_config,
                        config_commands=[save_cmd],
                        name="Save config (Juniper commit)",
                    )
                elif _is_cisco(platform):
                    save_cmd = "write memory"
                    r3 = task.run(
                        task=netmiko_send_command,
                        command_string=save_cmd,
                        name="Save config",
                        delay_factor=3,
                        max_loops=500,
                    )
                    save_output = (_extract_text(r3) or "").strip()
                    logger.info(f"[{host}] Save output: {save_output}")

                status = "OK"
                if to_remove and to_add:
                    info_text = f"Updated successfully. Removed: {', '.join(sorted(to_remove))}; Added: {', '.join(sorted(to_add))}"
                elif to_remove:
                    info_text = f"Updated successfully. Removed: {', '.join(sorted(to_remove))}"
                else:
                    info_text = f"Updated successfully. Added: {', '.join(sorted(to_add))}"

            else:
                # Verification failed
                missing = expected_set - verify_servers
                extra = verify_servers - expected_set
                error_msg = f"Verification failed. Missing: {missing}; Extra: {extra}"
                logger.error(f"[{host}] {error_msg}")
                status = "FAIL"
                info_text = f"Update failed - verification mismatch. {error_msg}"

        logger.info(f"[{host}] Update complete - Status: {status}")

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
            info_text = f"Update failed - {sanitize_error_message(e)}"

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

    return Result(host=task.host, changed=(status == "OK"), result=row)
