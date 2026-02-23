# src/actions/update_syslog.py
# Python 3.6+ / Nornir 2.5

"""
Update syslog server configuration based on playbooks/syslog.txt.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<details>)

Behavior:
1) Load expected syslog servers from playbooks/syslog.txt
2) Query device for currently configured syslog servers (show run)
3) Determine format (logging vs logging host) and use consistently
4) Remove old syslog servers not in playbook
5) Add new syslog servers from playbook
6) Verify configuration and save
"""

import logging
import re
import time
from typing import List, Set, Tuple
from pathlib import Path
from src.utils.csv_sanitizer import sanitize_for_csv, sanitize_error_message
from src.utils.enable_mode import enter_enable_mode_robust
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

def _load_syslog_playbook(playbook_path: str = "playbooks/syslog.txt") -> List[str]:
    """
    Load syslog server IPs from playbook file.
    Returns list of IP addresses (one per line), skipping comments and empty lines.
    """
    syslog_servers = []
    try:
        with open(playbook_path, "r") as f:
            for line in f:
                # Skip comments and empty lines
                if not line or line.strip().startswith('#'):
                    continue
                stripped = line.strip()
                if stripped:
                    syslog_servers.append(stripped)

        logger.info(f"Loaded playbook: {len(syslog_servers)} syslog server(s)")
    except FileNotFoundError:
        logger.warning(f"Playbook file not found: {playbook_path}")
    except Exception as e:
        logger.error(f"Failed to load playbook: {str(e)}")

    return syslog_servers


# --------------------------- Device parsing ---------------------------

def _parse_cisco_syslog_servers(output: str) -> Tuple[Set[str], str]:
    """
    Parse Cisco 'show run' output for syslog servers.

    Detects format used:
    - "logging <IP>" (older/simpler format)
    - "logging host <IP>" (newer format)

    Returns tuple of (set of IPs, format_type)
    format_type is either "logging" or "logging host"

    Example output:
    logging 10.1.1.200
    logging 10.1.1.201

    OR:

    logging host 10.1.1.200
    logging host 10.1.1.201
    """
    servers = set()
    format_type = "logging host"  # Default to newer format

    for line in output.splitlines():
        line = line.strip()

        # Try "logging host <IP>" format first (newer)
        match = re.match(r'^logging\s+host\s+(\S+)', line, re.IGNORECASE)
        if match:
            servers.add(match.group(1))
            format_type = "logging host"
            continue

        # Try "logging <IP>" format (older, but skip other logging commands)
        # Must be a valid IP address pattern (not keywords like "trap", "buffered", etc.)
        match = re.match(r'^logging\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
        if match:
            servers.add(match.group(1))
            # Only change to "logging" format if we haven't seen "logging host" yet
            if format_type == "logging host" and len(servers) == 1:
                format_type = "logging"

    return servers, format_type


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
    Updates syslog configuration based on playbook and returns a row dict in Result.result.
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
        logger.info(f"[{host}] Starting syslog update for {ip} (platform: {platform}, device_type: {device_type}, port: {port}, enable_secret_configured: {has_secret})")
    else:
        logger.info(f"[{host}] Starting syslog update for {ip} (platform: {platform})")

    try:
        # Step 1: Load expected syslog servers from playbook
        expected_servers = _load_syslog_playbook()
        if not expected_servers:
            logger.warning(f"[{host}] No syslog servers defined in playbook")
            status = "FAIL"
            info_text = "No syslog servers defined in playbook - create playbooks/syslog.txt"
            raise Exception("Playbook empty or missing")

        expected_set = set(expected_servers)
        logger.info(f"[{host}] Expected syslog servers: {expected_set}")

        # Step 2: Enter enable mode for Cisco devices
        if _is_cisco(platform):
            enable_success, enable_message = enter_enable_mode_robust(
                task=task,
                max_attempts=3,
                delay_between_attempts=15,
                force_new_connection=False
            )

            if not enable_success:
                error_msg = f"Enable mode failed: {enable_message}"
                logger.error(f"[{host}] {error_msg}")
                status = "FAIL"
                info_text = f"Enable mode failed - check enable password. {enable_message}"
                raise Exception(error_msg)

        # Step 3: Query current syslog configuration (entire config)
        if _is_juniper(platform):
            query_cmd = "show configuration system syslog | display set"
        elif _is_cisco(platform):
            query_cmd = "show run"
        else:
            query_cmd = "show run"

        logger.info(f"[{host}] Querying current syslog configuration...")
        r1 = task.run(
            task=netmiko_send_command,
            command_string=query_cmd,
            name="Query syslog config",
            delay_factor=3,
            max_loops=500,
        )

        current_output = (_extract_text(r1) or "").strip()
        logger.debug(f"[{host}] Current config retrieved (length: {len(current_output)} chars)")

        # Step 4: Parse currently configured servers and detect format
        if _is_cisco(platform):
            current_servers, syslog_format = _parse_cisco_syslog_servers(current_output)
            logger.info(f"[{host}] Detected syslog format: '{syslog_format}'")
        else:
            # For Juniper or other platforms (not implemented yet)
            current_servers = set()
            syslog_format = "logging host"

        logger.info(f"[{host}] Current syslog servers: {current_servers}")

        # Step 5: Determine changes needed
        to_remove = current_servers - expected_set
        to_add = expected_set - current_servers

        logger.info(f"[{host}] Servers to remove: {to_remove}")
        logger.info(f"[{host}] Servers to add: {to_add}")

        # Check if already compliant
        if not to_remove and not to_add:
            logger.info(f"[{host}] Syslog configuration already matches playbook")
            status = "OK"
            info_text = "Syslog already configured correctly"
        else:
            # Step 6: Apply configuration changes
            logger.info(f"[{host}] Applying syslog configuration changes...")

            config_commands = []

            # Build removal commands using detected format
            if to_remove:
                if _is_cisco(platform):
                    for server in sorted(to_remove):
                        if syslog_format == "logging host":
                            config_commands.append(f"no logging host {server}")
                        else:
                            config_commands.append(f"no logging {server}")

            # Build addition commands using detected format
            if to_add:
                if _is_cisco(platform):
                    for server in sorted(to_add):
                        if syslog_format == "logging host":
                            config_commands.append(f"logging host {server}")
                        else:
                            config_commands.append(f"logging {server}")

            logger.info(f"[{host}] Configuration commands:\n" + "\n".join(config_commands))

            # Apply configuration
            task.run(
                task=netmiko_send_config,
                config_commands=config_commands,
                name="Apply syslog config",
            )

            # Step 7: Verify configuration
            logger.info(f"[{host}] Verifying syslog configuration...")
            r2 = task.run(
                task=netmiko_send_command,
                command_string=query_cmd,
                name="Verify syslog config",
                delay_factor=3,
                max_loops=500,
            )

            verify_output = (_extract_text(r2) or "").strip()
            logger.debug(f"[{host}] Verification output retrieved (length: {len(verify_output)} chars)")

            # Parse verification output
            if _is_cisco(platform):
                verify_servers, _ = _parse_cisco_syslog_servers(verify_output)
            else:
                verify_servers = set()

            logger.info(f"[{host}] Verified syslog servers: {verify_servers}")

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
                info_text = "Updated successfully"

            else:
                # Verification failed
                missing = expected_set - verify_servers
                extra = verify_servers - expected_set
                error_msg = f"Verification failed. Missing: {missing}; Extra: {extra}"
                logger.error(f"[{host}] {error_msg}")
                status = "FAIL"
                info_text = f"Update failed - verification mismatch"

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
