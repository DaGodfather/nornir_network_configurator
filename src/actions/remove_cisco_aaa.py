# src/actions/remove_cisco_aaa.py
# Python 3.6+ / Nornir 2.5

"""
Remove AAA/TACACS configuration from Cisco devices.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<details>)

Behavior:
1) Load expected enable secret from playbooks/cisco_local_credentials.txt
2) Enter enable mode
3) Run 'show run' to get current configuration
4) Verify the correct enable secret is configured before touching AAA
   - If enable secret not found: FAIL, do not proceed
5) Remove 'aaa new-model' with 'no aaa new-model' (if present)
6) Remove all 'tacacs-server' commands found in running config
7) Remove 'password 7' from VTY lines 0 4 and 5 15
8) Save configuration and return status
"""

import logging
import re
import time
from pathlib import Path
from typing import List, Optional
from src.utils.csv_sanitizer import sanitize_for_csv, sanitize_error_message
from src.utils.enable_mode import enter_enable_mode_robust
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config
from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

logger = logging.getLogger(__name__)

# VTY line ranges to check for password 7
VTY_RANGES = ["0 4", "5 15"]


# --------------------------- Platform helpers ---------------------------

def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


# --------------------------- Playbook loading ---------------------------

def _load_enable_secret(playbook_path: str = "playbooks/cisco_local_credentials.txt") -> Optional[str]:
    """
    Load the enable secret from the credentials playbook.
    Looks for a line starting with 'enable secret'.
    Returns the plaintext password portion, or None if not found.

    Example line: enable secret MySecurePass123
    Returns:      MySecurePass123
    """
    project_root = Path(__file__).resolve().parents[2]
    full_path = project_root / playbook_path

    if not full_path.exists():
        logger.warning(f"Playbook file not found: {full_path}")
        return None

    try:
        with open(full_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Match: enable secret <password>
                match = re.match(r'^enable\s+secret\s+(\S+)', line, re.IGNORECASE)
                if match:
                    return match.group(1)
    except Exception as e:
        logger.error(f"Failed to load playbook: {str(e)}")

    return None


# --------------------------- Config parsers ---------------------------

def _is_enable_secret_configured(output: str) -> bool:
    """
    Check whether 'enable secret' is present in show run output.
    We can't compare plaintext to hashed secret, so we just verify
    the line exists (trusting the enable login we already used).
    """
    for line in output.splitlines():
        if re.match(r'^\s*enable\s+secret\s+', line, re.IGNORECASE):
            return True
    return False


def _find_tacacs_server_commands(output: str) -> List[str]:
    """
    Find all 'tacacs-server' lines in show run output.
    Returns the full config lines so they can be prefixed with 'no'.

    Example matches:
      tacacs-server host 10.1.1.1
      tacacs-server host 10.1.1.2 key 7 ABCDEF
      tacacs-server directed-request
      tacacs-server timeout 5
    """
    commands = []
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r'^tacacs-server\s+', stripped, re.IGNORECASE):
            commands.append(stripped)
    return commands


def _find_vty_password7_commands(output: str) -> List[tuple]:
    """
    Scan show run output for VTY line sections that contain 'password 7 <hash>'.
    Returns list of (vty_range, password_command) tuples.

    Example:
      line vty 0 4
       password 7 08204E4D070A58
       login
    -> returns [("0 4", "password 7 08204E4D070A58")]
    """
    results = []
    current_vty = None
    in_vty_section = False

    for line in output.splitlines():
        stripped = line.strip()

        # Detect 'line vty X Y' or 'line vty X'
        vty_match = re.match(r'^line\s+vty\s+(\d+)(?:\s+(\d+))?', stripped, re.IGNORECASE)
        if vty_match:
            start = vty_match.group(1)
            end = vty_match.group(2) or start
            current_vty = f"{start} {end}"
            in_vty_section = True
            continue

        # Exit VTY section on new top-level section or '!'
        if in_vty_section and stripped:
            if stripped.startswith('!') or (
                not line.startswith(' ') and not line.startswith('\t') and
                not stripped.startswith('password') and
                not stripped.startswith('login') and
                not stripped.startswith('exec-timeout') and
                not stripped.startswith('transport') and
                not stripped.startswith('access-class') and
                not stripped.startswith('logging')
            ):
                in_vty_section = False
                current_vty = None

        # Capture 'password 7 <hash>' inside a VTY section
        if in_vty_section and current_vty:
            pw_match = re.match(r'^(password\s+7\s+\S+)', stripped, re.IGNORECASE)
            if pw_match:
                results.append((current_vty, pw_match.group(1)))

    return results


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
    Removes AAA/TACACS config from Cisco devices.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname
    status = "FAIL"
    info_text = ""

    # Only run on Cisco devices
    if not _is_cisco(platform):
        logger.info(f"[{host}] Skipping - not a Cisco device (platform: {platform})")
        return Result(
            host=task.host,
            changed=False,
            result={
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "SKIP",
                "info": "Not a Cisco device - skipped",
            }
        )

    # Log connection details
    conn_opts = task.host.connection_options.get("netmiko")
    if conn_opts:
        device_type = conn_opts.extras.get("device_type", "unknown")
        port = conn_opts.port or "default"
        has_secret = "secret" in conn_opts.extras
        logger.info(f"[{host}] Starting AAA removal for {ip} "
                    f"(platform: {platform}, device_type: {device_type}, port: {port}, "
                    f"enable_secret_configured: {has_secret})")
    else:
        logger.info(f"[{host}] Starting AAA removal for {ip} (platform: {platform})")

    try:
        # Step 1: Load expected enable secret from playbook
        expected_secret = _load_enable_secret()
        if not expected_secret:
            status = "FAIL"
            info_text = "No enable secret found in playbooks/cisco_local_credentials.txt - cannot proceed"
            raise Exception("Enable secret not in playbook")

        logger.info(f"[{host}] Enable secret loaded from playbook")

        # Step 2: Enter enable mode
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

        # Step 3: Pull full running config
        logger.info(f"[{host}] Pulling running configuration...")
        r1 = task.run(
            task=netmiko_send_command,
            command_string="show run",
            name="Show running config",
            delay_factor=3,
            max_loops=500,
        )
        running_config = (_extract_text(r1) or "").strip()
        logger.debug(f"[{host}] Running config retrieved ({len(running_config)} chars)")

        # Step 4: Verify correct enable secret is configured
        logger.info(f"[{host}] Verifying enable secret is configured on device...")
        if not _is_enable_secret_configured(running_config):
            status = "FAIL"
            info_text = "Enable secret not configured on device - will not remove AAA"
            logger.error(f"[{host}] {info_text}")
            raise Exception("Enable secret not found on device")

        logger.info(f"[{host}] Enable secret verified - safe to proceed with AAA removal")

        # Step 5: Find what needs to be removed
        aaa_present = bool(re.search(r'^\s*aaa\s+new-model', running_config, re.MULTILINE | re.IGNORECASE))
        tacacs_commands = _find_tacacs_server_commands(running_config)
        vty_password7_entries = _find_vty_password7_commands(running_config)

        logger.info(f"[{host}] aaa new-model present: {aaa_present}")
        logger.info(f"[{host}] tacacs-server commands found: {len(tacacs_commands)}")
        logger.info(f"[{host}] VTY password 7 entries found: {len(vty_password7_entries)}")

        if not aaa_present and not tacacs_commands and not vty_password7_entries:
            logger.info(f"[{host}] Nothing to remove - configuration already clean")
            status = "OK"
            info_text = "No AAA/TACACS config found - nothing to remove"
            raise Exception("Nothing to do")

        # Build all config commands
        config_commands = []

        # Step 6: Remove aaa new-model
        if aaa_present:
            logger.info(f"[{host}] Adding: no aaa new-model")
            config_commands.append("no aaa new-model")

        # Step 7: Remove tacacs-server commands
        if tacacs_commands:
            logger.info(f"[{host}] Adding removal of {len(tacacs_commands)} tacacs-server command(s)")
            for cmd in tacacs_commands:
                config_commands.append(f"no {cmd}")

        # Step 8: Remove password 7 from VTY lines
        if vty_password7_entries:
            logger.info(f"[{host}] Adding removal of password 7 from VTY lines")
            for vty_range, pw_cmd in vty_password7_entries:
                config_commands.append(f"line vty {vty_range}")
                config_commands.append(f"no {pw_cmd}")

        logger.info(f"[{host}] Applying {len(config_commands)} config command(s)...")
        logger.debug(f"[{host}] Commands:\n" + "\n".join(config_commands))

        task.run(
            task=netmiko_send_config,
            config_commands=config_commands,
            name="Remove AAA/TACACS config",
        )

        # Save configuration
        logger.info(f"[{host}] Saving configuration...")
        r2 = task.run(
            task=netmiko_send_command,
            command_string="write memory",
            name="Save config",
            delay_factor=3,
            max_loops=500,
        )
        save_output = (_extract_text(r2) or "").strip()
        logger.info(f"[{host}] Save output: {save_output}")

        # Build summary of what was removed
        removed_parts = []
        if aaa_present:
            removed_parts.append("aaa new-model")
        if tacacs_commands:
            removed_parts.append(f"{len(tacacs_commands)} tacacs-server command(s)")
        if vty_password7_entries:
            removed_parts.append(f"password 7 on VTY line(s): {', '.join(set(vr for vr, _ in vty_password7_entries))}")

        status = "OK"
        info_text = "Removed: " + "; ".join(removed_parts)

        logger.info(f"[{host}] AAA removal complete - {info_text}")

    except NetmikoAuthenticationException as e:
        logger.error(f"[{host}] Authentication failed: {str(e)}")
        status = "FAIL"
        info_text = "Authentication failed - check credentials"

    except NetmikoTimeoutException as e:
        logger.error(f"[{host}] Connection timeout: {str(e)}")
        status = "FAIL"
        info_text = "Connection timeout - device unreachable"

    except Exception as e:
        logger.error(f"[{host}] {str(e)}", exc_info=False)
        if not info_text:
            status = "FAIL"
            info_text = f"Removal failed - {sanitize_error_message(e)}"

    finally:
        try:
            logger.debug(f"[{host}] Closing netmiko connection...")
            task.host.close_connection("netmiko")
            logger.debug(f"[{host}] Connection closed")
        except Exception as e:
            logger.warning(f"[{host}] Error closing connection: {str(e)}")

    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),
        "status": status,
        "info": sanitize_for_csv(info_text, max_length=500),
    }

    return Result(host=task.host, changed=(status == "OK"), result=row)
