# src/actions/update_cisco_vty_acl.py
# Python 3.6+ / Nornir 2.5

"""
Update Cisco VTY ACL based on playbook configuration.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<status message>)

Behavior:
1) Read desired ACL from playbooks/cisco_vty_acl.txt
2) Check if VTY_Access ACL exists on VTY lines
3) Check if ACL configuration is up to date
4) If update needed:
   a. Remove ACL from VTY lines
   b. Remove old VTY_Access access-list
   c. Re-apply ACL from playbook and verify
   d. Re-apply ACL to VTY lines
   e. Exit config mode
5) Write memory
6) Verify ACL was updated correctly
7) Return status based on verification
"""

import logging
import time
import re
from pathlib import Path
from typing import List, Tuple, Set
from src.utils.csv_sanitizer import sanitize_error_message
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config
from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

# Initialize logger
logger = logging.getLogger(__name__)

# ACL name - can be changed if needed
ACL_NAME = "VTY_Access"

# --------------------------- Platform helpers ---------------------------

def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


def _load_playbook(playbook_path: str = "playbooks/cisco_vty_acl.txt") -> List[str]:
    """
    Load and parse the playbook file.
    Returns a list of ACL configuration lines.

    Expected format:
    ip access-list extended VTY_Access
     permit tcp host 10.1.1.1 any eq 22
     permit tcp host 10.1.1.2 any eq 22
     deny ip any any log
    """
    acl_lines = []

    project_root = Path(__file__).resolve().parents[2]
    full_path = project_root / playbook_path

    if not full_path.exists():
        logger.warning(f"Playbook file not found: {full_path}")
        return acl_lines

    try:
        with open(full_path, 'r') as f:
            for line in f:
                line = line.rstrip()  # Remove trailing whitespace but keep leading spaces
                # Skip comments and empty lines
                if not line or line.strip().startswith('#'):
                    continue
                acl_lines.append(line)

        logger.info(f"Loaded playbook: {len(acl_lines)} ACL line(s)")
    except Exception as e:
        logger.error(f"Failed to load playbook: {str(e)}")

    return acl_lines


def _normalize_acl_entry(entry: str) -> str:
    """
    Normalize an ACL entry by:
    - Stripping leading/trailing whitespace
    - Collapsing multiple internal spaces to single space
    - Converting to lowercase for consistent comparison
    """
    # Strip and collapse whitespace
    normalized = ' '.join(entry.strip().split())
    return normalized.lower()


def _extract_acl_entries(acl_lines: List[str]) -> List[str]:
    """
    Extract just the ACL entries (permit/deny lines) from the full ACL config.
    Normalizes entries for consistent comparison.
    """
    entries = []
    for line in acl_lines:
        stripped = line.strip()
        # Skip the header line "ip access-list extended VTY_Access"
        if stripped.startswith("ip access-list"):
            continue
        if stripped:
            entries.append(_normalize_acl_entry(stripped))
    return entries


def _parse_current_acl(output: str) -> List[str]:
    """
    Parse 'show access-lists VTY_Access' output to extract ACL entries.
    Returns list of normalized entries (without sequence numbers or match counters).

    Example output with sequence numbers:
    Extended IP access list VTY_Access
        10 permit tcp host 10.1.1.1 any eq 22
        20 permit tcp host 10.1.1.2 any eq 22 (8 matches)
        30 deny ip any any log

    Example output without sequence numbers (older devices):
    Extended IP access list VTY_Access
     permit tcp host 10.1.1.1 any eq 22
     permit tcp host 10.1.1.2 any eq 22 (15 matches)
     deny ip any any log
    """
    entries = []
    for line in output.splitlines():
        line = line.strip()
        # Skip header and empty lines
        if not line or line.startswith("Extended") or line.startswith("Standard"):
            continue

        # Remove match counter if present (e.g., " (8 matches)")
        # This appears at the end of ACL entries on some devices
        line = re.sub(r'\s*\(\d+\s+matches?\)\s*$', '', line, flags=re.IGNORECASE)

        # Try to remove sequence number (leading digits) if present
        # Format: "10 permit tcp host 10.1.1.1 any eq 22"
        match = re.match(r'^\d+\s+(.+)$', line)
        if match:
            # Has sequence number - extract entry without it and normalize
            entries.append(_normalize_acl_entry(match.group(1)))
        elif line.startswith(('permit', 'deny', 'remark')):
            # No sequence number (older device) - normalize and use
            entries.append(_normalize_acl_entry(line))

    return entries


def _get_vty_lines_with_acl(output: str, acl_name: str) -> List[str]:
    """
    Parse 'show run' output to find which VTY lines have the ACL applied.
    Returns list of VTY line ranges (e.g., ["0 4", "5 15"]).

    Works by scanning full 'show run' output for 'line vty' blocks and checking
    for 'access-class' commands within those blocks.
    """
    vty_lines = []
    current_vty = None
    in_vty_section = False

    for line in output.splitlines():
        stripped = line.strip()

        # Detect VTY line definition
        vty_match = re.match(r'^line vty (\d+)(?: (\d+))?', stripped)
        if vty_match:
            start = vty_match.group(1)
            end = vty_match.group(2) or start
            current_vty = f"{start} {end}"
            in_vty_section = True
            continue

        # Exit VTY section when we hit another config section or '!' delimiter
        if in_vty_section and (stripped.startswith('!') or
                               (stripped and not stripped.startswith(' ') and
                                not stripped.startswith('access-class') and
                                not stripped.startswith('exec-timeout') and
                                not stripped.startswith('logging') and
                                not stripped.startswith('transport'))):
            in_vty_section = False
            current_vty = None

        # Check if this VTY has the ACL
        if in_vty_section and current_vty and f"access-class {acl_name}" in stripped:
            if current_vty not in vty_lines:
                vty_lines.append(current_vty)

    return vty_lines


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
    Updates Cisco VTY ACL and returns a row dict in Result.result.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname

    # Initialize status variables
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
        logger.info(f"[{host}] Starting VTY ACL update for {ip} "
                   f"(platform: {platform}, device_type: {device_type}, port: {port}, "
                   f"enable_secret_configured: {has_secret})")
    else:
        logger.info(f"[{host}] Starting VTY ACL update for {ip} (platform: {platform})")

    try:
        # Load playbook configuration
        logger.info(f"[{host}] Loading playbook configuration...")
        playbook_acl = _load_playbook()

        if not playbook_acl:
            logger.warning(f"[{host}] No ACL configuration found in playbook")
            status = "FAIL"
            info_text = "No ACL configuration defined in playbook"
            raise Exception("Empty playbook configuration")

        # Extract desired ACL entries from playbook
        desired_entries = _extract_acl_entries(playbook_acl)
        logger.info(f"[{host}] Desired ACL has {len(desired_entries)} entries")

        # Explicitly enter enable mode for Cisco devices
        enable_secret = task.host.data.get("enable_secret")
        if enable_secret:
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
                        logger.info(f"[{host}] Waiting 15 seconds before retry...")
                        time.sleep(15)
                    else:  # Second attempt failed
                        # Enable mode failure is FATAL for Cisco
                        error_msg = f"Enable mode failed after 2 attempts: {str(e)}"
                        logger.error(f"[{host}] {error_msg}")
                        status = "FAIL"
                        info_text = f"Enable mode failed - check enable password. Error: {str(e)}"
                        raise Exception(error_msg)

            if not enable_success:
                raise Exception("Enable mode failed after retry")

        # Step 1: Check current ACL configuration
        logger.info(f"[{host}] Checking current ACL '{ACL_NAME}'...")
        r1 = task.run(
            task=netmiko_send_command,
            command_string=f"show access-lists {ACL_NAME}",
            name=f"Show ACL {ACL_NAME}",
            delay_factor=3,
            max_loops=500
        )
        current_acl_output = (_extract_text(r1) or "").strip()
        logger.info(f"[{host}] Current ACL output:\n{current_acl_output}")

        # Check if ACL exists
        acl_exists = ACL_NAME in current_acl_output or "access list" in current_acl_output.lower()

        if acl_exists:
            current_entries = _parse_current_acl(current_acl_output)
            logger.info(f"[{host}] Current ACL has {len(current_entries)} entries")
        else:
            current_entries = []
            logger.info(f"[{host}] ACL '{ACL_NAME}' does not exist on device")

        # Step 2: Check VTY lines configuration
        logger.info(f"[{host}] Checking VTY lines configuration...")
        r2 = task.run(
            task=netmiko_send_command,
            command_string="show run",
            name="Show running config",
            delay_factor=3,
            max_loops=500
        )
        vty_output = (_extract_text(r2) or "").strip()
        logger.info(f"[{host}] VTY configuration:\n{vty_output}")

        vty_lines_with_acl = _get_vty_lines_with_acl(vty_output, ACL_NAME)
        logger.info(f"[{host}] VTY lines with ACL '{ACL_NAME}': {vty_lines_with_acl}")

        # Step 3: Determine if update is needed
        # Compare current entries with desired entries
        current_set = set(current_entries)
        desired_set = set(desired_entries)

        acl_matches = (current_set == desired_set)
        vty_configured = len(vty_lines_with_acl) > 0

        logger.info(f"[{host}] Verification - ACL matches: {acl_matches}, VTY configured: {vty_configured}")
        logger.info(f"[{host}] Current entries count: {len(current_entries)}, Desired entries count: {len(desired_entries)}")

        # Log detailed comparison if counts match but sets don't
        if len(current_entries) == len(desired_entries) and not acl_matches:
            logger.warning(f"[{host}] Entry counts match but sets differ - investigating...")
            missing = desired_set - current_set
            extra = current_set - desired_set
            logger.warning(f"[{host}] Missing from device ({len(missing)}): {missing}")
            logger.warning(f"[{host}] Extra on device ({len(extra)}): {extra}")

            # Sample first few entries for whitespace debugging
            if current_entries and desired_entries:
                logger.debug(f"[{host}] Sample current[0]: repr={repr(current_entries[0])}")
                logger.debug(f"[{host}] Sample desired[0]: repr={repr(desired_entries[0])}")

        if acl_matches and vty_configured:
            logger.info(f"[{host}] VTY ACL is already up to date")
            status = "OK"
            info_text = "VTY ACL is already up to date"
        else:
            # Step 4: Apply configuration changes
            logger.info(f"[{host}] Applying VTY ACL configuration changes...")

            # Step 4a: Remove ACL from VTY lines (if it exists)
            if vty_lines_with_acl:
                logger.info(f"[{host}] Removing ACL from VTY lines: {vty_lines_with_acl}")
                for vty_line in vty_lines_with_acl:
                    remove_cmds = [
                        f"line vty {vty_line}",
                        f"no access-class {ACL_NAME} in"
                    ]
                    logger.debug(f"[{host}] Removing ACL from VTY {vty_line}")
                    task.run(
                        task=netmiko_send_config,
                        config_commands=remove_cmds,
                        name=f"Remove ACL from VTY {vty_line}",
                    )

            # Step 4b: Remove old ACL (if it exists)
            if acl_exists:
                logger.info(f"[{host}] Removing old ACL '{ACL_NAME}'...")
                task.run(
                    task=netmiko_send_config,
                    config_commands=[f"no ip access-list extended {ACL_NAME}"],
                    name=f"Remove old ACL {ACL_NAME}",
                )

            # Step 4c: Re-apply ACL from playbook
            logger.info(f"[{host}] Applying new ACL from playbook...")
            logger.debug(f"[{host}] ACL commands:\n" + "\n".join(playbook_acl))

            task.run(
                task=netmiko_send_config,
                config_commands=playbook_acl,
                name=f"Apply ACL {ACL_NAME}",
            )

            # Verify ACL was created correctly
            logger.info(f"[{host}] Verifying ACL configuration...")
            r3 = task.run(
                task=netmiko_send_command,
                command_string=f"show access-lists {ACL_NAME}",
                name=f"Verify ACL {ACL_NAME}",
                delay_factor=3,
                max_loops=500
            )
            verify_acl_output = (_extract_text(r3) or "").strip()
            logger.info(f"[{host}] Verification ACL output:\n{verify_acl_output}")

            verify_entries = _parse_current_acl(verify_acl_output)
            verify_acl_matches = (set(verify_entries) == desired_set)

            # Log the comparison for debugging
            logger.info(f"[{host}] Parsed verification entries ({len(verify_entries)}): {verify_entries}")
            logger.info(f"[{host}] Desired entries ({len(desired_entries)}): {desired_entries}")

            if not verify_acl_matches:
                # Log the differences
                missing = desired_set - set(verify_entries)
                extra = set(verify_entries) - desired_set
                logger.error(f"[{host}] ACL verification failed after applying configuration")
                logger.error(f"[{host}] Missing entries: {missing}")
                logger.error(f"[{host}] Extra entries: {extra}")
                status = "FAIL"
                info_text = "ACL verification failed after applying configuration"
                raise Exception("ACL verification failed")

            logger.info(f"[{host}] ACL verified successfully")

            # Step 4d: Re-apply ACL to VTY lines
            # Apply to standard VTY line ranges: 0 4 and 5 15
            vty_ranges = ["0 4", "5 15"]
            logger.info(f"[{host}] Applying ACL to VTY lines: {vty_ranges}")

            for vty_range in vty_ranges:
                apply_cmds = [
                    f"line vty {vty_range}",
                    f"access-class {ACL_NAME} in"
                ]
                logger.debug(f"[{host}] Applying ACL to VTY {vty_range}")
                task.run(
                    task=netmiko_send_config,
                    config_commands=apply_cmds,
                    name=f"Apply ACL to VTY {vty_range}",
                )

            # Step 4e: Exit config mode
            logger.info(f"[{host}] Exiting configuration mode...")
            task.run(
                task=netmiko_send_config,
                config_commands=["end"],
                name="Exit config mode",
            )

            # Step 5: Save configuration
            logger.info(f"[{host}] Saving configuration...")
            r4 = task.run(
                task=netmiko_send_command,
                command_string="write memory",
                name="Save configuration",
                delay_factor=3,
                max_loops=500
            )
            save_output = (_extract_text(r4) or "").strip()
            logger.info(f"[{host}] Save output: {save_output}")

            # Step 6: Final verification
            logger.info(f"[{host}] Performing final verification...")

            # Re-check ACL
            r5 = task.run(
                task=netmiko_send_command,
                command_string=f"show access-lists {ACL_NAME}",
                name=f"Final verify ACL {ACL_NAME}",
                delay_factor=3,
                max_loops=500
            )
            final_acl_output = (_extract_text(r5) or "").strip()
            final_entries = _parse_current_acl(final_acl_output)
            final_acl_matches = (set(final_entries) == desired_set)

            # Re-check VTY lines
            r6 = task.run(
                task=netmiko_send_command,
                command_string="show run",
                name="Final verify running config",
                delay_factor=3,
                max_loops=500
            )
            final_vty_output = (_extract_text(r6) or "").strip()
            final_vty_lines = _get_vty_lines_with_acl(final_vty_output, ACL_NAME)
            final_vty_configured = len(final_vty_lines) > 0

            logger.info(f"[{host}] Final verification - ACL matches: {final_acl_matches}, "
                       f"VTY configured: {final_vty_configured}, VTY lines: {final_vty_lines}")

            if final_acl_matches and final_vty_configured:
                logger.info(f"[{host}] Final verification successful - all configuration matches")
                status = "OK"
                info_text = "Update was successful"
            elif final_acl_matches and not final_vty_configured:
                logger.warning(f"[{host}] ACL matches playbook but was not applied to VTY lines")
                status = "OK"
                info_text = "VTY ACL updated, No VTY ACL was applied to VTY lines"
            else:
                logger.warning(f"[{host}] Final verification failed - config does not match playbook")
                status = "FAIL"
                info_text = "Update was unsuccessful, please check device"

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
        info_text = f"Update was unsuccessful - {sanitize_error_message(e)}"

    finally:
        # Always close the connection to prevent hung sessions
        try:
            logger.debug(f"[{host}] Closing netmiko connection...")
            task.host.close_connection("netmiko")
            logger.debug(f"[{host}] Connection closed successfully")
        except Exception as e:
            logger.warning(f"[{host}] Error closing connection: {str(e)}")

    # Build result row
    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),
        "status": status,
        "info": info_text,
    }

    return Result(host=task.host, changed=(status == "OK"), result=row)
