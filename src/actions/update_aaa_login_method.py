# src/actions/update_aaa_login_method.py
# Python 3.6+ / Nornir 2.5

"""
Update AAA login method on Cisco devices.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"/"SKIP"), info(<details>)

Steps performed on each device:
1. Skip Juniper devices (return SKIP)
2. Verify enable secret is configured on device (from playbooks/cisco_local_credentials.txt)
3. Load new AAA commands from playbooks/cisco_aaa_login_method.txt
4. Capture original AAA authentication config for rollback
5. Apply new AAA authentication login/enable commands
6. Test new local login by opening a second Netmiko session using new local password
   - If test FAILS: Revert AAA config to original config
   - If test PASSES: Proceed with cleanup
7. Remove all TACACS server commands found in show run
8. Remove password 7 from VTY lines 0 4 and 5 15
9. Verify TACACS is fully removed by opening a third session with local credentials
   and running 'show run'. Fail if output contains TACACS session error messages.
   - If verify FAILS: Revert ALL changes (AAA + TACACS + VTY password 7)
   - If verify PASSES: Save configuration
10. Save configuration
"""

import logging
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config

from src.utils.csv_sanitizer import sanitize_for_csv, sanitize_error_message
from src.utils.enable_mode import enter_enable_mode_robust

logger = logging.getLogger(__name__)


# --------------------------- Platform helpers ---------------------------

def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


# --------------------------- Playbook loading ---------------------------

def _load_enable_secret(playbook_path: str = "playbooks/cisco_local_credentials.txt") -> Optional[str]:
    """
    Load the enable secret from the credentials playbook.
    Looks for a line starting with 'enable secret'.
    Returns the plaintext password portion, or None if not found.
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
                match = re.match(r'^enable\s+secret\s+(\S+)', line, re.IGNORECASE)
                if match:
                    return match.group(1)
    except Exception as e:
        logger.error(f"Failed to load enable secret playbook: {str(e)}")

    return None


def _load_aaa_commands(playbook_path: str = "playbooks/cisco_aaa_login_method.txt") -> List[str]:
    """
    Load AAA authentication commands from playbook file.
    Returns list of command strings (one per line), skipping comments and empty lines.
    """
    project_root = Path(__file__).resolve().parents[2]
    full_path = project_root / playbook_path

    if not full_path.exists():
        logger.warning(f"Playbook file not found: {full_path}")
        return []

    commands = []
    try:
        with open(full_path, 'r') as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                commands.append(stripped)
        logger.info(f"Loaded {len(commands)} AAA command(s) from playbook")
    except Exception as e:
        logger.error(f"Failed to load AAA commands playbook: {str(e)}")

    return commands


# --------------------------- Config parsers ---------------------------

def _is_enable_secret_configured(output: str) -> bool:
    """
    Check whether 'enable secret' is present in show run output.
    We verify the line exists (trusting the enable login already succeeded).
    """
    for line in output.splitlines():
        if re.match(r'^\s*enable\s+secret\s+', line, re.IGNORECASE):
            return True
    return False


def _get_original_aaa_auth_config(output: str) -> List[str]:
    """
    Extract current 'aaa authentication login' and 'aaa authentication enable'
    commands from show run output. Used for potential rollback.
    """
    commands = []
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r'^aaa\s+authentication\s+(login|enable)\s+', stripped, re.IGNORECASE):
            commands.append(stripped)
    return commands


def _find_tacacs_commands(output: str) -> List[str]:
    """
    Find all 'tacacs-server host' and 'tacacs-server key' commands in show run.
    Returns full command lines so they can be prefixed with 'no'.
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


# --------------------------- Test session ---------------------------

def _test_local_login(
    host_name: str,
    ip: str,
    port: int,
    device_type: str,
    username: str,
    local_password: str,
    enable_secret: str,
) -> Tuple[bool, str]:
    """
    Open a second independent Netmiko session to verify local authentication works.
    Uses local_password as the login credential.
    Returns (success: bool, message: str).
    """
    # With 'aaa authentication login/enable default enable', the device uses the
    # enable password for BOTH login and enable mode. local_password is the
    # credential being tested end-to-end, so use it as both 'password' and 'secret'.
    # Using enable_secret here causes enable() to fail because the two credentials
    # may differ and the device is now configured to use local_password for enable.
    logger.debug(
        f"[{host_name}] _test_local_login params: device_type={device_type} port={port} "
        f"username={username!r} local_password_set={bool(local_password)} "
        f"enable_secret_set={bool(enable_secret)}"
    )

    conn_params = {
        "device_type": device_type,
        "host": ip,
        "username": username,
        "password": local_password,
        "secret": local_password,
        "port": port,
        "timeout": 30,
        "conn_timeout": 30,
    }

    # Add Telnet-specific timing for slow/old devices
    if "telnet" in device_type.lower():
        conn_params["global_delay_factor"] = 4
        conn_params["auth_timeout"] = 60
        conn_params["banner_timeout"] = 45
        conn_params["fast_cli"] = False

    try:
        logger.info(f"[{host_name}] Opening test session (local auth) to {ip}:{port}")
        net_connect = ConnectHandler(**conn_params)
        logger.debug(f"[{host_name}] Test session connected - attempting enable()")

        # Attempt to enter enable mode to fully verify credentials
        net_connect.enable()
        logger.debug(f"[{host_name}] Test session enable() succeeded")

        net_connect.disconnect()
        logger.info(f"[{host_name}] Test session successful - local authentication works")
        return True, "Local authentication test passed"

    except NetmikoAuthenticationException as e:
        logger.error(f"[{host_name}] Test session auth failed: {str(e)}", exc_info=True)
        return False, "Local authentication test failed - credentials rejected"

    except NetmikoTimeoutException as e:
        logger.error(f"[{host_name}] Test session timed out: {str(e)}", exc_info=True)
        return False, "Local authentication test failed - connection timed out"

    except Exception as e:
        logger.error(f"[{host_name}] Test session error: {str(e)}", exc_info=True)
        return False, f"Local authentication test failed - {str(e)}"


# TACACS error strings that indicate the session is still TACACS-controlled
_TACACS_ERROR_PATTERNS = [
    "TACACS+ session has expired",
    "Please re-login to continue",
    "% TACACS+ session",
    "TACACS+ server timeout",
    "Authorization failed",
]


def _test_local_show_run(
    host_name: str,
    ip: str,
    port: int,
    device_type: str,
    username: str,
    local_password: str,
    enable_secret: str,
) -> Tuple[bool, str]:
    """
    Open a new Netmiko session with local credentials and run 'show run'.
    Checks that the output is valid config and does NOT contain TACACS error
    messages (e.g. 'TACACS+ session has expired. Please re-login to continue.').

    Returns (success: bool, message: str).
    """
    # With 'aaa authentication login/enable default enable', local_password is used
    # for both login and enable mode - use it as both 'password' and 'secret'.
    logger.debug(
        f"[{host_name}] _test_local_show_run params: device_type={device_type} port={port} "
        f"username={username!r} local_password_set={bool(local_password)} "
        f"enable_secret_set={bool(enable_secret)}"
    )

    conn_params = {
        "device_type": device_type,
        "host": ip,
        "username": username,
        "password": local_password,
        "secret": local_password,
        "port": port,
        "timeout": 60,
        "conn_timeout": 30,
    }

    if "telnet" in device_type.lower():
        conn_params["global_delay_factor"] = 4
        conn_params["auth_timeout"] = 60
        conn_params["banner_timeout"] = 45
        conn_params["fast_cli"] = False

    try:
        logger.info(f"[{host_name}] Opening verification session (local auth) to {ip}:{port}")
        net_connect = ConnectHandler(**conn_params)
        logger.debug(f"[{host_name}] Verification session connected - attempting enable()")

        net_connect.enable()
        logger.debug(f"[{host_name}] Verification session enable() succeeded - running show run")

        output = net_connect.send_command(
            "show run",
            delay_factor=3,
            max_loops=500,
        )
        net_connect.disconnect()

        logger.debug(f"[{host_name}] Verification show run output ({len(output)} chars)")

        # Check for any known TACACS error patterns
        for pattern in _TACACS_ERROR_PATTERNS:
            if pattern.lower() in output.lower():
                logger.error(
                    f"[{host_name}] TACACS error detected in show run output: '{pattern}'"
                )
                return False, f"TACACS still active - '{pattern}' found in output"

        # Sanity check: output should contain real config content
        if not output or len(output.strip()) < 50:
            logger.error(f"[{host_name}] show run returned empty/unexpected output")
            return False, "show run returned empty or unexpected output - verify manually"

        logger.info(f"[{host_name}] Verification show run successful - no TACACS errors")
        return True, "Local session show run successful - TACACS not interfering"

    except NetmikoAuthenticationException as e:
        logger.error(f"[{host_name}] Verification session auth failed: {str(e)}", exc_info=True)
        return False, "Verification session failed - credentials rejected"

    except NetmikoTimeoutException as e:
        logger.error(f"[{host_name}] Verification session timed out: {str(e)}", exc_info=True)
        return False, "Verification session failed - connection timed out"

    except Exception as e:
        logger.error(f"[{host_name}] Verification session error: {str(e)}", exc_info=True)
        return False, f"Verification session failed - {str(e)}"


# ------------------------------- Action --------------------------------

def run(task: Task, pm=None) -> Result:
    """
    Entry point required by app_main.py.
    Updates AAA login method and verifies with a second test session.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname
    status = "FAIL"
    info_text = ""

    # Skip Juniper devices
    if _is_juniper(platform):
        logger.info(f"[{host}] Skipping - Juniper device (platform: {platform})")
        return Result(
            host=task.host,
            changed=False,
            result={
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "SKIP",
                "info": "Skipped Juniper device",
            }
        )

    # Skip non-Cisco devices
    if not _is_cisco(platform):
        logger.info(f"[{host}] Skipping - unsupported platform: {platform}")
        return Result(
            host=task.host,
            changed=False,
            result={
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "SKIP",
                "info": f"Skipped - unsupported platform: {platform}",
            }
        )

    # Gather credentials and connection info
    local_test_password = (task.host.data or {}).get("local_test_password", "")
    username = task.host.username or ""
    enable_secret = (task.host.data or {}).get("enable_secret", "")

    conn_opts = task.host.connection_options.get("netmiko")
    if conn_opts:
        device_type = conn_opts.extras.get("device_type", "cisco_ios")
        port = int(conn_opts.port) if conn_opts.port else 22
    else:
        device_type = "cisco_ios"
        port = 22

    # Log connection details
    logger.info(
        f"[{host}] Starting AAA login method update for {ip} "
        f"(platform: {platform}, device_type: {device_type}, port: {port})"
    )

    try:
        # Step 1: Load expected enable secret from playbook
        expected_secret = _load_enable_secret()
        if not expected_secret:
            status = "FAIL"
            info_text = "No enable secret found in playbooks/cisco_local_credentials.txt - cannot proceed"
            raise Exception("Enable secret not in playbook")

        logger.info(f"[{host}] Enable secret loaded from playbook")

        # Step 2: Load AAA commands from playbook
        aaa_commands = _load_aaa_commands()
        if not aaa_commands:
            status = "FAIL"
            info_text = "No AAA commands found in playbooks/cisco_aaa_login_method.txt - cannot proceed"
            raise Exception("AAA commands not in playbook")

        logger.info(f"[{host}] AAA commands loaded: {aaa_commands}")

        # Step 3: Early exit if auth test already confirmed local creds work.
        # Devices with 'aaa authentication login default enable' show only a Password:
        # prompt over Telnet — Netmiko can't handle that login flow, and the auth test
        # already verified the device is updated using raw telnetlib.  No point
        # attempting a Netmiko connection that will always fail.
        if (task.host.data or {}).get("local_creds_verified"):
            logger.info(
                f"[{host}] local_creds_verified flag set by auth test - "
                f"device is already updated, skipping Netmiko connection"
            )
            status = "OK"
            info_text = "Device is already updated"
            raise Exception("Device already updated - early exit")

        # Step 4: Enter enable mode
        # First attempt: use the startup credentials (normal TACACS flow).
        # If that fails the device may already be updated and using local auth -
        # fall back to local_test_password so re-runs against updated devices work.
        enable_success, enable_message = enter_enable_mode_robust(
            task=task,
            max_attempts=3,
            delay_between_attempts=15,
            force_new_connection=False
        )

        # After enter_enable_mode_robust, refresh device_type and port — the function
        # may have internally switched from SSH to Telnet (broken SSH stack fallback).
        conn_opts_after = task.host.connection_options.get("netmiko")
        if conn_opts_after:
            device_type = conn_opts_after.extras.get("device_type", device_type)
            port = int(conn_opts_after.port) if conn_opts_after.port else port

        if not enable_success:
            # --- Local credentials fallback ---
            # Startup credentials failed. Device may already be updated and only
            # accepting local (non-TACACS) credentials.
            logger.warning(
                f"[{host}] Enable mode failed with startup credentials - "
                f"device may already be updated. Trying local credentials..."
            )

            # Switch the host to use local_test_password for both login and enable,
            # close the existing connection so Nornir reopens with the new credentials.
            task.host.password = local_test_password
            task.host.data["enable_secret"] = local_test_password
            conn_opts_ref = task.host.connection_options.get("netmiko")
            if conn_opts_ref:
                conn_opts_ref.extras["secret"] = local_test_password

            try:
                task.host.close_connection("netmiko")
            except Exception:
                pass

            enable_success, enable_message = enter_enable_mode_robust(
                task=task,
                max_attempts=2,
                delay_between_attempts=5,
                force_new_connection=False
            )

            if not enable_success:
                status = "FAIL"
                info_text = (
                    f"Enable mode failed with both startup and local credentials. {enable_message}"
                )
                raise Exception(f"Enable mode failed: {enable_message}")

            # Local credentials worked - device is already updated. Return OK immediately.
            logger.info(f"[{host}] Local credentials accepted - device is already updated, skipping changes")
            status = "OK"
            info_text = "Device is already updated"
            raise Exception("Device already updated - early exit")

        # Step 5: Pull running configuration
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

        # Step 5: Verify enable secret is configured on device
        logger.info(f"[{host}] Verifying enable secret is configured on device...")
        if not _is_enable_secret_configured(running_config):
            status = "FAIL"
            info_text = "Expected enable secret is not configured, please update"
            logger.error(f"[{host}] {info_text}")
            raise Exception("Enable secret not found on device")

        logger.info(f"[{host}] Enable secret verified - safe to proceed")

        # Step 6: Capture original AAA config for potential rollback
        original_aaa_commands = _get_original_aaa_auth_config(running_config)
        logger.info(f"[{host}] Original AAA auth config captured: {original_aaa_commands}")

        # Step 7: Apply new AAA login method commands
        logger.info(f"[{host}] Applying new AAA login method commands...")
        logger.debug(f"[{host}] AAA commands:\n" + "\n".join(aaa_commands))

        task.run(
            task=netmiko_send_config,
            config_commands=aaa_commands,
            name="Apply AAA login method",
        )

        logger.info(f"[{host}] AAA commands applied - proceeding to test local login")

        # Step 8: Test local login with a new independent session
        logger.info(f"[{host}] Opening second session to test local authentication...")
        test_success, test_message = _test_local_login(
            host_name=host,
            ip=ip,
            port=port,
            device_type=device_type,
            username=username,
            local_password=local_test_password,
            enable_secret=enable_secret,
        )

        if not test_success:
            # Revert AAA config to original using the still-open primary session
            logger.warning(f"[{host}] Local auth test failed - reverting AAA config to original...")

            if original_aaa_commands:
                revert_commands = original_aaa_commands
                logger.info(f"[{host}] Reverting with original commands: {revert_commands}")
            else:
                # No original AAA commands existed - remove what we added
                revert_commands = [f"no {cmd}" for cmd in aaa_commands]
                logger.info(f"[{host}] No original AAA found - negating applied commands")

            try:
                task.run(
                    task=netmiko_send_config,
                    config_commands=revert_commands,
                    name="Revert AAA config",
                )
                logger.info(f"[{host}] AAA config reverted successfully")
                revert_info = "AAA config reverted to original"
            except Exception as revert_err:
                logger.error(f"[{host}] Revert failed: {str(revert_err)}")
                revert_info = "WARNING: Revert may have failed - check device manually"

            status = "FAIL"
            info_text = f"Local auth test failed - {test_message}; {revert_info}"
            raise Exception("Local auth test failed - changes reverted")

        logger.info(f"[{host}] Local auth test passed - proceeding with TACACS/VTY cleanup")

        # Step 9: Find TACACS and password 7 entries to remove
        tacacs_commands = _find_tacacs_commands(running_config)
        vty_password7_entries = _find_vty_password7_commands(running_config)

        logger.info(f"[{host}] TACACS commands to remove: {len(tacacs_commands)}")
        logger.info(f"[{host}] VTY password 7 entries to remove: {len(vty_password7_entries)}")

        cleanup_commands = []

        if tacacs_commands:
            logger.info(f"[{host}] Adding removal of {len(tacacs_commands)} TACACS command(s)")
            for cmd in tacacs_commands:
                cleanup_commands.append(f"no {cmd}")

        if vty_password7_entries:
            logger.info(f"[{host}] Adding removal of password 7 from VTY lines")
            for vty_range, pw_cmd in vty_password7_entries:
                cleanup_commands.append(f"line vty {vty_range}")
                cleanup_commands.append(f"no {pw_cmd}")

        if cleanup_commands:
            logger.info(f"[{host}] Applying {len(cleanup_commands)} cleanup command(s)...")
            logger.debug(f"[{host}] Cleanup commands:\n" + "\n".join(cleanup_commands))
            task.run(
                task=netmiko_send_config,
                config_commands=cleanup_commands,
                name="Remove TACACS and VTY password 7",
            )
        else:
            logger.info(f"[{host}] No TACACS or VTY password 7 entries found - nothing to clean up")

        # Step 10: Verify TACACS fully removed by running show run via a new local session
        logger.info(f"[{host}] Opening verification session to confirm TACACS is not interfering...")
        verify_success, verify_message = _test_local_show_run(
            host_name=host,
            ip=ip,
            port=port,
            device_type=device_type,
            username=username,
            local_password=local_test_password,
            enable_secret=enable_secret,
        )

        if not verify_success:
            # Full revert: restore AAA, TACACS, and VTY password 7 on the primary session
            logger.warning(f"[{host}] Verification failed - reverting all config changes...")

            revert_all = []

            # Restore original AAA authentication commands
            if original_aaa_commands:
                revert_all.extend(original_aaa_commands)
            else:
                revert_all.extend([f"no {cmd}" for cmd in aaa_commands])

            # Re-add removed TACACS commands
            if tacacs_commands:
                revert_all.extend(tacacs_commands)

            # Re-add removed VTY password 7 entries
            if vty_password7_entries:
                for vty_range, pw_cmd in vty_password7_entries:
                    revert_all.append(f"line vty {vty_range}")
                    revert_all.append(pw_cmd)

            logger.debug(f"[{host}] Full revert commands:\n" + "\n".join(revert_all))

            try:
                task.run(
                    task=netmiko_send_config,
                    config_commands=revert_all,
                    name="Full revert - all changes",
                )
                logger.info(f"[{host}] All changes reverted successfully")
                revert_info = "All config changes reverted"
            except Exception as revert_err:
                logger.error(f"[{host}] Full revert failed: {str(revert_err)}")
                revert_info = "WARNING: Full revert may have failed - check device manually"

            status = "FAIL"
            info_text = f"Post-cleanup verification failed - {verify_message}; {revert_info}"
            raise Exception("TACACS verification failed - all changes reverted")

        logger.info(f"[{host}] Verification passed - TACACS confirmed removed, proceeding to save")

        # Step 11: Save configuration
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

        # Build result summary
        summary_parts = ["AAA login method updated", "Local auth test passed"]
        if tacacs_commands:
            summary_parts.append(f"{len(tacacs_commands)} TACACS command(s) removed")
        else:
            summary_parts.append("No TACACS commands found")
        if vty_password7_entries:
            vty_ranges = sorted(set(vr for vr, _ in vty_password7_entries))
            summary_parts.append(f"Password 7 removed from VTY line(s): {', '.join(vty_ranges)}")
        else:
            summary_parts.append("No VTY password 7 found")

        status = "OK"
        info_text = "; ".join(summary_parts)
        logger.info(f"[{host}] Update complete - {info_text}")

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
            info_text = f"Update failed - {sanitize_error_message(e)}"

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
