# src/actions/update_cisco_local_credentials.py
# Python 3.6+ / Nornir 2.5

"""
Update Cisco local credentials based on playbook configuration.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"), info(<status message>)

Behavior:
1) Read desired credentials from playbooks/cisco_local_credentials.txt
2) Verify current configuration against playbook
3) Update enable secret if needed
4) Remove old/unwanted usernames
5) Add correct usernames with proper hashed passwords
6) Save configuration and verify
7) Return status based on verification
"""

import logging
import time
import re
from pathlib import Path
from typing import List, Dict, Tuple
from src.utils.csv_sanitizer import sanitize_error_message
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config
from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

# Initialize logger
logger = logging.getLogger(__name__)

# --------------------------- Platform helpers ---------------------------

def _is_cisco(platform):
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


def _load_playbook(playbook_path: str = "playbooks/cisco_local_credentials.txt") -> Dict[str, List[str]]:
    """
    Load and parse the playbook file.
    Returns a dict with:
    - 'enable_secret': list of enable secret commands
    - 'usernames': list of username commands
    - 'other': list of other configuration commands (password policy, etc.)
    """
    config = {
        'enable_secret': [],
        'usernames': [],
        'other': []
    }

    project_root = Path(__file__).resolve().parents[2]
    full_path = project_root / playbook_path

    if not full_path.exists():
        logger.warning(f"Playbook file not found: {full_path}")
        return config

    try:
        with open(full_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Categorize commands
                if line.startswith('enable secret'):
                    config['enable_secret'].append(line)
                elif line.startswith('username '):
                    config['usernames'].append(line)
                else:
                    config['other'].append(line)

        logger.info(f"Loaded playbook: {len(config['enable_secret'])} enable secrets, "
                   f"{len(config['usernames'])} usernames, {len(config['other'])} other commands")
    except Exception as e:
        logger.error(f"Failed to load playbook: {str(e)}")

    return config


def _extract_usernames_from_playbook(username_commands: List[str]) -> List[str]:
    """
    Extract just the username portion from username commands.
    Example: "username admin privilege 15 secret hash" -> "admin"
    """
    usernames = []
    for cmd in username_commands:
        match = re.match(r'username\s+(\S+)', cmd)
        if match:
            usernames.append(match.group(1))
    return usernames


def _parse_current_usernames(output: str) -> List[str]:
    """
    Parse 'show run | i privilege 15' output to extract usernames.
    Example line: "username admin privilege 15 secret 5 $1$abc..."
    """
    usernames = []
    for line in output.splitlines():
        line = line.strip()
        if 'username ' in line and 'privilege 15' in line:
            match = re.match(r'username\s+(\S+)', line)
            if match:
                usernames.append(match.group(1))
    return usernames


def _verify_enable_secret(output: str, playbook_config: Dict) -> bool:
    """
    Verify if enable secret is configured.
    We can't verify the actual hash matches due to encryption,
    but we can verify it exists.
    """
    if not playbook_config['enable_secret']:
        return True  # No enable secret required

    # Check if 'enable secret' appears in the output
    for line in output.splitlines():
        if line.strip().startswith('enable secret'):
            return True

    return False


def _verify_usernames(output: str, playbook_config: Dict) -> Tuple[bool, List[str], List[str]]:
    """
    Verify usernames match the playbook.
    Returns: (all_match, missing_users, extra_users)
    """
    desired_users = set(_extract_usernames_from_playbook(playbook_config['usernames']))
    current_users = set(_parse_current_usernames(output))

    missing_users = list(desired_users - current_users)
    extra_users = list(current_users - desired_users)

    all_match = (len(missing_users) == 0 and len(extra_users) == 0)

    return all_match, missing_users, extra_users


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
    Updates Cisco local credentials and returns a row dict in Result.result.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname

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
        logger.info(f"[{host}] Starting local credentials update for {ip} "
                   f"(platform: {platform}, device_type: {device_type}, port: {port}, "
                   f"enable_secret_configured: {has_secret})")
    else:
        logger.info(f"[{host}] Starting local credentials update for {ip} (platform: {platform})")

    try:
        # Load playbook configuration
        logger.info(f"[{host}] Loading playbook configuration...")
        playbook_config = _load_playbook()

        if not playbook_config['usernames'] and not playbook_config['enable_secret']:
            logger.warning(f"[{host}] No credentials found in playbook")
            status = "FAIL"
            info_text = "No credentials defined in playbook"
            raise Exception("Empty playbook configuration")

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

        # Step 1: Get current configuration - check for existing usernames with privilege 15
        logger.info(f"[{host}] Checking current privilege 15 usernames...")
        r1 = task.run(
            task=netmiko_send_command,
            command_string="show run | i privilege 15",
            name="Show current privilege 15 users",
            delay_factor=2,
            max_loops=500
        )
        current_priv15_output = (_extract_text(r1) or "").strip()
        logger.info(f"[{host}] Current privilege 15 users:\n{current_priv15_output}")

        # Step 2: Get current secret configuration
        logger.info(f"[{host}] Checking current secret configuration...")
        r2 = task.run(
            task=netmiko_send_command,
            command_string="show run | i secret",
            name="Show current secrets",
            delay_factor=2,
            max_loops=500
        )
        current_secrets_output = (_extract_text(r2) or "").strip()
        logger.info(f"[{host}] Current secrets configuration:\n{current_secrets_output}")

        # Step 3: Verify if update is needed
        enable_match = _verify_enable_secret(current_secrets_output, playbook_config)
        users_match, missing_users, extra_users = _verify_usernames(
            current_priv15_output, playbook_config
        )

        logger.info(f"[{host}] Verification - Enable secret exists: {enable_match}, "
                   f"Users match: {users_match}, Missing: {missing_users}, Extra: {extra_users}")

        if enable_match and users_match:
            logger.info(f"[{host}] Local credentials are already up to date")
            status = "OK"
            info_text = "Local credentials are already up to date"
        else:
            # Step 4: Apply configuration changes
            logger.info(f"[{host}] Applying configuration changes...")
            config_commands = []

            # Add enable secret if defined (this can overwrite existing)
            if playbook_config['enable_secret']:
                config_commands.extend(playbook_config['enable_secret'])
                logger.info(f"[{host}] Adding enable secret command")

            # Remove old/unwanted usernames (those not in playbook)
            current_users = _parse_current_usernames(current_priv15_output)
            desired_users = _extract_usernames_from_playbook(playbook_config['usernames'])

            for user in current_users:
                if user not in desired_users:
                    config_commands.append(f"no username {user}")
                    logger.info(f"[{host}] Removing old username: {user}")

            # Add correct usernames from playbook
            config_commands.extend(playbook_config['usernames'])
            logger.info(f"[{host}] Adding {len(playbook_config['usernames'])} username(s)")

            # Add other configuration (password policy, etc.)
            if playbook_config['other']:
                config_commands.extend(playbook_config['other'])
                logger.info(f"[{host}] Adding {len(playbook_config['other'])} other config command(s)")

            logger.info(f"[{host}] Sending {len(config_commands)} configuration commands...")
            logger.debug(f"[{host}] Commands to send:\n" + "\n".join(config_commands))

            # Send configuration
            r3 = task.run(
                task=netmiko_send_config,
                config_commands=config_commands,
                name="Apply credential configuration",
            )
            logger.info(f"[{host}] Configuration commands sent")

            # Step 5: Save configuration
            logger.info(f"[{host}] Saving configuration...")
            r4 = task.run(
                task=netmiko_send_command,
                command_string="write memory",
                name="Save configuration",
                delay_factor=2,
                max_loops=500
            )
            save_output = (_extract_text(r4) or "").strip()
            logger.info(f"[{host}] Save output: {save_output}")

            # Step 6: Verify configuration was applied correctly
            logger.info(f"[{host}] Verifying configuration...")

            # Re-check privilege 15 users
            r5 = task.run(
                task=netmiko_send_command,
                command_string="show run | i privilege 15",
                name="Verify privilege 15 users",
                delay_factor=2,
                max_loops=500
            )
            verify_priv15_output = (_extract_text(r5) or "").strip()

            # Re-check secrets
            r6 = task.run(
                task=netmiko_send_command,
                command_string="show run | i secret",
                name="Verify secrets",
                delay_factor=2,
                max_loops=500
            )
            verify_secrets_output = (_extract_text(r6) or "").strip()

            logger.info(f"[{host}] Verification - Privilege 15 users:\n{verify_priv15_output}")
            logger.info(f"[{host}] Verification - Secrets:\n{verify_secrets_output}")

            # Verify results
            enable_verified = _verify_enable_secret(verify_secrets_output, playbook_config)
            users_verified, missing_after, extra_after = _verify_usernames(
                verify_priv15_output, playbook_config
            )

            if enable_verified and users_verified:
                logger.info(f"[{host}] Verification successful - all credentials match")
                status = "OK"
                info_text = "Update was successful"
            else:
                logger.warning(f"[{host}] Verification failed - config does not match playbook. "
                             f"Enable: {enable_verified}, Users: {users_verified}, "
                             f"Missing: {missing_after}, Extra: {extra_after}")
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
