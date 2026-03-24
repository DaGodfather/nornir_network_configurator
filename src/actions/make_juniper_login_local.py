# src/actions/make_juniper_login_local.py
# Python 3.6+ / Nornir 2.5

"""
Switch Juniper devices from TACACS to local authentication.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"/"SKIP"), info(<details>)

Steps performed on each device:
1. Skip non-Juniper devices (return SKIP)
2. Early exit if auth test already confirmed local creds work (local_creds_verified)
3. Load expected encrypted passwords from playbooks/juniper_local_credentials.txt
4. Connect and run 'show version' to detect JunOS major version
5. Determine version-correct hash format (< 15 → $1$, >= 15 → $5$)
6. Verify that the version-correct hash entries exist in device's running config
   - If missing or wrong hash format: FAIL without making any changes
   - This prevents removing TACACS if credentials were not properly updated first
7. Capture original authentication config for logging/reference
8. Open a SECOND session with local Juniper credentials to verify login works
   (tested WHILE TACACS is still active — avoids the stale-connection problem
   of the old 'commit confirmed + second session + confirming commit' flow)
   - FAIL: abort without touching the config
   - PASS: proceed
9. Enter config mode, delete TACACS config, commit:
     delete system authentication-order
     delete system tacplus-server
     delete system accounting
     commit
10. Return status

Fallback behavior:
- If initial connection with TACACS credentials fails and local Juniper credentials
  are provided, retry with local credentials. If that succeeds, the device is
  already updated - return OK immediately.
"""

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command

from src.utils.csv_sanitizer import sanitize_error_message
from src.utils.transport_discovery import apply_conn

logger = logging.getLogger(__name__)


# --------------------------- Platform helpers ---------------------------

def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


# --------------------------- Version / hash helpers ---------------------------

def _detect_junos_major_version(show_version_output: str) -> Optional[int]:
    """
    Extract the JunOS major version number from 'show version' output.
    Returns the integer major version (e.g. 12, 15) or None if not found.
    """
    match = re.search(r'[Jj][Uu][Nn][Oo][Ss][^\d]*(\d+)\.', show_version_output)
    if match:
        return int(match.group(1))
    return None


def _hash_prefix_for_version(major_version: int) -> str:
    """
    Return the correct encrypted-password hash prefix for the given JunOS major version.

      JunOS < 15  →  $1$  (MD5-crypt)
      JunOS >= 15 →  $5$  (SHA-256)

    This is authoritative — do not rely on what hash is currently in the device config,
    as a prior push may have placed the wrong format on the device.
    """
    if major_version < 15:
        return "$1$"
    return "$5$"


def _filter_by_hash_prefix(entries: List[str], hash_prefix: str) -> List[str]:
    """Return only the entries whose encrypted-password hash starts with hash_prefix."""
    filtered = []
    for entry in entries:
        match = re.search(r'encrypted-password\s+"?(\$\w+\$)', entry)
        if match:
            if match.group(1).startswith(hash_prefix):
                filtered.append(entry)
        else:
            filtered.append(entry)
    return filtered


# --------------------------- Playbook loading ---------------------------

def _load_playbook(
    playbook_path: str = "playbooks/juniper_local_credentials.txt",
) -> List[str]:
    """
    Load Juniper credential verification entries from the playbook.

    Expected format (JunOS 'set' commands, one per line):
        set system root-authentication encrypted-password "$6$..."
        set system login user <name> authentication encrypted-password "$6$..."

    Returns a list of stripped command strings (comments/blank lines excluded).
    """
    project_root = Path(__file__).resolve().parents[2]
    full_path = project_root / playbook_path

    if not full_path.exists():
        logger.warning(f"Playbook not found: {full_path}")
        return []

    entries = []
    try:
        with open(full_path, "r") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                entries.append(stripped)
        logger.info(f"Loaded {len(entries)} entry/entries from {playbook_path}")
    except Exception as e:
        logger.error(f"Failed to load Juniper playbook: {str(e)}")

    return entries


# --------------------------- Credential verification ---------------------------

def _extract_credential_key(entry: str) -> str:
    """
    Extract the credential path without the hash value.
    e.g. 'set system root-authentication encrypted-password "$6$..."'
      -> 'set system root-authentication encrypted-password'
    """
    match = re.match(r'(.+?encrypted-password)\s+', entry.strip())
    if match:
        return match.group(1).strip()
    return entry.strip()


def _verify_credentials(show_output: str, playbook_entries: List[str]) -> Tuple[bool, List[str]]:
    """
    Verify that at least one playbook entry per credential key is present on the device.

    Groups entries by credential key so that a playbook containing both $1$ (MD5) and
    $6$ (SHA-512) hashes for the same credential passes as long as one of them matches —
    i.e. the device has the correct hash for its JunOS version, regardless of which
    other versions are also in the file.

    Returns (all_present: bool, list_of_credential_keys_with_no_match).
    """
    config_lines = [" ".join(l.split()) for l in show_output.splitlines()]

    # Group entries by key
    key_to_entries = {}  # type: Dict[str, List[str]]
    for entry in playbook_entries:
        key = _extract_credential_key(entry)
        if key not in key_to_entries:
            key_to_entries[key] = []
        key_to_entries[key].append(entry)

    missing_keys = []
    for key, entries in key_to_entries.items():
        found = False
        for entry in entries:
            normalized = " ".join(entry.split())
            if any(normalized in line for line in config_lines):
                found = True
                break
        if not found:
            missing_keys.append(key)

    return (len(missing_keys) == 0), missing_keys


# --------------------------- Test session ---------------------------

def _test_local_login(
    host_name: str,
    ip: str,
    port: int,
    device_type: str,
    username: str,
    password: str,
) -> Tuple[bool, str]:
    """
    Open an independent Netmiko session to verify local credentials work on the device.
    Juniper has no enable mode - a successful connection + simple command is enough.

    Returns (success: bool, message: str).
    """
    conn_params = {
        "device_type": device_type,
        "host": ip,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
        "conn_timeout": 30,
    }

    try:
        logger.info(
            f"[{host_name}] Opening local-auth test session to {ip}:{port} "
            f"as user '{username}'"
        )
        net_connect = ConnectHandler(**conn_params)

        output = net_connect.send_command("show version", delay_factor=2)
        net_connect.disconnect()

        if output and len(output.strip()) > 10:
            logger.info(f"[{host_name}] Local-auth test session PASSED")
            return True, "Local authentication test passed"
        else:
            logger.error(f"[{host_name}] Local-auth test: 'show version' returned empty output")
            return False, "Local authentication test failed - show version returned empty output"

    except NetmikoAuthenticationException as e:
        logger.error(f"[{host_name}] Local-auth test: authentication rejected: {str(e)}")
        return False, "Local authentication test failed - credentials rejected"

    except NetmikoTimeoutException as e:
        logger.error(f"[{host_name}] Local-auth test: connection timed out: {str(e)}")
        return False, "Local authentication test failed - connection timed out"

    except Exception as e:
        logger.error(f"[{host_name}] Local-auth test error: {str(e)}", exc_info=True)
        return False, f"Local authentication test failed - {str(e)}"


# ------------------------------- Action --------------------------------

def run(task: Task, pm=None) -> Result:
    """
    Entry point required by app_main.py.
    Switches Juniper device from TACACS to local authentication.
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname
    status = "FAIL"
    info_text = ""

    # Only run on Juniper devices
    if not _is_juniper(platform):
        logger.info(f"[{host}] Skipping - not a Juniper device (platform: {platform})")
        return Result(
            host=task.host,
            changed=False,
            result={
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "SKIP",
                "info": f"Not a Juniper device - skipped (platform: {platform})",
            },
        )

    # Gather credentials and connection info
    local_juniper_username = (task.host.data or {}).get("local_juniper_username", "")
    local_juniper_password = (task.host.data or {}).get("local_juniper_password", "")

    conn_opts = task.host.connection_options.get("netmiko")
    if conn_opts:
        device_type = conn_opts.extras.get("device_type", "juniper")
        port = int(conn_opts.port) if conn_opts.port else 22
    else:
        device_type = "juniper"
        port = 22

    logger.info(
        f"[{host}] Starting make_juniper_login_local for {ip} "
        f"(platform: {platform}, device_type: {device_type}, port: {port})"
    )

    conn = None

    try:
        # Step 1: Early exit if auth test already confirmed local creds work
        if (task.host.data or {}).get("local_creds_verified"):
            logger.info(
                f"[{host}] local_creds_verified flag set by auth test - "
                f"device is already updated, skipping"
            )
            status = "OK"
            info_text = "Device is already updated"
            raise Exception("Device already updated - early exit")

        # Step 2: Load playbook entries
        playbook_entries = _load_playbook()
        if not playbook_entries:
            status = "FAIL"
            info_text = (
                "No credentials found in playbooks/juniper_local_credentials.txt - cannot proceed"
            )
            raise Exception("Empty Juniper playbook")

        # Step 3: Connect - try TACACS credentials first, fall back to local if they fail
        # Always force device_type=juniper regardless of what transport_cache.json says.
        # bootstrap_transport may have cached cisco_ios for this host if the platform was
        # not recognised at discovery time, causing config_mode() to call the Cisco handler.
        apply_conn(task.host, "juniper", port)
        try:
            conn = task.host.get_connection("netmiko", task.nornir.config)
            logger.info(f"[{host}] Connected with primary (TACACS) credentials")
        except Exception as primary_err:
            logger.error(f"[{host}] Primary credential connection failed: {str(primary_err)}")

            if local_juniper_username and local_juniper_password:
                logger.warning(
                    f"[{host}] Retrying with local Juniper credentials - "
                    f"device may already be updated"
                )
                task.host.username = local_juniper_username
                task.host.password = local_juniper_password
                apply_conn(task.host, "juniper", port)

                try:
                    conn = task.host.get_connection("netmiko", task.nornir.config)
                    logger.info(
                        f"[{host}] Connected with local credentials - device is already updated"
                    )
                    status = "OK"
                    info_text = "Device is already updated"
                    raise Exception("Device already updated - early exit")
                except Exception as local_err:
                    if str(local_err) == "Device already updated - early exit":
                        raise
                    status = "FAIL"
                    info_text = (
                        "Connection failed with both TACACS and local credentials: "
                        + sanitize_error_message(local_err)
                    )
                    raise Exception(f"Connection failed: {str(local_err)}")
            else:
                status = "FAIL"
                info_text = "Connection failed: " + sanitize_error_message(primary_err)
                raise Exception(f"Connection failed: {str(primary_err)}")

        # Step 4: Detect JunOS version — required to select correct hash format
        logger.info(f"[{host}] Detecting JunOS version...")
        show_ver = conn.send_command("show version", delay_factor=2)
        logger.debug(f"[{host}] show version output:\n{show_ver[:300]}")

        major_version = _detect_junos_major_version(show_ver)
        if major_version is None:
            status = "FAIL"
            info_text = "Could not detect JunOS version from 'show version' output"
            raise Exception("JunOS version detection failed")

        hash_prefix = _hash_prefix_for_version(major_version)
        hash_label = "$1$ (MD5-crypt)" if hash_prefix == "$1$" else "$5$ (SHA-256)"
        logger.info(f"[{host}] Detected JunOS {major_version}.x → expecting {hash_label} credentials")

        # Filter playbook entries to those matching the version-correct hash format
        version_entries = _filter_by_hash_prefix(playbook_entries, hash_prefix)
        if not version_entries:
            status = "FAIL"
            info_text = (
                f"No playbook entries found for JunOS {major_version}.x ({hash_label}). "
                f"Add {hash_prefix} hashes to playbooks/juniper_local_credentials.txt"
            )
            raise Exception("No matching playbook entries for device version")

        # Step 5: Verify version-correct hashes exist in device config
        logger.info(f"[{host}] Verifying {hash_label} credentials exist in device config...")
        show_output = conn.send_command(
            "show configuration system | display set",
            delay_factor=2,
        )
        logger.debug(f"[{host}] show configuration system output:\n{show_output[:500]}")

        all_present, missing = _verify_credentials(show_output, version_entries)
        if not all_present:
            status = "FAIL"
            missing_short = "; ".join(
                re.sub(r'encrypted-password\s+"\S+"', 'encrypted-password "<hidden>"', m)
                for m in missing
            )
            info_text = (
                f"Credential verification failed for JunOS {major_version}.x ({hash_label}) — "
                f"run update_juniper_local_credential first. Missing: {missing_short}"
            )
            logger.error(f"[{host}] Credential verification failed. Missing:\n" +
                         "\n".join(f"  {m}" for m in missing))
            raise Exception("Credential verification failed - aborting to protect access")

        logger.info(f"[{host}] Local credentials verified on device")

        # Step 5: Capture original auth config for logging/reference
        original_auth_lines = [
            line.strip()
            for line in show_output.splitlines()
            if re.search(
                r"(authentication-order|tacplus-server|accounting)", line, re.IGNORECASE
            )
        ]
        logger.info(
            f"[{host}] Original auth-related config ({len(original_auth_lines)} lines):\n"
            + "\n".join(f"  {l}" for l in original_auth_lines)
        )

        # Step 6: Test local credentials in a second session BEFORE making any changes.
        # Testing while TACACS is still active means:
        #   - A pass here guarantees local auth will work after TACACS is removed.
        #   - We avoid the stale-connection problem that plagued the old
        #     "commit confirmed 10 → test → confirming commit" flow, where the
        #     original session could go idle during the test and silently drop the
        #     confirming commit, causing every device to auto-revert.
        logger.info(
            f"[{host}] Testing local credentials in second session (TACACS still active)..."
        )
        test_ok, test_msg = _test_local_login(
            host, ip, port, device_type,
            local_juniper_username, local_juniper_password,
        )

        if not test_ok:
            status = "FAIL"
            info_text = (
                f"Local credential test failed — aborting without config changes. "
                f"Reason: {test_msg}"
            )
            raise Exception(f"Local auth test failed (pre-change): {test_msg}")

        logger.info(f"[{host}] Local credential test PASSED — proceeding with config changes")

        # Step 7: Enter config mode, delete TACACS config, commit
        logger.info(f"[{host}] Entering configuration mode...")
        conn.config_mode()

        delete_cmds = [
            "delete system authentication-order",
            "delete system tacplus-server",
            "delete system accounting",
        ]
        for cmd in delete_cmds:
            out = conn.send_command_timing(cmd, delay_factor=2)
            logger.debug(f"[{host}] '{cmd}' => {out.strip()[:120]}")

        logger.info(f"[{host}] Committing config changes...")
        commit_out = conn.send_command_timing("commit", delay_factor=8)
        logger.info(f"[{host}] Commit output: {commit_out.strip()[:300]}")

        if "error" in commit_out.lower() and "commit complete" not in commit_out.lower():
            logger.error(f"[{host}] Commit failed - rolling back")
            conn.send_command_timing("rollback 0", delay_factor=2)
            conn.exit_config_mode()
            status = "FAIL"
            info_text = f"Commit failed: {commit_out.strip()[:200]}"
            raise Exception("Commit failed")

        conn.exit_config_mode()
        status = "OK"
        info_text = "TACACS removed, local authentication active and confirmed"
        logger.info(f"[{host}] make_juniper_login_local completed successfully")

    except Exception as e:
        error_str = str(e)
        # Expected early-exit exceptions - not real errors
        if error_str in ("Device already updated - early exit",):
            logger.info(f"[{host}] {error_str}")
        elif not any(
            skip in error_str
            for skip in (
                "Commit failed",
                "Credential verification failed",
                "Connection failed",
                "Empty Juniper playbook",
                "Local auth test failed",
                "JunOS version detection failed",
                "No matching playbook entries",
            )
        ):
            logger.error(f"[{host}] Unexpected error: {error_str}", exc_info=True)
            if not info_text:
                info_text = sanitize_error_message(e)

    finally:
        try:
            logger.debug(f"[{host}] Closing netmiko connection...")
            task.host.close_connection("netmiko")
        except Exception:
            pass

    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),
        "status": status,
        "info": info_text,
    }

    return Result(host=task.host, changed=(status == "OK"), result=row)
