# src/actions/update_juniper_local_credential.py
# Python 3.6+ / Nornir 2.5

"""
Update local credentials (root-authentication and user encrypted-passwords) on
Juniper devices. Automatically selects the correct hash format for the device's
JunOS version from a single playbook file.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("OK"/"FAIL"/"SKIP"), info(<details>)

JunOS encryption formats (selected by version — authoritative):
  JunOS < 15   →  $1$  MD5-crypt  (12.x, 13.x, 14.x)
  JunOS >= 15  →  $5$  SHA-256    (15.x)

  The version determines which hash format SHOULD be on the device, not what IS
  there. A device may have a wrong-format hash in its config from a prior push —
  this action detects and corrects that by forcing the version-correct format.

Playbook format (playbooks/juniper_local_credentials.txt):
  Include entries for all hash versions you need to support. The action reads the
  device's current config to detect which hash format it uses ($1$, $5$, or $6$),
  then picks only those entries from the playbook.

  Example (multiple versions in one file):
    # SHA-512 for newer JunOS 15+
    set system root-authentication encrypted-password "$6$sha512hash..."
    set system login user netops authentication encrypted-password "$6$sha512hash..."
    # SHA-256 for some JunOS 15.x
    set system root-authentication encrypted-password "$5$sha256hash..."
    set system login user netops authentication encrypted-password "$5$sha256hash..."
    # MD5 for JunOS 12.x / 13.x / 14.x
    set system root-authentication encrypted-password "$1$md5hash..."
    set system login user netops authentication encrypted-password "$1$md5hash..."

Steps performed on each device:
1. Skip non-Juniper devices (return SKIP)
2. Early exit if local_creds_verified flag set
3. Load playbook entries from playbooks/juniper_local_credentials.txt
4. Force device_type=juniper and connect (TACACS first, local creds fallback)
5. Run 'show version' to detect JunOS major version (required)
6. Determine correct hash format from version (< 15 → $1$, >= 15 → $5$)
7. Run 'show configuration system | display set' to get current config
   - Warn if device's current hash format doesn't match the version-required format
8. Filter playbook entries to those matching the version-required hash format
9. Verify all target usernames already exist on device
   - root: always present
   - other users: must already have a 'set system login user <name>' entry
10. Compare current hashes vs playbook hashes
    - All match → return OK 'Already up to date'
11. Build set commands and apply:
    - set system root-authentication encrypted-password "<new_hash>"
    - set system login user <name> authentication encrypted-password "<new_hash>"
    - commit
12. Re-run 'show configuration system | display set' and verify hashes updated
13. Return status
"""

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command

from src.utils.csv_sanitizer import sanitize_error_message
from src.utils.transport_discovery import apply_conn

logger = logging.getLogger(__name__)

# Hash prefix → human-readable label
_HASH_LABELS = {
    "$6$": "SHA-512",
    "$5$": "SHA-256",
    "$1$": "MD5-crypt",
}


# --------------------------- Platform helpers ---------------------------

def _is_juniper(platform):
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


# --------------------------- Version / hash detection ---------------------------

def _detect_junos_major_version(show_version_output: str) -> Optional[int]:
    """
    Extract the JunOS major version number from 'show version' output.

    Example output lines:
      Junos: 12.3R12.4
      Junos: 15.1R7.9
      JUNOS Software Release [21.4R3.15]
    Returns the integer major version (e.g. 12, 15, 21) or None if not found.
    """
    match = re.search(r'[Jj][Uu][Nn][Oo][Ss][^\d]*(\d+)\.', show_version_output)
    if match:
        return int(match.group(1))
    return None


def _hash_prefix_for_version(major_version: int) -> str:
    """
    Return the correct encrypted-password hash prefix for the given JunOS major version.

      JunOS < 15  →  $1$  (MD5-crypt)  — only hash format supported on older JunOS
      JunOS >= 15 →  $5$  (SHA-256)    — standard on JunOS 15.x

    This is the AUTHORITATIVE source for which hash format a device should have.
    Do NOT rely on what hash is currently in the device's config — a previous
    misconfiguration could have pushed the wrong hash format to the device, which
    would cause incorrect passwords to look correct (different plaintext, same prefix).
    """
    if major_version < 15:
        return "$1$"
    return "$5$"


def _detect_hash_prefix_from_config(show_config: str) -> Optional[str]:
    """
    Detect the encrypted-password hash format currently in the device config.
    Used only for logging/warning purposes — hash selection uses _hash_prefix_for_version.

    Returns the prefix string (e.g. '$5$') or None if no hashed password found.
    """
    for line in show_config.splitlines():
        match = re.search(r'encrypted-password\s+"?(\$\d+\$)', line)
        if match:
            return match.group(1)
    return None


# --------------------------- Playbook helpers ---------------------------

def _load_playbook(
    playbook_path: str = "playbooks/juniper_local_credentials.txt",
) -> List[str]:
    """
    Load all credential entries from the playbook (both $1$ and $6$ versions).
    Skips comments and blank lines. Section/version markers are also skipped.

    Returns a flat list of 'set system ...' command strings.
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
                # Skip section/version markers like [12x] or [15x]
                if stripped.startswith("[") and stripped.endswith("]"):
                    continue
                entries.append(stripped)
        logger.info(f"Loaded {len(entries)} entry/entries from {playbook_path}")
    except Exception as e:
        logger.error(f"Failed to load playbook: {str(e)}")

    return entries


def _filter_by_hash_prefix(entries: List[str], hash_prefix: str) -> List[str]:
    """
    Return only the entries whose encrypted-password hash starts with hash_prefix.
    Entries without a recognizable hash (e.g. non-password lines) are kept as-is.
    """
    filtered = []
    for entry in entries:
        match = re.search(r'encrypted-password\s+"?(\$\w+\$)', entry)
        if match:
            if match.group(1).startswith(hash_prefix):
                filtered.append(entry)
        else:
            # Not a password entry - keep it (future-proofing)
            filtered.append(entry)
    return filtered


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


def _extract_hash_value(entry: str) -> str:
    """Extract the hash string from an encrypted-password entry (quotes stripped)."""
    match = re.search(r'encrypted-password\s+"([^"]+)"', entry)
    if match:
        return match.group(1)
    match = re.search(r'encrypted-password\s+(\S+)', entry)
    if match:
        return match.group(1).strip('"\'')
    return ""


def _extract_username(entry: str) -> Optional[str]:
    """
    Extract the username from a 'set system login user <name> ...' entry.
    Returns None for root-authentication entries.
    """
    match = re.search(r'set system login user (\S+)', entry)
    return match.group(1) if match else None


# --------------------------- Config comparison ---------------------------

def _check_needs_update(
    show_config: str, desired_entries: List[str]
) -> Tuple[bool, List[str]]:
    """
    Compare desired credential entries against the current device config.

    Returns (needs_update: bool, list_of_entries_that_differ_or_missing).
    An entry needs updating if its key is present in the config but the hash
    differs, or if the key is absent entirely.
    """
    config_lines = [" ".join(l.split()) for l in show_config.splitlines()]
    needs_update = []

    for entry in desired_entries:
        key = _extract_credential_key(entry)
        desired_hash = _extract_hash_value(entry)

        # Find matching key in current config
        current_hash = None
        for line in config_lines:
            if line.startswith(key):
                current_hash = _extract_hash_value(line)
                break

        if current_hash != desired_hash:
            needs_update.append(entry)
            if current_hash is None:
                logger.debug(f"  Key not found in config: {key}")
            else:
                logger.debug(f"  Hash differs for key: {key}")

    return (len(needs_update) > 0), needs_update


# --------------------------- Username existence check ---------------------------

def _verify_usernames_exist(
    show_config: str, desired_entries: List[str]
) -> Tuple[bool, List[str]]:
    """
    For each non-root credential entry, verify that a 'set system login user <name>'
    line already exists in the device config.
    Root authentication is always present.

    Returns (all_exist: bool, list_of_missing_usernames).
    """
    missing = []
    checked = set()

    for entry in desired_entries:
        username = _extract_username(entry)
        if username is None:
            continue  # root-authentication, always present
        if username in checked:
            continue
        checked.add(username)

        user_key = f"set system login user {username}"
        found = any(
            " ".join(line.split()).startswith(user_key)
            for line in show_config.splitlines()
        )
        if not found:
            missing.append(username)
            logger.warning(f"Username '{username}' not found in device config")

    return (len(missing) == 0), missing


# ------------------------------- Action --------------------------------

def run(task: Task, pm=None) -> Result:
    """
    Entry point required by app_main.py.
    Updates Juniper local credentials to match the playbook.
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
        port = int(conn_opts.port) if conn_opts.port else 22
    else:
        port = 22

    logger.info(
        f"[{host}] Starting update_juniper_local_credential for {ip} "
        f"(platform: {platform}, port: {port})"
    )

    try:
        # Step 1: Early exit if local_creds_verified
        if (task.host.data or {}).get("local_creds_verified"):
            logger.info(f"[{host}] local_creds_verified flag set - device already updated")
            status = "OK"
            info_text = "Device is already updated"
            raise Exception("Device already updated - early exit")

        # Step 2: Load playbook entries (all versions combined)
        all_entries = _load_playbook()
        if not all_entries:
            status = "FAIL"
            info_text = (
                "No credentials found in playbooks/juniper_local_credentials.txt - cannot proceed"
            )
            raise Exception("Empty Juniper playbook")

        # Step 3: Force juniper device_type and connect
        apply_conn(task.host, "juniper", port)
        try:
            conn = task.host.get_connection("netmiko", task.nornir.config)
            logger.info(f"[{host}] Connected with primary credentials")
        except Exception as primary_err:
            logger.error(f"[{host}] Primary credential connection failed: {str(primary_err)}")

            if local_juniper_username and local_juniper_password:
                logger.warning(f"[{host}] Retrying with local Juniper credentials...")
                task.host.username = local_juniper_username
                task.host.password = local_juniper_password
                apply_conn(task.host, "juniper", port)

                try:
                    conn = task.host.get_connection("netmiko", task.nornir.config)
                    logger.info(
                        f"[{host}] Connected with local credentials - device already updated"
                    )
                    status = "OK"
                    info_text = "Device is already updated"
                    raise Exception("Device already updated - early exit")
                except Exception as local_err:
                    if str(local_err) == "Device already updated - early exit":
                        raise
                    status = "FAIL"
                    info_text = (
                        "Connection failed with both primary and local credentials: "
                        + sanitize_error_message(local_err)
                    )
                    raise Exception(f"Connection failed: {str(local_err)}")
            else:
                status = "FAIL"
                info_text = "Connection failed: " + sanitize_error_message(primary_err)
                raise Exception(f"Connection failed: {str(primary_err)}")

        # Step 4: Detect JunOS version — required for correct hash format selection
        logger.info(f"[{host}] Detecting JunOS version...")
        show_ver = conn.send_command("show version", delay_factor=2)
        logger.debug(f"[{host}] show version output:\n{show_ver[:300]}")

        major_version = _detect_junos_major_version(show_ver)
        if major_version is None:
            status = "FAIL"
            info_text = "Could not detect JunOS version from 'show version' output"
            raise Exception("JunOS version detection failed")

        # Step 5: Determine the correct hash format for this version
        hash_prefix = _hash_prefix_for_version(major_version)
        hash_label = _HASH_LABELS.get(hash_prefix, hash_prefix)
        logger.info(
            f"[{host}] Detected JunOS {major_version}.x → "
            f"expected hash format: {hash_label} ({hash_prefix})"
        )

        # Step 6: Get current config
        logger.info(f"[{host}] Reading current configuration...")
        show_config = conn.send_command(
            "show configuration system | display set",
            delay_factor=2,
        )
        logger.debug(f"[{host}] show config output:\n{show_config[:500]}")

        # Warn if the device's current hash format doesn't match what the version requires.
        # This can happen if a wrong hash was previously pushed to the device.
        current_hash_prefix = _detect_hash_prefix_from_config(show_config)
        if current_hash_prefix and current_hash_prefix != hash_prefix:
            current_label = _HASH_LABELS.get(current_hash_prefix, current_hash_prefix)
            logger.warning(
                f"[{host}] Config has {current_label} ({current_hash_prefix}) hashes but "
                f"JunOS {major_version}.x requires {hash_label} ({hash_prefix}) — "
                f"will update to correct format"
            )

        # Filter playbook entries to those matching the version-required hash format
        version_entries = _filter_by_hash_prefix(all_entries, hash_prefix)
        if not version_entries:
            status = "FAIL"
            info_text = (
                f"No playbook entries found for JunOS {major_version}.x "
                f"({hash_label}, {hash_prefix}). "
                f"Add {hash_prefix} hashes to playbooks/juniper_local_credentials.txt"
            )
            raise Exception("No matching playbook entries for device version")

        logger.info(
            f"[{host}] Using {len(version_entries)} playbook entry/entries "
            f"for JunOS {major_version}.x ({hash_label})"
        )

        # Step 7: Verify all target usernames exist before attempting to update
        users_exist, missing_users = _verify_usernames_exist(show_config, version_entries)
        if not users_exist:
            status = "FAIL"
            info_text = (
                f"Username(s) not found on device - create accounts first: "
                + ", ".join(missing_users)
            )
            raise Exception(f"Missing usernames: {', '.join(missing_users)}")

        # Step 8: Check if update is actually needed
        needs_update, differing_entries = _check_needs_update(show_config, version_entries)
        if not needs_update:
            logger.info(f"[{host}] All credentials already match playbook - no update needed")
            status = "OK"
            info_text = "Local credentials already up to date"
            raise Exception("Already up to date - early exit")

        logger.info(
            f"[{host}] {len(differing_entries)} credential(s) need updating"
        )

        # Step 9: Build and apply config commands
        logger.info(f"[{host}] Entering configuration mode...")
        conn.config_mode()

        for entry in differing_entries:
            key = _extract_credential_key(entry)
            logger.info(f"[{host}] Applying: {key} <hash>")
            out = conn.send_command_timing(entry, delay_factor=2)
            logger.debug(f"[{host}] => {out.strip()[:120]}")

        logger.info(f"[{host}] Committing changes...")
        commit_out = conn.send_command_timing("commit", delay_factor=5)
        logger.info(f"[{host}] Commit output: {commit_out.strip()[:300]}")

        if "error" in commit_out.lower() and "commit complete" not in commit_out.lower():
            conn.send_command_timing("rollback 0", delay_factor=2)
            conn.exit_config_mode()
            status = "FAIL"
            info_text = f"Commit failed: {commit_out.strip()[:200]}"
            raise Exception("Commit failed")

        conn.exit_config_mode()

        # Step 10: Verify
        logger.info(f"[{host}] Verifying changes...")
        show_config_after = conn.send_command(
            "show configuration system | display set",
            delay_factor=2,
        )

        still_needs_update, still_differing = _check_needs_update(
            show_config_after, version_entries
        )
        if still_needs_update:
            status = "FAIL"
            failed_keys = ", ".join(_extract_credential_key(e) for e in still_differing)
            info_text = f"Update applied but verification failed for: {failed_keys}"
            logger.error(f"[{host}] Post-commit verification failed: {failed_keys}")
        else:
            n = len(differing_entries)
            version_str = f"JunOS {major_version}.x" if major_version else "unknown version"
            status = "OK"
            info_text = (
                f"Updated {n} credential(s) successfully "
                f"({version_str}, {hash_label})"
            )
            logger.info(f"[{host}] Credential update verified successfully")

    except Exception as e:
        error_str = str(e)
        if error_str in (
            "Device already updated - early exit",
            "Already up to date - early exit",
        ):
            logger.info(f"[{host}] {error_str}")
        elif not any(
            skip in error_str
            for skip in (
                "Connection failed",
                "Empty Juniper playbook",
                "JunOS version detection failed",
                "No matching playbook entries",
                "Missing usernames",
                "Commit failed",
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
