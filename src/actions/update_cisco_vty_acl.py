# src/actions/update_cisco_acl.py
# Python 3.6+ / Nornir 2.5

"""
Update Cisco standard ACL with new entries from an input file.

This module conforms to app_main.py's expectations:
- It defines `run(task, pm)` -> Result
- It returns a Result whose `.result` is a dict with keys:
    device, ip, platform, model, status("Success"/"Failed"), info(<message>)

Behavior:
1) Read new ACL entries from input/acl_entries.txt
2) Prompt user for target ACL name and insertion position
3) For each Cisco device:
   - Verify ACL exists
   - Check if entries already exist
   - Verify ACL is applied to vty 0 4 and vty 5 15
   - Remove ACL from vty lines
   - Update ACL with new entries at specified position
   - Verify new ACL configuration
   - Re-apply ACL to vty lines

Dry-run mode (--dry-run):
- Performs all pre-checks without making changes
- Shows what the new ACL would look like
- Logs old and new ACL configurations
"""

import os
import re
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path

from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config


# ======================== Platform Detection ========================

def _is_cisco(platform):
    """Check if platform is Cisco IOS/IOS-XE/NX-OS."""
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos")


# ======================== ACL Entry Management ========================

def read_acl_entries_from_file(filepath="input/acl_entries.txt"):
    """
    Read new ACL entries from input file.
    
    Args:
        filepath: Path to input file containing ACL entries
        
    Returns:
        List of ACL entry strings (one per line)
        
    Raises:
        FileNotFoundError: If input file doesn't exist
    """
    try:
        with open(filepath, 'r') as f:
            entries = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        return entries
    except FileNotFoundError:
        raise FileNotFoundError("Input file '{}' not found. Please create it with ACL entries.".format(filepath))


def prompt_user_for_acl_config():
    """
    Prompt user for ACL name and insertion position.
    
    Returns:
        Tuple of (acl_name, position) where position is 1-based index
    """
    print("\n" + "="*60)
    acl_name = input("Enter target ACL name: ").strip()
    
    while True:
        try:
            position = int(input("Enter position to insert new entries (1=first, 2=second, etc.): ").strip())
            if position < 1:
                print("Position must be 1 or greater.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")
    
    return acl_name, position


def parse_acl_from_config(config_output, acl_name):
    """
    Parse ACL entries from 'show run' output.
    
    Args:
        config_output: Output from 'show run' command
        acl_name: Name of the ACL to extract
        
    Returns:
        List of ACL entry lines (permit/deny statements)
    """
    entries = []
    in_acl = False
    
    for line in config_output.splitlines():
        line = line.strip()
        
        # Start of target ACL
        if line.startswith("ip access-list standard {}".format(acl_name)):
            in_acl = True
            continue
        
        # End of ACL section (next ACL or end of config block)
        if in_acl and (line.startswith("ip access-list") or line.startswith("!") or not line):
            if line.startswith("!"):
                break
            if line.startswith("ip access-list"):
                break
        
        # Collect ACL entries
        if in_acl and (line.startswith("permit") or line.startswith("deny") or line.startswith("remark")):
            entries.append(" " + line)  # Preserve indentation
    
    return entries


def insert_entries_at_position(existing_entries, new_entries, position):
    """
    Insert new entries at specified position in existing ACL.
    
    Args:
        existing_entries: List of existing ACL entries
        new_entries: List of new entries to insert
        position: 1-based position (1=first, 2=second, etc.)
        
    Returns:
        List of combined ACL entries
    """
    # Convert to 0-based index
    insert_idx = position - 1
    
    # Ensure position is valid
    insert_idx = max(0, min(insert_idx, len(existing_entries)))
    
    return existing_entries[:insert_idx] + new_entries + existing_entries[insert_idx:]


def check_entries_already_exist(existing_entries, new_entries):
    """
    Check if any new entries already exist in ACL.
    
    Args:
        existing_entries: List of existing ACL entries
        new_entries: List of new entries to check
        
    Returns:
        Tuple of (bool, list) - (all_exist, duplicate_entries)
    """
    # Normalize entries for comparison (strip whitespace and sequence numbers)
    def normalize(entry):
        # Remove leading numbers and whitespace
        normalized = re.sub(r'^\s*\d+\s*', '', entry).strip()
        return normalized
    
    existing_normalized = [normalize(e) for e in existing_entries]
    duplicates = []
    
    for new_entry in new_entries:
        normalized_new = normalize(new_entry)
        if normalized_new in existing_normalized:
            duplicates.append(new_entry)
    
    return len(duplicates) == len(new_entries), duplicates


# ======================== VTY Line Verification ========================

def get_vty_acl_config(task, vty_range):
    """
    Get ACL configuration for specified vty line range.
    
    Args:
        task: Nornir task object
        vty_range: String like "0 4" or "5 15"
        
    Returns:
        String containing vty configuration output
    """
    cmd = "show run | section line vty {}".format(vty_range)
    result = task.run(task=netmiko_send_command, command_string=cmd, name="Check vty {}".format(vty_range))
    return result.result.strip()


def extract_acl_from_vty(vty_output):
    """
    Extract ACL name from vty configuration.
    
    Args:
        vty_output: Output from 'show run | section line vty'
        
    Returns:
        ACL name or None if not found
    """
    for line in vty_output.splitlines():
        if "access-class" in line and "in" in line:
            # Format: " access-class ACL_NAME in"
            match = re.search(r'access-class\s+(\S+)\s+in', line)
            if match:
                return match.group(1)
    return None


def verify_acl_on_vty_lines(task, acl_name):
    """
    Verify ACL is applied to both vty 0 4 and vty 5 15.
    
    Args:
        task: Nornir task object
        acl_name: Name of ACL to verify
        
    Returns:
        Tuple of (success: bool, message: str, vty_04_acl: str, vty_515_acl: str)
    """
    vty_04_output = get_vty_acl_config(task, "0 4")
    vty_515_output = get_vty_acl_config(task, "5 15")
    
    vty_04_acl = extract_acl_from_vty(vty_04_output)
    vty_515_acl = extract_acl_from_vty(vty_515_output)
    
    if vty_04_acl != acl_name and vty_515_acl != acl_name:
        return False, "ACL '{}' not found on vty 0 4 (found: {}) or vty 5 15 (found: {})".format(
            acl_name, vty_04_acl or "None", vty_515_acl or "None"), vty_04_acl, vty_515_acl
    elif vty_04_acl != acl_name:
        return False, "ACL '{}' not found on vty 0 4 (found: {})".format(acl_name, vty_04_acl or "None"), vty_04_acl, vty_515_acl
    elif vty_515_acl != acl_name:
        return False, "ACL '{}' not found on vty 5 15 (found: {})".format(acl_name, vty_515_acl or "None"), vty_04_acl, vty_515_acl
    
    return True, "ACL verified on both vty lines", vty_04_acl, vty_515_acl


# ======================== ACL Update Operations ========================

def remove_acl_from_vty(task, vty_range, acl_name):
    """
    Remove ACL from specified vty line range.
    
    Args:
        task: Nornir task object
        vty_range: String like "0 4" or "5 15"
        acl_name: Name of ACL to remove
    """
    commands = [
        "line vty {}".format(vty_range),
        "no access-class {} in".format(acl_name)
    ]
    task.run(task=netmiko_send_config, config_commands=commands, name="Remove ACL from vty {}".format(vty_range))


def apply_acl_to_vty(task, vty_range, acl_name):
    """
    Apply ACL to specified vty line range.
    
    Args:
        task: Nornir task object
        vty_range: String like "0 4" or "5 15"
        acl_name: Name of ACL to apply
    """
    commands = [
        "line vty {}".format(vty_range),
        "access-class {} in".format(acl_name)
    ]
    task.run(task=netmiko_send_config, config_commands=commands, name="Apply ACL to vty {}".format(vty_range))


def update_acl(task, acl_name, new_acl_entries):
    """
    Update ACL by removing and re-creating with new entries.
    
    Args:
        task: Nornir task object
        acl_name: Name of ACL to update
        new_acl_entries: List of complete ACL entries (with proper indentation)
    """
    # Remove old ACL
    remove_cmd = ["no ip access-list standard {}".format(acl_name)]
    task.run(task=netmiko_send_config, config_commands=remove_cmd, name="Remove old ACL")
    
    # Create new ACL with entries
    create_commands = ["ip access-list standard {}".format(acl_name)] + new_acl_entries
    task.run(task=netmiko_send_config, config_commands=create_commands, name="Create updated ACL")


def verify_acl_update(task, acl_name, expected_entries):
    """
    Verify ACL was updated correctly.
    
    Args:
        task: Nornir task object
        acl_name: Name of ACL to verify
        expected_entries: List of expected ACL entries
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    # Get current ACL
    result = task.run(task=netmiko_send_command, command_string="show run | section ip access-list standard {}".format(acl_name))
    current_entries = parse_acl_from_config(result.result, acl_name)
    
    # Normalize for comparison
    def normalize(entry):
        return re.sub(r'^\s*\d+\s*', '', entry).strip()
    
    current_normalized = [normalize(e) for e in current_entries]
    expected_normalized = [normalize(e) for e in expected_entries]
    
    if current_normalized == expected_normalized:
        return True, "ACL updated successfully"
    else:
        return False, "ACL verification failed - entries don't match expected configuration"


# ======================== Main Action Entry Point ========================

# Module-level variables to store user input (shared across all device tasks)
_ACL_NAME = None
_POSITION = None
_NEW_ENTRIES = None
_DRY_RUN = False


def run(task, pm, dry_run=False):
    """
    Entry point required by app_main.py.
    Updates Cisco standard ACL with new entries from input file.
    
    Args:
        task: Nornir task object
        pm: Progress manager for UI updates
        dry_run: If True, perform pre-checks only without making changes
        
    Returns:
        Result object with dict containing: device, ip, platform, model, status, info
        
    This section is for reporting and requires to send back a dictionary. The following format must be returned:

    Example:
    rows = [
        {"device": "edge1", "ip": "192.0.2.11", "platform": "cisco_ios", "model": "ISR4431", "status": "Success", "info": "ACL has been updated"},
        {"device": "jnp-qfx1", "ip": "192.0.2.21", "platform": "juniper_junos", "model": "QFX5120", "status": "Failed", "info": "Not a Cisco device"},
    ]
    """
    global _ACL_NAME, _POSITION, _NEW_ENTRIES, _DRY_RUN
    
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname
    
    # Store dry_run flag
    _DRY_RUN = dry_run
    
    # Initialize result row
    row = {
        "device": host,
        "ip": ip,
        "platform": platform,
        "model": task.host.get("model", "N/A"),
        "status": "Failed",
        "info": ""
    }
    
    # Progress update
    if pm is not None:
        try:
            pm.update(host=host, description="Starting ACL update")
        except Exception:
            pass
    
    # ---- Pre-flight checks ----
    
    # 1. Verify this is a Cisco device
    if not _is_cisco(platform):
        row["info"] = "Skipped - Not a Cisco device"
        if pm:
            try:
                pm.advance(host=host)
                pm.update(host=host, description="Skipped (non-Cisco)")
            except Exception:
                pass
        return Result(host=task.host, changed=False, result=row)
    
    # 2. Read input file and prompt user (only once for first device)
    if _NEW_ENTRIES is None:
        try:
            _NEW_ENTRIES = read_acl_entries_from_file()
            
            # Clear screen and display entries
            os.system('clear')
            print("\n" + "="*60)
            print("NEW ACL ENTRIES TO BE ADDED:")
            print("="*60)
            for idx, entry in enumerate(_NEW_ENTRIES, 1):
                print("{}. {}".format(idx, entry))
            print("="*60 + "\n")
            
            # Prompt for ACL name and position
            _ACL_NAME, _POSITION = prompt_user_for_acl_config()
            
            print("\nTarget ACL: {}".format(_ACL_NAME))
            print("Insert position: {}".format(_POSITION))
            print("\nProceeding with {} mode...\n".format("DRY-RUN" if dry_run else "UPDATE"))
            
        except FileNotFoundError as e:
            row["info"] = str(e)
            if pm:
                try:
                    pm.advance(host=host)
                    pm.update(host=host, description="Failed (no input file)")
                except Exception:
                    pass
            return Result(host=task.host, changed=False, failed=True, result=row)
    
    # ---- Connect and execute ----
    
    try:
        # 3. Get current running config for ACL
        if pm:
            try:
                pm.update(host=host, description="Checking ACL existence")
            except Exception:
                pass
        
        result = task.run(task=netmiko_send_command, command_string="show run | section ip access-list standard {}".format(_ACL_NAME))
        config_output = result.result
        
        # 4. Verify ACL exists
        if "ip access-list standard {}".format(_ACL_NAME) not in config_output:
            row["info"] = "Pre-check Failed" if dry_run else "ACL '{}' not found on device".format(_ACL_NAME)
            if pm:
                try:
                    pm.advance(host=host)
                    pm.update(host=host, description="Failed (ACL not found)")
                except Exception:
                    pass
            return Result(host=task.host, changed=False, failed=True, result=row)
        
        # Parse existing ACL entries
        existing_entries = parse_acl_from_config(config_output, _ACL_NAME)
        
        # 5. Check if entries already exist
        if pm:
            try:
                pm.update(host=host, description="Checking for duplicates")
            except Exception:
                pass
        
        all_exist, duplicates = check_entries_already_exist(existing_entries, _NEW_ENTRIES)
        if all_exist:
            row["status"] = "Success"
            row["info"] = "Pre-check Passed" if dry_run else "All entries already exist in ACL - no update needed"
            if pm:
                try:
                    pm.advance(host=host)
                    pm.update(host=host, description="Completed (no changes needed)")
                except Exception:
                    pass
            return Result(host=task.host, changed=False, result=row)
        
        # 6. Verify ACL is on vty lines
        if pm:
            try:
                pm.update(host=host, description="Verifying vty lines")
            except Exception:
                pass
        
        vty_ok, vty_msg, vty_04_acl, vty_515_acl = verify_acl_on_vty_lines(task, _ACL_NAME)
        if not vty_ok:
            row["info"] = "Pre-check Failed" if dry_run else vty_msg
            if pm:
                try:
                    pm.advance(host=host)
                    pm.update(host=host, description="Failed (vty check)")
                except Exception:
                    pass
            return Result(host=task.host, changed=False, failed=True, result=row)
        
        # Create new ACL configuration
        new_acl_entries = insert_entries_at_position(existing_entries, _NEW_ENTRIES, _POSITION)
        
        # ---- Dry-run mode: log and exit ----
        if dry_run:
            if pm:
                try:
                    pm.update(host=host, description="Logging dry-run results")
                except Exception:
                    pass
            
            # Log old and new ACL
            print("\n" + "="*60)
            print("DRY-RUN for device: {}".format(host))
            print("="*60)
            print("\nOLD ACL ({}):\n".format(_ACL_NAME))
            print("ip access-list standard {}".format(_ACL_NAME))
            for entry in existing_entries:
                print(entry)
            
            print("\n" + "-"*60)
            print("\nNEW ACL ({}) - WOULD BE APPLIED:\n".format(_ACL_NAME))
            print("ip access-list standard {}".format(_ACL_NAME))
            for entry in new_acl_entries:
                print(entry)
            print("\n" + "="*60 + "\n")
            
            row["status"] = "Success"
            row["info"] = "Pre-check Passed"
            
            if pm:
                try:
                    pm.advance(host=host)
                    pm.update(host=host, description="Dry-run complete")
                except Exception:
                    pass
            
            return Result(host=task.host, changed=False, result=row)
        
        # ---- Regular mode: apply changes ----
        
        # 7. Remove ACL from vty lines
        if pm:
            try:
                pm.update(host=host, description="Removing ACL from vty lines")
            except Exception:
                pass
        
        remove_acl_from_vty(task, "0 4", _ACL_NAME)
        remove_acl_from_vty(task, "5 15", _ACL_NAME)
        
        # 8. Update ACL
        if pm:
            try:
                pm.update(host=host, description="Updating ACL")
            except Exception:
                pass
        
        update_acl(task, _ACL_NAME, new_acl_entries)
        
        # 9. Verify ACL update
        if pm:
            try:
                pm.update(host=host, description="Verifying ACL update")
            except Exception:
                pass
        
        verify_ok, verify_msg = verify_acl_update(task, _ACL_NAME, new_acl_entries)
        if not verify_ok:
            row["info"] = "ACL didn't update properly"
            if pm:
                try:
                    pm.advance(host=host)
                    pm.update(host=host, description="Failed (verification)")
                except Exception:
                    pass
            return Result(host=task.host, changed=True, failed=True, result=row)
        
        # 10. Re-apply ACL to vty lines
        if pm:
            try:
                pm.update(host=host, description="Re-applying ACL to vty lines")
            except Exception:
                pass
        
        apply_acl_to_vty(task, "0 4", _ACL_NAME)
        apply_acl_to_vty(task, "5 15", _ACL_NAME)
        
        # Success!
        row["status"] = "Success"
        row["info"] = "ACL has been updated"
        
        if pm:
            try:
                pm.advance(host=host)
                pm.update(host=host, description="Completed")
            except Exception:
                pass
        
        return Result(host=task.host, changed=True, result=row)
        
    except Exception as e:
        # Catch authentication/connection errors
        error_msg = str(e)
        if "authentication" in error_msg.lower() or "login" in error_msg.lower():
            row["info"] = "Authentication failed: {}".format(error_msg)
        else:
            row["info"] = "Pre-check Failed" if dry_run else "Error: {}".format(error_msg)
        
        if pm:
            try:
                pm.advance(host=host)
                pm.update(host=host, description="Failed (error)")
            except Exception:
                pass
        
        return Result(host=task.host, changed=False, failed=True, result=row)