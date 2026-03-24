# src/app_main.py
# Python 3.6+ / Nornir 2.5
import importlib
import logging
import os
import csv
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Tuple
from getpass import getpass, getuser

logger = logging.getLogger(__name__)

from nornir import InitNornir
from nornir.core.task import Task, Result
from nornir.plugins.functions.text import print_result

from src.utils.table_printer import print_device_table
from .utils.arg_parser import CliArgs
from .utils.rich_progress import get_progress_manager
from .utils.transport_discovery import bootstrap_transport
from .utils.auth_test import test_authentication
from .utils.device_filter import apply_device_filter
from .utils.ping_check import is_reachable


# Map CLI flags -> module name inside src/actions/
ACTION_MAP = {
    "update_vty_acl":            "update_vty_acl",
    "audit_vty_acl":             "audit_vty_acl",
    "audit_ntp":             "audit_ntp",
    "update_ntp":            "update_ntp",
    "update_syslog":         "update_syslog",
    "audit_domain_name":     "audit_domain_name",
    "update_domain_name":    "update_domain_name",
    "audit_local_passowrd":  "audit_local_passowrd",
    "update_local_passowrd": "update_local_passowrd",
    "update_tacacs":         "update_tacacs",
    "update_cisco_vty_acl":   "update_cisco_vty_acl",
    "update_cisco_local_credentials": "update_cisco_local_credentials",
    "update_aaa_login_method": "update_aaa_login_method",
    "make_juniper_login_local": "make_juniper_login_local",
    "update_juniper_local_credential": "update_juniper_local_credential",
    "from_text_file":        "from_text_file",
    "test":                  "test",

}


def choose_action(args) -> Tuple[Callable[[Task, object], Result], str]:
    """Return (callable, action_flag). Exactly one flag must be set."""
    selected = [flag for flag in ACTION_MAP if getattr(args, flag, False)]
    if not selected:
        raise ValueError("No action selected. Pass one flag (e.g. -update_acl).")
    if len(selected) > 1:
        raise ValueError("Multiple actions selected. Choose exactly one.")

    action_flag = selected[0]
    module_name = ACTION_MAP[action_flag]

    # Import src.actions.<module_name>, package-safe
    module_path = f"{__package__}.actions.{module_name}"  # __package__ == 'src'
    module = importlib.import_module(module_path)

    if not hasattr(module, "run"):
        raise ValueError("Each action module must define: run(task, pm) -> Result")

    return getattr(module, "run"), action_flag


def save_results_to_csv(rows, action_name, output_dir="output"):
    """
    Save results to CSV file in the output directory.

    Args:
        rows: List of dictionaries containing results
        action_name: Name of the action that was run
        output_dir: Directory to save CSV file (default: 'output')
    """
    if not rows:
        print("No results to save to CSV.")
        return

    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    # Generate filename
    csv_filename = output_path / "network_change_results.csv"

    try:
        # Get all possible keys from all rows (in case some rows have different keys)
        all_keys = set()
        for row in rows:
            all_keys.update(row.keys())

        # Fixed column order with 'info' always last
        preferred_order = ["device", "ip", "platform", "model", "status"]
        fieldnames = [col for col in preferred_order if col in all_keys]
        # Append any remaining columns (excluding 'info') in sorted order
        remaining = sorted(all_keys - set(preferred_order) - {"info"})
        fieldnames.extend(remaining)
        # Always put 'info' last
        if "info" in all_keys:
            fieldnames.append("info")

        # Write to CSV
        with open(csv_filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"✅ Results saved to: {csv_filename}")
        print(f"   Total records: {len(rows)}")

    except Exception as e:
        print(f"⚠️  Warning: Failed to save CSV: {str(e)}")


def main_task(task: Task, action: Callable[[Task, object], Result], pm=None) -> Result:
    """Nornir task wrapper that passes progress manager to the action for real-time updates."""
    host = task.host.name
    ip = task.host.hostname or ""

    # Determine port from discovered connection options (22=SSH, 23=Telnet)
    conn_opts = task.host.connection_options.get("netmiko")
    port = int(conn_opts.port) if conn_opts and conn_opts.port else None

    # Ping/reachability check before attempting login
    # Wrap only this call so a probe error is treated as unreachable,
    # while any other failures fall through to Nornir's default handling.
    try:
        reachable = is_reachable(ip, port=port)
    except Exception as e:
        logger.warning(f"[{host}] Reachability check error: {str(e)} - treating as unreachable")
        reachable = False

    if not reachable:
        logger.warning(f"[{host}] Device unreachable at {ip} (port {port}) - skipping")

        row = {
            "device": host,
            "ip": ip,
            "platform": task.host.platform or "",
            "model": (task.host.data or {}).get("model", "N/A"),
            "status": "FAIL",
            "info": "Device is unreachable, maybe offline",
        }

        if pm is not None:
            try:
                pm.advance(host="Overall Progress")
            except Exception:
                pass

        return Result(host=task.host, failed=False, result=row)

    result = action(task, pm)

    # Update progress after task completes
    if pm is not None:
        try:
            pm.advance(host="Overall Progress")
        except Exception:
            pass

    return result


def main() -> None:
    # Start runtime tracking
    start_time = time.time()
    start_datetime = datetime.now()

    # ---- CLI ----
    cliargs = CliArgs()
    cliargs.parse()

    # ---- Creds ----
    username = getuser()
    password = getpass(prompt="Password: ")
    enable_secret = getpass(prompt="Enable password (press Enter if same as login password): ")

    # If enable password is empty, use the same password
    if not enable_secret:
        enable_secret = password

    # ---- Local credentials (use_local mode) ----
    local_username = None
    local_password = None

    if cliargs.args.use_local:
        print("\n" + "="*60)
        print("LOCAL CREDENTIALS MODE (-use_local)")
        print("="*60)
        print("Local credentials will be tried FIRST on all devices.")
        print("TACACS credentials will be used as fallback if local fails.")
        print()
        print("NOTE: For Cisco devices the local username is sent via SSH.")
        print("      Leave blank to reuse your TACACS username.")
        print()
        local_input = input(f"Local username [{username}]: ").strip()
        local_username = local_input if local_input else username
        local_password = getpass(prompt="Local password: ")
        print()

    # ---- Resolve inventory/config.yaml from project root ----
    project_root = Path(__file__).resolve().parents[1]  # .../your_project
    config_path = project_root / "inventory" / "config.yaml"

    # ---- Nornir init (2.5) ----
    nr = InitNornir(config_file=str(config_path))

    # ---- Apply device filter (if filter file exists) ----
    total_inventory = len(nr.inventory.hosts)
    nr, not_found_devices = apply_device_filter(nr, filter_file="inventory/device_filter_list.txt")

    # Set creds on each host
    for host in nr.inventory.hosts.values():
        if cliargs.args.use_local:
            # Local creds are primary; store TACACS as fallback for auth test
            host.username = local_username
            host.password = local_password
            host.data["enable_secret"] = local_password
            host.data["tacacs_username"] = username
            host.data["tacacs_password"] = password
            host.data["tacacs_enable"] = enable_secret
            # Juniper actions look for these specific keys
            host.data["local_juniper_username"] = local_username
            host.data["local_juniper_password"] = local_password
        else:
            host.username = username
            host.password = password
            # Store enable secret in host data for use by connection options
            host.data["enable_secret"] = enable_secret

    device_count = len(nr.inventory.hosts)

    # ---- Select action ----
    try:
        action_fn, action_name = choose_action(cliargs.args)
    except ValueError as e:
        print("Error: {}".format(e))
        raise SystemExit(2)

    # ---- Action-specific prompts (before clearing screen) ----
    if action_name == "update_aaa_login_method":
        print("\n" + "="*60)
        print("ACTION: Update AAA Login Method")
        print("="*60)
        print("A second test session will be opened to verify local")
        print("authentication works BEFORE TACACS is removed.")
        print()
        local_test_password = getpass(prompt="New local password (used to test AAA login): ")
        for host in nr.inventory.hosts.values():
            host.data["local_test_password"] = local_test_password
        print()

    if action_name == "make_juniper_login_local":
        print("\n" + "="*60)
        print("ACTION: Make Juniper Login Local")
        print("="*60)
        print("A second session will be opened with local credentials")
        print("to verify login works BEFORE the commit is confirmed.")
        print("If the test fails the config change is automatically reverted.")
        print()
        local_juniper_username = input("Local Juniper username: ")
        local_juniper_password = getpass(prompt="Local Juniper password: ")
        for host in nr.inventory.hosts.values():
            host.data["local_juniper_username"] = local_juniper_username
            host.data["local_juniper_password"] = local_juniper_password
        print()

    # Clear the screen.
    os.system("clear")

    # Display action and device count
    print("\n" + "="*60)
    print(f"Action: {action_name}")
    print(f"Total inventory: {total_inventory} device(s)")
    if device_count < total_inventory:
        print(f"Filtered to: {device_count} device(s) (using device_filter_list.txt)")
    else:
        print(f"Devices: {device_count} device(s) will be processed")
    print("="*60 + "\n")

    # ---- Action step banner ----
    if action_name == "update_aaa_login_method":
        print("=" * 60)
        print("Steps performed on each device:")
        print("  1. Verify enable secret is configured on device")
        print("     (from playbooks/cisco_local_credentials.txt)")
        print("  2. Load new AAA commands")
        print("     (from playbooks/cisco_aaa_login_method.txt)")
        print("  3. Apply new AAA authentication login/enable commands")
        print("  4. Open a SECOND session to test local authentication")
        print("     - FAIL: Revert AAA config to original")
        print("     - PASS: Proceed with cleanup")
        print("  5. Remove all TACACS server commands from device")
        print("  6. Remove password 7 from VTY lines 0 4 and 5 15")
        print("  7. Open a THIRD session - run 'show run' to verify TACACS")
        print("     is fully removed (no 'TACACS+ session has expired' errors)")
        print("     - FAIL: Revert ALL changes (AAA + TACACS + VTY password 7)")
        print("     - PASS: Save configuration")
        print("  8. Save configuration (write memory)")
        print("  NOTE: Juniper devices are skipped automatically")
        print("=" * 60 + "\n")

    if action_name == "make_juniper_login_local":
        print("=" * 60)
        print("Steps performed on each Juniper device:")
        print("  1. Skip non-Juniper devices automatically")
        print("  2. Load expected encrypted passwords")
        print("     (from playbooks/juniper_local_credentials.txt)")
        print("  3. Verify those encrypted passwords exist on the device")
        print("     - FAIL: Abort without making any changes")
        print("  4. Apply config changes and 'commit confirmed 10':")
        print("       delete system authentication-order")
        print("       delete system tacplus-server")
        print("       delete system accounting")
        print("  5. Open a SECOND session to test local authentication")
        print("     - PASS: Send confirming 'commit' - changes saved permanently")
        print("     - FAIL: Send 'rollback 1' + 'commit' - config reverted")
        print("  NOTE: If primary (TACACS) credentials fail, local credentials")
        print("        are tried automatically. If that works, device is already")
        print("        updated and will be marked OK.")
        print("=" * 60 + "\n")

    if action_name == "update_juniper_local_credential":
        print("=" * 60)
        print("Steps performed on each Juniper device:")
        print("  1. Skip non-Juniper devices automatically")
        print("  2. Load credentials from playbooks/juniper_local_credentials.txt")
        print("     (supports both $6$ SHA-512 for 15.x+ and $1$ MD5 for 12.x-14.x)")
        print("  3. Connect to device and run 'show version' to detect JunOS version")
        print("  4. Auto-select the correct hash format for this device's version")
        print("     - FAIL: No matching hash entries found for device version")
        print("  5. Verify target username(s) already exist on device")
        print("     - FAIL: Username not found (create accounts manually first)")
        print("  6. Compare current hashes vs playbook hashes")
        print("     - Already match: return OK 'Already up to date'")
        print("  7. Apply updated set commands and commit")
        print("  8. Verify changes were applied successfully")
        print("  NOTE: Intended to run BEFORE make_juniper_login_local")
        print("        so local accounts are ready before TACACS is removed.")
        print("=" * 60 + "\n")

    # if not test, create cache for transport type
    # Pre-stage: apply cached decisions and discover for unknown hosts
    if action_name != 'test':
        print("Creating/Updating transport_cache.json for logging into device.....")
        disc = bootstrap_transport(nr, cache_path="transport_cache.json")

        # Test authentication on first device before proceeding
        print("\n" + "="*60)
        auth_success, auth_message = test_authentication(nr)
        print(auth_message)
        print("="*60)

        if not auth_success:
            print("\n❌ Authentication test failed!")
            print("Please check your credentials and try again.")
            print("Exiting...\n")
            raise SystemExit(1)

        print("✅ Authentication successful! Proceeding with all devices...\n")

        # The auth test may have run failed tasks (e.g. wrong creds on already-updated
        # devices) which Nornir records in nr.data.failed_hosts.  Since nr.filter() shares
        # the same GlobalState object, those failures would cause the main nr.run() to
        # skip those hosts entirely (on_good=True, on_failed=False by default).
        # Reset failed_hosts now so all inventory hosts are processed by the action.
        nr.data.failed_hosts.clear()

    # Print test banner/message if this is a test run.
    if action_name == "test":
        print("\n\nThis is only a TEST!!\n\n")

    # Create a single progress bar for overall completion
    pm = get_progress_manager()

    # Single progress bar tracking overall completion
    with pm:
        # Add one task for overall progress (not per-host)
        overall_task = pm.add_task(
            host=f"Overall Progress",
            total=device_count,
            description=f"Running {action_name} - 0/{device_count} complete",
            platform="",
        )

        # Run tasks with progress manager for real-time updates
        result = nr.run(
            name="Action: {}".format(action_name),
            task=main_task,
            action=action_fn,  # passed into main_task(**kwargs)
            pm=pm,  # Pass progress manager for real-time updates
        )

    # Close all connections to prevent hung sessions
    print("\nClosing all device connections...")
    for host_name, host_obj in nr.inventory.hosts.items():
        try:
            host_obj.close_connections()
        except Exception as e:
            print(f"Warning: Failed to close connection for {host_name}: {e}")

    #print_result(result)
    def last_dict(mr):
        """Return the last .result that is a dict from a MultiResult (or {})."""
        for r in reversed(mr):            # walk from most recent
            v = getattr(r, "result", None)
            if isinstance(v, dict):
                return v
        return {}

    rows = []

    # Ensure ALL hosts from inventory are in results (even if execution failed completely)
    for host_name in nr.inventory.hosts:
        if host_name in result:
            # Host was executed - get its result
            mr = result[host_name]
            payload = last_dict(mr)            # this is your {'device':..., 'ip':...} dict
            if not payload:                    # fallback if action didn't return a dict
                payload = {
                    "device": host_name,
                    "ip": nr.inventory.hosts[host_name].hostname or "",
                    "platform": nr.inventory.hosts[host_name].platform or "",
                    "model": (nr.inventory.hosts[host_name].data or {}).get("model", "N/A"),
                    "status": "FAIL" if mr.failed else "OK",
                    "info": "",
                }
            else:
                # ensure status reflects execution outcome, if you want:
                payload.setdefault("status", "FAIL" if mr.failed else "OK")
        else:
            # Host was NOT executed at all - create FAIL entry
            payload = {
                "device": host_name,
                "ip": nr.inventory.hosts[host_name].hostname or "",
                "platform": nr.inventory.hosts[host_name].platform or "",
                "model": (nr.inventory.hosts[host_name].data or {}).get("model", "N/A"),
                "status": "FAIL",
                "info": "Device was not executed - check logs for details",
            }
        rows.append(payload)

    # Pretty print with Rich (uses the helper we wrote earlier)
    print("\n\n")
    print_device_table(rows)

    # Save results to CSV
    save_results_to_csv(rows, action_name)

    # Calculate and display runtime
    end_time = time.time()
    end_datetime = datetime.now()
    runtime_seconds = end_time - start_time
    runtime_delta = timedelta(seconds=runtime_seconds)

    # Format runtime nicely
    hours, remainder = divmod(int(runtime_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    print("\n" + "="*60)
    print("Runtime Summary:")
    print(f"  Start Time: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  End Time:   {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    if hours > 0:
        print(f"  Duration:   {hours}h {minutes}m {seconds}s ({runtime_seconds:.2f} seconds)")
    elif minutes > 0:
        print(f"  Duration:   {minutes}m {seconds}s ({runtime_seconds:.2f} seconds)")
    else:
        print(f"  Duration:   {runtime_seconds:.2f} seconds")
    print("="*60 + "\n")

    # Display devices not found in inventory (if any)
    if not_found_devices:
        print("="*60)
        print("⚠️  WARNING: Devices Not Found in Inventory")
        print("="*60)
        print(f"The following {len(not_found_devices)} device(s) from device_filter_list.txt")
        print("were NOT found in inventory/hosts.yaml:")
        print()
        for device in sorted(not_found_devices):
            print(f"  - {device}")
        print()
        print("These devices were skipped. Please verify device names in:")
        print("  - inventory/device_filter_list.txt")
        print("  - inventory/hosts.yaml")
        print("="*60 + "\n")


if __name__ == "__main__":
    # IMPORTANT: run as a module from project root:
    #   python -m src.app_main -update_acl
    main()
