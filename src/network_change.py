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

        # Sort keys for consistent column order
        fieldnames = sorted(all_keys)

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
    ip = task.host.hostname

    # Determine port from discovered connection options (22=SSH, 23=Telnet)
    conn_opts = task.host.connection_options.get("netmiko")
    port = int(conn_opts.port) if conn_opts and conn_opts.port else None

    # Ping/reachability check before attempting login
    if not is_reachable(ip, port=port):
        logger.warning(f"[{host}] Device unreachable at {ip} (port {port}) - skipping")

        row = {
            "device": host,
            "ip": ip,
            "platform": task.host.platform or "",
            "model": (task.host.data or {}).get("model", "N/A"),
            "status": "FAIL",
            "info": "Device is unreachable, maybe offline",
        }

        # Advance progress so the bar still moves
        if pm is not None:
            try:
                pm.advance(host="Overall Progress")
            except Exception:
                pass

        return Result(host=task.host, failed=True, result=row)

    result = action(task, pm)

    # Update progress after task completes
    if pm is not None:
        try:
            pm.advance(host=f"Overall Progress")
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
