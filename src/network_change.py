# src/app_main.py
# Python 3.6+ / Nornir 2.5
import importlib
import os
from pathlib import Path
from typing import Callable, Tuple
from getpass import getpass, getuser

from nornir import InitNornir
from nornir.core.task import Task, Result
from nornir.plugins.functions.text import print_result

from src.utils.table_printer import print_device_table
from .utils.arg_parser import CliArgs
from .utils.rich_progress import get_progress_manager
from .utils.transport_discovery import bootstrap_transport


# Map CLI flags -> module name inside src/actions/
ACTION_MAP = {
    "update_vty_acl":            "update_vty_acl",
    "audit_vty_acl":             "audit_vty_acl",
    "audit_ntp":             "audit_ntp",
    "update_ntp":            "update_ntp",
    "audit_domain_name":     "audit_domain_name",
    "update_domain_name":    "update_domain_name",
    "audit_local_passowrd":  "audit_local_passowrd",
    "update_local_passowrd": "update_local_passowrd",
    "update_tacacs":         "update_tacacs",
    "update_cisco_vty_acl":   "update_cisco_vty_acl",
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


def main_task(task: Task, action: Callable[[Task, object], Result]) -> Result:
    """Nornir task wrapper that hands the ProgressManager to the action."""
    pm = get_progress_manager()
    return action(task, pm)


def main() -> None:
    # ---- CLI ----
    cliargs = CliArgs()
    cliargs.parse()

    # ---- Creds ----
    username = getuser()
    password = getpass()

    # ---- Resolve inventory/config.yaml from project root ----
    project_root = Path(__file__).resolve().parents[1]  # .../your_project
    config_path = project_root / "inventory" / "config.yaml"

    # ---- Nornir init (2.5) ----
    nr = InitNornir(config_file=str(config_path))

    # Set creds on each host
    for host in nr.inventory.hosts.values():
        host.username = username
        host.password = password

    tasks = len(nr.inventory.hosts)
    print("\nRunning task on {} device(s)".format(tasks))

    # ---- Select action ----
    try:
        action_fn, action_name = choose_action(cliargs.args)
    except ValueError as e:
        print("Error: {}".format(e))
        raise SystemExit(2)
    
    # Clear the screen.
    os.system("clear")

    # if not test, create cache for transport type
    # Pre-stage: apply cached decisions and discover for unknown hosts
    if action_name != 'test':
        print("Creating/Updating transport_cache.json for logging into device.....")
        disc = bootstrap_transport(nr, cache_path="transport_cache.json")

    pm = get_progress_manager()

    # Print test banner/message if this is a test run.
    if action_name == "test":
        print("\n\nThis is only a TEST!!\n\n")

    # One row per host (total=1 => per-host unit of work)
    with pm:
        for host in nr.inventory.hosts.values():
            pm.add_task(
                host=host.name,
                total=1,
                description="Queued ({})".format(action_name),
                platform=str(host.platform or ""),
            )
        # (connection options already set)
        result = nr.run(
            name="Action: {}".format(action_name),
            task=main_task,
            action=action_fn,  # passed into main_task(**kwargs)
        )

        # Ensure rows show complete
        for host in nr.inventory.hosts:
            pm.complete(host=host)

    #print_result(result)
    def last_dict(mr):
        """Return the last .result that is a dict from a MultiResult (or {})."""
        for r in reversed(mr):            # walk from most recent
            v = getattr(r, "result", None)
            if isinstance(v, dict):
                return v
        return {}

    rows = []

    for host, mr in result.items():        # mr is a MultiResult for this host
        payload = last_dict(mr)            # this is your {'device':..., 'ip':...} dict
        if not payload:                    # fallback if action didn't return a dict
            payload = {
                "device": host,
                "ip": nr.inventory.hosts[host].hostname or "",
                "platform": nr.inventory.hosts[host].platform or "",
                "model": (nr.inventory.hosts[host].data or {}).get("model", "N/A"),
                "status": "FAIL" if mr.failed else "OK",
                "info": "",
            }
        else:
            # ensure status reflects execution outcome, if you want:
            payload.setdefault("status", "FAIL" if mr.failed else "OK")
        rows.append(payload)

    # Pretty print with Rich (uses the helper we wrote earlier)
    print("\n\n")
    print_device_table(rows)


if __name__ == "__main__":
    # IMPORTANT: run as a module from project root:
    #   python -m src.app_main -update_acl
    main()
