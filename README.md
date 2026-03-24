# J2 Migration – Network Change Automation (Nornir 2.5)

Automate configuration audits and changes across Cisco IOS/IOS-XE and Juniper Junos using **Python 3.6.8** and **Nornir 2.5**. The app uses a modular “action” pattern (e.g., `audit_ntp`, `update_ntp`) plus a Rich-style progress UI and a pretty table summary.

> ⚠️ **Compatibility target:** Nornir **2.5** on Python **3.6.8**. Some notes are included in case 3.x-only imports slip in by accident.

---

## Features
- 🔌 **Multi-vendor:** Cisco IOS/IOS-XE and Juniper Junos via Netmiko
- 🧱 **Modular actions:** Add new actions under `src/actions/` and map them in `ACTION_MAP`
- 📊 **Pretty device table:** Summarizes per-host results
- 🚦 **Progress display:** Rich-style progress across hosts
- 🧭 **Transport discovery:** Helper to pick SSH / console / etc.
- 🧪 **Audit vs Update:** `audit_*` read-only; `update_*` make changes

---

## Project layout
```
.
├─ src/
│  ├─ app_main.py                 # entrypoint (Python 3.6+ / Nornir 2.5)
│  ├─ actions/
│  │  ├─ audit_ntp.py
│  │  ├─ update_ntp.py
│  │  ├─ audit_acl.py
│  │  └─ update_acl.py
│  └─ utils/
│     ├─ arg_parser.py
│     ├─ rich_progress.py
│     ├─ table_printer.py
│     └─ transport_discovery.py
├─ inventory/
│  ├─ hosts.yaml
│  ├─ groups.yaml
│  └─ defaults.yaml
├─ config.yaml                    # Nornir config (SimpleInventory)
├─ requirements-py36.txt          # pinned deps for Python 3.6.8 (fill in versions)
└─ README.md
```

---

## Quick start

### 1) Python & venv
```bash
python3.6 -V   # should be 3.6.8
python3.6 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-py36.txt
```
> 💡 If you also run newer Python (e.g., 3.10+), keep a separate lock file (e.g., `requirements-modern.txt`).

### 2) Nornir config
`config.yaml` (example):
```yaml
core:
  num_workers: 20
inventory:
  plugin: SimpleInventory
  options:
    host_file: inventory/hosts.yaml
    group_file: inventory/groups.yaml
    defaults_file: inventory/defaults.yaml
```

### 3) Inventory
`inventory/hosts.yaml` (snippet):
```yaml
r1:
  hostname: 10.0.0.11
  groups: [ios]
  data:
    site: nyc
qfx1:
  hostname: 10.0.0.21
  groups: [junos]
  data:
    site: rdu
```
`inventory/groups.yaml`:
```yaml
ios:
  platform: ios
junos:
  platform: junos
```
`inventory/defaults.yaml`:
```yaml
username: ""
password: ""
port: 22
```
> Credentials can be prompted in `app_main.py` (`getpass()`/`getuser()`), or you can populate defaults / env-vars.

### 4) Run an action
```bash
# Example: audit NTP across all hosts
python -m src.app_main --action audit_ntp

# Example: update NTP (be careful!)
python -m src.app_main --action update_ntp
```
Available actions are defined in `ACTION_MAP` inside `src/app_main.py`. Current examples:
```
update_acl, audit_acl,
audit_ntp, update_ntp,
audit_domain_name, update_domain_name
```

---

## Writing a new action

Create a new module in `src/actions/` and add an entry to `ACTION_MAP` in `app_main.py`.

**Module template (Nornir 2.5):**
```python
# src/actions/audit_example.py
from nornir.core.task import Task, Result

def run(task: Task, **kwargs) -> Result:
    # do work here (netmiko, napalm, etc.)
    out = {
        "device": str(task.host),
        "ip": task.host.hostname,
        "platform": task.host.platform,
        "model": task.host.get("model", "N/A"),
        "status": "OK",
        "info": "example",
    }
    return Result(host=task.host, changed=False, result=out)
```

**Accessing your returned dict (AggregatedResult gotcha):**
```python
agg = nr.run(name="Action: example", task=run)
rows = []
for host, multi_result in agg.items():
    r = multi_result[0]           # first sub-result from your task
    rows.append(r.result)         # <-- this is the dict you returned
```
> Tip: Avoid `print(agg.result)` — `AggregatedResult` doesn’t have a `result` attribute.

**Netmiko usage (2.5 import path):**
```python
from nornir.plugins.tasks.networking import netmiko_send_command
from nornir.core.task import Task, Result

def run(task: Task) -> Result:
    r = task.run(netmiko_send_command, command_string="show clock")
    return Result(host=task.host, changed=False, result={"clock": r.result})
```

---

## Safety & change-control
- **Start with audits** (`audit_*`) before any `update_*` action
- **Juniper:** prefer `commit confirmed 5` patterns in your change actions
- **Cisco:** capture a pre-change snapshot (e.g., `show run | i ntp`, `show clock`, model/serial)
- **Logs:** write per-host logs and keep a run summary (consider shipping to Splunk)
- **Blast-radius control:** limit with host/group filters; test on a small subset first

---

## Troubleshooting

### “Too many open files” (`[Errno 24]`)
- Lower `num_workers` in `config.yaml`
- Ensure you **close connections** after large runs: `nr.close_connections()`
- Increase OS limits (`ulimit -n`) if appropriate

### Progress UI flicker
- On some TTYs, high refresh rates + progress bars can flicker. Reduce update frequency or fall back to simpler console output in non-TTY contexts.

### SSH/auth issues
- Verify `platform` matches the device (`ios`, `junos`) and credentials are set (defaults vs prompts)
- Confirm management reachability (ACLs, VRFs, jump hosts)

---

## Version cheat-sheet (2.5 vs 3.x)

| Topic | Nornir 2.5 | Nornir 3.x (if you write it by accident) |
|---|---|---|
| Init | `from nornir import InitNornir` | `from nornir import InitNornir` (same) |
| Netmiko tasks import | `from nornir.plugins.tasks.networking import netmiko_send_command` | `from nornir_netmiko.tasks import netmiko_send_command` |
| Print results | `from nornir.plugins.functions.text import print_result` | `from nornir_utils.plugins.functions import print_result` |
| Inventory plugin name | `SimpleInventory` | `SimpleInventory` (moved under `nornir.core`/`nornir_utils` patterns) |
| Result access | `agg[host][0].result` | same idea |

> If you paste 3.x import paths and see errors, use the 2.5 column above.

---

## Dependencies

Maintain two requirement files and pin versions as needed:

- `requirements-py36.txt` → for Python **3.6.8** with **Nornir 2.5** and a **Netmiko** version compatible with 3.6
- `requirements-modern.txt` → for Python **3.10+** and modern libs (use if/when you upgrade)

> You can keep a small matrix here noting which versions you’ve validated internally.

---

## Docker (optional)

If you prefer a reproducible Python 3.6 environment, use a dev container. Example image: `py36_net_configurator:dev`.

```
# Build
docker build --platform=linux/amd64 -t py36_net_configurator:dev .

# Run (mount your repo)
docker run --rm -it -v "$PWD":/workspace -w /workspace py36_net_configurator:dev bash
```

> If using VS Code Attach to Container on older distros, you may see GLIBC warnings; either use a newer base image or run the app via plain Docker.

---

## Testing
- Prefer `pytest` with small, deterministic inventories (or mocked Netmiko sessions)
- Unit-test action modules as pure functions returning `Result`
- Consider a “dry-run” mode for update actions (no device writes)

---

## Roadmap / TODO (edit as you like)
- [ ] Pin & publish known-good dependency sets for py3.6 vs modern
- [ ] Add CSV/JSON export of the pretty table
- [ ] Add `--limit`/`--filter` CLI examples to this README
- [ ] Add unit tests for each `audit_*` action
- [ ] Create a Junos `commit confirmed` helper in `utils`

---

## Contributing
- Follow the existing action pattern under `src/actions/`
- Keep functions typed (`typing` works on 3.6), add docstrings, and log sensibly
- Run lint/tests locally before PRs

---

## License
Choose a license (e.g., MIT). Add it as `LICENSE` in the repo root.

---

## Credits
Built with ❤️ by the J2 Migration team. Contributions welcome!
