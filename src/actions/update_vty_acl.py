
    # src/actions/update_vty_acl.py
    # Python 3.6+ / Nornir 2.5

    """Update VTY 'access-class in' ACLs by inserting new entries at the top.

    This action integrates with the project's app_main runner (Nornir 2.5) and
    adheres to the standard row-dict contract used by the pretty table summary.

    High-level workflow (per host):
      1) Discover ACLs attached to VTY lines using
         :func:`fetch_vty_acl_info` from ``audit_vty_access_list.py``.
      2) Parse the current VTY line configuration to map which VTY ranges use
         which ACL(s) and preserve key attributes (IPv6 vs IPv4, ``vrf-also``).
      3) Prompt the user once per execution for one or more new ACL entries.
         The prompt displays a banner with valid examples. Type ``end`` to finish.
      4) Remove ACL bindings from the impacted VTY lines (blast-radius control).
      5) Insert the new entry lines at the **top** of each referenced ACL:
         - For IPv4, attempt a resequence (``10 10``) then insert with low
           sequence numbers (5, 6, ...).
         - For IPv6, insert at low sequence numbers directly (feature availability
           varies by platform).
      6) Verify that each ACL now contains the provided entries.
      7) Re-apply the original ACL bindings to the VTY lines.

    Result contract
    ----------------
    The function :func:`run` returns a :class:`nornir.core.task.Result` with
    ``result`` set to a dictionary shaped like:

    >>> {
    ...   "device": <host name>,
    ...   "ip": <hostname/ip>,
    ...   "platform": <platform>,
    ...   "model": <model or 'N/A'>,
    ...   "status": "OK" | "FAIL",
    ...   "info": "ACL updated" | "ACL not updated",
    ... }

    Reuse design
    ------------
    - The module provides small helpers for show/config commands so future
      scripts can import and reuse them without re-implementing CLI plumbing.
    - The ACL discovery step is delegated to
      ``audit_vty_access_list.fetch_vty_acl_info`` so that *audit* and *update*
      share identical parsing logic.

    Safety notes
    ------------
    - Removing ACLs from VTY lines is temporary and only done for the duration
      of the update; ACLs are re-applied at the end even if an update fails.
    - Consider testing on a limited subset of devices and enabling AAA/tacacs
      session redundancy to avoid lockouts.
    """

    from __future__ import print_function
    import re
    import threading
    from typing import List, Tuple, Dict, Optional
    from nornir.core.task import Task, Result
    from nornir.plugins.tasks.networking import netmiko_send_command, netmiko_send_config

    # Import the reusable fetch helper from the audit module
    try:
        from .audit_vty_access_list import fetch_vty_acl_info  # relative import when used as a package
    except Exception:
        # direct import fallback if PYTHONPATH includes src/actions
        from audit_vty_access_list import fetch_vty_acl_info

    # --------------------------- Module state (prompt once) ---------------------------
    _ENTRIES_LOCK = threading.Lock()
    _CACHED_ENTRIES = None  # type: Optional[List[str]]

    # --------------------------- Helpers: platform ---------------------------
    def _is_cisco(platform):
        """Return True if the given platform string looks like Cisco IOS/IOS-XE/NX-OS."""
        p = (platform or "").lower()
        return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos")

    # --------------------------- Helpers: Nornir wrappers ---------------------------
    def _extract_text(nr_result):
        """Extract plain text from a Nornir/Netmiko result.

        Handles both a single :class:`Result` and a :class:`MultiResult`. Returns
        an empty string on failure.
        """
        out = getattr(nr_result, "result", None)
        if isinstance(out, str):
            return out
        try:
            return nr_result[0].result
        except Exception:
            return ""

    def _send_show(task: Task, command: str, name: str = None) -> str:
        """Run a show command via Netmiko and return its raw output string."""
        r = task.run(task=netmiko_send_command, command_string=command, name=name or command)
        return (_extract_text(r) or "").strip()

    def _send_cfg(task: Task, commands: List[str], name: str = None) -> str:
        """Send a list of config commands via Netmiko and return raw device feedback.

        The function performs a simple error scan for common IOS error tokens;
        callers should still perform semantic verification with separate show
        commands.
        """
        r = task.run(task=netmiko_send_config, config_commands=commands, name=name or "config")
        return (_extract_text(r) or "").strip()

    # --------------------------- User banner & prompt ---------------------------
    _BANNER = """
    =====================  VTY ACL UPDATE – INPUT FORMAT  =====================
    Enter the ACL entry you want to add at the TOP of each named ACL discovered.
    Type exactly as you would inside the ACL config mode.

    Examples (copy/paste one per line):
      permit 10.0.0.0
      deny 12.0.0.0 0.0.0.255
      permit 11.0.0.0 eq 23
      permit icmp 10.1.1.0 0.0.0.255 172.16.1.0 0.0.0.255

    When done, type: end
    ==========================================================================
"""

    def _prompt_new_entries() -> List[str]:
        """Prompt the operator for one or more ACL entries.

        Returns a list of non-empty lines that start with ``permit`` or ``deny``.
        Input is terminated by the literal ``end`` (case-insensitive).
        """
        print(_BANNER)
        entries = []  # type: List[str]
        while True:
            try:
                line = input("New ACL entry (or 'end'): ").strip()
            except EOFError:
                break
            if not line:
                continue
            if line.lower() == "end":
                break
            if not (line.lower().startswith("permit ") or line.lower().startswith("deny ")):
                print("Entry must start with 'permit' or 'deny'. Try again.")
                continue
            entries.append(line)
        return entries

    def _get_new_entries_once() -> List[str]:
        """Get new ACL entries, prompting only once per program execution.

        The result is cached in a module-global variable so that concurrent
        Nornir workers do not re-prompt the user.
        """
        global _CACHED_ENTRIES
        if _CACHED_ENTRIES is None:
            with _ENTRIES_LOCK:
                if _CACHED_ENTRIES is None:
                    _CACHED_ENTRIES = _prompt_new_entries()
        return _CACHED_ENTRIES or []

    # --------------------------- Parse VTY mapping ---------------------------
    _VTY_START = re.compile(r"^\s*line\s+vty\s+(\d+)(?:\s+(\d+))?\s*$", re.IGNORECASE)
    _ACL_LINE = re.compile(r"^\s*(ipv6\s+)?access-class\s+(\S+)\s+in(\s+vrf-also)?\s*$", re.IGNORECASE)

    def _get_vty_sections(task: Task) -> str:
        """Return the full 'line vty' configuration section for the device.

        Tries ``show running-config | section line vty`` first and falls back to
        ``show run | s line vty`` for older platforms.
        """
        text = _send_show(task, "show running-config | section line vty", name="section line vty")
        if not text:
            text = _send_show(task, "show run | s line vty", name="s line vty")
        return text

    def _parse_vty_map(section_text: str) -> List[Dict[str, str]]:
        """Parse VTY sections to map VTY ranges to attached ACLs.

        Parameters
        ----------
        section_text : str
            The output from :func:`_get_vty_sections`.

        Returns
        -------
        List[Dict[str, str]]
            A list of dictionaries with keys:
              - ``range``: e.g. ``"0 4"``
              - ``acl``: ACL name
              - ``is_ipv6``: ``"1"`` for IPv6 ACLs, ``"0"`` for IPv4
              - ``suffix``: ``"in"`` or ``"in vrf-also"``
        """
        result = []  # type: List[Dict[str, str]]
        current_range = None  # type: Optional[str]
        for raw in section_text.splitlines():
            line = raw.rstrip()
            m = _VTY_START.match(line)
            if m:
                start = m.group(1)
                end = m.group(2) or m.group(1)
                current_range = "%s %s" % (start, end)
                continue
            if current_range is None:
                continue
            a = _ACL_LINE.match(line)
            if a:
                is6 = bool(a.group(1))
                acl = a.group(2)
                suffix = "in" + (a.group(3) or "")
                result.append({"range": current_range, "acl": acl, "is_ipv6": "1" if is6 else "0", "suffix": suffix})
        return result

    # --------------------------- ACL helpers ---------------------------
    _STD_HDR = re.compile(r"Standard IP access list\s+(\S+)", re.IGNORECASE)
    _EXT_HDR = re.compile(r"Extended IP access list\s+(\S+)", re.IGNORECASE)
    _IPV6_HDR = re.compile(r"IPv6 access list\s+(\S+)", re.IGNORECASE)

    def _detect_acl_type(task: Task, name: str, is_ipv6_hint: bool) -> str:
        """Detect the ACL type for a given name.

        Returns one of ``'standard'``, ``'extended'``, or ``'ipv6'``. If the
        type cannot be determined from show commands, defaults to ``'extended'``.
        """
        if is_ipv6_hint:
            return "ipv6"
        out = _send_show(task, "show ip access-lists %s" % name, name="show ip access-lists %s" % name)
        if _STD_HDR.search(out):
            return "standard"
        if _EXT_HDR.search(out):
            return "extended"
        # try generic
        out2 = _send_show(task, "show access-lists %s" % name, name="show access-lists %s" % name)
        if _STD_HDR.search(out2):
            return "standard"
        if _EXT_HDR.search(out2):
            return "extended"
        # ipv6?
        out6 = _send_show(task, "show ipv6 access-list %s" % name, name="show ipv6 access-list %s" % name)
        if _IPV6_HDR.search(out6):
            return "ipv6"
        return "extended"

    def _acl_show(task: Task, name: str, typ: str) -> str:
        """Return the text of the ACL by name and type (IPv4/IPv6)."""
        if typ == "ipv6":
            return _send_show(task, "show ipv6 access-list %s" % name)
        out = _send_show(task, "show ip access-lists %s" % name)
        return out or _send_show(task, "show access-lists %s" % name)

    def _enter_acl_mode_cmds(name: str, typ: str) -> List[str]:
        """Return the config-mode command(s) to enter the ACL submode."""
        if typ == "ipv6":
            return ["ipv6 access-list %s" % name]
        if typ == "standard":
            return ["ip access-list standard %s" % name]
        return ["ip access-list extended %s" % name]

    def _try_resequence_cmds(name: str, typ: str) -> Optional[List[str]]:
        """Return resequence commands for IPv4 ACLs, or ``None`` for IPv6 or unsupported.

        On IOS-XE, resequencing is typically performed with::

            ip access-list resequence <ACL_NAME> 10 10
        """
        if typ == "ipv6":
            return None
        return ["ip access-list resequence %s 10 10" % name]

    def _add_entries_top(task: Task, name: str, typ: str, entries: List[str]) -> bool:
        """Insert entries at the top of an ACL using sequence numbers.

        Attempts to resequence IPv4 ACLs to ``10 10`` before inserting at low
        sequence numbers (5, 6, ...). For IPv6, inserts starting at 1.

        Returns ``True`` if no obvious CLI errors were detected in device
        feedback; final correctness is verified separately by reading back
        the ACL text and checking for all entries.
        """
        ok = True
        # attempt resequence for IPv4
        reseq = _try_resequence_cmds(name, typ)
        if reseq:
            _send_cfg(task, reseq, name="resequence %s" % name)
        # build commands within ACL submode
        cmds = _enter_acl_mode_cmds(name, typ)
        # choose low sequences unlikely to collide
        seq = 5 if reseq else 1
        for e in entries:
            cmds.append("%d %s" % (seq, e))
            seq += 1  # maintain relative order
        cmds.append("exit")
        out = _send_cfg(task, cmds, name="update ACL %s" % name)
        # naive check for error tokens
        if any(tok in out.lower() for tok in ("% invalid", "error", "incomplete", "ambiguous")):
            ok = False
        return ok

    # --------------------------- VTY apply/remove ---------------------------
    def _remove_vty_acls(task: Task, mapping: List[Dict[str, str]]) -> None:
        """Temporarily remove ACL bindings from VTY lines based on mapping."""
        cmds = []
        # group by range
        by_range = {}  # type: Dict[str, List[Dict[str, str]]]
        for m in mapping:
            by_range.setdefault(m["range"], []).append(m)
        for rng, items in by_range.items():
            cmds.append("line vty %s" % rng)
            for m in items:
                prefix = "ipv6 access-class" if m["is_ipv6"] == "1" else "access-class"
                cmds.append("no %s %s %s" % (prefix, m["acl"], m["suffix"]))
            cmds.append("exit")
        if cmds:
            _send_cfg(task, cmds, name="remove VTY access-class")

    def _reapply_vty_acls(task: Task, mapping: List[Dict[str, str]]) -> None:
        """Restore ACL bindings to VTY lines using the previously captured mapping."""
        cmds = []
        by_range = {}
        for m in mapping:
            by_range.setdefault(m["range"], []).append(m)
        for rng, items in by_range.items():
            cmds.append("line vty %s" % rng)
            for m in items:
                prefix = "ipv6 access-class" if m["is_ipv6"] == "1" else "access-class"
                cmds.append("%s %s %s" % (prefix, m["acl"], m["suffix"]))
            cmds.append("exit")
        if cmds:
            _send_cfg(task, cmds, name="re-apply VTY access-class")

    # ------------------------------- Action ---------------------------------
    def run(task: Task, pm=None) -> Result:
        """Nornir action entry point to update VTY ACLs and return a summary row.

        Parameters
        ----------
        task : Task
            Nornir task with current host context.
        pm : optional
            Progress manager (if your runner passes one); ignored if not provided.

        Returns
        -------
        Result
            ``Result.result`` is the standard row dictionary for the pretty table.
        """
        host = task.host.name
        platform = task.host.platform
        ip = task.host.hostname

        if not _is_cisco(platform):
            row = {
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "OK",
                "info": "Not applicable (non-Cisco platform)",
            }
            return Result(host=task.host, changed=False, result=row)

        # Discover ACLs present on VTY and build mapping of VTY ranges -> ACLs
        raw, acl_names = fetch_vty_acl_info(task)
        section = _get_vty_sections(task)
        mapping = _parse_vty_map(section)
        # Filter mapping to only ACLs we discovered (defensive)
        if acl_names:
            mapping = [m for m in mapping if m["acl"] in acl_names]

        if not mapping:
            row = {
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "FAIL",
                "info": "No 'access-class in' lines found on VTY",
            }
            return Result(host=task.host, changed=False, result=row)

        # Ask the user for new entries (once per execution) unless provided via host data
        new_entries = task.host.get("new_acl_entries") or _get_new_entries_once()
        if not new_entries:
            row = {
                "device": host,
                "ip": ip,
                "platform": platform,
                "model": task.host.get("model", "N/A"),
                "status": "FAIL",
                "info": "ACL not updated (no new entries provided)",
            }
            return Result(host=task.host, changed=False, result=row)

        # Remove VTY bindings first (blast radius control)
        _remove_vty_acls(task, mapping)

        # Update each unique ACL once
        success_all = True
        handled = set()  # type: set
        for m in mapping:
            name = m["acl"]
            if name in handled:
                continue
            handled.add(name)
            typ = _detect_acl_type(task, name, is_ipv6_hint=(m["is_ipv6"] == "1"))
            before = _acl_show(task, name, typ)
            ok = _add_entries_top(task, name, typ, new_entries)
            after = _acl_show(task, name, typ)
            # verify containment of all new entries in 'after'
            if not ok or not all(e.lower() in after.lower() for e in new_entries):
                success_all = False

        # Re-apply previous VTY bindings regardless; if ACL update failed we still restore
        _reapply_vty_acls(task, mapping)

        status = "OK" if success_all else "FAIL"
        info = "ACL updated" if success_all else "ACL not updated"

        row = {
            "device": host,
            "ip": ip,
            "platform": platform,
            "model": task.host.get("model", "N/A"),
            "status": status,
            "info": info,
        }
        return Result(host=task.host, changed=True, result=row)
