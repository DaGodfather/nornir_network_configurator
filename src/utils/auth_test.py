# src/utils/auth_test.py
"""
Test authentication on devices before running bulk operations.
Tries multiple devices in case the first is down or unreachable.
Validates credentials and enable mode access.
If SSH fails with a banner/protocol error, clears the cache and retries via Telnet.
"""

import logging
import telnetlib
import time
from typing import Tuple, Optional
from nornir.core import Nornir
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command
from src.utils.transport_discovery import (
    apply_conn, load_cache, save_cache, platform_to_netmiko_types, is_port_open
)
from src.utils.enable_mode import enter_enable_mode_robust
from src.utils.ping_check import is_reachable

logger = logging.getLogger(__name__)


def _test_password_only_telnet(
    host_name: str, ip: str, port: int, password: str, timeout: int = 20
) -> Tuple[bool, str]:
    """
    Test Telnet login for devices using password-only auth (no Username: prompt).
    Used when 'aaa authentication login default enable' is configured — the device
    skips the username prompt and expects only the enable password at login.

    Netmiko's cisco_ios_telnet always sends a username before waiting for prompts,
    which confuses the device and causes 'telnet connection closed'. This function
    uses raw telnetlib so we can respond only when the Password: prompt appears.
    """
    try:
        tn = telnetlib.Telnet(ip, port, timeout=timeout)

        # Read past the MOTD/banner and wait for the Password: prompt.
        idx, _, _ = tn.expect(
            [b"Password:", b"password:", b"assword "],
            timeout=timeout,
        )
        if idx < 0:
            tn.close()
            return False, "No password prompt received within timeout"

        tn.write(password.encode("ascii") + b"\n")

        # Give the device a moment to process and return the exec prompt.
        time.sleep(3)
        response = tn.read_very_eager().decode("ascii", errors="ignore")
        tn.close()

        if ">" in response or "#" in response:
            logger.info(f"[{host_name}] Password-only telnet login successful")
            return True, "Password-only telnet login successful"
        else:
            logger.warning(
                f"[{host_name}] Unexpected response after password: {response[:100]!r}"
            )
            return False, f"Login failed - no exec prompt in response: {response[:80]!r}"

    except Exception as e:
        logger.error(f"[{host_name}] Password-only telnet test error: {str(e)}")
        return False, f"Telnet connection error: {str(e)}"


def _is_cisco(platform: Optional[str]) -> bool:
    """Check if platform is Cisco."""
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


def _is_juniper(platform: Optional[str]) -> bool:
    """Check if platform is Juniper."""
    p = (platform or "").lower()
    return p in ("juniper", "junos", "juniper_junos")


def test_single_device(task: Task) -> Result:
    """
    Test authentication and enable mode on a single device.

    Returns:
        Result with success/failure info
    """
    host = task.host.name
    platform = task.host.platform
    ip = task.host.hostname

    logger.info(f"[{host}] Testing authentication to {ip}...")

    try:
        # Get connection details
        conn_opts = task.host.connection_options.get("netmiko")
        if conn_opts:
            device_type = conn_opts.extras.get("device_type", "unknown")
            port = conn_opts.port or "default"
            logger.info(f"[{host}] Connection: device_type={device_type}, port={port}")

        # Try to get connection and enter enable mode for Cisco
        if _is_cisco(platform):
            logger.info(f"[{host}] Testing enable mode...")
            enable_success, enable_message = enter_enable_mode_robust(
                task=task,
                max_attempts=3,
                delay_between_attempts=15,
                force_new_connection=False
            )

            if not enable_success:
                error_msg = f"Enable mode failed: {enable_message}"
                logger.error(f"[{host}] {error_msg}")
                return Result(
                    host=task.host,
                    failed=True,
                    result={"success": False, "error": error_msg}
                )

            logger.info(f"[{host}] Enable mode test successful: {enable_message}")

        # Send a simple test command
        test_cmd = "show version | include Version" if _is_cisco(platform) else "show version"
        logger.info(f"[{host}] Sending test command: {test_cmd}")

        r = task.run(
            task=netmiko_send_command,
            command_string=test_cmd,
            name="Auth test command",
            delay_factor=2,
            max_loops=500
        )

        output = r.result if isinstance(r.result, str) else str(r.result)

        if output and len(output.strip()) > 0:
            logger.info(f"[{host}] Authentication test PASSED")
            logger.debug(f"[{host}] Test output: {output[:100]}...")
            return Result(
                host=task.host,
                result={"success": True, "message": "Authentication successful"}
            )
        else:
            error_msg = "Command returned empty output"
            logger.error(f"[{host}] {error_msg}")
            return Result(
                host=task.host,
                failed=True,
                result={"success": False, "error": error_msg}
            )

    except Exception as e:
        error_str = str(e)
        # Detect broken SSH stack (device accepts TCP/22 but drops connection).
        # Flag it so test_authentication() can clear the cache and retry via Telnet.
        ssh_banner_keywords = (
            "Error reading SSH protocol banner",
            "kex_exchange_identification",
            "Connection closed by remote host",
            "SSH negotiation failed",
        )
        is_ssh_banner_error = any(kw.lower() in error_str.lower() for kw in ssh_banner_keywords)

        error_msg = f"Authentication test failed: {error_str}"
        logger.error(f"[{host}] {error_msg}", exc_info=True)
        return Result(
            host=task.host,
            failed=True,
            result={
                "success": False,
                "error": error_msg,
                "ssh_banner_error": is_ssh_banner_error,
            }
        )

    finally:
        # Close connection after test
        try:
            logger.debug(f"[{host}] Closing test connection...")
            task.host.close_connection("netmiko")
        except Exception:
            pass


def test_authentication(nr: Nornir, max_attempts: int = 3) -> Tuple[bool, str]:
    """
    Test authentication on devices in the inventory.
    Walks the full device list, skipping unreachable devices, until up to
    max_attempts reachable devices have been tested.

    Args:
        nr: Nornir instance with inventory and credentials
        max_attempts: Maximum number of reachable devices to test (default: 3)

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not nr.inventory.hosts:
        return False, "No hosts found in inventory"

    host_names = list(nr.inventory.hosts.keys())
    total_hosts = len(host_names)

    print(f"\nTesting authentication against {total_hosts} device(s) in inventory...")

    failed_hosts = []
    tested_count = 0   # how many reachable devices attempted
    success_count = 0  # how many have passed (we stop after 1)

    for host_name in host_names:
        if success_count >= 1:
            break
        # Hard safety cap: don't test more than max_attempts * 5 reachable devices
        if tested_count >= max_attempts * 5:
            break

        host_obj = nr.inventory.hosts[host_name]
        ip = host_obj.hostname or ""

        # --- Ping check first ---
        conn_opts = host_obj.connection_options.get("netmiko")
        port = int(conn_opts.port) if conn_opts and conn_opts.port else None

        try:
            reachable = is_reachable(ip, port=port)
        except Exception as e:
            logger.warning(f"[{host_name}] Reachability check error: {str(e)} - skipping")
            reachable = False

        if not reachable:
            print(f"  ⏭  Skipping {host_name} ({ip}) - Device is unreachable, maybe offline")
            logger.warning(f"[{host_name}] Ping check failed - skipping auth test")
            failed_hosts.append((host_name, "Device is unreachable, maybe offline"))
            continue

        # --- Device is reachable - run auth test ---
        tested_count += 1
        print(f"\nAuth test attempt {tested_count}: {host_name} ({ip})")
        print("Please wait...")

        test_nr = nr.filter(name=host_name)
        result = test_nr.run(task=test_single_device, name="Authentication Test")

        if host_name in result:
            host_result = result[host_name][0]
            result_data = host_result.result

            if host_result.failed or not result_data.get("success"):
                error = result_data.get("error", "Unknown error")

                # Detect broken SSH stack - clear cache and retry via Telnet on same host
                if result_data.get("ssh_banner_error"):
                    print(f"⚠️  SSH banner failure on {host_name} - SSH port is open but broken.")
                    print(f"   Falling back to Telnet for {host_name}...")
                    logger.warning(f"[{host_name}] SSH banner error detected - attempting Telnet fallback")

                    _, telnet_type = platform_to_netmiko_types(host_obj.platform)

                    if telnet_type and is_port_open(ip, 23, timeout=2.0):
                        apply_conn(host_obj, telnet_type, 23)
                        host_obj["mgmt_transport"] = "telnet"
                        host_obj["device_type"] = telnet_type
                        host_obj["port"] = 23

                        cache = load_cache("transport_cache.json")
                        cache[host_name] = {"transport": "telnet", "device_type": telnet_type, "port": 23}
                        save_cache(cache, "transport_cache.json")
                        logger.info(f"[{host_name}] Cache updated to Telnet")

                        print(f"   Retrying authentication via Telnet...")
                        nr.data.failed_hosts.discard(host_name)
                        retry_nr = nr.filter(name=host_name)
                        retry_result = retry_nr.run(task=test_single_device, name="Authentication Test (Telnet)")
                        if host_name in retry_result:
                            retry_host_result = retry_result[host_name][0]
                            retry_data = retry_host_result.result
                            if not retry_host_result.failed and retry_data.get("success"):
                                success_msg = f"Authentication test PASSED on {host_name} (via Telnet fallback)"
                                if failed_hosts:
                                    failed_list = ", ".join([f"{h[0]}" for h in failed_hosts])
                                    success_msg += f"\n(Previous attempts failed on: {failed_list})"
                                return True, success_msg
                            else:
                                error = retry_data.get("error", "Unknown error")
                                print(f"❌ Telnet fallback also FAILED on {host_name}: {error}")
                    else:
                        print(f"   Telnet (port 23) is not available on {host_name}.")

                elif host_obj.data.get("local_test_password"):
                    # Primary credentials failed and a local test password is available
                    # (e.g. update_aaa_login_method action). Device may already be updated
                    # and no longer accepting TACACS credentials - try local creds.
                    local_test_password = host_obj.data["local_test_password"]
                    print(f"⚠️  Primary auth failed on {host_name} - device may already be updated.")
                    print(f"   Retrying with local test password...")
                    logger.warning(
                        f"[{host_name}] Primary auth failed - retrying with local_test_password"
                    )

                    # Update ALL credential locations so any subsequent Nornir/enable_mode
                    # calls use local_test_password (including the manual enable fallback
                    # in enter_enable_mode_robust which reads host.data["enable_secret"]).
                    host_obj.password = local_test_password
                    host_obj.data["enable_secret"] = local_test_password
                    conn_opts_ref = host_obj.connection_options.get("netmiko")
                    if conn_opts_ref:
                        conn_opts_ref.extras["secret"] = local_test_password
                    try:
                        host_obj.close_connection("netmiko")
                    except Exception:
                        pass

                    # Devices configured with 'aaa authentication login default enable'
                    # show only a Password: prompt over Telnet (no Username: prompt).
                    # Netmiko always sends a username before waiting for prompts, which
                    # the device treats as a wrong password and closes the connection.
                    # Use raw telnetlib so we respond only when Password: appears.
                    device_type = (
                        conn_opts_ref.extras.get("device_type", "") if conn_opts_ref else ""
                    )
                    telnet_port = (
                        int(conn_opts_ref.port) if conn_opts_ref and conn_opts_ref.port else 23
                    )

                    if "telnet" in device_type.lower():
                        logger.info(
                            f"[{host_name}] Using password-only telnet test (no username prompt)"
                        )
                        retry_ok, retry_msg = _test_password_only_telnet(
                            host_name, ip, telnet_port, local_test_password
                        )
                        if retry_ok:
                            # Mark that the action can skip Netmiko connection attempts —
                            # device is already updated and uses password-only telnet auth
                            # that Netmiko can't handle.
                            host_obj.data["local_creds_verified"] = True
                            success_msg = (
                                f"Authentication test PASSED on {host_name} "
                                f"(via local test password - device may already be updated)"
                            )
                            if failed_hosts:
                                failed_list = ", ".join([f"{h[0]}" for h in failed_hosts])
                                success_msg += f"\n(Previous attempts failed on: {failed_list})"
                            return True, success_msg
                        else:
                            error = retry_msg
                            print(f"❌ Local test password fallback also FAILED on {host_name}: {error}")
                    else:
                        # SSH devices: Netmiko handles username+password correctly even with
                        # 'aaa authentication login default enable', so use the normal task.
                        nr.data.failed_hosts.discard(host_name)
                        retry_nr = nr.filter(name=host_name)
                        retry_result = retry_nr.run(
                            task=test_single_device, name="Authentication Test (Local Creds)"
                        )
                        if host_name in retry_result:
                            retry_host_result = retry_result[host_name][0]
                            retry_data = retry_host_result.result
                            if not retry_host_result.failed and retry_data.get("success"):
                                host_obj.data["local_creds_verified"] = True
                                success_msg = (
                                    f"Authentication test PASSED on {host_name} "
                                    f"(via local test password - device may already be updated)"
                                )
                                if failed_hosts:
                                    failed_list = ", ".join([f"{h[0]}" for h in failed_hosts])
                                    success_msg += f"\n(Previous attempts failed on: {failed_list})"
                                return True, success_msg
                            else:
                                error = retry_data.get("error", "Unknown error")
                                print(f"❌ Local test password fallback also FAILED on {host_name}: {error}")

                elif (
                    _is_juniper(host_obj.platform)
                    and host_obj.data.get("local_juniper_password")
                    and not host_obj.data.get("tacacs_username")
                ):
                    # Juniper local credentials fallback (make_juniper_login_local / update_juniper_local_credential).
                    # Only when NOT in use_local mode (tacacs_username absent means TACACS is primary).
                    # Device may already be switched to local auth.
                    local_jun_username = host_obj.data.get(
                        "local_juniper_username", host_obj.username
                    )
                    local_jun_password = host_obj.data["local_juniper_password"]
                    print(f"⚠️  Primary auth failed on {host_name} - device may already be updated.")
                    print(f"   Retrying with local Juniper credentials...")
                    logger.warning(
                        f"[{host_name}] Primary auth failed - retrying with local_juniper_password"
                    )

                    host_obj.username = local_jun_username
                    host_obj.password = local_jun_password

                    # transport_cache.json may have cached a wrong device_type
                    # (e.g. cisco_ios) for this Juniper host. Reset connection
                    # options to juniper so Netmiko uses the correct handler.
                    conn_opts_ref = host_obj.connection_options.get("netmiko")
                    jun_port = (
                        int(conn_opts_ref.port)
                        if conn_opts_ref and conn_opts_ref.port
                        else 22
                    )
                    apply_conn(host_obj, "juniper", jun_port)

                    try:
                        host_obj.close_connection("netmiko")
                    except Exception:
                        pass

                    nr.data.failed_hosts.discard(host_name)
                    retry_nr = nr.filter(name=host_name)
                    retry_result = retry_nr.run(
                        task=test_single_device,
                        name="Authentication Test (Local Juniper Creds)",
                    )
                    if host_name in retry_result:
                        retry_host_result = retry_result[host_name][0]
                        retry_data = retry_host_result.result
                        if not retry_host_result.failed and retry_data.get("success"):
                            host_obj.data["local_creds_verified"] = True
                            success_msg = (
                                f"Authentication test PASSED on {host_name} "
                                f"(via local Juniper credentials - device may already be updated)"
                            )
                            if failed_hosts:
                                failed_list = ", ".join([f"{h[0]}" for h in failed_hosts])
                                success_msg += f"\n(Previous attempts failed on: {failed_list})"
                            return True, success_msg
                        else:
                            error = retry_data.get("error", "Unknown error")
                            print(f"❌ Local Juniper credentials also FAILED on {host_name}: {error}")

                elif host_obj.data.get("tacacs_username"):
                    # use_local mode: local credentials (primary) failed — fall back to TACACS.
                    # This handles devices that are not yet switched to local auth.
                    tacacs_user = host_obj.data["tacacs_username"]
                    tacacs_pass = host_obj.data["tacacs_password"]
                    tacacs_enable = host_obj.data.get("tacacs_enable", tacacs_pass)
                    print(f"⚠️  Local credentials failed on {host_name} - trying TACACS fallback...")
                    logger.warning(
                        f"[{host_name}] Local credentials failed (use_local mode) - retrying with TACACS"
                    )

                    host_obj.username = tacacs_user
                    host_obj.password = tacacs_pass
                    host_obj.data["enable_secret"] = tacacs_enable
                    # Keep local_juniper_username/password so Juniper actions can still use them
                    try:
                        host_obj.close_connection("netmiko")
                    except Exception:
                        pass

                    nr.data.failed_hosts.discard(host_name)
                    retry_nr = nr.filter(name=host_name)
                    retry_result = retry_nr.run(
                        task=test_single_device,
                        name="Authentication Test (TACACS fallback)",
                    )
                    if host_name in retry_result:
                        retry_host_result = retry_result[host_name][0]
                        retry_data = retry_host_result.result
                        if not retry_host_result.failed and retry_data.get("success"):
                            # TACACS worked — device is not yet on local auth.
                            # Keep TACACS as the active credentials for this run.
                            success_msg = (
                                f"Authentication test PASSED on {host_name} "
                                f"(via TACACS fallback - device not yet on local auth)"
                            )
                            if failed_hosts:
                                failed_list = ", ".join([f"{h[0]}" for h in failed_hosts])
                                success_msg += f"\n(Previous attempts failed on: {failed_list})"
                            return True, success_msg
                        else:
                            error = retry_data.get("error", "Unknown error")
                            print(f"❌ TACACS fallback also FAILED on {host_name}: {error}")

                failed_hosts.append((host_name, error))
                print(f"❌ FAILED on {host_name}: {error}")
                print(f"Trying next device...")
            else:
                success_msg = f"Authentication test PASSED on {host_name}"
                if failed_hosts:
                    failed_list = ", ".join([f"{h[0]}" for h in failed_hosts])
                    success_msg += f"\n(Previous attempts failed on: {failed_list})"
                return True, success_msg
        else:
            error = f"No result returned for {host_name}"
            failed_hosts.append((host_name, error))
            print(f"❌ FAILED on {host_name}: {error}")
            print(f"Trying next device...")

    # All reachable devices tested and failed (or none were reachable)
    failed_summary = "\n".join([f"  - {h[0]}: {h[1]}" for h in failed_hosts])
    return False, f"Authentication test FAILED on all tested device(s):\n{failed_summary}"
