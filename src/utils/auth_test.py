# src/utils/auth_test.py
"""
Test authentication on devices before running bulk operations.
Tries multiple devices in case the first is down or unreachable.
Validates credentials and enable mode access.
If SSH fails with a banner/protocol error, clears the cache and retries via Telnet.
"""

import logging
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


def _is_cisco(platform: Optional[str]) -> bool:
    """Check if platform is Cisco."""
    p = (platform or "").lower()
    return p in ("cisco_ios", "ios", "ios-xe", "iosxe", "cisco_nxos", "nxos", "cisco_ios_telnet")


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

    print(f"\nTesting authentication (will test up to {max_attempts} reachable device(s) from {total_hosts} in inventory)...")

    failed_hosts = []
    tested_count = 0  # how many reachable devices have been auth-tested

    for host_name in host_names:
        if tested_count >= max_attempts:
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
        print(f"\nAuth test {tested_count}/{max_attempts}: {host_name} ({ip})")
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
