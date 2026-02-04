# src/utils/auth_test.py
"""
Test authentication on a single device before running bulk operations.
Validates credentials and enable mode access.
"""

import logging
from typing import Tuple, Optional
from nornir.core import Nornir
from nornir.core.task import Task, Result
from nornir.plugins.tasks.networking import netmiko_send_command

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
        enable_secret = task.host.data.get("enable_secret")
        if _is_cisco(platform) and enable_secret:
            logger.info(f"[{host}] Testing enable mode...")
            try:
                conn = task.host.get_connection("netmiko", task.nornir.config)
                if not conn.check_enable_mode():
                    conn.enable()
                    logger.info(f"[{host}] Successfully entered enable mode")
                else:
                    logger.info(f"[{host}] Already in enable mode")
            except Exception as e:
                error_msg = f"Enable mode failed: {str(e)}"
                logger.error(f"[{host}] {error_msg}")
                return Result(
                    host=task.host,
                    failed=True,
                    result={"success": False, "error": error_msg}
                )

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
        error_msg = f"Authentication test failed: {str(e)}"
        logger.error(f"[{host}] {error_msg}", exc_info=True)
        return Result(
            host=task.host,
            failed=True,
            result={"success": False, "error": error_msg}
        )

    finally:
        # Close connection after test
        try:
            logger.debug(f"[{host}] Closing test connection...")
            task.host.close_connection("netmiko")
        except Exception:
            pass


def test_authentication(nr: Nornir) -> Tuple[bool, str]:
    """
    Test authentication on the first device in the inventory.

    Args:
        nr: Nornir instance with inventory and credentials

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not nr.inventory.hosts:
        return False, "No hosts found in inventory"

    # Get first host
    first_host_name = list(nr.inventory.hosts.keys())[0]
    first_host = nr.inventory.hosts[first_host_name]

    print(f"\nTesting authentication on: {first_host_name} ({first_host.hostname})")
    print("Please wait...")

    # Filter to only the first host
    test_nr = nr.filter(name=first_host_name)

    # Run the test
    result = test_nr.run(task=test_single_device, name="Authentication Test")

    # Check result
    if first_host_name in result:
        host_result = result[first_host_name][0]  # Get first result
        result_data = host_result.result

        if host_result.failed or not result_data.get("success"):
            error = result_data.get("error", "Unknown error")
            return False, f"Authentication test FAILED on {first_host_name}: {error}"
        else:
            return True, f"Authentication test PASSED on {first_host_name}"
    else:
        return False, f"No result returned for {first_host_name}"
