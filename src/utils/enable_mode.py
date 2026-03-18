# src/utils/enable_mode.py
"""
Robust enable mode handling for Cisco devices.
Includes multiple retry strategies and workarounds for problematic devices.
"""

import logging
import time
from typing import Tuple, Optional
from nornir.core.task import Task
from src.utils.transport_discovery import apply_conn, is_port_open, load_cache, save_cache

logger = logging.getLogger(__name__)


def enter_enable_mode_robust(
    task: Task,
    max_attempts: int = 3,
    delay_between_attempts: int = 15,
    force_new_connection: bool = False,
) -> Tuple[bool, str]:
    """
    Robustly enter enable mode on a Cisco device with multiple fallback strategies.

    Args:
        task: Nornir task object
        max_attempts: Maximum number of attempts (default: 3)
        delay_between_attempts: Seconds to wait between attempts (default: 15)
        force_new_connection: Force close and reopen connection on first failure (default: False)

    Returns:
        Tuple of (success: bool, message: str)

    Strategies used:
    1. Standard enable() call
    2. Close connection and retry (clears any stuck state)
    3. Send newline before enable (clears partial commands)
    4. Use send_command_timing() instead of enable() (for devices with non-standard prompts)
    5. Extended delay with multiple checks
    """
    host = task.host.name
    enable_secret = task.host.data.get("enable_secret")

    if not enable_secret:
        logger.info(f"[{host}] No enable_secret configured - skipping enable mode")
        return True, "No enable_secret configured"

    logger.info(f"[{host}] Attempting to enter enable mode (max {max_attempts} attempts)...")

    _telnet_switched = False  # only switch SSH→Telnet once per call

    for attempt in range(max_attempts):
        try:
            # Strategy 2: On second attempt (or first if forced), close and reopen connection to clear state
            if attempt == 1 or (attempt == 0 and force_new_connection):
                logger.info(f"[{host}] Closing connection to clear state before retry...")
                try:
                    task.host.close_connection("netmiko")
                    time.sleep(3)  # Brief pause to ensure clean close
                    logger.info(f"[{host}] Connection closed, will reopen...")
                except Exception as e:
                    logger.warning(f"[{host}] Error closing connection: {str(e)}")

            # Get connection (or reconnect if closed)
            logger.debug(f"[{host}] Getting netmiko connection (attempt {attempt + 1})...")
            try:
                conn = task.host.get_connection("netmiko", task.nornir.config)
                logger.info(f"[{host}] Connection established successfully")
            except Exception as conn_error:
                error_msg = f"Failed to establish connection: {str(conn_error)}"
                logger.error(f"[{host}] {error_msg}")
                # If we can't connect, try next attempt
                if attempt < max_attempts - 1:
                    logger.info(f"[{host}] Waiting {delay_between_attempts} seconds before retry...")
                    time.sleep(delay_between_attempts)
                    continue
                else:
                    return False, error_msg

            # Strategy 1: Check if already in enable mode
            logger.debug(f"[{host}] Checking if already in enable mode...")
            if conn.check_enable_mode():
                logger.info(f"[{host}] Already in enable mode (attempt {attempt + 1})")
                return True, f"Already in enable mode (attempt {attempt + 1})"

            # Strategy 3: Send newline to clear any partial commands
            if attempt > 0:
                try:
                    logger.debug(f"[{host}] Sending newline to clear buffer...")
                    conn.write_channel("\n")
                    time.sleep(1)
                except Exception as e:
                    logger.debug(f"[{host}] Error sending newline: {str(e)}")

            # Strategy 4: Standard enable() method
            logger.info(f"[{host}] Calling enable() method (attempt {attempt + 1})...")
            conn.enable()

            # Verify we're in enable mode
            time.sleep(2)  # Give device time to process
            if conn.check_enable_mode():
                logger.info(f"[{host}] Successfully entered enable mode (attempt {attempt + 1})")
                return True, f"Enable mode successful (attempt {attempt + 1})"
            else:
                logger.warning(f"[{host}] enable() returned but check_enable_mode() still False")
                # Continue to next attempt

        except Exception as e:
            error_str = str(e)
            logger.warning(f"[{host}] Enable mode attempt {attempt + 1} failed: {error_str}")

            # SSH → Telnet fallback: if SSH fails and port 23 is open, switch transport
            # and update cache. The next retry attempt will use Telnet automatically.
            if not _telnet_switched:
                conn_opts_check = task.host.connection_options.get("netmiko")
                current_dt = (
                    conn_opts_check.extras.get("device_type", "") if conn_opts_check else ""
                )
                if "telnet" not in current_dt.lower():
                    ip = task.host.hostname or ""
                    if is_port_open(ip, 23, timeout=2.0):
                        logger.warning(
                            f"[{host}] SSH failed, port 23 open - switching to Telnet "
                            f"and updating transport cache"
                        )
                        apply_conn(task.host, "cisco_ios_telnet", 23)
                        cache = load_cache("transport_cache.json")
                        cache[host] = {
                            "transport": "telnet",
                            "device_type": "cisco_ios_telnet",
                            "port": 23,
                        }
                        save_cache(cache, "transport_cache.json")
                        _telnet_switched = True
                        logger.info(f"[{host}] transport_cache.json updated to Telnet")

            # Strategy 5: On last attempt before final, try manual enable command
            if attempt == max_attempts - 2:
                try:
                    logger.info(f"[{host}] Trying manual 'enable' command with send_command_timing...")
                    conn = task.host.get_connection("netmiko", task.nornir.config)

                    logger.info(f"[{host}] Connection was made to device successfully")
                    # Send enable command manually
                    output = conn.send_command_timing("enable", delay_factor=4)
                    logger.debug(f"[{host}] Output after 'enable': {output[:100]}")

                    # Check if password prompt appeared
                    if "assword" in output.lower():
                        logger.debug(f"[{host}] Sending enable password...")
                        output = conn.send_command_timing(enable_secret, delay_factor=4)
                        logger.debug(f"[{host}] Output after password: {output[:100]}")

                    # Verify with check_enable_mode
                    time.sleep(2)
                    if conn.check_enable_mode():
                        logger.info(f"[{host}] Manual enable command successful!")
                        return True, "Enable mode successful via manual command"

                except Exception as manual_error:
                    logger.warning(f"[{host}] Manual enable attempt failed: {str(manual_error)}")

            # Not the last attempt, wait before retrying
            if attempt < max_attempts - 1:
                logger.info(f"[{host}] Waiting {delay_between_attempts} seconds before retry...")
                time.sleep(delay_between_attempts)
            else:
                # Last attempt failed
                error_msg = f"Enable mode failed after {max_attempts} attempts: {error_str}"
                logger.error(f"[{host}] {error_msg}")
                return False, error_msg

    # All attempts exhausted
    error_msg = f"Enable mode failed after {max_attempts} attempts"
    logger.error(f"[{host}] {error_msg}")
    return False, error_msg


def enter_enable_mode_simple(task: Task, max_attempts: int = 2) -> None:
    """
    Simplified enable mode entry with basic retry logic.
    Raises Exception if enable mode fails.

    Args:
        task: Nornir task object
        max_attempts: Maximum number of attempts (default: 2)

    Raises:
        Exception: If enable mode fails after all attempts
    """
    success, message = enter_enable_mode_robust(
        task=task,
        max_attempts=max_attempts,
        delay_between_attempts=15,
        force_new_connection=False
    )

    if not success:
        raise Exception(message)

    logger.info(f"[{task.host.name}] {message}")
