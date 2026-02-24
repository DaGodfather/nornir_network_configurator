# src/utils/ping_check.py
# Python 3.6+ / Nornir 2.5

"""
Lightweight reachability check before attempting device login.

Uses a raw TCP connect against port 22 (SSH) or port 23 (Telnet) based on
the already-discovered transport, rather than ICMP ping which often requires
root privileges and may be blocked by ACLs on management networks.

Falls back to ICMP ping using the system 'ping' command if TCP probe is
inconclusive.
"""

import logging
import socket
import subprocess
import platform as sys_platform

logger = logging.getLogger(__name__)


def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Returns True if a TCP connection to host:port succeeds within timeout.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _icmp_ping(host: str, timeout: int = 3) -> bool:
    """
    Returns True if the host responds to ICMP ping.
    Uses the system ping command (works without root on most OSes).
    """
    try:
        # Linux: ping -c 1 -W <timeout>
        # macOS: ping -c 1 -W <timeout_ms>
        os_name = sys_platform.system().lower()
        if os_name == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_reachable(host: str, port: int = None, timeout: float = 3.0) -> bool:
    """
    Check if a device is reachable before attempting login.

    Strategy:
    1. TCP probe against the known management port (22 or 23)
    2. If no port given, try port 22 then port 23
    3. Falls back to ICMP ping if TCP probe is inconclusive

    Args:
        host:    IP address or hostname to check
        port:    Port to probe (22 for SSH, 23 for Telnet). None = auto-detect.
        timeout: Seconds to wait for TCP connect.

    Returns:
        True if device appears reachable, False otherwise.
    """
    if port:
        result = _tcp_probe(host, port, timeout)
        logger.debug(f"[{host}] TCP probe port {port}: {'reachable' if result else 'unreachable'}")
        if result:
            return True
    else:
        # Try SSH then Telnet
        for p in (22, 23):
            if _tcp_probe(host, p, timeout):
                logger.debug(f"[{host}] TCP probe port {p}: reachable")
                return True

    # TCP failed - try ICMP as last resort
    result = _icmp_ping(host, timeout=int(timeout))
    logger.debug(f"[{host}] ICMP ping fallback: {'reachable' if result else 'unreachable'}")
    return result
