# src/utils/device_filter.py
"""
Utility for filtering Nornir inventory based on a device list file.
"""

import logging
from pathlib import Path
from typing import List, Tuple, Set
from nornir.core import Nornir

logger = logging.getLogger(__name__)


def load_device_filter_list(filter_file: str = "inventory/device_filter_list.txt") -> List[str]:
    """
    Load device names from a filter list file.

    Args:
        filter_file: Path to the filter list file (default: inventory/device_filter_list.txt)

    Returns:
        List of device names (one per line, comments and empty lines ignored)
    """
    project_root = Path(__file__).resolve().parents[2]
    filter_path = project_root / filter_file

    if not filter_path.exists():
        logger.warning(f"Device filter file not found: {filter_path}")
        return []

    devices = []
    try:
        with open(filter_path, 'r') as f:
            for line in f:
                # Strip whitespace and ignore comments/empty lines
                device = line.strip()
                if device and not device.startswith('#'):
                    devices.append(device)

        logger.info(f"Loaded {len(devices)} device(s) from filter list: {filter_path}")
        return devices

    except Exception as e:
        logger.error(f"Failed to load device filter list: {str(e)}")
        return []


def filter_inventory(nr: Nornir, device_list: List[str]) -> Tuple[Nornir, Set[str]]:
    """
    Filter Nornir inventory to only include devices in the device list.

    Args:
        nr: Nornir instance with full inventory
        device_list: List of device names to filter for

    Returns:
        Tuple of:
        - Filtered Nornir instance (only devices in the list)
        - Set of devices that were not found in inventory
    """
    if not device_list:
        logger.info("No device filter applied - using all inventory")
        return nr, set()

    # Get all hosts in inventory
    inventory_hosts = set(nr.inventory.hosts.keys())

    # Convert filter list to set for comparison
    requested_devices = set(device_list)

    # Find devices that exist in both
    found_devices = requested_devices & inventory_hosts

    # Find devices that were requested but not found
    not_found_devices = requested_devices - inventory_hosts

    if not_found_devices:
        logger.warning(f"Devices not found in inventory: {', '.join(sorted(not_found_devices))}")

    if not found_devices:
        logger.error("No devices from filter list were found in inventory!")
        return nr, not_found_devices

    logger.info(f"Filtering inventory to {len(found_devices)} device(s)")

    # Filter the inventory to only include found devices
    filtered_nr = nr.filter(filter_func=lambda host: host.name in found_devices)

    return filtered_nr, not_found_devices


def apply_device_filter(nr: Nornir, filter_file: str = "inventory/device_filter_list.txt",
                       use_filter: bool = True) -> Tuple[Nornir, Set[str]]:
    """
    Load device filter list and apply it to the Nornir inventory.

    Args:
        nr: Nornir instance with full inventory
        filter_file: Path to filter list file
        use_filter: Whether to apply the filter (default: True)

    Returns:
        Tuple of:
        - Filtered Nornir instance
        - Set of devices that were not found in inventory
    """
    if not use_filter:
        logger.info("Device filtering disabled - using all inventory")
        return nr, set()

    # Load the filter list
    device_list = load_device_filter_list(filter_file)

    if not device_list:
        logger.info("No devices in filter list - using all inventory")
        return nr, set()

    # Apply the filter
    return filter_inventory(nr, device_list)
