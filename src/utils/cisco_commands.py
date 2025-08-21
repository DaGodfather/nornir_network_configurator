from nornir.core.task import Result, Task
from nornir.plugins.tasks.networking import (
    netmiko_send_command,
    netmiko_send_config,
    netmiko_save_config
)

def get_show_run(task: Task) -> str:
    """ 
    Get shwo run and return string
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run",
        )
    
    return result.result


def get_access_list_standard_names(task: Task) -> str:
    """ 
    Get 'show run | i access-list standard' and return string

    Example Return output:

    ip access-list standard MONITORING_TOOLS
    ip access-list standard NTP_SERVERS
    ip access-list standard REMOTE_ACCESS
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i access-list standard",
        )
    
    return result.result


def get_show_run_ntp_info(task: Task) -> str:
    """ 
    Get 'show run | i ntp server' and return string

    Example Return output:

    ntp server 10.XX.XX.1
    ntp server 10.xx.xx.2
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i ntp server",
        )
    
    return result.result


def get_show_run_domain_name(task: Task) -> str:
    """ 
    Get 'show run | i ntp server' and return string

    Example Return output:

    ip domain name brtspd.net
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i domain name",
        )
    
    return result.result


def get_show_run_snmp_host(task: Task) -> str:
    """ 
    Get 'show run | i snmp-server host' and return string

    Example Return output:

    snmp-server host 10.XX.XX.16 version 2c comunity_String
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i snmp-server host",
        )
    
    return result.result


def get_show_run_snmp_community(task: Task) -> str:
    """ 
    Get 'show run | i snmp-server community' and return string

    Example Return output:

    snmp-server community comm_string RO MONITORING_TOOLS
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i snmp-server community",
        )
    
    return result.result


def get_show_run_snmp(task: Task) -> str:
    """ 
    Get 'show run | i snmp-server ' and return string

    This will return all snmp-server commands
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i snmp-server",
        )
    
    return result.result


def get_show_run_logging_host(task: Task) -> str:
    """ 
    Get 'show run | i logging host' and return string

    Example Return output:

    logging host 10.XX.XX.15
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i logging host",
        )
    
    return result.result


def get_show_run_aaa(task: Task) -> str:
    """ 
    Issues 'show run aaa' and return string
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run aaa",
        )
    
    return result.result


def get_show_run_username(task: Task) -> str:
    """ 
    Issues 'show run | i username' and return string

    This is to return the local user account
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i username",
        )
    
    return result.result


def get_show_run_enable(task: Task) -> str:
    """ 
    Issues 'show run | i enable' and return string

    This is to return the enable secret config line
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | i enable",
        )
    
    return result.result


def get_show_banner_exec(task: Task) -> str:
    """ 
    Issues 'show banner excec' and return string

    This will return the banner exec that is conifugured
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show banner exec",
        )
    
    return result.result


""" 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This section below are all the commands to configure the device.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

def configure_ntp_cisco(task: Task, ip: str) -> None:
    """
    Sends "ntp server {ip}" with supplied IP address string.
    """

    result = task.run(
        task=netmiko_send_command,
        command_string=f"ntp server {ip}",
        )
    
    return None


def configure_logging_cisco(task: Task, ip: str) -> None:
    """
    Sends "logging host {ip}" with supplied IP address string.
    """

    result = task.run(
        task=netmiko_send_command,
        command_string=f"logging host {ip}",
        )
    
    return None


def send_command_cisco(task: Task, command: str) -> None:
    """
    Sends supplied command string.
    """

    result = task.run(
        task=netmiko_send_command,
        command_string=f"{command}",
        )
    
    return None

"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This Section below are all the cisco functions from used of the commands above.  

All functions below are using results derived from commands above. A single file was used
to avoid multipble files. 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""


