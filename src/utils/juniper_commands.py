from nornir.core.task import Result, Task
from nornir_netmiko.tasks import (
    netmiko_save_config,
    netmiko_send_command,
    netmiko_send_config
)

def get_show_run(task: Task) -> str:
    """ 
    Get shwo run and return string
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show config | display set"
        read_timeout = 500
        )
    
    return result.result


def get_show_run_ntp_info(task: Task) -> str:
    """ 
    Get 'show run | display set | match 'ntp server'' and return string

    Example Return output:

    ntp server 10.XX.XX.1
    ntp server 10.xx.xx.2
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | display set | match 'ntp server'"
        read_timeout = 500
        )
    
    return result.result


def get_show_run_domain_name(task: Task) -> str:
    """ 
    Get 'show run | display set | match name-server' and return string

    Example Return output:

    ip domain name brtspd.net
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | display set | match name-server"
        read_timeout = 500
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
        command_string="show run | display set | match snmp"
        read_timeout = 500
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
        command_string="show run | i snmp-server community"
        read_timeout = 500
        )
    
    return result.result


def get_show_run_syslog_host(task: Task) -> str:
    """ 
    Get 'show run | display set | match 'syslog host'' and return string

    Example Return output:

    set system syslog host 151.119.20.47 any notice
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run | display set | match 'syslog host'"
        read_timeout = 500
        )
    
    return result.result


def get_show_run_aaa(task: Task) -> str:
    """ 
    Get 'show aaa' and return string
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run aaa"
        read_timeout = 500
        )
    
    return result.result

"""
This section below are all the commands to configure the device.
"""

def configure_ntp(task: Task, ip:) -> None:
    """
    Task
    """

    result = task.run(
        task=netmiko_send_command,
        command_string="show run aaa"
        read_timeout = 500
        )
    
    return none



"""
This Section below are all the cisco functions from used of the commands above.  

All functions below are using results derivede from commands about. A single file was used
to preserve multipble files. 
"""


