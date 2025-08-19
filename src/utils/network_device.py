"""
This Class define the network device.
"""

class NetworkDevice:
    def __init__(self,
                 hostname: str,
                 ip: str):
        self.ip = ip

    def __str__(self):
        return f"N etworkDevice(hostanme-{self.hostname}, ip={self.ip})" 
    
    def __repr__(self):
        return str(self)
    

class CiscoDevice(NetworkDevice):
    pass

class JuniperDevice(NetworkDevice):
    pass