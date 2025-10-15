import argparse




class CliArgs:

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Brightspeed Managment Network Change script.")
        self.parser.add_argument("-update_vty_acl", action="store_true", help="Update VTY ACLs on Cisco devices")
        self.parser.add_argument("-audit_vty_acl", action="store_true", help="Audit VTY ACLs on Cisco devices")
        self.parser.add_argument("-audit_ntp", action="store_true", help="Audit NTP config on devices")
        self.parser.add_argument("-update_ntp", action="store_true", help="Update NTP config on devices")
        self.parser.add_argument("-audit_domain_name", action="store_true", help="Audit domain name config on devices")
        self.parser.add_argument("-update_domain_name", action="store_true", help="Update domain name config on devices")
        self.parser.add_argument("-audit_local_password", action="store_true", help="Audit local password config on devices")
        self.parser.add_argument("-update_local_password", action="store_true", help="Update local password new standard config")
        self.parser.add_argument("-update_tacacs", action="store_true", help="Update TACACS to new standard config")
        self.parser.add_argument("-from_text_file", action="store_true", help="audit TACACS to new standard config")
        self.parser.add_argument("-update_cisco_vty_acl", action="store_true", help="Update Cisco ACL using 'input/acl_entries.txt' file")
        self.parser.add_argument("-dry_run", action="store_true", help="Used for dry, no all actions support this") #This is not in the CLI mapping
        self.parser.add_argument("-test", action="store_true", help="Test action items will be called.")

        self.args = None

    
    def parse(self):
        self.args = self.parser.parse_args()

    def is_any_change_option_true(self):
        for arg in vars(self.args):
            if 'cahnge' in arg:
                if getattr(self.args, arg):
                    return True
        return False
    