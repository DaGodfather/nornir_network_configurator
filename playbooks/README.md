# Playbooks Directory

This directory contains configuration templates and playbooks used by the network automation scripts.

## Purpose

The playbooks define the desired configuration state for various network device settings. Update actions will read these files to determine what configuration should be applied to devices.

## Available Playbooks

### Example Files (Development)

These files serve as templates and examples. In production, you should:
1. Copy the `.example.txt` files
2. Remove the `.example` extension
3. Customize with your production values

- **ntp.example.txt** - NTP server configuration template
- **syslog.example.txt** - Syslog server and logging configuration template
- **local_credentials.example.txt** - Local user accounts and password policy template

## Production Usage

In your production environment:

1. Create actual configuration files by copying the examples:
   ```bash
   cp ntp.example.txt ntp.txt
   cp syslog.example.txt syslog.txt
   cp local_credentials.example.txt local_credentials.txt
   ```

2. Edit each file with your production values:
   - Update IP addresses to match your infrastructure
   - Configure appropriate usernames and passwords
   - Adjust settings to meet your security requirements

3. The `.txt` files (without `.example`) will be ignored by git and won't be committed to the repository

## File Format

All playbook files follow these conventions:

- **One command per line**: Each configuration command should be on its own line
- **Comments**: Lines starting with `#` are treated as comments and ignored
- **Blank lines**: Empty lines are ignored
- **Platform-specific**: Commands should be in the format expected by the target platform (Cisco IOS, NX-OS, Juniper, etc.)

## Security Considerations

- **Never commit production credentials** to the repository
- **Use strong passwords** for all user accounts
- **Pre-hash passwords** when possible for additional security
- **Restrict file permissions** on playbook files containing sensitive data
- **Rotate credentials regularly** and update playbook files accordingly

## Future Playbooks

Additional playbook types will be added as needed:
- TACACS+ configuration
- SNMP settings
- VTY ACLs
- Banner messages
- Domain name settings
- And more...
