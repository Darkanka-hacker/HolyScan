import subprocess

class HostsManager:
    def __init__(self):
        self.hosts_file = '/etc/hosts'

    def add_domain(self, ip, domain):
        """ Add a domain to the hosts file. """
        # Check if the entry already exists
        if self.entry_exists(ip, domain):
            return  # Skip adding if it already exists

        # Append the new entry to the hosts file
        updated_lines = self.read_hosts()
        updated_lines.append(f"{ip} {domain}\n")
        self.write_hosts(updated_lines)

    def entry_exists(self, ip, domain):
        """ Check if an entry exists in the hosts file. """
        lines = self.read_hosts()
        entry = f"{ip} {domain}\n"
        return entry in lines

    def read_hosts(self):
        """ Read the hosts file. """
        with open(self.hosts_file, 'r') as f:
            return f.readlines()

    def write_hosts(self, updated_lines):
        """ Write to the hosts file. Prompt for sudo if necessary. """
        try:
            with open(self.hosts_file, 'a') as f:  # Change 'w' to 'a' to append
                f.writelines(updated_lines)
        except PermissionError:
            self.prompt_for_sudo(updated_lines)

    def prompt_for_sudo(self, updated_lines):
        """ Prompt for sudo password and write to the hosts file. """
        try:
            # Create a temporary file
            temp_hosts_file = '/tmp/hosts.tmp'
            with open(temp_hosts_file, 'w') as f:
                f.writelines(updated_lines)

            # Use subprocess to move the temp file to /etc/hosts
            subprocess.run(['sudo', 'mv', temp_hosts_file, self.hosts_file], check=True)
        except Exception as e:
            print(f"Failed to write to hosts file: {e}")

