import subprocess

class Sublist3r:
    def __init__(self, domain):
        self.domain = domain

    def run_scan(self):
        # Sublist3r command for subdomain enumeration
        sublist3r_command = ['sublist3r', '-d', self.domain]
        process = subprocess.Popen(sublist3r_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            return stdout.decode('utf-8')
        if stderr:
            return stderr.decode('utf-8')

