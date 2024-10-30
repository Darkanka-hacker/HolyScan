from plugin_base import BasePlugin
from PyQt5.QtWidgets import QTextEdit
from subprocess import Popen, PIPE, STDOUT

class NmapPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "Nmap"
        self.nmap_tab = QTextEdit()  # UI component for the Nmap output

    def create_tab(self):
        """Create and return the Nmap tab."""
        self.nmap_tab.setReadOnly(True)
        return self.nmap_tab

    def start_scan(self, target):
        """Run Nmap scan."""
        nmap_command = ['nmap', '-A', '-Pn', target, '-T4']
        process = Popen(nmap_command, stdout=PIPE, stderr=STDOUT)
        stdout, _ = process.communicate()  # Get output
        nmap_output = stdout.decode('utf-8')
        self.nmap_tab.setText(nmap_output)  # Display Nmap results

