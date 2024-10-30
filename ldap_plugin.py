from plugin_base import BasePlugin
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QTextEdit, QTabWidget, QVBoxLayout, QWidget
import subprocess

class LdapScanThread(QThread):
    output_signal = pyqtSignal(str)  # Signal to emit output from LDAP scan
    error_signal = pyqtSignal(str)   # Signal to emit error from LDAP scan
    scan_finished_signal = pyqtSignal(list)  # Signal to emit when scan finishes

    def __init__(self, ip):
        super().__init__()
        self.ip = ip
        self.results = []

    def run(self):
        """Run the Nmap and LDAP scans."""
        self.run_nmap_scan()
        self.run_ldap_scan()

    def run_nmap_scan(self):
        """Run the Nmap scan using ldap-related scripts."""
        nmap_command = f'nmap -sV --script "ldap* and not brute" {self.ip}'
        print(f"Running command: {nmap_command}")
        try:
            process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if stdout:
                for line in stdout.splitlines():
                    self.results.append(f"Nmap: {line}")
                    self.output_signal.emit(f"Nmap: {line}")  # Emit Nmap output for real-time display

            if stderr:
                for error_line in stderr.splitlines():
                    self.error_signal.emit(f"Error: {error_line}")

        except Exception as e:
            self.error_signal.emit(f"Error running Nmap scan: {str(e)}")

    def run_ldap_scan(self):
        """Run the LDAP scan using ldapsearch."""
        ldapsearch_command = f'ldapsearch -x -h {self.ip} -s base'
        print(f"Running command: {ldapsearch_command}")
        try:
            process = subprocess.Popen(ldapsearch_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if stdout:
                for line in stdout.splitlines():
                    self.results.append(f"LDAP: {line}")
                    self.output_signal.emit(f"LDAP: {line}")  # Emit LDAP output for real-time display

            if stderr:
                for error_line in stderr.splitlines():
                    self.error_signal.emit(f"Error: {error_line}")

            # Emit the results once the LDAP scan is finished
            self.scan_finished_signal.emit(self.results)

        except Exception as e:
            self.error_signal.emit(f"Error running LDAP scan: {str(e)}")

class LdapPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self._name = "LDAP"
        self.tabs = QTabWidget()
        self.ldap_thread = None  # Track the running thread
        self.scan_in_progress = False  # Flag to track if a scan is already in progress

    def create_tab(self):
        """Create and return the LDAP results tab."""
        self.tab = QTextEdit()
        self.tab.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(self.tab)

        container = QWidget()
        container.setLayout(layout)
        self.tabs.addTab(container, "LDAP Results")
        return self.tabs

    def start_scan(self, ip):
        """Start the LDAP scan."""
        if self.scan_in_progress:
            print("LDAP scan already in progress, skipping duplicate scan.")
            return  # Prevent duplicate scans

        self.scan_in_progress = True  # Set flag to true to indicate scan is in progress

        if self.ldap_thread and self.ldap_thread.isRunning():
            self.ldap_thread.quit()
            self.ldap_thread.wait()

        self.ldap_thread = LdapScanThread(ip)
        self.ldap_thread.output_signal.connect(self.update_output)
        self.ldap_thread.error_signal.connect(self.update_output)  # Show errors in the output
        self.ldap_thread.scan_finished_signal.connect(self.show_results)
        self.ldap_thread.start()

    def stop(self):
        """Stop the LDAP thread."""
        if self.ldap_thread and self.ldap_thread.isRunning():
            self.ldap_thread.quit()
            self.ldap_thread.wait()

    def update_output(self, output):
        """Update the LDAP results tab with new output."""
        if hasattr(self, 'tab'):
            self.tab.append(output)

    def show_results(self, results):
        """Handle LDAP scan completion."""
        print("LDAP scan finished, displaying results...")
        if hasattr(self, 'tab'):
            self.tab.append("\n".join(results))
        self.scan_in_progress = False  # Reset the scan flag when done
