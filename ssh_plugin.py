import os
import re
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QMessageBox
from PyQt5.QtGui import QFont
from PyQt5.QtCore import pyqtSignal, QThread
from subprocess import Popen, PIPE

class SSHScanThread(QThread):
    output_signal = pyqtSignal(str)      # Signal to emit output lines from Hydra
    error_signal = pyqtSignal(str)       # Signal to emit error messages
    finished_signal = pyqtSignal()       # Signal to indicate scan completion
    valid_login_signal = pyqtSignal(str, str) # Signal to indicate a valid login found with username and password

    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def run(self):
        """Run the SSH brute-force scan using hydra with temp files for usernames and passwords."""
        if not self.ip or not isinstance(self.ip, str):
            self.error_signal.emit("Invalid IP address provided for SSH scan.")
            return

        command = [
            'hydra', '-L', 'temp_usernames.txt', '-P', 'temp_passwords.txt', self.ip, 'ssh', '-t', '4'
        ]
        try:
            process = Popen(command, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)

            # Read each line as it becomes available
            while True:
                output_line = process.stdout.readline()
                if not output_line:
                    break  # Exit loop if no more lines are available
                self.output_signal.emit(output_line.strip())
                print("DEBUG: Output line:", output_line.strip())  # Debug: Print each output line to console

                # Check for Hydra's success format and extract login details
                match = re.search(r"login: (\S+)\s+password: (\S+)", output_line)
                if match:
                    username, password = match.groups()
                    self.valid_login_signal.emit(username, password)  # Emit signal with username and password

            # Capture remaining stderr after stdout is done
            stderr_output = process.stderr.read()
            if stderr_output:
                for error_line in stderr_output.splitlines():
                    self.error_signal.emit(f"Error: {error_line}")

        except Exception as e:
            self.error_signal.emit(f"SSH Scan Error: {str(e)}")
        finally:
            self.finished_signal.emit()


class SSHPlugin:
    _name = "SSH Scanner"

    def __init__(self):
        self.tab = None
        self.output_area = None
        self.ssh_thread = None
        self.ip_address = None

    def create_tab(self):
        """Create the SSH plugin's tab in the main application."""
        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)

        # Set up the output area for displaying scan results
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont('Courier', 10))
        self.output_area.setStyleSheet("background-color: #3e3e3e; color: #eee; padding: 8px;")
        layout.addWidget(self.output_area)

        # Run button to manually start the SSH brute-force scan
        self.run_button = QPushButton("Run SSH Brute Force")
        self.run_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        self.run_button.clicked.connect(self.run_scan)  # Connect button to run_scan method
        layout.addWidget(self.run_button)

        return self.tab

    def run_scan(self):
        """Initiate the SSH brute-force scan and disable the button during the scan."""
        if not self.ip_address:
            self.update_output("Error: Target IP address not set.")
            return

        # Disable button while scan is running and start the scan
        self.run_button.setEnabled(False)
        self.start_scan(self.ip_address)

    def start_scan(self, ip_address):
        """Run the SSH brute-force scan with the provided IP address."""
        if not self.ip_address:
            self.ip_address = ip_address

        if not self.ip_address or not isinstance(self.ip_address, str):
            self.update_output("Invalid IP address provided for SSH scan.")
            self.run_button.setEnabled(True)
            return

        if self.ssh_thread and self.ssh_thread.isRunning():
            self.ssh_thread.quit()
            self.ssh_thread.wait()

        # Initialize and start the SSH scan thread
        self.ssh_thread = SSHScanThread(self.ip_address)
        self.ssh_thread.output_signal.connect(self.update_output)
        self.ssh_thread.error_signal.connect(self.update_output)
        self.ssh_thread.finished_signal.connect(self.scan_finished)
        self.ssh_thread.valid_login_signal.connect(self.prompt_ssh_connection)
        self.ssh_thread.start()

    def scan_finished(self):
        """Re-enable the run button when the scan is complete."""
        self.run_button.setEnabled(True)
        self.update_output("\nScan completed.\n")

    def prompt_ssh_connection(self, username, password):
        """Prompt the user to connect using SSH if valid credentials are found."""
        response = QMessageBox.question(
            None,
            "SSH Login Found",
            f"Valid credentials found:\nUsername: {username}\nPassword: {password}\n\nDo you want to open an SSH connection?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if response == QMessageBox.Yes:
            self.open_terminal_ssh(username)

    def open_terminal_ssh(self, username):
        """Open a new terminal and connect to the SSH server with the found username."""
        command = f"gnome-terminal -- bash -c 'ssh {username}@{self.ip_address}; exec bash'"
        os.system(command)

    def update_output(self, output):
        """Update the SSH results tab with new output."""
        if self.output_area:
            self.output_area.append(output)
