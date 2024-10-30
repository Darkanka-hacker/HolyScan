import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QMessageBox

class KerberosPlugin:
    _name = "Kerberos Scanner"

    def __init__(self):
        self.tab = None
        self.output_area = None
        self.run_button = None
        self.kerberos_thread = None  # Track the running thread if needed

    def create_tab(self):
        """Create the plugin's tab in the main application."""
        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.run_button = QPushButton('Run Kerberos Scan')
        self.run_button.clicked.connect(self.on_manual_scan)
        layout.addWidget(self.run_button)

        return self.tab

    def start_scan(self, ip_address):
        """Start the Kerberos scan."""
        if self.kerberos_thread and self.kerberos_thread.isRunning():
            self.kerberos_thread.quit()
            self.kerberos_thread.wait()

        self.run_scan(ip_address)

    def stop(self):
        """Stop the Kerberos process."""
        if self.kerberos_thread and self.kerberos_thread.isRunning():
            self.kerberos_thread.terminate()
            self.kerberos_thread.wait()

    def on_manual_scan(self):
        """Triggered when the 'Run Kerberos Scan' button is pressed manually."""
        self.display_output("Please run the scan via the main interface.")

    def run_scan(self, ip_address):
        """Run the Kerberos scan using netexec."""
        command = ['netexec', 'smb', ip_address, '-u', 'stefan', '-p', '', '--rid-brute']

        try:
            # Run the command and capture the output
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            output = stdout.decode('utf-8') + stderr.decode('utf-8')
            self.display_output(output)

            # Check if there is an error related to missing modules or any other issue with netexec
            if "ModuleNotFoundError" in output:
                self.display_output("Error: netexec is missing some required modules. Please ensure all dependencies are installed.")
                return

            # Parse the output to extract usernames
            self.extract_and_display_usernames(output)

            # After the Kerberos scan completes, run the smbscan.py script
            self.run_smb_scan(ip_address)

        except Exception as e:
            self.display_output(f"Error running Kerberos scan: {e}")

    def extract_and_display_usernames(self, output):
        """Extracts usernames from the Kerberos scan output and displays them."""
        user_lines = output.splitlines()
        users = []

        for line in user_lines:
            if "SidTypeUser" in line or "SidTypeGroup" in line:
                # Split the line to extract the username
                parts = line.split("\\")
                if len(parts) == 2:
                    username = parts[1].split()[0]  # Get the username
                    users.append(username)

        if users:
            # Write usernames to the users.txt file
            try:
                with open("users.txt", "w") as user_file:
                    for user in users:
                        user_file.write(f"{user}\n")
                self.display_output(f"Usernames found:\n{', '.join(users)}\n\nUsernames saved to users.txt.")
            except Exception as e:
                self.display_output(f"Error writing to file: {e}")
        else:
            self.display_output("No valid usernames found in the output.")

    def run_smb_scan(self, ip_address):
        """Run the smbscan.py script after the Kerberos scan."""
        smbscan_command = [
            'python3', '/home/andreas/tools/smbscan/src/smbscan.py',
            ip_address, '--download-files', '--max-depth', '3'
        ]

        try:
            self.display_output(f"Running SMB scan with smbscan.py on {ip_address}...")
            # Run the smbscan command
            process = subprocess.Popen(smbscan_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            output = stdout.decode('utf-8') + stderr.decode('utf-8')
            self.display_output(output)

        except Exception as e:
            self.display_output(f"Error running smbscan: {e}")

    def display_output(self, output):
        """Display the command output in the text area."""
        if self.output_area:
            self.output_area.append(output)
