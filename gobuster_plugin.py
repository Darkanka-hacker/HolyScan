from plugin_base import BasePlugin
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import QTextEdit, QTabWidget, QVBoxLayout, QProgressBar, QWidget, QPushButton
import subprocess
import re
from collections import deque  # For managing subdomain queue

class GobusterThread(QThread):
    output_signal = pyqtSignal(str)  # Signal to emit output from Gobuster
    progress_signal = pyqtSignal(int)  # Signal to emit progress updates

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self.exclude_length = None
        self.wordlist_path = 'wordlist/gobuster.txt'  # Wordlist path for Gobuster
        self.total_lines = self.get_wordlist_size()  # Calculate the total number of lines in the wordlist

    def run(self):
        """Run the Gobuster scan."""
        gobuster_command = [
            'gobuster', 'dir', '-u', f'http://{self.ip_address}', '-w',
            self.wordlist_path, '--no-error', '--no-progress', '--retry', '3', '--timeout', '30s', '-t', '50'
        ]

        if self.exclude_length:
            gobuster_command.append(f'--exclude-length={self.exclude_length}')

        print("Running command:", ' '.join(gobuster_command))

        try:
            process = subprocess.Popen(gobuster_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            current_line = 0  # Initialize current line count

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break

                if output:
                    current_line += 1
                    self.output_signal.emit(output.strip())  # Emit the output to be displayed
                    if self.total_lines > 0:  # Avoid division by zero if wordlist not found
                        progress = int((current_line / self.total_lines) * 100)
                        self.progress_signal.emit(progress)  # Emit progress

            process.wait()
            error_output = process.stderr.read()
            if error_output:
                self.output_signal.emit(f"Error: {error_output.strip()}")

        except Exception as e:
            self.output_signal.emit(f"Error while running Gobuster: {str(e)}")

    def get_wordlist_size(self):
        """Count the total number of lines in the wordlist."""
        try:
            with open(self.wordlist_path, 'r') as f:
                return sum(1 for _ in f)  # Count lines in the wordlist
        except FileNotFoundError:
            self.output_signal.emit("Wordlist file not found.")
            return 0


class GobusterPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self._name = "Gobuster"  # Set the name of the plugin
        self.results = []  # Store results for final output formatting
        self.tabs = QTabWidget()  # Create a tab widget to hold results tabs
        self.tabs.setTabsClosable(True)  # Allow tabs to be closed
        self.current_scan_thread = None  # Track the current running scan thread
        self.progress_bar = QProgressBar()  # Initialize the progress bar
        self.subdomain_check_button = None  # Button to check for subdomains after scan
        self.subdomain_check_timer = QTimer()  # Timer to trigger subdomain checks
        self.found_subdomains = set()  # To track all found subdomains
        self.subdomain_queue = deque()  # Queue to manage subdomains for sequential scanning

    def create_tab(self):
        """Create and return the Gobuster results tab."""
        self.tab = QTextEdit()
        self.tab.setReadOnly(True)

        # Create a layout to hold the text editor and progress bar
        layout = QVBoxLayout()
        layout.addWidget(self.tab)
        layout.addWidget(self.progress_bar)

        # Create a QWidget to hold the layout
        container = QWidget()
        container.setLayout(layout)

        # Add container widget as a tab
        self.tabs.addTab(container, "Gobuster Results")
        return self.tabs  # Return the tab widget for the plugin

    def start_scan(self, ip_address):
        """Start the Gobuster scan."""
        # Check /etc/hosts for a domain associated with the IP address
        base_domain = self.check_hosts_file(ip_address)
        if base_domain:
            ip_address = base_domain

        # Add the IP or domain to the subdomain queue if there's a running scan
        if self.current_scan_thread and self.current_scan_thread.isRunning():
            self.subdomain_queue.append(ip_address)
            return  # Queue the subdomain for scanning after the current one

        # Otherwise, start the scan directly
        self._initiate_scan(ip_address)

    def _initiate_scan(self, ip_address):
        """Initiate a new scan for the given IP address."""
        self.gobuster_thread = GobusterThread(ip_address)
        self.gobuster_thread.output_signal.connect(self.update_output)
        self.gobuster_thread.progress_signal.connect(self.update_progress)  # Connect to progress updates
        self.gobuster_thread.finished.connect(self.check_for_subdomains)  # Connect to check for subdomains
        self.gobuster_thread.finished.connect(self.scan_finished)  # Connect to handle scan finished
        self.gobuster_thread.start()
        self.current_scan_thread = self.gobuster_thread  # Track the current running thread

    def check_hosts_file(self, ip_address):
        """Check /etc/hosts for a domain associated with the given IP address."""
        try:
            with open('/etc/hosts', 'r') as hosts_file:
                for line in hosts_file:
                    if ip_address in line:
                        parts = line.split()
                        # Return the first domain found for the given IP address
                        if len(parts) > 1:
                            return parts[1]  # Return the first domain
        except FileNotFoundError:
            self.update_output("Error: /etc/hosts file not found.")
        return None

    def update_output(self, output):
        """Update the Gobuster results tab with new output."""
        # Remove ANSI escape sequences from the output
        output = re.sub(r'\x1B\[[0-?9]*[;[0-?9]*[mK]', '', output)

        # Filter out unwanted progress lines and keep only the results
        if re.match(r'^Progress: \d+ / \d+', output):
            return  # Ignore lines with progress information

        if "Error: the server returns a status code that matches the provided options" in output:
            length_match = re.search(r'Length: (\d+)', output)
            if length_match:
                length = length_match.group(1)
                self.gobuster_thread.exclude_length = length  # Set length to exclude
                self.gobuster_thread.run()  # Re-run Gobuster with the exclude-length option
                return

        # Store output in results list
        if hasattr(self, 'tab'):
            # Only add relevant output (not progress) to the tab and results
            if not re.match(r'Progress: \d+ / \d+', output):
                self.add_output_to_tab(output)

    def add_output_to_tab(self, output):
        """Add output to the current tab."""
        if hasattr(self, 'tab'):
            self.tab.append(output)  # Append output to the tab
        self.results.append(output)  # Collect output for final formatting

    def update_progress(self, progress):
        """Update the progress bar during the scan."""
        self.progress_bar.setValue(progress)

    def finalize_output(self):
        """Finalize the Gobuster output for display."""
        if hasattr(self, 'tab'):
            # Build the final output summary, removing redundant progress lines
            summary = "============================================================\n"
            summary += "Gobuster Scan Results Summary\n"
            summary += "============================================================\n"
            for result in self.results:
                if not re.match(r'Progress: \d+ / \d+', result):  # Ignore progress results
                    summary += result + "\n"
            summary += "============================================================\n"
            self.add_output_to_tab(summary)

    def check_for_subdomains(self):
        """Check /etc/hosts for any subdomains after the initial scan."""
        ip_address = self.gobuster_thread.ip_address  # Get the initial IP address used for scanning
        subdomains = self.get_subdomains_from_hosts(ip_address)  # Get subdomains from /etc/hosts

        if subdomains:  # Only start scans if subdomains were found
            new_subdomains = set(subdomains) - self.found_subdomains  # Find new subdomains not already scanned
            self.found_subdomains.update(subdomains)  # Track all found subdomains
            if new_subdomains:
                for subdomain in new_subdomains:
                    self.subdomain_queue.append(subdomain)  # Queue subdomains for scanning
            # If no scan is currently running, start the next one
            if not self.current_scan_thread or not self.current_scan_thread.isRunning():
                if self.subdomain_queue:
                    next_subdomain = self.subdomain_queue.popleft()  # Get the next subdomain in the queue
                    self._initiate_scan(next_subdomain)  # Start the next scan
        else:
            self.update_output("No additional subdomains found.")  # Notify if no new subdomains found

        self.add_subdomain_check_button()  # Add button to check subdomains again after scan finishes

    def add_subdomain_check_button(self):
        """Add a button to check for subdomains after the scan is finished."""
        if self.subdomain_check_button:
            return  # Prevent creating multiple buttons

        self.subdomain_check_button = QPushButton("Check for Subdomains Again")
        self.subdomain_check_button.clicked.connect(self.check_for_subdomains_again)

        # Add the button to the layout
        container = self.tabs.widget(self.tabs.currentIndex())
        container.layout().addWidget(self.subdomain_check_button)

        # Set up a timer to automatically trigger the subdomain check every 30 seconds
        self.subdomain_check_timer.timeout.connect(self.check_for_subdomains_again)
        self.subdomain_check_timer.start(30000)  # 30 seconds

    def check_for_subdomains_again(self):
        """Check for subdomains in the hosts file again and start new scans if found."""
        ip_address = self.gobuster_thread.ip_address
        subdomains = self.get_subdomains_from_hosts(ip_address)

        if subdomains:  # If new subdomains are found
            new_subdomains = set(subdomains) - self.found_subdomains  # Find newly added subdomains
            if new_subdomains:
                self.found_subdomains.update(new_subdomains)  # Update found subdomains
                for subdomain in new_subdomains:
                    self.subdomain_queue.append(subdomain)  # Queue the subdomains for scanning
            # If no scan is currently running, start the next one
            if not self.current_scan_thread or not self.current_scan_thread.isRunning():
                if self.subdomain_queue:
                    next_subdomain = self.subdomain_queue.popleft()
                    self._initiate_scan(next_subdomain)
        else:
            self.update_output("No additional subdomains found.")  # No subdomains found

    def get_subdomains_from_hosts(self, base_ip_address):
        """Retrieve subdomains from /etc/hosts file, excluding the base domain."""
        subdomains = []
        base_domain = None

        try:
            with open('/etc/hosts', 'r') as hosts_file:
                for line in hosts_file:
                    if base_ip_address in line:
                        parts = line.split()
                        if len(parts) > 1:
                            # Set the base domain for the initial scan
                            if base_domain is None:
                                base_domain = parts[1]
                            else:
                                # Check if it is a subdomain
                                subdomain = parts[1]
                                if subdomain != base_domain and subdomain.count('.') > 1:  # Check if it's a subdomain
                                    subdomains.append(subdomain)  # Add the subdomain to the list
        except FileNotFoundError:
            self.update_output("Error: /etc/hosts file not found.")
        return subdomains

    def scan_finished(self):
        """Reset the current scan thread after finishing."""
        self.current_scan_thread = None  # Reset the current running thread
        self.progress_bar.setValue(100)  # Set the progress bar to complete

        # Check if there are any queued subdomains to scan
        if self.subdomain_queue:
            next_subdomain = self.subdomain_queue.popleft()  # Get the next subdomain in the queue
            self._initiate_scan(next_subdomain)  # Start the next scan from the queue
