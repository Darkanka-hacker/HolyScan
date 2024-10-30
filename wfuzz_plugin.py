from plugin_base import BasePlugin
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import QTextEdit, QTabWidget, QMessageBox, QProgressBar, QVBoxLayout, QWidget
import subprocess
import re
from collections import defaultdict
import os

class WfuzzThread(QThread):
    output_signal = pyqtSignal(str)  # Signal to emit output from Wfuzz
    scan_finished_signal = pyqtSignal(list)  # Signal to emit when the scan finishes with raw results
    progress_signal = pyqtSignal(int)  # Signal to update the progress bar

    def __init__(self, ip, domain):
        super().__init__()
        self.ip = ip
        self.domain = domain
        self.results = []  # To store the scan results
        self.status_word_count = defaultdict(int)  # To count occurrences of (status_code, word_count)
        self.wordlist_path = '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt'
        self.total_words = self.get_wordlist_size()  # Total lines in the wordlist

    def run(self):
        """Run the Wfuzz scan."""
        self.run_scan()

    def get_wordlist_size(self):
        """Count the total number of lines in the wordlist for progress tracking."""
        try:
            with open(self.wordlist_path, 'r') as f:
                return sum(1 for _ in f)
        except FileNotFoundError:
            self.output_signal.emit("Wordlist file not found.")
            return 0

    def run_scan(self):
        """Run a Wfuzz scan and collect the results."""
        wfuzz_command = [
            'wfuzz', '-w', self.wordlist_path,
            '-H', f"Host: FUZZ.{self.domain}", '-t', '100', self.ip
        ]

        print("Running command:", ' '.join(wfuzz_command))

        try:
            process = subprocess.Popen(wfuzz_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            current_line = 0  # Track the number of processed lines

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break

                if output.strip():  # Ignore empty lines
                    current_line += 1
                    filtered_output = self.filter_output(output.strip())  # Filter the output
                    if filtered_output:
                        self.results.append(filtered_output)  # Store the result
                        self.output_signal.emit(filtered_output)  # Emit for real-time display

                    # Update progress bar
                    if self.total_words > 0:
                        progress = int((current_line / self.total_words) * 100)
                        self.progress_signal.emit(progress)

            process.wait()

            error_output = process.stderr.read()
            if error_output:
                self.output_signal.emit(f"Error: {error_output.strip()}")

            # Emit results after the scan finishes
            self.scan_finished_signal.emit(self.results)

        except Exception as e:
            self.output_signal.emit(f"Error while running Wfuzz: {str(e)}")

    def filter_output(self, line):
        """Filter and parse the output line to capture necessary data."""
        ansi_escape = re.compile(r'\x1B\[[0-?9;]*[mK]')
        clean_line = ansi_escape.sub('', line)

        # Updated regex pattern to match the expected output format
        match = re.match(r'^\S+\s+(\d+)\s+\d+\s+L\s+(\d+)\s+W\s+\d+\s+Ch\s+"([^"]+)"', clean_line)
        if match:
            status_code = match.group(1)  # Capture the status code
            word_count = int(match.group(2))  # Capture the word count
            subdomain = match.group(3)  # Capture the subdomain

            # Count occurrences of the (status_code, word_count) combination
            self.status_word_count[(status_code, word_count)] += 1

            return f"{status_code} {word_count} \"{subdomain}\""  # Return parsed result

        return None


class WfuzzPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self._name = "Wfuzz"  # Set the name of the plugin
        self.tabs = QTabWidget()  # Initialize a tab widget to manage tabs
        self.progress_bar = QProgressBar()  # Initialize the progress bar

    def create_tab(self):
        """Create and return the Wfuzz results tab."""
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
        self.tabs.addTab(container, "Wfuzz Results")
        return self.tabs

    def start_scan(self, ip, domain):
        """Start the Wfuzz scan with the given IP and domain."""
        self.wfuzz_thread = WfuzzThread(ip, domain)  # Start the scan
        self.wfuzz_thread.output_signal.connect(self.update_output)
        self.wfuzz_thread.scan_finished_signal.connect(self.show_filtered_results)  # Handle scan finished event
        self.wfuzz_thread.progress_signal.connect(self.update_progress)  # Handle progress update
        self.wfuzz_thread.start()

    def update_output(self, output):
        """Update the Wfuzz results tab with new output."""
        if hasattr(self, 'tab'):
            self.tab.append(output)

    def update_progress(self, progress):
        """Update the progress bar during the scan."""
        self.progress_bar.setValue(progress)

    def show_filtered_results(self, raw_results):
        """Filter the results after scan and display in a new tab."""
        print("Scan finished. Filtering results...")

        # Find the most common (status_code, word_count) combination
        most_common_combination = max(self.wfuzz_thread.status_word_count, key=self.wfuzz_thread.status_word_count.get)

        status_code_to_filter, word_count_to_filter = most_common_combination
        print(f"Most common status code: {status_code_to_filter}, word count: {word_count_to_filter}")
        print("Filtering out these results...")

        filtered_results = []
        for result in raw_results:
            status_code, word_count, subdomain = self.parse_result(result)
            if status_code != status_code_to_filter or word_count != word_count_to_filter:
                filtered_results.append(result)
                # Check if subdomain exists in hosts file and prompt the user to add it if necessary
                full_domain = f"{subdomain}.{self.wfuzz_thread.domain}"
                if not self.subdomain_exists_in_hosts(full_domain):
                    self.ask_to_add_to_hosts(full_domain, self.wfuzz_thread.ip)

        # Add new tab for filtered results
        if filtered_results:
            self.add_filtered_results_tab(filtered_results)

    def add_filtered_results_tab(self, filtered_results):
        """Add a new tab to display filtered results."""
        self.filtered_tab = QTextEdit()
        self.filtered_tab.setReadOnly(True)
        self.tabs.addTab(self.filtered_tab, "Filtered Wfuzz Results")

        # Show filtered results in the new tab
        for res in filtered_results:
            self.filtered_tab.append(res)

    def parse_result(self, result):
        """Parse the result string and return status_code, word_count, and subdomain."""
        match = re.match(r'(\d+)\s+(\d+)\s+"([^"]+)"', result)
        if match:
            status_code = match.group(1)
            word_count = int(match.group(2))
            subdomain = match.group(3)
            return status_code, word_count, subdomain
        return None, None, None

    def subdomain_exists_in_hosts(self, domain):
        """Check if the subdomain already exists in the /etc/hosts file."""
        try:
            with open('/etc/hosts', 'r') as hosts_file:
                for line in hosts_file:
                    if domain in line:
                        return True  # Subdomain already exists
        except Exception as e:
            print(f"Error checking /etc/hosts: {str(e)}")
        return False  # Subdomain does not exist

    def ask_to_add_to_hosts(self, domain, ip_address):
        """Prompt the user to add the subdomain to the /etc/hosts file."""
        full_entry = f"{ip_address} {domain}"
        response = QMessageBox.question(None, "Add to /etc/hosts",
                                        f"Do you want to add the following entry to /etc/hosts?\n\n{full_entry}",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if response == QMessageBox.Yes:
            self.add_to_hosts(full_entry)

    def add_to_hosts(self, entry):
        """Add the entry to the /etc/hosts file."""
        try:
            with open('/etc/hosts', 'a') as hosts_file:
                hosts_file.write(f"{entry}\n")
            print(f"Added to /etc/hosts: {entry}")
        except Exception as e:
            print(f"Error adding to /etc/hosts: {str(e)}")
