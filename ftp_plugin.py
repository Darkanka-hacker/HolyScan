from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton
from PyQt5.QtGui import QFont
from PyQt5.QtCore import pyqtSignal, QThread
from subprocess import Popen, PIPE

class FtpScanThread(QThread):
    output_signal = pyqtSignal(str)  # Signal to emit output lines from Hydra
    error_signal = pyqtSignal(str)   # Signal to emit error messages

    def __init__(self, ip, use_temp_files=False):
        super().__init__()
        self.ip = ip
        self.use_temp_files = use_temp_files

    def run(self):
        """Run the FTP brute-force scan using hydra."""
        # Choose command based on whether to use the temp files for usernames and passwords
        if self.use_temp_files:
            command = [
                'hydra', '-L', 'temp_usernames.txt', '-P', 'temp_passwords.txt',
                f'ftp://{self.ip}'
            ]
        else:
            command = [
                'hydra', '-C', 'wordlist/ftp-betterdefaultpasslist.txt',
                f'ftp://{self.ip}'
            ]

        try:
            process = Popen(command, stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = process.communicate()

            # Emit each line of stdout as output
            if stdout:
                for line in stdout.splitlines():
                    self.output_signal.emit(line)

            # Emit each line of stderr as an error if any
            if stderr:
                for error_line in stderr.splitlines():
                    self.error_signal.emit(f"Error: {error_line}")

        except Exception as e:
            self.error_signal.emit(f"FTP Scan Error: {str(e)}")

class FtpPlugin:
    _name = "FTP Scanner"

    def __init__(self):
        self.tab = None
        self.output_area = None
        self.ftp_thread = None
        self.ip_address = None

    def create_tab(self):
        """Create the FTP plugin's tab in the main application."""
        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)

        # Set up the output area for displaying scan results
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont('Courier', 10))
        self.output_area.setStyleSheet("background-color: #3e3e3e; color: #eee; padding: 8px;")
        layout.addWidget(self.output_area)

        # Button to re-run the scan with temp files
        self.re_run_button = QPushButton("Re-run Scan with Temp Files")
        self.re_run_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        self.re_run_button.clicked.connect(self.re_run_scan)
        layout.addWidget(self.re_run_button)

        return self.tab

    def start_scan(self, ip_address):
        """Start the FTP brute-force scan."""
        self.ip_address = ip_address
        if self.ftp_thread and self.ftp_thread.isRunning():
            self.ftp_thread.quit()
            self.ftp_thread.wait()

        # Initialize and start the initial FTP scan thread
        self.ftp_thread = FtpScanThread(ip_address)
        self.ftp_thread.output_signal.connect(self.update_output)
        self.ftp_thread.error_signal.connect(self.update_output)
        self.ftp_thread.start()

    def re_run_scan(self):
        """Re-run the FTP brute-force scan with temp files for usernames and passwords."""
        if not self.ip_address:
            self.update_output("Error: IP address not set for FTP re-scan.")
            return

        # Check if there's an active thread and wait if necessary
        if self.ftp_thread and self.ftp_thread.isRunning():
            self.ftp_thread.quit()
            self.ftp_thread.wait()

        # Start the FTP scan thread using the temp files
        self.ftp_thread = FtpScanThread(self.ip_address, use_temp_files=True)
        self.ftp_thread.output_signal.connect(self.update_output)
        self.ftp_thread.error_signal.connect(self.update_output)
        self.ftp_thread.start()

    def update_output(self, output):
        """Update the FTP results tab with new output."""
        if self.output_area:
            self.output_area.append(output)
