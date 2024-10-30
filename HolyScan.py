import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit, QLineEdit,
                             QTabWidget, QMainWindow, QMessageBox, QLabel, QHBoxLayout, QFrame)
from PyQt5.QtGui import QFont, QMovie, QIcon
from PyQt5.QtCore import Qt
from subprocess import Popen, PIPE
import re

# Plugin Imports
from wfuzz_plugin import WfuzzPlugin
from gobuster_plugin import GobusterPlugin
from kerberos_plugin import KerberosPlugin
from ldap_plugin import LdapPlugin
from ftp_plugin import FtpPlugin
from ssh_plugin import SSHPlugin
from winrm_plugin import WinRMPlugin

# ========================================
# ScanManager Class - Handles scanning logic
# ========================================
class ScanManager:
    def __init__(self, plugin_manager, ui_manager):
        self.plugin_manager = plugin_manager
        self.ui_manager = ui_manager
        self.port_scan_mapping = {
            21: self.run_ftp_scan,
            22: self.run_ssh_scan,
            80: self.run_http_scans,
            88: self.run_kerberos_scan,
            389: self.run_ldap_scan,
            3268: self.run_ldap_scan,
            5985: self.run_winrm_scan
        }
        self.got_domain = False
        self.ldap_scan_triggered = False

    def run_nmap_scan(self, target):
        self.ui_manager.show_loading()
        nmap_command = ['nmap', '-p 21,22,80,88,389,3268,5985', '-A', '-Pn', target, '-T5']
        process = Popen(nmap_command, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        self.ui_manager.hide_loading()

        nmap_output = stdout.decode('utf-8')
        ip_address, domain = self.extract_ip_and_domain(nmap_output)

        # Check for domain in /etc/hosts if not found in nmap results
        if not domain:
            domain = self.lookup_domain_in_hosts(ip_address)

        print(f"DEBUG: Extracted IP: {ip_address}, Domain: {domain}")  # Debugging line
        open_ports = self.extract_open_ports(nmap_output)
        print(f"DEBUG: Open Ports: {open_ports}")  # Debugging line
        self.trigger_scans(open_ports, ip_address, domain)
        return nmap_output

    def extract_open_ports(self, nmap_output):
        port_pattern = re.compile(r'(\d+)/tcp\s+open')
        return [int(match.group(1)) for match in port_pattern.finditer(nmap_output)]

    def extract_ip_and_domain(self, nmap_output):
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', nmap_output)
        domain_match = re.search(r'Did not follow redirect to http[s]?://([^\s/]+)', nmap_output)
        domain = domain_match.group(1) if domain_match and domain_match.group(1) != 'nmap.org' else None
        return ip_match.group(0) if ip_match else None, domain

    def lookup_domain_in_hosts(self, ip_address):
        """Check /etc/hosts for a domain associated with the IP address."""
        try:
            with open('/etc/hosts', 'r') as hosts_file:
                for line in hosts_file:
                    # Split each line and check if the IP matches and there's a valid domain
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == ip_address:
                        # Return the first entry with only one dot, indicating a root domain
                        for part in parts[1:]:
                            if part.count('.') == 1:
                                print(f"DEBUG: Found domain in hosts file: {part}")  # Debugging line
                                return part
        except Exception as e:
            print(f"Error reading /etc/hosts: {str(e)}")
        return None

    def trigger_scans(self, open_ports, ip_address, domain):
        for port in open_ports:
            if port == 80:
                self.run_http_scans(ip_address, domain)
            elif port in self.port_scan_mapping:
                if port in [389, 3268] and not self.ldap_scan_triggered:
                    self.run_ldap_scan(ip_address, domain)
                    self.ldap_scan_triggered = True
                else:
                    self.port_scan_mapping[port](ip_address, domain)

    def run_http_scans(self, ip_address, domain):
        if domain:
            print(f"DEBUG: Starting both Gobuster and Wfuzz scans for domain: {domain}")  # Debugging line
            self.ui_manager.show_holy_message(f"Running Gobuster and Wfuzz scans for domain: {domain}")
            self.plugin_manager.run_plugin('GobusterPlugin', domain)
            self.plugin_manager.run_plugin('WfuzzPlugin', ip_address, domain)
            self.got_domain = True
        else:
            print(f"DEBUG: No domain found. Running only Gobuster with IP: {ip_address}")  # Debugging line
            self.ui_manager.show_holy_message(f"No domain found. Running Gobuster with IP: {ip_address}")
            self.plugin_manager.run_plugin('GobusterPlugin', ip_address)

    def ask_to_add_to_hosts(self, domain, ip_address):
        full_entry = f"{ip_address} {domain}"
        response = QMessageBox.question(None, "Add to /etc/hosts",
                                        f"Do you wish to sanctify the hosts file with this entry?\n\n{full_entry}",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if response == QMessageBox.Yes:
            self.add_to_hosts(full_entry)
            self.ui_manager.show_holy_message(f"Domain added to /etc/hosts: {domain}. Running Gobuster and Wfuzz...")
            self.run_http_scans(ip_address, domain)
        else:
            self.plugin_manager.run_plugin('GobusterPlugin', ip_address)

    def add_to_hosts(self, full_entry):
        try:
            with open('/etc/hosts', 'a') as hosts_file:
                hosts_file.write(f"\n{full_entry}\n")
            print(f"The entry {full_entry} has been blessed into /etc/hosts.")
        except Exception as e:
            print(f"Error adding to /etc/hosts: {str(e)}")

    def run_ldap_scan(self, ip_address, _):
        self.plugin_manager.run_plugin('LdapPlugin', ip_address)

    def run_kerberos_scan(self, ip_address, _):
        self.plugin_manager.run_plugin('KerberosPlugin', ip_address)

    def run_ftp_scan(self, ip_address, _):
        self.plugin_manager.run_plugin('FtpPlugin', ip_address)

    def run_ssh_scan(self, ip_address, _):
        """Initiates the SSH Plugin manually with the given IP address."""
        self.plugin_manager.run_plugin('SSHPlugin', ip_address)

    def run_winrm_scan(self, ip_address, _):
        """Initiates the WinRM Plugin manually with the given IP address."""
        self.plugin_manager.run_plugin('WinRMPlugin', ip_address)

# ========================================
# PluginManager Class - Manages plugin loading and execution
# ========================================
class PluginManager:
    def __init__(self, ui_manager):
        self.plugins = {}
        self.ui_manager = ui_manager
        self.loaded_plugins = set()
        self.load_plugins()

    def load_plugins(self):
        plugin_classes = [WfuzzPlugin, GobusterPlugin, KerberosPlugin, LdapPlugin, FtpPlugin, SSHPlugin, WinRMPlugin]
        for plugin_class in plugin_classes:
            try:
                plugin_instance = plugin_class()
                self.plugins[plugin_class.__name__] = plugin_instance
                print(f"Loaded plugin: {plugin_instance._name}")
            except Exception as e:
                print(f"Error loading plugin {plugin_class.__name__}: {e}")

    def run_plugin(self, plugin_name, *args):
        plugin = self.plugins.get(plugin_name)
        if plugin:
            if plugin_name not in self.loaded_plugins:
                plugin_tab = plugin.create_tab()
                self.ui_manager.add_plugin_tab(plugin, plugin_tab)
                self.loaded_plugins.add(plugin_name)
            try:
                plugin.start_scan(*args)
            except Exception as e:
                print(f"Error running plugin {plugin_name}: {e}")

# ========================================
# UIManager Class - Manages UI Elements and Tabs
# ========================================
class UIManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('HolyScan')
        self.resize(1200, 700)
        self.setWindowIcon(QIcon("holy_icon.png"))

        # Main widget and layout with a margin and spacing for a clean look
        self.central_widget = QWidget()
        self.central_widget.setStyleSheet("background-color: #2e2e2e;")
        self.setCentralWidget(self.central_widget)

        # Main layout with expandable sidebar
        main_layout = QHBoxLayout(self.central_widget)
        left_layout = QVBoxLayout()
        main_layout.addLayout(left_layout, 2)

        # Input field for target IP or domain
        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText('Enter the divine target (IP/domain)')
        self.target_input.setFont(QFont('Arial', 12))
        self.target_input.setStyleSheet("padding: 8px; border: 1px solid #aaa; border-radius: 4px; color: white; background-color: #3e3e3e;")
        left_layout.addWidget(self.target_input)

        # Button to run the scan
        self.scan_button = QPushButton('Invoke Holy Scan')
        self.scan_button.setFont(QFont('Arial', 12, QFont.Bold))
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50; color: white; padding: 10px;
                border-radius: 5px; font-size: 14px;
            }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:pressed { background-color: #3e8e41; }
        """)
        left_layout.addWidget(self.scan_button)

        # Tabs to display different scan results
        self.tab_widget = QTabWidget(self)
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #aaa; border-radius: 5px; }
            QTabBar::tab {
                background: #3e3e3e; padding: 10px; font-size: 12px;
                color: #ccc;
                border-top-left-radius: 5px; border-top-right-radius: 5px;
            }
            QTabBar::tab:selected { background: #4CAF50; color: white; }
            QTabBar::tab:hover { background: #4a4a4a; }
        """)
        left_layout.addWidget(self.tab_widget)

        # Initial tab for scan results
        self.scan_result_tab = QTextEdit(self)
        self.scan_result_tab.setReadOnly(True)
        self.scan_result_tab.setFont(QFont('Arial', 11))
        self.scan_result_tab.setStyleSheet("background-color: #3e3e3e; color: #eee; padding: 8px;")
        self.tab_widget.addTab(self.scan_result_tab, "Divine Scan Results")

        # Loading screen with centralized animation
        self.loading_label = QLabel(self)
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setStyleSheet("background-color: rgba(46, 46, 46, 200);")
        self.loading_label.setGeometry(self.width() // 4, self.height() // 4, 400, 400)
        self.movie = QMovie("loading.gif")
        self.loading_label.setMovie(self.movie)
        self.loading_label.setVisible(False)

        # Expandable user/pass entry panel
        self.right_panel = QFrame()
        self.right_panel.setStyleSheet("background-color: #3e3e3e; color: white;")
        self.right_panel.setMinimumWidth(300)
        self.right_panel.setMaximumWidth(300)
        self.right_panel.setVisible(False)
        right_layout = QVBoxLayout(self.right_panel)

        # Username input and add button
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter Username")
        self.username_input.setStyleSheet("padding: 6px;")
        right_layout.addWidget(self.username_input)

        self.add_username_button = QPushButton("Add Username")
        self.add_username_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        self.add_username_button.clicked.connect(self.add_username)
        right_layout.addWidget(self.add_username_button)

        # Password input and add button
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("padding: 6px;")
        right_layout.addWidget(self.password_input)

        self.add_password_button = QPushButton("Add Password")
        self.add_password_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        self.add_password_button.clicked.connect(self.add_password)
        right_layout.addWidget(self.add_password_button)

        # Add right panel to main layout
        main_layout.addWidget(self.right_panel)

        # Toggle button for the right panel at the bottom of the main layout
        self.expand_button = QPushButton("Show Credentials Panel")
        self.expand_button.setStyleSheet("background-color: #3e8e41; color: white; padding: 8px;")
        self.expand_button.clicked.connect(self.toggle_panel)
        left_layout.addWidget(self.expand_button)

    def toggle_panel(self):
        self.right_panel.setVisible(not self.right_panel.isVisible())
        if self.right_panel.isVisible():
            self.expand_button.setText("Hide Credentials Panel")
        else:
            self.expand_button.setText("Show Credentials Panel")

    def add_username(self):
        username = self.username_input.text().strip()
        if username:
            try:
                with open("temp_usernames.txt", "a") as file:
                    file.write(f"{username}\n")
                self.show_holy_message(f"Added username: {username}")
                self.username_input.clear()
            except Exception as e:
                self.show_holy_message(f"Error saving username: {str(e)}")

    def add_password(self):
        password = self.password_input.text().strip()
        if password:
            try:
                with open("temp_passwords.txt", "a") as file:
                    file.write(f"{password}\n")
                self.show_holy_message("Added password.")
                self.password_input.clear()
            except Exception as e:
                self.show_holy_message(f"Error saving password: {str(e)}")

    def set_scan_output(self, output):
        self.scan_result_tab.setText(output)

    def add_plugin_tab(self, plugin, tab):
        self.tab_widget.addTab(tab, plugin._name)
        self.tab_widget.setCurrentWidget(tab)

    def show_holy_message(self, message):
        self.scan_result_tab.append(f"🕊 {message}\n")

    def show_loading(self):
        self.loading_label.setVisible(True)
        self.movie.start()

    def hide_loading(self):
        self.movie.stop()
        self.loading_label.setVisible(False)

# ========================================
# Main Application - Glue everything together
# ========================================
if __name__ == '__main__':
    app = QApplication(sys.argv)

    ui_manager = UIManager()
    plugin_manager = PluginManager(ui_manager)
    scan_manager = ScanManager(plugin_manager, ui_manager)

    ui_manager.scan_button.clicked.connect(lambda: ui_manager.set_scan_output(
        scan_manager.run_nmap_scan(ui_manager.target_input.text().strip())
    ))

    ui_manager.show()
    sys.exit(app.exec_())
