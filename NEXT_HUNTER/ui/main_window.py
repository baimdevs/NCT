"""
NEXT HUNTER - Main GUI Application
Interface untuk Kali Linux Tools Collection
"""

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QMessageBox,
    QFileDialog, QSpinBox, QListWidget, QListWidgetItem, QCheckBox,
    QGroupBox, QFormLayout, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap
from PyQt5.QtCore import QSize

import sys
import os
from tools.kali_tools import NetworkTools, WebTools, SystemTools, WifiTools


class WorkerThread(QThread):
    """Thread untuk menjalankan tools tanpa freeze GUI"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, tool_func, *args):
        super().__init__()
        self.tool_func = tool_func
        self.args = args
    
    def run(self):
        try:
            self.tool_func(*self.args)
        except Exception as e:
            self.output_signal.emit(f"[!] Error: {str(e)}")
        finally:
            self.finished_signal.emit()


class NextHunterGUI(QMainWindow):
    """Main GUI Application untuk NEXT HUNTER"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NEXT HUNTER - Kali Linux Tools Collection")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set dark theme
        self.setStyleSheet(self.get_stylesheet())
        
        # Initialize tools
        self.network_tools = None
        self.web_tools = None
        self.system_tools = None
        self.wifi_tools = None
        
        self.current_thread = None
        
        # Setup UI
        self.setup_ui()
    
    def get_stylesheet(self):
        """Dark theme stylesheet untuk NEXT HUNTER"""
        return """
            QMainWindow {
                background-color: #1e1e1e;
            }
            QWidget {
                background-color: #1e1e1e;
                color: #00ff00;
            }
            QTabWidget {
                background-color: #1e1e1e;
                border: 1px solid #00ff00;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #00ff00;
                padding: 5px 15px;
                margin-right: 2px;
                border: 1px solid #00ff00;
            }
            QTabBar::tab:selected {
                background-color: #00ff00;
                color: #1e1e1e;
                font-weight: bold;
            }
            QPushButton {
                background-color: #00ff00;
                color: #1e1e1e;
                border: 1px solid #00ff00;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #00dd00;
                border: 1px solid #00dd00;
            }
            QPushButton:pressed {
                background-color: #00aa00;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #2d2d2d;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 5px;
                border-radius: 3px;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 2px solid #00ff00;
            }
            QLabel {
                color: #00ff00;
                font-weight: bold;
            }
            QCheckBox {
                color: #00ff00;
                spacing: 5px;
            }
            QCheckBox::indicator {
                border: 1px solid #00ff00;
                border-radius: 2px;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff00;
            }
            QGroupBox {
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 5px;
                padding: 10px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            QListWidget {
                background-color: #2d2d2d;
                color: #00ff00;
                border: 1px solid #00ff00;
                borderradius: 3px;
            }
            QProgressBar {
                background-color: #2d2d2d;
                border: 1px solid #00ff00;
                color: #00ff00;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
            }
        """
    
    def setup_ui(self):
        """Setup User Interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Tab Widget
        self.tabs = QTabWidget()
        
        # Network Tab
        self.tabs.addTab(self.create_network_tab(), "NETWORK")
        
        # Web Tab
        self.tabs.addTab(self.create_web_tab(), "WEB")
        
        # System Tab
        self.tabs.addTab(self.create_system_tab(), "SYSTEM")
        
        # WiFi Tab
        self.tabs.addTab(self.create_wifi_tab(), "WIFI")
        
        # Utilities Tab
        self.tabs.addTab(self.create_utilities_tab(), "UTILITIES")
        
        main_layout.addWidget(self.tabs)
        
        central_widget.setLayout(main_layout)
    
    def create_header(self):
        """Create header widget"""
        header = QGroupBox("NEXT HUNTER v1.0 - Advanced Kali Linux Tools")
        header_layout = QHBoxLayout()
        
        title_label = QLabel("🎯 NEXT HUNTER")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        subtitle_label = QLabel("Professional Penetration Testing Toolkit")
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_label.setFont(subtitle_font)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(subtitle_label)
        
        header.setLayout(header_layout)
        return header
    
    def create_network_tab(self):
        """Create Network Tools Tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Nmap Scanning
        nmap_group = QGroupBox("NMAP Scanning")
        nmap_layout = QFormLayout()
        
        self.nmap_target = QLineEdit()
        self.nmap_target.setPlaceholderText("192.168.1.1 or example.com")
        nmap_layout.addRow("Target:", self.nmap_target)
        
        self.nmap_type = QComboBox()
        self.nmap_type.addItems(["-sV", "-sS", "-sU", "-A", "-sn"])
        nmap_layout.addRow("Scan Type:", self.nmap_type)
        
        nmap_btn = QPushButton("Start Nmap Scan")
        nmap_btn.clicked.connect(self.run_nmap_scan)
        nmap_layout.addRow(nmap_btn)
        
        nmap_group.setLayout(nmap_layout)
        layout.addWidget(nmap_group)
        
        # DNS Enumeration
        dns_group = QGroupBox("DNS Enumeration")
        dns_layout = QFormLayout()
        
        self.dns_domain = QLineEdit()
        self.dns_domain.setPlaceholderText("example.com")
        dns_layout.addRow("Domain:", self.dns_domain)
        
        dns_btn = QPushButton("Enumerate DNS")
        dns_btn.clicked.connect(self.run_dns_enum)
        dns_layout.addRow(dns_btn)
        
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)
        
        # WHOIS Lookup
        whois_group = QGroupBox("WHOIS Lookup")
        whois_layout = QFormLayout()
        
        self.whois_domain = QLineEdit()
        self.whois_domain.setPlaceholderText("example.com")
        whois_layout.addRow("Domain:", self.whois_domain)
        
        whois_btn = QPushButton("WHOIS Lookup")
        whois_btn.clicked.connect(self.run_whois)
        whois_layout.addRow(whois_btn)
        
        whois_group.setLayout(whois_layout)
        layout.addWidget(whois_group)
        
        # Port Check
        port_group = QGroupBox("Port Checking")
        port_layout = QFormLayout()
        
        self.port_host = QLineEdit()
        self.port_host.setPlaceholderText("192.168.1.1")
        port_layout.addRow("Host:", self.port_host)
        
        self.port_number = QSpinBox()
        self.port_number.setRange(1, 65535)
        self.port_number.setValue(80)
        port_layout.addRow("Port:", self.port_number)
        
        port_btn = QPushButton("Check Port")
        port_btn.clicked.connect(self.run_port_check)
        port_layout.addRow(port_btn)
        
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)
        
        # Output
        output_label = QLabel("Output:")
        layout.addWidget(output_label)
        
        self.network_output = QTextEdit()
        self.network_output.setReadOnly(True)
        self.network_output.setMaximumHeight(300)
        layout.addWidget(self.network_output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_web_tab(self):
        """Create Web Tools Tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Gobuster
        gobuster_group = QGroupBox("Directory Enumeration (Gobuster)")
        gobuster_layout = QFormLayout()
        
        self.gobuster_url = QLineEdit()
        self.gobuster_url.setPlaceholderText("http://example.com")
        gobuster_layout.addRow("Target URL:", self.gobuster_url)
        
        self.gobuster_wordlist = QLineEdit()
        self.gobuster_wordlist.setText("/usr/share/wordlists/dirb/common.txt")
        gobuster_layout.addRow("Wordlist:", self.gobuster_wordlist)
        
        gobuster_browse = QPushButton("Browse")
        gobuster_browse.clicked.connect(lambda: self.browse_file(self.gobuster_wordlist))
        gobuster_layout.addRow(gobuster_browse)
        
        gobuster_btn = QPushButton("Start Gobuster Scan")
        gobuster_btn.clicked.connect(self.run_gobuster)
        gobuster_layout.addRow(gobuster_btn)
        
        gobuster_group.setLayout(gobuster_layout)
        layout.addWidget(gobuster_group)
        
        # Nikto
        nikto_group = QGroupBox("Web Server Scanning (Nikto)")
        nikto_layout = QFormLayout()
        
        self.nikto_url = QLineEdit()
        self.nikto_url.setPlaceholderText("http://example.com")
        nikto_layout.addRow("Target URL:", self.nikto_url)
        
        nikto_btn = QPushButton("Start Nikto Scan")
        nikto_btn.clicked.connect(self.run_nikto)
        nikto_layout.addRow(nikto_btn)
        
        nikto_group.setLayout(nikto_layout)
        layout.addWidget(nikto_group)
        
        # SQLMap
        sqlmap_group = QGroupBox("SQL Injection Testing (SQLMap)")
        sqlmap_layout = QFormLayout()
        
        self.sqlmap_url = QLineEdit()
        self.sqlmap_url.setPlaceholderText("http://example.com/page?id=1")
        sqlmap_layout.addRow("Target URL:", self.sqlmap_url)
        
        self.sqlmap_method = QComboBox()
        self.sqlmap_method.addItems(["GET", "POST"])
        sqlmap_layout.addRow("Method:", self.sqlmap_method)
        
        sqlmap_btn = QPushButton("Test SQL Injection")
        sqlmap_btn.clicked.connect(self.run_sqlmap)
        sqlmap_layout.addRow(sqlmap_btn)
        
        sqlmap_group.setLayout(sqlmap_layout)
        layout.addWidget(sqlmap_group)
        
        # Output
        output_label = QLabel("Output:")
        layout.addWidget(output_label)
        
        self.web_output = QTextEdit()
        self.web_output.setReadOnly(True)
        self.web_output.setMaximumHeight(300)
        layout.addWidget(self.web_output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_system_tab(self):
        """Create System Tools Tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Hash Tools
        hash_group = QGroupBox("Hash Generation")
        hash_layout = QFormLayout()
        
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter text to hash")
        hash_layout.addRow("Input:", self.hash_input)
        
        md5_btn = QPushButton("Generate MD5")
        md5_btn.clicked.connect(self.generate_md5)
        hash_layout.addRow(md5_btn)
        
        sha256_btn = QPushButton("Generate SHA256")
        sha256_btn.clicked.connect(self.generate_sha256)
        hash_layout.addRow(sha256_btn)
        
        self.hash_output = QLineEdit()
        self.hash_output.setReadOnly(True)
        hash_layout.addRow("Hash Output:", self.hash_output)
        
        hash_group.setLayout(hash_layout)
        layout.addWidget(hash_group)
        
        # John the Ripper
        john_group = QGroupBox("Password Cracking (John the Ripper)")
        john_layout = QFormLayout()
        
        self.john_file = QLineEdit()
        self.john_file.setPlaceholderText("Select hash file")
        john_layout.addRow("Hash File:", self.john_file)
        
        john_browse = QPushButton("Browse")
        john_browse.clicked.connect(lambda: self.browse_file(self.john_file))
        john_layout.addRow(john_browse)
        
        john_btn = QPushButton("Start John Cracking")
        john_btn.clicked.connect(self.run_john)
        john_layout.addRow(john_btn)
        
        john_group.setLayout(john_layout)
        layout.addWidget(john_group)
        
        # Hashcat
        hashcat_group = QGroupBox("Password Cracking (Hashcat)")
        hashcat_layout = QFormLayout()
        
        self.hashcat_file = QLineEdit()
        self.hashcat_file.setPlaceholderText("Select hash file")
        hashcat_layout.addRow("Hash File:", self.hashcat_file)
        
        hashcat_browse = QPushButton("Browse")
        hashcat_browse.clicked.connect(lambda: self.browse_file(self.hashcat_file))
        hashcat_layout.addRow(hashcat_browse)
        
        self.hashcat_wordlist = QLineEdit()
        self.hashcat_wordlist.setText("/usr/share/wordlists/rockyou.txt")
        hashcat_layout.addRow("Wordlist:", self.hashcat_wordlist)
        
        self.hashcat_type = QSpinBox()
        self.hashcat_type.setRange(0, 32000)
        self.hashcat_type.setValue(0)
        hashcat_layout.addRow("Hash Type:", self.hashcat_type)
        
        hashcat_btn = QPushButton("Start Hashcat Cracking")
        hashcat_btn.clicked.connect(self.run_hashcat)
        hashcat_layout.addRow(hashcat_btn)
        
        hashcat_group.setLayout(hashcat_layout)
        layout.addWidget(hashcat_group)
        
        # Output
        output_label = QLabel("Output:")
        layout.addWidget(output_label)
        
        self.system_output = QTextEdit()
        self.system_output.setReadOnly(True)
        self.system_output.setMaximumHeight(250)
        layout.addWidget(self.system_output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_wifi_tab(self):
        """Create WiFi Tools Tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Monitor Mode
        monitor_group = QGroupBox("Monitor Mode")
        monitor_layout = QFormLayout()
        
        self.monitor_interface = QLineEdit()
        self.monitor_interface.setPlaceholderText("wlan0")
        monitor_layout.addRow("Interface:", self.monitor_interface)
        
        monitor_btn = QPushButton("Start Monitor Mode")
        monitor_btn.clicked.connect(self.run_monitor_mode)
        monitor_layout.addRow(monitor_btn)
        
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
        
        # Airodump
        airodump_group = QGroupBox("Wireless Network Scanning (Airodump-ng)")
        airodump_layout = QFormLayout()
        
        self.airodump_interface = QLineEdit()
        self.airodump_interface.setPlaceholderText("wlan0mon")
        airodump_layout.addRow("Monitor Interface:", self.airodump_interface)
        
        airodump_btn = QPushButton("Start Airodump Scan")
        airodump_btn.clicked.connect(self.run_airodump)
        airodump_layout.addRow(airodump_btn)
        
        airodump_group.setLayout(airodump_layout)
        layout.addWidget(airodump_group)
        
        info_label = QLabel("⚠️ WARNING: WiFi tools require root/sudo access and compatible hardware!")
        info_label.setStyleSheet("color: #ffff00; font-weight: bold;")
        layout.addWidget(info_label)
        
        # Output
        output_label = QLabel("Output:")
        layout.addWidget(output_label)
        
        self.wifi_output = QTextEdit()
        self.wifi_output.setReadOnly(True)
        self.wifi_output.setMaximumHeight(300)
        layout.addWidget(self.wifi_output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_utilities_tab(self):
        """Create Utilities Tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # System Info
        info_group = QGroupBox("System Information")
        info_layout = QVBoxLayout()
        
        get_ip_btn = QPushButton("Get Local IP Address")
        get_ip_btn.clicked.connect(self.get_local_ip)
        info_layout.addWidget(get_ip_btn)
        
        self.local_ip_output = QLineEdit()
        self.local_ip_output.setReadOnly(True)
        info_layout.addWidget(self.local_ip_output)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Tools Info
        tools_group = QGroupBox("Available Tools")
        tools_layout = QVBoxLayout()
        
        self.tools_list = QListWidget()
        tools_data = [
            "🔍 NMAP - Network Scanning & Enumeration",
            "🌐 DNS - Domain Name System Enumeration",
            "📋 WHOIS - Domain Registration Information",
            "🔌 Port Scanner - TCP/UDP Port Checking",
            "📁 Gobuster - Directory Enumeration",
            "🌍 Nikto - Web Server Vulnerability Scanner",
            "💉 SQLMap - SQL Injection Testing",
            "📱 Airmon-ng - Wireless Monitor Mode",
            "📡 Airodump-ng - Wireless Network Scanning",
            "🔐 John the Ripper - Password Cracking",
            "⚡ Hashcat - GPU Password Cracking",
            "🔑 Hash Generator - MD5/SHA256 Hashing",
        ]
        
        for tool in tools_data:
            self.tools_list.addItem(tool)
        
        tools_layout.addWidget(self.tools_list)
        tools_group.setLayout(tools_layout)
        layout.addWidget(tools_group)
        
        # About
        about_group = QGroupBox("About NEXT HUNTER")
        about_layout = QVBoxLayout()
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setText(
            "NEXT HUNTER v1.0\n\n"
            "Advanced Kali Linux Tools Collection\n\n"
            "A professional penetration testing toolkit with a modern GUI interface.\n\n"
            "Features:\n"
            "• Network Reconnaissance & Scanning\n"
            "• Web Application Testing\n"
            "• System Security Tools\n"
            "• Wireless Network Analysis\n"
            "• Password Cracking & Hash Generation\n\n"
            "⚠️ Use only on systems you have permission to test!\n"
            "For educational and authorized security testing only.\n\n"
            "© 2024 NEXT HUNTER Team"
        )
        about_layout.addWidget(about_text)
        about_group.setLayout(about_layout)
        layout.addWidget(about_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    # Network Tools Methods
    def run_nmap_scan(self):
        """Run Nmap scan"""
        target = self.nmap_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target!")
            return
        
        scan_type = self.nmap_type.currentText()
        
        self.network_output.append(f"\n[*] Starting Nmap scan on {target}...\n")
        
        self.network_tools = NetworkTools(self.network_output.append)
        self.network_tools.nmap_scan(target, scan_type)
    
    def run_dns_enum(self):
        """Run DNS enumeration"""
        domain = self.dns_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "Error", "Please enter a domain!")
            return
        
        self.network_output.append(f"\n[*] DNS enumeration for {domain}...\n")
        
        self.network_tools = NetworkTools(self.network_output.append)
        self.network_tools.dns_enumeration(domain)
    
    def run_whois(self):
        """Run WHOIS lookup"""
        domain = self.whois_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "Error", "Please enter a domain!")
            return
        
        self.network_output.append(f"\n[*] WHOIS lookup for {domain}...\n")
        
        self.network_tools = NetworkTools(self.network_output.append)
        self.network_tools.whois_lookup(domain)
    
    def run_port_check(self):
        """Run port check"""
        host = self.port_host.text().strip()
        port = self.port_number.value()
        
        if not host:
            QMessageBox.warning(self, "Error", "Please enter a host!")
            return
        
        self.network_output.append(f"\n[*] Checking port {port} on {host}...\n")
        
        self.network_tools = NetworkTools(self.network_output.append)
        self.network_tools.port_check(host, port)
    
    # Web Tools Methods
    def run_gobuster(self):
        """Run Gobuster"""
        url = self.gobuster_url.text().strip()
        wordlist = self.gobuster_wordlist.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL!")
            return
        
        self.web_output.append(f"\n[*] Starting Gobuster on {url}...\n")
        
        self.web_tools = WebTools(self.web_output.append)
        self.web_tools.gobuster_scan(url, wordlist)
    
    def run_nikto(self):
        """Run Nikto"""
        url = self.nikto_url.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL!")
            return
        
        self.web_output.append(f"\n[*] Starting Nikto scan on {url}...\n")
        
        self.web_tools = WebTools(self.web_output.append)
        self.web_tools.nikto_scan(url)
    
    def run_sqlmap(self):
        """Run SQLMap"""
        url = self.sqlmap_url.text().strip()
        method = self.sqlmap_method.currentText()
        
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL!")
            return
        
        self.web_output.append(f"\n[*] Starting SQLMap on {url}...\n")
        
        self.web_tools = WebTools(self.web_output.append)
        self.web_tools.sqlmap_test(url, method)
    
    # System Tools Methods
    def generate_md5(self):
        """Generate MD5 hash"""
        text = self.hash_input.text().strip()
        if not text:
            QMessageBox.warning(self, "Error", "Please enter text!")
            return
        
        self.system_tools = SystemTools()
        hash_value = self.system_tools.md5_hash(text)
        self.hash_output.setText(hash_value)
        self.system_output.append(f"[+] MD5: {hash_value}")
    
    def generate_sha256(self):
        """Generate SHA256 hash"""
        text = self.hash_input.text().strip()
        if not text:
            QMessageBox.warning(self, "Error", "Please enter text!")
            return
        
        self.system_tools = SystemTools()
        hash_value = self.system_tools.sha256_hash(text)
        self.hash_output.setText(hash_value)
        self.system_output.append(f"[+] SHA256: {hash_value}")
    
    def run_john(self):
        """Run John the Ripper"""
        hash_file = self.john_file.text().strip()
        
        if not hash_file:
            QMessageBox.warning(self, "Error", "Please select a hash file!")
            return
        
        self.system_output.append(f"\n[*] Starting John the Ripper...\n")
        
        self.system_tools = SystemTools(self.system_output.append)
        self.system_tools.john_crack(hash_file)
    
    def run_hashcat(self):
        """Run Hashcat"""
        hash_file = self.hashcat_file.text().strip()
        wordlist = self.hashcat_wordlist.text().strip()
        hash_type = self.hashcat_type.value()
        
        if not hash_file:
            QMessageBox.warning(self, "Error", "Please select a hash file!")
            return
        
        self.system_output.append(f"\n[*] Starting Hashcat...\n")
        
        self.system_tools = SystemTools(self.system_output.append)
        self.system_tools.hashcat_crack(hash_file, wordlist, hash_type)
    
    # WiFi Tools Methods
    def run_monitor_mode(self):
        """Start monitor mode"""
        interface = self.monitor_interface.text().strip()
        
        if not interface:
            QMessageBox.warning(self, "Error", "Please enter an interface!")
            return
        
        self.wifi_output.append(f"\n[*] Starting monitor mode on {interface}...\n")
        
        self.wifi_tools = WifiTools(self.wifi_output.append)
        self.wifi_tools.airmon_start(interface)
    
    def run_airodump(self):
        """Run Airodump scan"""
        interface = self.airodump_interface.text().strip()
        
        if not interface:
            QMessageBox.warning(self, "Error", "Please enter an interface!")
            return
        
        self.wifi_output.append(f"\n[*] Starting Airodump on {interface}...\n")
        
        self.wifi_tools = WifiTools(self.wifi_output.append)
        self.wifi_tools.airodump_scan(interface)
    
    # Utilities Methods
    def get_local_ip(self):
        """Get local IP address"""
        self.network_tools = NetworkTools()
        ip = self.network_tools.get_local_ip()
        self.local_ip_output.setText(ip)
    
    def browse_file(self, line_edit):
        """File browser dialog"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", os.path.expanduser("~"))
        if file_path:
            line_edit.setText(file_path)
