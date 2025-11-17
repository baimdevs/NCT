"""
NEXT HUNTER - Utility Functions
Helper functions dan utilities
"""

import os
import json
import subprocess
from datetime import datetime
from typing import List, Dict, Tuple


class Logger:
    """Simple logging utility"""
    
    def __init__(self, enable_file=False, log_file="next_hunter.log"):
        self.enable_file = enable_file
        self.log_file = log_file
    
    def _get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def info(self, message):
        timestamp = self._get_timestamp()
        log_msg = f"[{timestamp}] [INFO] {message}"
        print(log_msg)
        if self.enable_file:
            self._write_to_file(log_msg)
    
    def warning(self, message):
        timestamp = self._get_timestamp()
        log_msg = f"[{timestamp}] [WARNING] {message}"
        print(log_msg)
        if self.enable_file:
            self._write_to_file(log_msg)
    
    def error(self, message):
        timestamp = self._get_timestamp()
        log_msg = f"[{timestamp}] [ERROR] {message}"
        print(log_msg)
        if self.enable_file:
            self._write_to_file(log_msg)
    
    def success(self, message):
        timestamp = self._get_timestamp()
        log_msg = f"[{timestamp}] [SUCCESS] {message}"
        print(log_msg)
        if self.enable_file:
            self._write_to_file(log_msg)
    
    def _write_to_file(self, message):
        try:
            with open(self.log_file, 'a') as f:
                f.write(message + "\n")
        except:
            pass


class CommandValidator:
    """Validate dan sanitize command inputs"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        return url.startswith(('http://', 'https://'))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name"""
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not part.replace('-', '').isalnum():
                return False
        
        return True
    
    @staticmethod
    def validate_file_path(path: str) -> bool:
        """Validate file path exists"""
        return os.path.exists(path) and os.path.isfile(path)
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize user input"""
        # Remove potentially dangerous characters
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')']
        for char in dangerous_chars:
            text = text.replace(char, '')
        return text.strip()


class SystemInfo:
    """Get system information"""
    
    @staticmethod
    def get_interface_list() -> List[str]:
        """Get list of network interfaces"""
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and 'LOOPBACK' not in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        interface = parts[1].strip()
                        if interface:
                            interfaces.append(interface)
            
            return interfaces
        except:
            return []
    
    @staticmethod
    def get_wordlist_suggestions() -> List[str]:
        """Get available wordlists"""
        wordlist_paths = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/wordlists/seclist/Discovery/Web-Content/raft-small-files.txt",
        ]
        
        available = []
        for path in wordlist_paths:
            if os.path.exists(path):
                available.append(path)
        
        return available
    
    @staticmethod
    def is_root() -> bool:
        """Check if running as root"""
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


class ScanResult:
    """Container untuk hasil scan"""
    
    def __init__(self, tool_name: str, target: str, status: str = "running"):
        self.tool_name = tool_name
        self.target = target
        self.status = status  # running, completed, failed
        self.results = []
        self.timestamp = datetime.now()
        self.error = None
    
    def add_result(self, result: str):
        """Add result line"""
        self.results.append(result)
    
    def set_status(self, status: str, error: str = None):
        """Set scan status"""
        self.status = status
        if error:
            self.error = error
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'tool': self.tool_name,
            'target': self.target,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'results': self.results,
            'error': self.error
        }
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), indent=2)
    
    def save_to_file(self, filename: str):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                f.write(self.to_json())
            return True
        except:
            return False


class OutputFormatter:
    """Format output untuk display"""
    
    @staticmethod
    def format_header(text: str, char: str = "=", width: int = 50) -> str:
        """Format header"""
        padding = (width - len(text)) // 2
        return f"{char * padding} {text} {char * padding}"
    
    @staticmethod
    def format_success(text: str) -> str:
        """Format success message"""
        return f"[+] {text}"
    
    @staticmethod
    def format_error(text: str) -> str:
        """Format error message"""
        return f"[!] {text}"
    
    @staticmethod
    def format_info(text: str) -> str:
        """Format info message"""
        return f"[*] {text}"
    
    @staticmethod
    def format_warning(text: str) -> str:
        """Format warning message"""
        return f"[?] {text}"


class ResultExporter:
    """Export scan results"""
    
    @staticmethod
    def export_json(results: List[ScanResult], filename: str):
        """Export to JSON"""
        data = [r.to_dict() for r in results]
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def export_text(results: List[ScanResult], filename: str):
        """Export to TXT"""
        with open(filename, 'w') as f:
            for result in results:
                f.write(f"Tool: {result.tool_name}\n")
                f.write(f"Target: {result.target}\n")
                f.write(f"Time: {result.timestamp}\n")
                f.write(f"Status: {result.status}\n")
                f.write("Results:\n")
                for line in result.results:
                    f.write(f"  {line}\n")
                f.write("\n" + "="*50 + "\n\n")
    
    @staticmethod
    def export_csv(results: List[ScanResult], filename: str):
        """Export to CSV"""
        import csv
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Tool', 'Target', 'Status', 'Timestamp', 'Results'])
            
            for result in results:
                writer.writerow([
                    result.tool_name,
                    result.target,
                    result.status,
                    result.timestamp.isoformat(),
                    '\n'.join(result.results)
                ])
