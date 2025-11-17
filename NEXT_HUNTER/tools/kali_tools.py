"""
NEXT HUNTER - Kali Linux Tools Collection
Module untuk network scanning dan reconnaissance
"""

import subprocess
import socket
import threading
from typing import Callable, List, Dict

class NetworkTools:
    """Tools untuk network scanning dan enumeration"""
    
    def __init__(self, output_callback: Callable = None):
        self.output_callback = output_callback
        self.is_running = False
    
    def log_output(self, message: str):
        """Log output ke callback"""
        if self.output_callback:
            self.output_callback(message)
        else:
            print(message)
    
    def nmap_scan(self, target: str, scan_type: str = "-sV") -> bool:
        """
        Jalankan Nmap scan
        target: IP atau hostname
        scan_type: -sS (SYN), -sV (Version), -A (Aggressive), etc
        """
        try:
            self.log_output(f"[*] Starting Nmap scan on {target} dengan tipe: {scan_type}")
            cmd = ["nmap", scan_type, target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                self.log_output(result.stdout)
            if result.stderr:
                self.log_output(f"[!] Error: {result.stderr}")
            
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.log_output("[!] Nmap scan timeout")
            return False
        except Exception as e:
            self.log_output(f"[!] Error running nmap: {str(e)}")
            return False
    
    def netdiscover_scan(self, interface: str = None, range: str = None) -> bool:
        """
        Jalankan Netdiscover untuk ARP scanning
        interface: Network interface (eth0, wlan0, etc)
        range: IP range untuk scan
        """
        try:
            self.log_output("[*] Starting Netdiscover ARP scan...")
            cmd = ["netdiscover", "-p"]
            
            if interface:
                cmd.extend(["-i", interface])
            if range:
                cmd.extend(["-r", range])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error running netdiscover: {str(e)}")
            return False
    
    def whois_lookup(self, domain: str) -> bool:
        """
        WHOIS lookup untuk domain
        """
        try:
            self.log_output(f"[*] WHOIS lookup for {domain}")
            cmd = ["whois", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def dns_enumeration(self, domain: str) -> bool:
        """
        DNS enumeration dengan dig
        """
        try:
            self.log_output(f"[*] DNS enumeration for {domain}")
            cmd = ["dig", "+noall", "+answer", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def port_check(self, host: str, port: int, timeout: int = 5) -> bool:
        """
        Simple port checking
        """
        try:
            self.log_output(f"[*] Checking port {port} on {host}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                self.log_output(f"[+] Port {port} is OPEN on {host}")
                return True
            else:
                self.log_output(f"[-] Port {port} is CLOSED on {host}")
                return False
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def get_local_ip(self) -> str:
        """
        Dapatkan local IP address
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"


class WebTools:
    """Tools untuk web enumeration dan scanning"""
    
    def __init__(self, output_callback: Callable = None):
        self.output_callback = output_callback
    
    def log_output(self, message: str):
        """Log output ke callback"""
        if self.output_callback:
            self.output_callback(message)
        else:
            print(message)
    
    def gobuster_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> bool:
        """
        Directory enumeration dengan Gobuster
        """
        try:
            self.log_output(f"[*] Starting Gobuster scan on {url}")
            self.log_output(f"[*] Using wordlist: {wordlist}")
            
            cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-v"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def sqlmap_test(self, url: str, method: str = "GET") -> bool:
        """
        SQL Injection testing dengan SQLmap
        """
        try:
            self.log_output(f"[*] Testing SQL Injection on {url}")
            cmd = ["sqlmap", "-u", url, "--batch", "-v", "1"]
            
            if method == "POST":
                cmd.insert(2, "--data")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def nikto_scan(self, url: str) -> bool:
        """
        Web server scanning dengan Nikto
        """
        try:
            self.log_output(f"[*] Starting Nikto scan on {url}")
            cmd = ["nikto", "-h", url, "-Display", "1234EP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False


class SystemTools:
    """Tools untuk system enumeration dan password cracking"""
    
    def __init__(self, output_callback: Callable = None):
        self.output_callback = output_callback
    
    def log_output(self, message: str):
        """Log output ke callback"""
        if self.output_callback:
            self.output_callback(message)
        else:
            print(message)
    
    def hashcat_crack(self, hash_file: str, wordlist: str, hash_type: int = 0) -> bool:
        """
        Password cracking dengan Hashcat
        hash_type: 0=MD5, 1=MD5($pass.$salt), 3=MD5($salt.$pass), etc
        """
        try:
            self.log_output(f"[*] Starting Hashcat crack")
            self.log_output(f"[*] Hash type: {hash_type}, Wordlist: {wordlist}")
            
            cmd = ["hashcat", "-m", str(hash_type), "-a", "0", hash_file, wordlist, "--force"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.stdout:
                self.log_output(result.stdout)
            if result.stderr:
                self.log_output(f"[*] {result.stderr}")
            
            return True
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def john_crack(self, hash_file: str, wordlist: str = None) -> bool:
        """
        Password cracking dengan John the Ripper
        """
        try:
            self.log_output(f"[*] Starting John the Ripper")
            cmd = ["john", hash_file, "--show"]
            
            if wordlist:
                cmd.extend(["--wordlist", wordlist])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def md5_hash(self, text: str) -> str:
        """
        Generate MD5 hash
        """
        import hashlib
        return hashlib.md5(text.encode()).hexdigest()
    
    def sha256_hash(self, text: str) -> str:
        """
        Generate SHA256 hash
        """
        import hashlib
        return hashlib.sha256(text.encode()).hexdigest()


class WifiTools:
    """Tools untuk wireless network analysis"""
    
    def __init__(self, output_callback: Callable = None):
        self.output_callback = output_callback
    
    def log_output(self, message: str):
        """Log output ke callback"""
        if self.output_callback:
            self.output_callback(message)
        else:
            print(message)
    
    def airmon_start(self, interface: str) -> bool:
        """
        Start monitor mode
        """
        try:
            self.log_output(f"[*] Starting monitor mode on {interface}")
            cmd = ["sudo", "airmon-ng", "start", interface]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return result.returncode == 0
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
    
    def airodump_scan(self, interface: str) -> bool:
        """
        Scan wireless networks
        """
        try:
            self.log_output(f"[*] Scanning wireless networks on {interface}")
            cmd = ["sudo", "airodump-ng", interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.stdout:
                self.log_output(result.stdout)
            
            return True
        except Exception as e:
            self.log_output(f"[!] Error: {str(e)}")
            return False
