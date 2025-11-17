"""
NEXT HUNTER - Configuration File
"""

# Application Settings
APP_NAME = "NEXT HUNTER"
APP_VERSION = "1.0"
APP_AUTHOR = "NEXT HUNTER Team"

# GUI Settings
WINDOW_WIDTH = 1200
WINDOW_HEIGHT = 800
DARK_THEME = True

# Default Wordlists
DEFAULT_GOBUSTER_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_HASHCAT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

# Timeout Settings (in seconds)
NMAP_TIMEOUT = 300
NIKTO_TIMEOUT = 300
GOBUSTER_TIMEOUT = 600
SQLMAP_TIMEOUT = 600
DNS_TIMEOUT = 30
WHOIS_TIMEOUT = 30

# Network Settings
DEFAULT_NMAP_SCAN_TYPE = "-sV"
DEFAULT_PORT_TIMEOUT = 5

# Hash Settings
MD5_HASH_TYPE = 0
SHA256_HASH_TYPE = 256

# Hashcat Hash Types
HASHCAT_HASH_TYPES = {
    "MD5": 0,
    "MD5($pass.$salt)": 1,
    "MD5($salt.$pass)": 3,
    "SHA1": 100,
    "SHA256": 1400,
    "SHA512": 1700,
    "bcrypt": 3200,
    "Wordpress": 400,
    "PHP": 400,
}

# Colors
COLOR_SUCCESS = "#00ff00"
COLOR_ERROR = "#ff0000"
COLOR_WARNING = "#ffff00"
COLOR_INFO = "#00ddff"
COLOR_BG = "#1e1e1e"
COLOR_INPUT_BG = "#2d2d2d"

# Log Settings
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
ENABLE_FILE_LOGGING = False
LOG_FILE = "next_hunter.log"
