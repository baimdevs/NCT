# NEXT HUNTER - Kali Linux Tools Collection

**Advanced Penetration Testing Toolkit with Modern GUI**

![Version](https://img.shields.io/badge/version-1.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

## 🎯 Overview

NEXT HUNTER adalah kumpulan tools Kali Linux yang dikemas dalam satu interface GUI yang modern dan user-friendly. Dirancang untuk memudahkan penetration tester dan ethical hacker dalam melakukan reconnaissance, enumeration, dan testing.

## ✨ Features

### Network Tools
- **NMAP Scanning** - Network discovery dan port scanning
- **DNS Enumeration** - Domain name system enumeration
- **WHOIS Lookup** - Domain registration information
- **Port Checking** - TCP/UDP port connectivity testing

### Web Tools  
- **Gobuster** - Directory enumeration
- **Nikto** - Web server vulnerability scanning
- **SQLMap** - SQL injection testing

### System Tools
- **Hash Generation** - MD5 dan SHA256 hashing
- **John the Ripper** - Password cracking
- **Hashcat** - GPU-accelerated password cracking

### WiFi Tools
- **Airmon-ng** - Wireless monitor mode
- **Airodump-ng** - Wireless network scanning

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Kali Linux atau Linux dengan tools Kali
- PyQt5

### Setup

1. **Clone atau download repository:**
```bash
cd /workspaces/NCT/NEXT_HUNTER
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Ensure Kali tools are installed:**
```bash
sudo apt update
sudo apt install -y nmap whois dnsutils gobuster nikto sqlmap aircrack-ng john hashcat
```

4. **Make script executable:**
```bash
chmod +x main.py
```

## 🎮 Usage

### Run the application:
```bash
python3 main.py
```

Atau dengan sudo (untuk WiFi tools):
```bash
sudo python3 main.py
```

### GUI Layout

1. **NETWORK Tab** - Network reconnaissance tools
2. **WEB Tab** - Web application testing tools
3. **SYSTEM Tab** - System and password cracking tools
4. **WIFI Tab** - Wireless network tools
5. **UTILITIES Tab** - Helper tools dan system info

## 📋 Tool Details

### Network Tools

#### NMAP Scanning
- Input target IP/hostname
- Select scan type (-sV, -sS, -sU, -A, -sn)
- View detailed scan results in output panel

#### DNS Enumeration
- Perform DNS lookups using dig
- View DNS records and resolution info

#### WHOIS Lookup
- Get domain registration information
- View registrar and ownership details

#### Port Checking
- Check specific port connectivity
- Quick TCP port validation

### Web Tools

#### Gobuster
- Directory and file enumeration
- Custom wordlist support
- Verbose output logging

#### Nikto
- Web server vulnerability scanning
- Detailed vulnerability reporting
- Display levels customization

#### SQLMap
- Automated SQL injection testing
- GET dan POST method support
- Database enumeration

### System Tools

#### Hash Generation
- Generate MD5 hashes
- Generate SHA256 hashes
- Copy hash to clipboard ready

#### John the Riiper
- Crack password hashes
- Multiple hash format support
- Wordlist-based cracking

#### Hashcat
- GPU-accelerated cracking
- Multiple hash types support
- Optimized performance

### WiFi Tools

#### Monitor Mode
- Enable wireless interface monitor mode
- Prepare for network sniffing

#### Airodump-ng
- Scan nearby wireless networks
- View SSID, BSSID, signal strength
- Display channel information

⚠️ **WARNING**: WiFi tools require:
- Root/sudo access
- Compatible wireless adapter
- Proper permissions

## ⚙️ Configuration

### Default Wordlists
- Gobuster: `/usr/share/wordlists/dirb/common.txt`
- Hashcat: `/usr/share/wordlists/rockyou.txt`

Dapat diubah di GUI atau edit di `tools/kali_tools.py`

## 🔧 Troubleshooting

### "Command not found" errors
```bash
# Install missing tools
sudo apt install -y [tool-name]
```

### PyQt5 import errors
```bash
pip install --upgrade PyQt5
```

### Permission denied for WiFi tools
```bash
# Run with sudo
sudo python3 main.py
```

## 📝 Examples

### 1. Network Scanning
```
Target: 192.168.1.0/24
Scan Type: -sV
```

### 2. Web Directory Enumeration
```
URL: http://target.com
Wordlist: /usr/share/wordlists/dirb/common.txt
```

### 3. Hash Generation
```
Input: mysecurepassword
Output: 5d41402abc4b2a76b9719d911017c592 (MD5)
```

## 🔐 Legal Notice

⚠️ **DISCLAIMER**

NEXT HUNTER hanya boleh digunakan untuk:
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Security research dengan izin
- ✅ Testing sistem anda sendiri

❌ **DILARANG untuk:**
- Unauthorized access/testing
- Illegal hacking activities
- Violation of laws & regulations

**Gunakan secara bertanggung jawab!**

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Developer

NEXT HUNTER Team

## 🤝 Contributing

Contributions welcome! Feel free to submit issues dan pull requests.

## 📧 Support

For issues, questions, atau suggestions, please open an issue on the repository.

---

**Happy Hunting! 🎯**

*Remember: With great power comes great responsibility.*
