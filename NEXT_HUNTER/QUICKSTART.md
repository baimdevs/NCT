# NEXT HUNTER - Quick Start Guide

## 🚀 Instalasi Cepat

### 1. Clone atau Download
```bash
cd /workspaces/NCT/NEXT_HUNTER
```

### 2. Jalankan Setup Script
```bash
chmod +x install.sh
./install.sh
```

Atau manual:
```bash
pip3 install -r requirements.txt
sudo apt update
sudo apt install -y nmap whois dnsutils gobuster nikto sqlmap aircrack-ng john hashcat
```

### 3. Run Aplikasi
```bash
python3 main.py
```

Dengan sudo (untuk tools WiFi):
```bash
sudo python3 main.py
```

---

## 📖 Panduan Penggunaan

### Network Tab

#### NMAP Scanning
1. Masukkan target (IP atau hostname)
2. Pilih scan type dari dropdown
3. Klik "Start Nmap Scan"
4. Tunggu hasil di output panel

**Scan Types:**
- `-sV`: Version detection
- `-sS`: SYN stealth scan
- `-sU`: UDP scan
- `-A`: Aggressive scan
- `-sn`: Ping scan

#### DNS Enumeration
1. Masukkan domain name
2. Klik "Enumerate DNS"
3. View DNS records

#### WHOIS Lookup
1. Masukkan domain
2. Klik "WHOIS Lookup"
3. Lihat domain registration info

#### Port Check
1. Masukkan hostname/IP
2. Set port number
3. Klik "Check Port"

---

### Web Tab

#### Gobuster Directory Enumeration
1. Masukkan target URL (contoh: http://example.com)
2. Pilih wordlist atau use default
3. Klik "Start Gobuster Scan"
4. Monitor findings di output

#### Nikto Web Server Scan
1. Masukkan target URL
2. Klik "Start Nikto Scan"
3. Review vulnerability findings

#### SQLMap SQL Injection Test
1. Masukkan target URL dengan parameter (contoh: http://example.com/page?id=1)
2. Pilih HTTP method (GET/POST)
3. Klik "Test SQL Injection"
4. Analyze results

---

### System Tab

#### Hash Generation
1. Masukkan teks yang ingin di-hash
2. Klik "Generate MD5" atau "Generate SHA256"
3. Hash akan ditampilkan di output field

#### John the Ripper
1. Browse dan select hash file
2. Klik "Start John Cracking"
3. Monitor proses cracking

#### Hashcat
1. Browse dan select hash file
2. Pilih/browse wordlist
3. Set hash type (0=MD5, 100=SHA1, 1400=SHA256, dll)
4. Klik "Start Hashcat Cracking"

---

### WiFi Tab

⚠️ Requires sudo/root access dan compatible wireless adapter

#### Start Monitor Mode
1. Masukkan wireless interface (contoh: wlan0)
2. Klik "Start Monitor Mode"
3. Interface akan switch ke monitor mode

#### Airodump-ng Scanning
1. Masukkan monitor interface (contoh: wlan0mon)
2. Klik "Start Airodump Scan"
3. View nearby wireless networks

---

### Utilities Tab

- **Get Local IP**: Tampilkan IP address lokal
- **Available Tools**: Daftar tools yang tersedia
- **About**: Informasi tentang NEXT HUNTER

---

## 💡 Tips & Tricks

### 1. Default Wordlists
```bash
# Gobuster default
/usr/share/wordlists/dirb/common.txt

# Hashcat default
/usr/share/wordlists/rockyou.txt
```

### 2. Install Additional Wordlists
```bash
# Dari repository
sudo apt install wordlists seclists

# Dari SecLists GitHub
git clone https://github.com/danielmiessler/SecLists.git
```

### 3. Network Interface Detection
```bash
# List all interfaces
ip link show

# Get specific interface info
ifconfig wlan0
```

### 4. Check if Nmap Installed
```bash
which nmap
nmap --version
```

---

## 🔧 Troubleshooting

### PyQt5 Error
```bash
pip3 install --upgrade PyQt5 PyQt5-sip
```

### Command not found
```bash
# Install missing tool
sudo apt install [tool-name]

# Verify installation
which [tool-name]
```

### Permission Denied
```bash
# Make files executable
chmod +x main.py install.sh

# Run with sudo
sudo python3 main.py
```

### Nmap/Tool Timeout
- Increase timeout di `tools/kali_tools.py`
- Gunakan simpler scan type
- Check network connectivity

### WiFi Tools Not Working
```bash
# Check wireless adapter
iwconfig

# Install drivers if needed
sudo apt install wireless-tools

# Run with sudo
sudo python3 main.py
```

---

## 📊 Output Examples

### NMAP Scan
```
[*] Starting Nmap scan on 192.168.1.1...
[*] Nmap output:
Starting Nmap 7.93...
Nmap scan report for 192.168.1.1
Port    State    Service
22/tcp  open     ssh
80/tcp  open     http
443/tcp open     https
```

### DNS Enumeration
```
[*] DNS enumeration for google.com
google.com. 300 IN A 142.250.185.46
```

### Hash Generation
```
[+] MD5: 5d41402abc4b2a76b9719d911017c592
```

---

## 🎯 Use Cases

### 1. Website Reconnaissance
```
1. NMAP scan target server
2. DNS enumeration
3. WHOIS lookup
4. Gobuster directory scan
5. Nikto vulnerability scan
```

### 2. Password Testing
```
1. Generate hash dari target password
2. Use hash untuk testing cracking tools
3. Test dengan John atau Hashcat
```

### 3. WiFi Security Assessment
```
1. Start monitor mode pada wireless adapter
2. Airodump scan untuk discover networks
3. Analyze captured data
```

---

## ⚖️ Legal & Ethics

### ✅ Allowed
- Testing authorized systems
- Educational purpose
- Security research dengan izin
- Personal learning

### ❌ Illegal
- Unauthorized testing
- Accessing systems tanpa permission
- Violating laws & regulations
- Malicious intent

**Always get explicit permission sebelum testing!**

---

## 📞 Support

- Baca README.md untuk dokumentasi lengkap
- Check `tools/kali_tools.py` untuk source code
- Modify `config.py` untuk custom settings

---

## 🔄 Keyboard Shortcuts

- `Ctrl+C`: Stop current operation (terminal mode)
- `Tab`: Move between tabs
- `Enter`: Run current tool

---

Happy Hunting! 🎯

**Remember: Knowledge adalah power. Use it wisely!**
