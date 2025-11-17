#!/bin/bash

# NEXT HUNTER - Installation Script
# Automated installation untuk Kali Linux

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         NEXT HUNTER - Installation Script                   ║"
echo "║     Advanced Kali Linux Tools Collection with GUI           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on Linux
if [[ ! "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[!] This script requires Linux OS"
    exit 1
fi

# Check for Python3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Installing..."
    sudo apt update
    sudo apt install -y python3 python3-pip
fi

echo "[+] Python3 found: $(python3 --version)"
echo ""

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 not found. Installing..."
    sudo apt install -y python3-pip
fi

echo "[+] pip3 found"
echo ""

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[!] Failed to install Python dependencies"
    exit 1
fi

echo "[+] Python dependencies installed successfully"
echo ""

# Install Kali Linux tools
echo "[*] Installing Kali Linux tools..."
echo "[*] This requires sudo access"
echo ""

TOOLS=(
    "nmap"
    "whois"
    "dnsutils"
    "gobuster"
    "nikto"
    "sqlmap"
    "aircrack-ng"
    "john"
    "hashcat"
    "dig"
)

echo "[?] Install the following tools? (y/n)"
echo ""
for tool in "${TOOLS[@]}"; do
    echo "    - $tool"
done
echo ""

read -p "[?] Continue? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Updating package list..."
    sudo apt update
    
    echo "[*] Installing tools..."
    sudo apt install -y "${TOOLS[@]}"
    
    if [ $? -eq 0 ]; then
        echo "[+] All tools installed successfully!"
    else
        echo "[!] Some tools failed to install"
        echo "[*] You can install them manually with: sudo apt install <tool-name>"
    fi
else
    echo "[*] Skipping tool installation"
    echo "[*] You can install them later with: sudo apt install <tool-name>"
fi

echo ""

# Make scripts executable
echo "[*] Setting permissions..."
chmod +x main.py
chmod +x setup.py
chmod +x install.sh
echo "[+] Permissions set"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Installation Complete!                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] To start NEXT HUNTER:"
echo ""
echo "    python3 main.py"
echo ""
echo "[*] For WiFi tools, use sudo:"
echo ""
echo "    sudo python3 main.py"
echo ""
echo "[*] For more information, see README.md"
echo ""
