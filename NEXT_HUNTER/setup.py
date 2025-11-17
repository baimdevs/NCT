#!/usr/bin/env python3
"""
NEXT HUNTER - Setup Script
Installation dan configuration helper
"""

import subprocess
import sys
import os


def run_command(cmd, description=""):
    """Run shell command"""
    print(f"\n[*] {description}")
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True)
        print(f"[+] {description} - Success!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] {description} - Failed with code {e.returncode}")
        return False
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return False


def check_python_version():
    """Check Python version"""
    version = sys.version_info
    print(f"[*] Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("[!] Python 3.8+ required!")
        return False
    
    print("[+] Python version OK")
    return True


def install_python_packages():
    """Install Python dependencies"""
    print("\n" + "="*50)
    print("Installing Python Dependencies...")
    print("="*50)
    
    return run_command(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        "Installing Python packages"
    )


def install_kali_tools():
    """Install required Kali Linux tools"""
    print("\n" + "="*50)
    print("Installing Kali Linux Tools...")
    print("="*50)
    
    tools = [
        "nmap",
        "whois",
        "dnsutils",
        "gobuster",
        "nikto",
        "sqlmap",
        "aircrack-ng",
        "john",
        "hashcat"
    ]
    
    print("[*] This will install the following tools:")
    for tool in tools:
        print(f"    - {tool}")
    
    response = input("\n[?] Continue with installation? (y/n): ").strip().lower()
    
    if response != 'y':
        print("[*] Skipping Kali tools installation")
        return True
    
    # Update package list
    if not run_command(["sudo", "apt", "update"], "Updating package list"):
        return False
    
    # Install tools
    cmd = ["sudo", "apt", "install", "-y"] + tools
    return run_command(cmd, "Installing Kali tools")


def verify_tools():
    """Verify installed tools"""
    print("\n" + "="*50)
    print("Verifying Tools Installation...")
    print("="*50)
    
    tools = {
        "nmap": "nmap -h",
        "whois": "whois --help",
        "dig": "dig -h",
        "gobuster": "gobuster --help",
    }
    
    available_tools = []
    missing_tools = []
    
    for tool, cmd in tools.items():
        try:
            subprocess.run(cmd.split(), capture_output=True, timeout=5)
            print(f"[+] {tool}: Found")
            available_tools.append(tool)
        except:
            print(f"[-] {tool}: NOT FOUND")
            missing_tools.append(tool)
    
    print(f"\n[*] Available tools: {len(available_tools)}/{len(tools)}")
    
    if missing_tools:
        print(f"\n[!] Missing tools: {', '.join(missing_tools)}")
        print("[*] You can install them later with: sudo apt install <tool-name>")
    
    return len(missing_tools) == 0


def setup_permissions():
    """Setup file permissions"""
    print("\n" + "="*50)
    print("Setting Up Permissions...")
    print("="*50)
    
    try:
        os.chmod("main.py", 0o755)
        print("[+] Made main.py executable")
        return True
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return False


def show_usage():
    """Show usage information"""
    print("\n" + "="*50)
    print("Setup Complete!")
    print("="*50)
    print("\n[*] NEXT HUNTER is ready to use!\n")
    print("[*] To start the application:\n")
    print("    python3 main.py")
    print("\n[*] For WiFi tools, use sudo:\n")
    print("    sudo python3 main.py")
    print("\n[*] For more information, see README.md\n")


def main():
    """Main setup function"""
    print("\n" + "="*50)
    print("NEXT HUNTER - Setup Script")
    print("="*50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python packages
    if not install_python_packages():
        print("[!] Failed to install Python packages")
        sys.exit(1)
    
    # Install Kali tools
    if not install_kali_tools():
        print("[!] Some tools failed to install")
    
    # Verify tools
    verify_tools()
    
    # Setup permissions
    setup_permissions()
    
    # Show usage
    show_usage()
    
    print("[+] Setup completed successfully!")


if __name__ == "__main__":
    main()
