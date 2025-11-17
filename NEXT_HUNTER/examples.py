#!/usr/bin/env python3
"""
NEXT HUNTER - Example Scripts
Contoh penggunaan tools secara programmatic
"""

from tools.kali_tools import NetworkTools, WebTools, SystemTools, WifiTools
from utils import Logger, CommandValidator, SystemInfo, ScanResult

# Initialize logger
logger = Logger(enable_file=True, log_file="next_hunter_example.log")

def example_network_tools():
    """Example: Network Tools"""
    print("\n" + "="*50)
    print("Example 1: Network Tools")
    print("="*50)
    
    net_tools = NetworkTools(output_callback=logger.info)
    
    # Get local IP
    logger.info(f"Local IP: {net_tools.get_local_ip()}")
    
    # Validate input
    test_ip = "192.168.1.1"
    if CommandValidator.validate_ip(test_ip):
        logger.info(f"IP {test_ip} is valid")
    
    # Port check (example only - won't actually run)
    logger.info("To run actual scans, execute from GUI or adjust security settings")


def example_hash_generation():
    """Example: Hash Generation"""
    print("\n" + "="*50)
    print("Example 2: Hash Generation")
    print("="*50)
    
    sys_tools = SystemTools()
    
    test_string = "Hello NEXT HUNTER"
    
    md5_hash = sys_tools.md5_hash(test_string)
    sha256_hash = sys_tools.sha256_hash(test_string)
    
    logger.success(f"MD5({test_string}): {md5_hash}")
    logger.success(f"SHA256({test_string}): {sha256_hash}")


def example_validation():
    """Example: Input Validation"""
    print("\n" + "="*50)
    print("Example 3: Input Validation")
    print("="*50)
    
    # Validate IP
    test_ips = ["192.168.1.1", "256.256.256.256", "10.0.0.1"]
    for ip in test_ips:
        result = CommandValidator.validate_ip(ip)
        logger.info(f"IP {ip}: {result}")
    
    # Validate URL
    test_urls = ["http://example.com", "https://google.com", "invalid.url"]
    for url in test_urls:
        result = CommandValidator.validate_url(url)
        logger.info(f"URL {url}: {result}")
    
    # Validate Domain
    test_domains = ["example.com", "google.com", "invalid"]
    for domain in test_domains:
        result = CommandValidator.validate_domain(domain)
        logger.info(f"Domain {domain}: {result}")


def example_system_info():
    """Example: System Information"""
    print("\n" + "="*50)
    print("Example 4: System Information")
    print("="*50)
    
    # Get network interfaces
    interfaces = SystemInfo.get_interface_list()
    logger.info(f"Network Interfaces: {interfaces}")
    
    # Get available wordlists
    wordlists = SystemInfo.get_wordlist_suggestions()
    logger.success(f"Available Wordlists:")
    for wordlist in wordlists:
        logger.success(f"  - {wordlist}")
    
    # Check if root
    is_root = SystemInfo.is_root()
    logger.info(f"Running as root: {is_root}")


def example_scan_result():
    """Example: Scan Result Storage"""
    print("\n" + "="*50)
    print("Example 5: Scan Result Storage")
    print("="*50)
    
    # Create scan result
    result = ScanResult("nmap", "192.168.1.1", status="completed")
    
    # Add results
    result.add_result("Port 22/tcp: OPEN (SSH)")
    result.add_result("Port 80/tcp: OPEN (HTTP)")
    result.add_result("Port 443/tcp: OPEN (HTTPS)")
    
    # Display result
    logger.success(f"Tool: {result.tool_name}")
    logger.success(f"Target: {result.target}")
    logger.success(f"Status: {result.status}")
    logger.success(f"Results:")
    for r in result.results:
        logger.success(f"  - {r}")
    
    # Save to JSON
    result.save_to_file("scan_result.json")
    logger.success("Result saved to scan_result.json")


def example_sanitization():
    """Example: Input Sanitization"""
    print("\n" + "="*50)
    print("Example 6: Input Sanitization")
    print("="*50)
    
    dangerous_inputs = [
        "normal_input; rm -rf /",
        "injection$(whoami)",
        "test|cat /etc/passwd",
        "`id`",
        "normal_input"
    ]
    
    for inp in dangerous_inputs:
        clean = CommandValidator.sanitize_input(inp)
        logger.info(f"Original: {inp}")
        logger.info(f"Sanitized: {clean}")
        print()


def example_logging():
    """Example: Logging"""
    print("\n" + "="*50)
    print("Example 7: Logging Features")
    print("="*50)
    
    logger.info("This is an info message")
    logger.success("This is a success message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    logger.success("All messages have been logged to: next_hunter_example.log")


def main():
    """Run all examples"""
    print("\n")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         NEXT HUNTER - Example Scripts                       ║")
    print("║     Demonstration of NEXT HUNTER Core Functionality        ║")
    print("╚════════════════════════════════════════════════════════════╝")
    
    try:
        example_network_tools()
        example_hash_generation()
        example_validation()
        example_system_info()
        example_scan_result()
        example_sanitization()
        example_logging()
        
        print("\n" + "="*50)
        print("All examples completed successfully!")
        print("="*50)
        print("\nCheck 'next_hunter_example.log' for detailed logs")
        print("Run 'python3 main.py' to start the GUI application\n")
        
    except Exception as e:
        logger.error(f"Error running examples: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
