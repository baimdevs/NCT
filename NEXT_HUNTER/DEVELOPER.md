# NEXT HUNTER - Developer Documentation

## 📚 Architecture Overview

```
NEXT HUNTER/
├── main.py                 # Entry point
├── tools/
│   ├── __init__.py
│   └── kali_tools.py      # Tool implementations
├── ui/
│   ├── __init__.py
│   └── main_window.py     # GUI components
├── utils.py               # Utility functions
├── config.py              # Configuration
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🛠️ Core Modules

### 1. tools/kali_tools.py

Main module containing tool implementations:

#### NetworkTools
```python
from tools.kali_tools import NetworkTools

# Initialize
net = NetworkTools(output_callback=print)

# Methods
net.nmap_scan(target="192.168.1.1", scan_type="-sV")
net.dns_enumeration(domain="example.com")
net.whois_lookup(domain="example.com")
net.port_check(host="192.168.1.1", port=80)
net.get_local_ip()
```

#### WebTools
```python
from tools.kali_tools import WebTools

web = WebTools(output_callback=print)

# Methods
web.gobuster_scan(url="http://example.com", wordlist="/path/to/wordlist.txt")
web.nikto_scan(url="http://example.com")
web.sqlmap_test(url="http://example.com/page?id=1", method="GET")
```

#### SystemTools
```python
from tools.kali_tools import SystemTools

sys = SystemTools(output_callback=print)

# Methods
sys.hashcat_crack(hash_file="hashes.txt", wordlist="rockyou.txt", hash_type=0)
sys.john_crack(hash_file="hashes.txt", wordlist="rockyou.txt")
sys.md5_hash(text="password123")
sys.sha256_hash(text="password123")
```

#### WifiTools
```python
from tools.kali_tools import WifiTools

wifi = WifiTools(output_callback=print)

# Methods
wifi.airmon_start(interface="wlan0")
wifi.airodump_scan(interface="wlan0mon")
```

---

### 2. ui/main_window.py

GUI implementation using PyQt5

#### Key Classes
- `NextHunterGUI`: Main application window
- `WorkerThread`: Background execution thread

#### Methods
```python
# Create tabs
create_network_tab()    # Network tools tab
create_web_tab()        # Web tools tab
create_system_tab()     # System tools tab
create_wifi_tab()       # WiFi tools tab
create_utilities_tab()  # Utilities tab

# Tool runners
run_nmap_scan()
run_dns_enum()
run_gobuster()
run_sqlmap()
run_john()
run_hashcat()
```

---

### 3. utils.py

Utility classes dan functions

#### Logger
```python
from utils import Logger

logger = Logger(enable_file=True, log_file="app.log")
logger.info("Information message")
logger.warning("Warning message")
logger.error("Error message")
logger.success("Success message")
```

#### CommandValidator
```python
from utils import CommandValidator

CommandValidator.validate_ip("192.168.1.1")      # True/False
CommandValidator.validate_port(8080)              # True/False
CommandValidator.validate_url("http://...")       # True/False
CommandValidator.validate_domain("example.com")   # True/False
CommandValidator.validate_file_path("/path/file") # True/False
CommandValidator.sanitize_input(user_input)       # Clean input
```

#### SystemInfo
```python
from utils import SystemInfo

interfaces = SystemInfo.get_interface_list()
wordlists = SystemInfo.get_wordlist_suggestions()
is_root = SystemInfo.is_root()
```

#### ScanResult
```python
from utils import ScanResult

result = ScanResult("nmap", "192.168.1.1")
result.add_result("Port 80 open")
result.set_status("completed")
result.save_to_file("result.json")
```

#### ResultExporter
```python
from utils import ResultExporter

ResultExporter.export_json(results, "output.json")
ResultExporter.export_text(results, "output.txt")
ResultExporter.export_csv(results, "output.csv")
```

---

## 🔌 Creating Custom Tools

### Adding New Tool

1. **Add class di tools/kali_tools.py:**
```python
class CustomTools:
    def __init__(self, output_callback=None):
        self.output_callback = output_callback
    
    def log_output(self, message):
        if self.output_callback:
            self.output_callback(message)
    
    def custom_tool(self, arg1, arg2):
        self.log_output("[*] Running custom tool...")
        # Implementation
        self.log_output("[+] Done!")
```

2. **Add UI in ui/main_window.py:**
```python
def create_custom_tab(self):
    widget = QWidget()
    layout = QVBoxLayout()
    
    # Add controls
    self.custom_input = QLineEdit()
    custom_btn = QPushButton("Run Custom Tool")
    custom_btn.clicked.connect(self.run_custom_tool)
    
    # Add to layout
    layout.addWidget(QLabel("Input:"))
    layout.addWidget(self.custom_input)
    layout.addWidget(custom_btn)
    
    self.custom_output = QTextEdit()
    layout.addWidget(self.custom_output)
    
    widget.setLayout(layout)
    return widget
```

3. **Add method untuk run tool:**
```python
def run_custom_tool(self):
    input_value = self.custom_input.text().strip()
    self.custom_output.append("[*] Starting custom tool...\n")
    
    from tools.kali_tools import CustomTools
    custom = CustomTools(self.custom_output.append)
    custom.custom_tool(input_value)
```

---

## 🎨 GUI Customization

### Change Theme Colors
Edit `get_stylesheet()` method di `ui/main_window.py`:

```python
QMainWindow {
    background-color: #1e1e1e;  # Background color
}
QPushButton {
    background-color: #00ff00;  # Button color
    color: #1e1e1e;             # Text color
}
```

### Add New Tab
```python
self.tabs.addTab(self.create_custom_tab(), "CUSTOM")
```

---

## ⚙️ Configuration

Modify `config.py`:

```python
# Timeouts
NMAP_TIMEOUT = 300
NIKTO_TIMEOUT = 300

# Default paths
DEFAULT_GOBUSTER_WORDLIST = "/path/to/wordlist.txt"

# Colors
COLOR_SUCCESS = "#00ff00"
COLOR_ERROR = "#ff0000"
```

---

## 🧪 Testing

### Unit Test Example
```python
from tools.kali_tools import SystemTools

def test_md5_hash():
    sys = SystemTools()
    result = sys.md5_hash("test")
    assert result == "098f6bcd4621d373cade4e832627b4f6"
    print("[+] MD5 hash test passed")

def test_validate_ip():
    from utils import CommandValidator
    assert CommandValidator.validate_ip("192.168.1.1") == True
    assert CommandValidator.validate_ip("999.999.999.999") == False
    print("[+] IP validation test passed")
```

---

## 🔐 Security Best Practices

1. **Validate all user inputs**
```python
if not CommandValidator.validate_ip(user_input):
    raise ValueError("Invalid IP address")
```

2. **Sanitize dangerous characters**
```python
clean_input = CommandValidator.sanitize_input(user_input)
```

3. **Check permissions**
```python
if SystemInfo.is_root():
    # Can run WiFi tools
    pass
```

4. **Handle exceptions**
```python
try:
    result = tool.run(arg)
except Exception as e:
    logger.error(f"Tool failed: {str(e)}")
```

---

## 📝 API Reference

### NetworkTools

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| nmap_scan | target, scan_type | bool | NMAP network scan |
| dns_enumeration | domain | bool | DNS lookup |
| whois_lookup | domain | bool | WHOIS information |
| port_check | host, port, timeout | bool | Port connectivity |
| get_local_ip | - | str | Local IP address |

### WebTools

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| gobuster_scan | url, wordlist | bool | Directory enumeration |
| nikto_scan | url | bool | Web vulnerability scan |
| sqlmap_test | url, method | bool | SQL injection test |

### SystemTools

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| hashcat_crack | hash_file, wordlist, hash_type | bool | Hashcat cracking |
| john_crack | hash_file, wordlist | bool | John cracking |
| md5_hash | text | str | MD5 hash |
| sha256_hash | text | str | SHA256 hash |

---

## 🚀 Performance Tips

1. **Use threading untuk long operations**
```python
from PyQt5.QtCore import QThread

thread = WorkerThread(self.tool.run, args)
thread.output_signal.connect(self.output_text.append)
thread.start()
```

2. **Set appropriate timeouts**
```python
subprocess.run(cmd, timeout=300)  # 5 minutes
```

3. **Buffer large outputs**
```python
output_lines = []
for line in result.split('\n'):
    if line.strip():
        output_lines.append(line)
```

---

## 📚 Additional Resources

- [PyQt5 Documentation](https://doc.qt.io/qtforpython/)
- [Kali Linux Tools](https://www.kali.org/tools/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

---

**Happy coding! 💻**
