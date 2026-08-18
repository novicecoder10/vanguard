# Vanguard EDR - Package Information

## Package Details

**Package Name:** `vanguard-edr`  
**Version:** 1.0.0  
**License:** MIT  
**Author:** Gautam Karat  
**Repository:** https://github.com/novicecoder10/vanguard  

## Installation Methods

### Method 1: From Source (Development)
```bash
git clone https://github.com/novicecoder10/vanguard.git
cd vanguard
pip install -e .
```

### Method 2: From GitHub with Pip
```bash
pip install git+https://github.com/novicecoder10/vanguard.git
```

### Method 3: Development with Optional Dependencies
```bash
pip install -e ".[dev,frida]"
```

## Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| flask | ≥2.0.0 | Central server web framework |
| customtkinter | ≥5.0.0 | Agent GUI components |
| pywin32 | ≥305 | Windows API access (Sysmon) |
| tensorflow | ≥2.4.0 | Deep learning framework |
| tf-keras | ≥2.11.0 | Keras 2 compatibility layer |
| numpy | ≥1.20.0 | Numerical computing |
| watchdog | ≥2.1.0 | File system event monitoring |

## Optional Dependencies

### For API Hooking (Frida Instrumentation)
```bash
pip install vanguard-edr[frida]
```

| Package | Version | Purpose |
|---------|---------|---------|
| frida | ≥15.0.0 | Dynamic instrumentation engine |
| frida-tools | ≥11.0.0 | Frida CLI tools |

**Note:** Frida support requires Administrator privileges and Windows platform.

### For Development
```bash
pip install vanguard-edr[dev]
```

| Package | Version | Purpose |
|---------|---------|---------|
| pytest | ≥6.0 | Testing framework |
| black | ≥21.0 | Code formatter |
| flake8 | ≥3.9.0 | Linter |
| mypy | ≥0.910 | Type checker |

## System Requirements

### Agent (Windows)
- **OS:** Windows 7 SP1+ (tested on Windows 10/11)
- **Python:** 3.9, 3.10, or 3.11
- **RAM:** Minimum 2GB (4GB recommended)
- **Disk:** 500MB for installation + model weights (13.5MB)
- **Privileges:** Administrator (for Sysmon, file deletion, process termination)
- **Dependencies:**
  - Microsoft Sysmon (optional but recommended)
  - TensorFlow 2.4.0+ (included in pip install)

### Server (Linux/Windows/macOS)
- **OS:** Any (Linux, Windows, macOS)
- **Python:** 3.9, 3.10, or 3.11
- **RAM:** Minimum 1GB
- **Disk:** 100MB for installation + database
- **Port:** 5000 (configurable)
- **Network:** Accessible from agent machines

## Package Structure

```
vanguard-edr/
├── setup.py                           # Package setup configuration
├── pyproject.toml                     # Modern project metadata
├── MANIFEST.in                        # Distribution file inclusion
├── LICENSE                            # MIT License
├── README.md                          # Project overview
├── CHANGELOG.md                       # Version history
├── PACKAGES.md                        # This file
│
├── vanguard_agent/                    # Agent package
│   ├── __init__.py
│   ├── main_gui.py                    # Main entry point (GUI)
│   ├── vanguard_service.py            # Service entry point (headless)
│   ├── sysmon_monitor.py              # Sysmon event monitoring
│   ├── extension_scanner.py           # File signature scanning
│   ├── ml_analyzer.py                 # ML classification
│   ├── database.py                    # SQLite persistence
│   ├── sync_client.py                 # Server synchronization
│   ├── api_hook_monitor.py            # Frida API hooking (optional)
│   ├── frida_hook_selftest.py         # Frida validation
│   ├── ransomware_extensions.json     # Signature database
│   ├── behavioral-malware-detection-based-on-api-calls_model.h5  # CNN-LSTM model
│   ├── icon.png                       # Application icon
│   ├── icon.ico                       # Windows icon
│   └── README.md                      # Agent documentation
│
├── vanguard_server/                   # Server package
│   ├── __init__.py
│   ├── server.py                      # Flask server
│   └── templates/
│       └── index.html                 # Dashboard UI
│       └── README.md                  # Server documentation
│
└── docs/                              # Documentation
    ├── ARCHITECTURE.md                # System design
    ├── API_SPECIFICATION.md           # API documentation
    ├── DOCUMENTATION.md               # User guide
    ├── END_TO_END_TEST_PLAN.md        # Testing guide
    └── CLICKHOUSE_MIGRATION_PLAN.md   # Future scalability
```

## Module Entry Points

### Agent CLI
```bash
# GUI mode (default)
python -m vanguard_agent.main_gui

# Service mode (headless)
python -m vanguard_agent.vanguard_service

# Frida validation (optional)
python -m vanguard_agent.frida_hook_selftest
```

### Server CLI
```bash
python -m vanguard_server.server
```

## Environment Variables

```bash
# TensorFlow Configuration
export TF_USE_LEGACY_KERAS=1          # Use Keras 2 compatibility
export TF_CPP_MIN_LOG_LEVEL=2         # Reduce TensorFlow verbosity

# Flask Configuration (server)
export FLASK_ENV=production
export FLASK_DEBUG=0

# Agent Configuration
export VANGUARD_SERVER_URL=http://localhost:5000
export VANGUARD_LOG_LEVEL=INFO
```

## Dependency Resolution

The package uses standard Python dependency resolution:

```bash
# Show dependency tree
pip install pipdeptree
pipdeptree -p vanguard-edr

# Update dependencies
pip install --upgrade vanguard-edr

# Pin versions for reproducibility
pip install vanguard-edr==1.0.0
```

## Build & Distribution

### Build Source Distribution
```bash
python -m build
```

### Build Wheel
```bash
pip install wheel
python setup.py bdist_wheel
```

### Upload to PyPI (When Ready)
```bash
twine upload dist/*
```

## Compatibility

| Python | Supported | Tested |
|--------|-----------|--------|
| 3.8 | ❌ | ❌ |
| 3.9 | ✅ | ✅ |
| 3.10 | ✅ | ✅ |
| 3.11 | ✅ | ✅ |
| 3.12+ | ⚠️ | ❌ |

## Platform Support

| OS | Agent | Server | Status |
|----|-------|--------|--------|
| Windows | ✅ Full | ✅ Full | Production-ready |
| Linux | ⚠️ Limited | ✅ Full | Development/Server only |
| macOS | ⚠️ Limited | ✅ Full | Development/Server only |

## Security Notes

- No external dependencies with known CVEs (as of v1.0.0)
- TensorFlow model downloaded once during installation
- All communications should use HTTPS in production (currently HTTP)
- Frida requires Administrator privileges

## Support & Documentation

- **Issues:** https://github.com/novicecoder10/vanguard/issues
- **Discussions:** https://github.com/novicecoder10/vanguard/discussions
- **Documentation:** See `docs/` folder
- **Changelog:** See `CHANGELOG.md`

## Contributing

See `CONTRIBUTING.md` (if available) or open an issue to discuss changes.

## License

MIT License - See `LICENSE` file for details.
