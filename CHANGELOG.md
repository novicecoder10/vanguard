# Changelog

All notable changes to Vanguard EDR will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-12

### Added
- Initial release of Vanguard EDR - Full-stack Endpoint Detection & Response system
- **Vanguard Agent**: Real-time Windows threat detection and active remediation
  - Sysmon event monitoring and correlation
  - CNN-LSTM deep learning behavioral classification
  - Ransomware detection via file extension signatures
  - Mass file-operation rate-based detection
  - Process termination and binary deletion (active remediation)
  - Real-time file watchdog with signature updates from GitHub
  - CustomTkinter GUI with live dashboard and real-time monitoring
  - Windows Service deployment mode (headless operation)
  
- **Vanguard Server**: Centralized security console
  - Flask-based REST API for log aggregation
  - Server-Sent Events (SSE) for real-time dashboard updates
  - MITRE ATT&CK technique mapping and visualization
  - Multi-agent support with per-agent filtering
  - SQLite-based persistence
  
- **Live API-Hook Behavioral Detection** (Optional)
  - Frida-based Win32 API call instrumentation
  - Real-time registry access monitoring
  - Spawn-gating and reactive attach modes
  - Per-PID API call throttling

### Security & Stability Fixes
- Fix 2: Path resolution (script-relative file paths)
- Fix 4: Error message clarity (distinct import/load error handling)
- Fix 6: Mitigation failure tracking
- Fix 9: TensorFlow 2.21.0 + Keras 3 compatibility
- Fix 11: Signature specificity and model narrow-vocabulary exposure
- Fix 11b-d: Memory leak fixes (unbounded dict/set growth)
- Fix 12a: Self-toolchain protection (Frida helper detection)
- Fix 12b: Protected process names allowlist
- Fix 13: Registry value name qualification for persistence detection
- Database: WAL journal mode for both agent and server DBs
- Self-protection: Agent avoids detecting/killing its own processes

### Documentation
- Complete architecture documentation (ARCHITECTURE.md)
- API specification (API_SPECIFICATION.md)
- Installation and usage guide (DOCUMENTATION.md)
- End-to-end test plan (END_TO_END_TEST_PLAN.md)
- Windows Fix Log with technical details (WINDOWS_FIX_LOG.md)
- Project instructions (CLAUDE.md)

### Known Limitations
- No authentication on ingestion endpoints (trusted network only)
- Flask runs in debug mode (not production-hardened)
- CNN-LSTM model requires TensorFlow installation
- Frida-based API hooking Windows/Administrator only
- False-positive risk on ordinary software (signature specificity needed)
- No graduated alert severity scoring

## Future Roadmap

### Planned for v1.1
- [ ] Graduated alert severity scoring
- [ ] Persistent configuration (config file instead of hardcoded)
- [ ] Enhanced UI with theme support
- [ ] Additional behavioral signatures (T1059, T1547, T1547.013)
- [ ] Export functionality (CSV, JSON reports)

### Planned for v2.0
- [ ] ClickHouse migration for scalable multi-agent deployments
- [ ] Web-based agent management console
- [ ] Role-based access control (RBAC)
- [ ] TLS/mTLS encryption for agent-server communication
- [ ] API authentication (API keys, OAuth)
- [ ] Cloud deployment support (Azure Sentinel integration)
- [ ] Real malware model training pipeline
- [ ] Advanced behavioral ML with attention mechanisms

---

## Installation

### Agent (Windows)
```bash
pip install vanguard-edr
python -m vanguard_agent.main_gui
```

### Server
```bash
pip install vanguard-edr
python -m vanguard_server.server
```

### Optional (Frida-based API Hooking)
```bash
pip install vanguard-edr[frida]
```

## Contributing

Contributions are welcome! Please note that this is a research/prototype project.

## License

See LICENSE file for details.

## Security & Disclaimer

This is a prototype/research EDR system, not hardened production software. 
See ARCHITECTURE.md § Security notes for known gaps before deploying to production.
