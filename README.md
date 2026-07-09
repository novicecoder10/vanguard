# Vanguard EDR - Full-Stack Endpoint Detection & Response System

Vanguard is a lightweight, full-stack Endpoint Detection and Response (EDR) prototype designed to monitor Win32 system behaviors in real-time, execute deep learning threat classifications, apply active incident mitigation, and aggregate security alerts into a centralized console.

The system consists of two main components:
1.  **Vanguard EDR Agent Client (`vanguard_agent`):** A Win32 monitoring client with an integrated file watchdog, a CNN-LSTM deep learning behavior classifier, active process termination, and incident remediation handlers.
2.  **Vanguard Central Security Console (`vanguard_server`):** A centralized Flask server that aggregates and visualizes security logs and threat intelligence synchronized from multiple endpoints in real-time.

---

## Technical Architecture

```
                                      ┌────────────────────────────────┐
                                      │    Central Security Console    │
                                      │       (Flask Server :5000)     │
                                      └───────────────▲────────────────┘
                                                      │
                                           (JSON Post Sync Client)
                                                      │
 ┌────────────────────────────────────────────────────┴────────────────────────────────────────────────────┐
 │  Vanguard EDR Agent (Client Endpoint)                                                                   │
 │                                                                                                         │
 │  ┌───────────────────────┐      ┌─────────────────────────┐      ┌──────────────────┐      ┌─────────┐  │
 │  │   Sysmon Event Log    │ ───> │  Python Logging Sensor  │ ───> │  Local SQLite DB │ ───> │ GUI Log │  │
 │  │ (Microsoft-Windows)   │      │   (Win32 EvtSubscribe)  │      │  (vanguard_logs) │      │ Console │  │
 │  └───────────────────────┘      └─────────────────────────┘      └──────────────────┘      └─────────┘  │
 │                                              │                                                          │
 │                                              ▼                                                          │
 │                                 ┌─────────────────────────┐                                             │
 │                                 │  CNN-LSTM API Sequence  │                                             │
 │                                 │        Classifier       │                                             │
 │                                 └────────────┬────────────┘                                             │
 │                                              │                                                          │
 │                                        (Malicious flag)                                                 │
 │                                              ▼                                                          │
 │                                 ┌─────────────────────────┐                                             │
 │                                 │    Active Mitigation    │ ───> (Terminate PID & Delete Binary)        │
 │                                 │         Daemon          │                                             │
 │                                 └─────────────────────────┘                                             │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
vanguard/
├── vanguard_agent/                # Endpoint Agent Client Application
│   ├── cpp_sources/               # Low-level Win32 monitoring C++ source files
│   ├── database.py                # Local SQLite log indexer handler
│   ├── extension_scanner.py       # Helper checking target files for signature matches
│   ├── main_gui.py                # Thread-safe CustomTkinter visualization dashboard
│   ├── ml_analyzer.py             # Keras CNN-LSTM sequence classification engine
│   ├── sync_client.py             # Background local-to-central db logs synchronizer
│   ├── sysmon_monitor.py          # Sysmon event log subscriber thread
│   ├── ransomware_extensions.json # Live cached extension list (updates every 4h)
│   ├── README.md                  # Detailed Client Agent documentation
│   └── Vanguard_Windows_Setup.txt # Step-by-step Windows deployment & testing guide
└── vanguard_server/               # Centralized Server Application
    ├── server.py                  # Flask logging collector API & Web Server
    ├── templates/                 # Frontend dashboard views
    └── README.md                  # Server deployment documentation
```

---

## Quick Start Guide

### 1. Set Up the Central Server
1. Navigate to the server folder:
   ```bash
   cd vanguard_server
   ```
2. Install dependencies:
   ```bash
   pip install flask
   ```
3. Start the console server:
   ```bash
   python server.py
   ```
   *The dashboard will be hosted at `http://127.0.0.1:5000`.*

### 2. Set Up the EDR Agent (Windows Client)
1. Install Microsoft Sysmon by executing this in an Administrator command prompt:
   ```cmd
   sysmon.exe -i -n
   ```
2. Navigate to the agent folder:
   ```cmd
   cd vanguard_agent
   ```
3. Install dependencies:
   ```cmd
   pip install customtkinter pywin32 tensorflow numpy
   ```
4. Run the EDR agent client console:
   ```cmd
   python main_gui.py
   ```
   *Verify that the status bar shows green indicators for active Sysmon and Central Server connections.*

---

## Threat Detection Features
*   **Always-On File Watchdog:** Instantly quarantines (deletes) newly created files matching 100+ known ransomware extension signatures in target folders.
*   **Active Remediation:** When malicious behavior is detected, the agent automatically kills the target process ID (`taskkill` / `kill -9`) and erases the binary payload from disk.
*   **Deep Learning Classifier:** Evaluates sliding windows of 100 sequential system API logs via a CNN-LSTM network to detect execution anomalies.
*   **Central Logs Sync:** Retains logs locally in a serverless SQLite cache when offline and syncs them to the dashboard as soon as network connection is restored.
