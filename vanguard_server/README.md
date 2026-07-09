# Vanguard Centralized EDR Server Console

The Vanguard Server Console is a centralized security operations receiver designed to aggregate logs, threat feeds, and mitigation alerts pushed from active Vanguard EDR endpoint agents.

It hosts a web-based threat analysis console built with a dark slate layout, live metric counters, and security feed grids.

---

## Features

1.  **Central Logs Receiver:** Exposes endpoints `/api/logs` and `/api/alerts` to receive HTTP POST requests from multiple client agents.
2.  **Central Security Database:** Stores consolidated event data from all devices inside a central SQLite database (`central_logs.db`).
3.  **Operations Dashboard:** Serves an interactive HTML dashboard featuring:
    *   **Live Metrics:** Aggregate count of total monitored endpoints, log records, and high-threat alerts.
    *   **Consolidated Live Feeds:** Real-time event log stream showing host, PID, image name, and status across all endpoints.
    *   **Remediation log:** Grouped alert stream highlighting active process terminations, watchdog file deletions, and MITRE ATT&CK technique IDs.

---

## Windows Setup & Execution

### 1. Install Dependencies
Ensure Python 3.9+ is installed. Open Command Prompt inside this folder and run:
```cmd
pip install flask
```

### 2. Start the Server
Run the Flask API script:
```cmd
python server.py
```
*The server will start hosting on **`http://127.0.0.1:5000`**.*

---

## Central Dashboard Console
1. Open your web browser on any machine in the subnet.
2. Navigate to: **`http://localhost:5000`** (or use the server's local IP address if connecting from remote endpoints).
3. The dashboard will automatically update as EDR agents transmit logs and incident mitigations.
