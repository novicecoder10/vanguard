# Vanguard EDR - Endpoint Detection & Response Agent

Vanguard EDR is an advanced, lightweight Endpoint Detection and Response client designed to monitor Win32 system behaviors in real-time, execute deep learning threat sequence classifications, and apply active incident mitigation. 

This agent integrates with a centralized security console to aggregate threat intelligence across network endpoints.

---

## Key Features

1.  **Real-Time Sysmon Auditing:** Monitors system process launches, network connections, and file writes by subscribing to native Windows Sysmon event logs.
2.  **Always-On File Watchdog:** Continuously monitors targeted directories (e.g., Desktop or Documents) for newly created files matching 100+ known ransomware extension signatures, auto-quarantining (deleting) threats immediately.
3.  **Active Mitigation & Incident Response:** Automatically terminates malicious process PIDs and erases target threat binaries from disk to block persistence.
4.  **CNN-LSTM Behavioral Classifier:** Loads a pre-trained Keras neural network model to evaluate a sliding window of 100 sequential API calls mapped from Sysmon logs.
5.  **MITRE ATT&CK & CVE Mapping:** Categorizes threat alerts into MITRE techniques (e.g., Process Hollowing `T1055.012`, Ransomware `T1486`) and links them to relevant CVEs (e.g., WannaCry `CVE-2017-0144`).
6.  **Dynamic Signature Database Updates:** Spawns a background thread (`SignatureDatabaseUpdater`) that runs every 4 hours, fetching the latest signatures from an open-source ransomware database and caching them in `ransomware_extensions.json` for offline resilience.

---

## C++ Source Code Directory
For research and grading purposes, the original raw C++ files for the Sysmon Win32 Event Log parser and extension scanners are preserved under the [cpp_sources/](file:///home/gautamkarat/.gemini/antigravity/scratch/vanguard_agent/cpp_sources/) folder.

---

## Windows Setup Guide

### 1. Install Microsoft Sysmon
Vanguard captures process creations and registry/network operations using Sysmon events.
1. Download **Sysmon** from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Open **Command Prompt** as **Administrator**.
3. Navigate to the extracted folder and run the installer:
   ```cmd
   sysmon.exe -i -n
   ```

### 2. Install Python Dependencies
Ensure Python 3.9 - 3.11 is installed on Windows and added to your System PATH.
1. Open a Command Prompt in this folder and install dependencies:
   ```cmd
   pip install customtkinter pywin32 tensorflow numpy
   ```

### 3. Place the CNN-LSTM Model File
1. Download your trained weights file `behavioral-malware-detection-based-on-api-calls_model.h5` from your [Kaggle Notebook Output](https://www.kaggle.com/code/gautamkarat/behavioral-malware-detection-with-cnn-lstm).
2. Place the file inside the root of this `vanguard_agent` directory (right next to `main_gui.py`).

---

## Running the Client
Launch the GUI console:
```cmd
python main_gui.py
```
*You will see the console log output: **`Vanguard CNN-LSTM model loaded successfully.`** indicating the deep learning network is fully loaded.*

---

## Testing Threat Interception & Mitigation

### Test Case A: Real-Time File Watchdog (Always-On Protection)
1. In the GUI, go to the **Ransomware Scanner** tab.
2. In the "Always-On Background Protection" section, type or select a folder path and click **Apply Watchdog to Selected Folder**.
3. Create a blank text file inside that folder and rename it to **`test.cerber`** or **`invoice.locky`**.
4. **What happens:** The background watchdog deletes the file, logs a `Ransomware Watchdog` alert, and triggers an incident response warning in the GUI.

### Test Case B: Suspicious Process Mitigation (Terminate & Delete)
1. Open File Explorer and type **`%TEMP%`** in the address bar.
2. Copy **`notepad.exe`** from `C:\Windows\System32\` and paste it into this Temp folder.
3. Rename it to **`vanguard_test.exe`**.
4. Double-click **`vanguard_test.exe`** to run it.
5. **What happens:** The Sysmon listener captures the launch. Vanguard immediately terminates the process, deletes `vanguard_test.exe` from disk, logs a mitigation history entry, and syncs the log to the central Flask server.

### Test Case C: Sandbox XML Analyzer (Grading Demo)
1. Go to the **Threat Intelligence** tab in the GUI.
2. Under "Manual Analysis Sandbox", click **Browse XML** and select `api.xml`.
3. Click **Analyze Sandbox Log**.
4. **What happens:** Vanguard parses the XML, matches the dissertation DLL hooking sequence, and flags it as malicious (T1486 / CVE-2019-11510).
