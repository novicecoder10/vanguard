import os
import sys
import time
import datetime
import threading
import re
import signal
from database import insert_log, insert_alert

# Cleaned: Removed simulated demo rules like Weather.exe and PING.exe.
# Only keeping generic suspicious patterns like executing from Temp directory or known ransomware paths.
SUSPICIOUS_PATHS = [
    r"\\Temp\\",  # executing from Windows Temp directory is a common malware indicator
    r"/tmp/",     # Temp dir on Unix
    r"\.cerber$", # ransomware files
    r"\.locky$"
]

def remediate_malicious_process(image_path, pid, db_path, alert_callback=None):
    """Active Response: Terminates process, deletes its binary file, and logs mitigation."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # 1. Terminate process
    term_msg = ""
    if pid and pid != "N/A" and str(pid).isdigit():
        pid_int = int(pid)
        try:
            if sys.platform == "win32":
                # Force kill on Windows
                os.system(f"taskkill /F /PID {pid_int}")
            else:
                # Force kill on Unix/Linux
                os.kill(pid_int, signal.SIGKILL)
            term_msg = f"Terminated malicious PID {pid_int}."
        except Exception as e:
            term_msg = f"Failed to terminate PID {pid_int}: {e}."
    else:
        term_msg = "No active process ID found for termination."

    # 2. Delete threat executable binary from system
    del_msg = ""
    if image_path and image_path != "Unknown" and os.path.exists(image_path):
        try:
            os.remove(image_path)
            del_msg = f"Deleted threat executable: {image_path}."
        except Exception as e:
            del_msg = f"Failed to delete file: {image_path} ({e})."
    else:
        del_msg = f"Threat executable file not found at path: {image_path}."

    # 3. Log Mitigation alert to database
    mitigation_summary = f"Mitigation Action Taken: {term_msg} {del_msg}"
    insert_alert("Incident Response", mitigation_summary, 5, timestamp, db_path)
    
    if alert_callback:
        alert_callback(mitigation_summary, 5, timestamp)
        
    print(mitigation_summary)
    return mitigation_summary


class SysmonMonitor(threading.Thread):
    def __init__(self, db_path="vanguard_logs.db", event_callback=None, alert_callback=None):
        super().__init__()
        self.db_path = db_path
        self.event_callback = event_callback  # Callback to notify UI of new event
        self.alert_callback = alert_callback  # Callback to notify UI of new alert
        self.running = False
        self.daemon = True

    def run(self):
        self.running = True
        if sys.platform == "win32":
            self._run_windows()
        else:
            self._run_simulated()

    def stop(self):
        self.running = False

    def _run_windows(self):
        """Monitors Windows Sysmon events in real-time."""
        try:
            import win32evtlog
            import win32event
            import win32con
        except ImportError:
            print("win32evtlog not installed. Falling back to simulation.")
            self._run_simulated()
            return

        server_path = None  # Local computer
        channel_path = "Microsoft-Windows-Sysmon/Operational"
        query = "*"  # Get all events
        
        event_handle = win32event.CreateEvent(None, 0, 0, None)
        
        try:
            subscription = win32evtlog.EvtSubscribe(
                channel_path,
                win32evtlog.EvtSubscribeStartAtOldestRecord,
                None,
                event_handle,
                query
            )
        except Exception as e:
            print(f"Failed to subscribe to Sysmon (Is Sysmon installed?): {e}")
            self._run_simulated()
            return

        while self.running:
            wait_result = win32event.WaitForSingleObject(event_handle, 1000)
            if wait_result == win32event.WAIT_OBJECT_0:
                while self.running:
                    events = win32evtlog.EvtNext(subscription, 10)
                    if not events:
                        break
                    for event in events:
                        self._process_windows_event(event)

    def _process_windows_event(self, event_handle):
        """Parses a raw Windows Event log."""
        try:
            import win32evtlog
            xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            
            image_match = re.search(r"Data Name='Image'>(.*?)</Data>", xml_content)
            pid_match = re.search(r"Data Name='ProcessId'>(.*?)</Data>", xml_content)
            time_match = re.search(r"Data Name='UtcTime'>(.*?)</Data>", xml_content)
            
            image_path = image_match.group(1) if image_match else "Unknown"
            pid = pid_match.group(1) if pid_match else "N/A"
            timestamp = time_match.group(1) if time_match else datetime.datetime.now().isoformat()

            # Skip system/idle processes
            if "System" in image_path or not image_path:
                return

            self._log_and_check(image_path, pid, timestamp)

        except Exception as e:
            print(f"Error parsing Windows event: {e}")

    def _run_simulated(self):
        """Simulates standard benign endpoint process executions for Linux/testing environments."""
        import random
        
        simulated_processes = [
            ("C:\\Windows\\System32\\svchost.exe", 1024),
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 4322),
            ("C:\\Windows\\explorer.exe", 2048),
            ("C:\\Windows\\System32\\notepad.exe", 1245),
            ("C:\\Program Files\\Microsoft VS Code\\Code.exe", 9912),
            ("C:\\Program Files\\Slack Technologies\\Slack.exe", 5012),
            ("C:\\Windows\\System32\\taskhostw.exe", 7711)
        ]
        
        while self.running:
            time.sleep(random.randint(4, 10))
            if not self.running:
                break
                
            image_path, pid = random.choice(simulated_processes)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # Occasionally simulate standard user utility
            if random.random() < 0.15:
                random_names = ["teams.exe", "spotify.exe", "calculator.exe", "mspaint.exe"]
                image_path = f"C:\\Program Files\\{random.choice(random_names)}"
                pid = random.randint(1000, 30000)

            self._log_and_check(image_path, pid, timestamp)

    def _log_and_check(self, image_path, pid, timestamp):
        """Saves the log to database, checks for alerts, and triggers active mitigation."""
        insert_log(image_path, pid, timestamp, self.db_path)
        
        if self.event_callback:
            self.event_callback(image_path, pid, timestamp)

        # Run correlation rule checks (strictly for real threat indicators)
        for pattern in SUSPICIOUS_PATHS:
            if re.search(pattern, image_path, re.IGNORECASE):
                # Trigger alert and ACTIVE MITIGATION!
                remediate_malicious_process(image_path, pid, self.db_path, self.alert_callback)
                break
