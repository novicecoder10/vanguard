import threading
import time
import json
import urllib.request
import urllib.error
import sqlite3
import socket

class SyncClient(threading.Thread):
    def __init__(self, db_path="vanguard_logs.db", server_url="http://127.0.0.1:5000", sync_interval=5):
        super().__init__()
        self.db_path = db_path
        self.server_url = server_url
        self.sync_interval = sync_interval
        
        # Unique identifier for this endpoint (hostname)
        self.agent_id = socket.gethostname()
        
        # Last synced IDs (in-memory tracking)
        self.last_synced_log_id = 0
        self.last_synced_alert_id = 0
        
        self.running = False
        self.daemon = True
        self._load_last_state()

    def _load_last_state(self):
        """Loads state by checking DB ranges initially."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Start syncing from recent records
        cursor.execute("SELECT MAX(id) FROM logindexer")
        val_log = cursor.fetchone()[0]
        self.last_synced_log_id = val_log if val_log is not None else 0
        
        cursor.execute("SELECT MAX(id) FROM alerts")
        val_alert = cursor.fetchone()[0]
        self.last_synced_alert_id = val_alert if val_alert is not None else 0
        
        conn.close()

    def run(self):
        self.running = True
        print(f"Sync client started. Target Server: {self.server_url}")
        
        while self.running:
            # Sync logs
            self.sync_logs()
            
            # Sync alerts
            self.sync_alerts()
            
            # Wait for next sync interval
            for _ in range(self.sync_interval):
                if not self.running:
                    break
                time.sleep(1)

    def stop(self):
        self.running = False

    def sync_logs(self):
        """Fetches unsynced logs and sends them to the remote server."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, return_image, return_id, return_date_time FROM logindexer WHERE id > ? ORDER BY id ASC LIMIT 100",
            (self.last_synced_log_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return
            
        logs_to_send = [dict(row) for row in rows]
        payload = {
            "agent_id": self.agent_id,
            "logs": logs_to_send
        }
        
        url = f"{self.server_url}/api/logs"
        success = self._send_post_request(url, payload)
        
        if success:
            # Update last synced log id to the highest ID processed in this batch
            self.last_synced_log_id = max(log['id'] for log in logs_to_send)

    def sync_alerts(self):
        """Fetches unsynced alerts and sends them to the remote server."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, timestamp, type, description, score FROM alerts WHERE id > ? ORDER BY id ASC LIMIT 50",
            (self.last_synced_alert_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return
            
        alerts_to_send = [dict(row) for row in rows]
        payload = {
            "agent_id": self.agent_id,
            "alerts": alerts_to_send
        }
        
        url = f"{self.server_url}/api/alerts"
        success = self._send_post_request(url, payload)
        
        if success:
            self.last_synced_alert_id = max(alert['id'] for alert in alerts_to_send)

    def _send_post_request(self, url, json_data):
        """Sends HTTP POST request using built-in urllib to avoid external dependencies."""
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(json_data).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            # 3-second timeout for server response
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    return True
        except urllib.error.URLError as e:
            # Server might be offline, ignore logs quietly and retry later
            pass
        except Exception as e:
            print(f"Sync error: {e}")
        return False
