import os
import sys
import time
import threading
import datetime
import json
from database import insert_alert

# Default baseline ransomware extensions from your C++ code
DEFAULT_EXTENSIONS = {
    "micro", "zepto", "cerber", "locky", "cerber3", "cryp1", "mole", "onion", "axx", "osiris",
    "crypz", "crypt", "locked", "odin", "ccc", "cerber2", "sage", "globe", "exx", "good",
    "wallet", "1txt", "decrypt2017", "encrypt", "ezz", "zzzzz", "MERRY", "enciphered", "r5a", "aesir",
    "ecc", "enigma", "cryptowall", "encrypted", "loli", "breaking_bad", "coded", "ha3", "damage", "wcry",
    "lol!", "cryptolocker", "dharma", "MRCR1", "sexy", "crjoker", "fantom", "keybtc@inbox_com", "rrk", "legion",
    "kratos", "LeChiffre", "kraken", "zcrypt", "maya", "file0locked", "crinf", "serp", "potato", "ytbl",
    "surprise", "angelamerkel", "windows10", "lesli", "serpent", "PEGS1", "dale", "pdcr", "zzz", "xyz",
    "1cbu1", "venusf", "coverton", "thor", "rnsmwr", "evillock", "wflx", "nuclear55", "darkness",
    "encr", "rekt", "kernel_time", "zyklon", "Dexter", "locklock", "cry", "VforVendetta", "btc", "raid10",
    "dCrypt", "zorro", "AngleWare", "EnCiPhErEd", "purge", "realfs0ciety@sigaint.org.fs0ciety", "shit", "atlas",
    "crypted", "padcrypt", "xxx", "hush", "vbransom", "cryeye", "unavailable", "braincrypt", "fucked", "crypte",
    "_AiraCropEncrypted", "stn", "paym", "spora", "RARE1", "alcatraz", "pzdc", "aaa", "ttt", "odcodc",
    "vvv", "ruby", "pays", "comrade", "antihacker2017", "herbst", "szf", "exotic", "RMCM1", "crptrgr",
    "kkk", "rdm", "BarRax", "vindows", "helpmeencedfiles", "hnumkhotep", "CCCRRRPPP", "kyra", "fun", "rip",
    "73i87A", "bitstak", "kernel_complete", "payrms", "a5zfn", "perl", "noproblemwedecfiles", "lcked", "p5tkjw",
    "paymst", "magic", "payms", "d4nk", "SecureCrypted", "kostya", "lovewindows", "madebyadam", "powerfulldecrypt",
    "gefickt", "kernel_pid", "ifuckedyou", "grt", "conficker", "edgel", "PoAr2w", "oops", "adk", "Whereisyourfiles",
    "czvxce", "theworldisyours", "razy", "rmd", "kimcilware", "paymrss", "dxxd", "pec", "rokku", "lock93",
    "vxlock", "pubg", "crab"
}

RANSOMWARE_EXTENSIONS = set(DEFAULT_EXTENSIONS)

def load_local_signatures():
    global RANSOMWARE_EXTENSIONS
    if os.path.exists("ransomware_extensions.json"):
        try:
            with open("ransomware_extensions.json", "r") as f:
                data = json.load(f)
                RANSOMWARE_EXTENSIONS = set(data)
                print(f"Loaded {len(RANSOMWARE_EXTENSIONS)} ransomware signatures from local database.")
        except Exception as e:
            print(f"Error loading local signatures: {e}. Using default list.")
    else:
        save_local_signatures(list(DEFAULT_EXTENSIONS))

def save_local_signatures(exts_list):
    try:
        with open("ransomware_extensions.json", "w") as f:
            json.dump(exts_list, f, indent=4)
    except Exception as e:
        print(f"Error saving local signatures: {e}")

def update_signatures_online():
    """Fetches the latest ransomware extensions from public repository in the background."""
    global RANSOMWARE_EXTENSIONS
    # Use ricardojb's open source ransomware extensions signatures JSON database
    url = "https://raw.githubusercontent.com/ricardojb/ransomware-extensions/master/signatures.json"
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            online_exts = set()
            for ext in data.keys():
                cleaned = ext.strip().lower().replace(".", "")
                if cleaned:
                    online_exts.add(cleaned)
            
            if online_exts:
                # Merge online signatures with default baseline
                merged = DEFAULT_EXTENSIONS.union(online_exts)
                RANSOMWARE_EXTENSIONS = merged
                save_local_signatures(list(merged))
                print(f"Vanguard Signature DB update success. Total signatures: {len(RANSOMWARE_EXTENSIONS)}")
                return True
    except Exception as e:
        print(f"Vanguard Signature DB update failed (network offline or timeout): {e}. Using cached list.")
    return False

# Initialize database signature set
load_local_signatures()


class SignatureDatabaseUpdater(threading.Thread):
    def __init__(self, interval_hours=4):
        super().__init__()
        self.interval = interval_hours * 3600
        self.running = False
        self.daemon = True

    def run(self):
        self.running = True
        # Try to run initial update immediately
        update_signatures_online()
        
        while self.running:
            time.sleep(self.interval)
            if not self.running:
                break
            update_signatures_online()

    def stop_updater(self):
        self.running = False


class ExtensionScanner(threading.Thread):
    def __init__(self, target_dir, db_path="vanguard_logs.db", progress_callback=None, result_callback=None, alert_callback=None):
        super().__init__()
        self.target_dir = target_dir
        self.db_path = db_path
        self.progress_callback = progress_callback  # Callback for reporting files scanned
        self.result_callback = result_callback      # Callback for final completion status
        self.alert_callback = alert_callback        # Callback for real-time alert trigger
        self.stop_requested = False
        self.daemon = True

    def run(self):
        scanned_count = 0
        threat_count = 0
        
        if not os.path.exists(self.target_dir):
            if self.result_callback:
                self.result_callback(0, 0, f"Error: Directory '{self.target_dir}' does not exist.")
            return

        for root, dirs, files in os.walk(self.target_dir):
            if self.stop_requested:
                break
                
            for file in files:
                if self.stop_requested:
                    break
                    
                scanned_count += 1
                file_path = os.path.join(root, file)
                
                _, ext = os.path.splitext(file)
                ext = ext.lstrip('.').lower()
                
                if ext in RANSOMWARE_EXTENSIONS:
                    threat_count += 1
                    
                    action_taken = "Deleted/Quarantined"
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        action_taken = f"Quarantine Failed ({e})"
                        
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    description = f"Known ransomware extension (.{ext}) detected and {action_taken}: {file_path}"
                    
                    insert_alert("Ransomware File", description, 5, timestamp, self.db_path)
                    
                    if self.alert_callback:
                        self.alert_callback(description, 5, timestamp)
                
                if scanned_count % 10 == 0 and self.progress_callback:
                    self.progress_callback(scanned_count, threat_count)

        if self.result_callback:
            status_msg = "Scan completed successfully." if not self.stop_requested else "Scan cancelled by user."
            self.result_callback(scanned_count, threat_count, status_msg)

    def cancel(self):
        self.stop_requested = True


class ContinuousRansomwareMonitor(threading.Thread):
    def __init__(self, watch_dir, db_path="vanguard_logs.db", alert_callback=None):
        super().__init__()
        self.watch_dir = watch_dir
        self.db_path = db_path
        self.alert_callback = alert_callback
        self.running = False
        self.daemon = True
        self.seen_files = set()

    def run(self):
        self.running = True
        
        # Populate initial baseline file set
        if os.path.exists(self.watch_dir):
            try:
                for root, _, files in os.walk(self.watch_dir):
                    for file in files:
                        self.seen_files.add(os.path.join(root, file))
            except Exception as e:
                print(f"Watchdog initialization error on path {self.watch_dir}: {e}")

        while self.running:
            time.sleep(10)
            if not self.running:
                break
                
            if not os.path.exists(self.watch_dir):
                continue

            try:
                for root, _, files in os.walk(self.watch_dir):
                    if not self.running:
                        break
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        if file_path not in self.seen_files:
                            self.seen_files.add(file_path)
                            
                            _, ext = os.path.splitext(file)
                            ext = ext.lstrip('.').lower()
                            
                            if ext in RANSOMWARE_EXTENSIONS:
                                action_taken = "Quarantined (Deleted)"
                                try:
                                    os.remove(file_path)
                                except Exception as e:
                                    action_taken = f"Quarantine Failed ({e})"
                                    
                                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                                description = f"Ransomware Watchdog: Detected .{ext} file at {file_path}. Action: {action_taken}."
                                
                                insert_alert("Ransomware Watchdog", description, 5, timestamp, self.db_path)
                                
                                if self.alert_callback:
                                    self.alert_callback(description, 5, timestamp)
            except Exception as e:
                print(f"Watchdog error: {e}")

    def stop_monitor(self):
        self.running = False
