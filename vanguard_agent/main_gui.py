import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
import datetime
from database import init_db, fetch_recent_logs, fetch_recent_alerts, clear_all_data, get_db_connection, insert_alert
from sysmon_monitor import SysmonMonitor, remediate_malicious_process
from extension_scanner import ExtensionScanner, ContinuousRansomwareMonitor, SignatureDatabaseUpdater
from ml_analyzer import MLAnalyzer
from sync_client import SyncClient

# Configure appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class EDRApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Vanguard EDR - Endpoint Detection & Response Agent")
        self.geometry("1100x650")
        
        # Initialize Database
        init_db()
        
        # Initialize ML Analyzer
        self.ml_analyzer = MLAnalyzer()
        
        # State variables
        self.sysmon_monitor = None
        self.sync_client = None
        self.active_scanner = None
        self.watchdog_monitor = None
        self.signature_updater = None
        self.db_path = "vanguard_logs.db"
        self.server_url = "http://127.0.0.1:5000"
        
        self.last_analyzed_log_id = 0
        
        # Setup UI layout
        self._build_sidebar()
        self._build_main_container()
        
        # Load initial data
        self.update_dashboard_stats()
        self.refresh_monitor_table()
        
        # Start Sysmon logging background thread
        self.start_sysmon_monitor()
        
        # Start Centralized Server Sync Client
        self.start_sync_client()
        
        # Start Always-On Continuous File Monitor (Defaults to current working directory)
        self.start_file_watchdog(".")

        # Start Dynamic Signatures Updater (Updates signatures from GitHub every 4 hours)
        self.start_signature_updater()

        # Start periodic status updates
        self.update_sync_status_label()
        
        # Start automated real-time background ML classification
        self.run_background_ml_classification()

    def _build_sidebar(self):
        # Sidebar Frame
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Title/Logo
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="VANGUARD EDR", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.subtitle_label = ctk.CTkLabel(self.sidebar_frame, text="Endpoint Agent v1.2", font=ctk.CTkFont(size=11, slant="italic"))
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 30))

        # Navigation Buttons
        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=self.show_dashboard, anchor="w")
        self.btn_dashboard.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_monitor = ctk.CTkButton(self.sidebar_frame, text="Real-Time Monitor", command=self.show_monitor, anchor="w")
        self.btn_monitor.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.btn_scanner = ctk.CTkButton(self.sidebar_frame, text="Ransomware Scanner", command=self.show_scanner, anchor="w")
        self.btn_scanner.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        self.btn_analyzer = ctk.CTkButton(self.sidebar_frame, text="Threat Intelligence", command=self.show_analyzer, anchor="w")
        self.btn_analyzer.grid(row=5, column=0, padx=20, pady=10, sticky="ew")

        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="Settings & Database", command=self.show_settings, anchor="w")
        self.btn_settings.grid(row=6, column=0, padx=20, pady=10, sticky="ew")

        # Status indicators
        self.status_container = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.status_container.grid(row=7, column=0, padx=20, pady=(50, 20), sticky="s")
        
        # Agent Status
        self.status_frame = ctk.CTkFrame(self.status_container, fg_color="transparent")
        self.status_frame.pack(anchor="w", pady=2)
        self.status_dot = ctk.CTkLabel(self.status_frame, text="●", text_color="#10B981", font=ctk.CTkFont(size=14))
        self.status_dot.grid(row=0, column=0, padx=(0, 5))
        self.status_text = ctk.CTkLabel(self.status_frame, text="Sysmon Active", font=ctk.CTkFont(size=11))
        self.status_text.grid(row=0, column=1)

        # Sync Status
        self.sync_frame = ctk.CTkFrame(self.status_container, fg_color="transparent")
        self.sync_frame.pack(anchor="w", pady=2)
        self.sync_dot = ctk.CTkLabel(self.sync_frame, text="●", text_color="#94A3B8", font=ctk.CTkFont(size=14))
        self.sync_dot.grid(row=0, column=0, padx=(0, 5))
        self.sync_text = ctk.CTkLabel(self.sync_frame, text="Sync Connecting...", font=ctk.CTkFont(size=11))
        self.sync_text.grid(row=0, column=1)

    def _build_main_container(self):
        # Create container for main views
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Tab Frames dictionary
        self.tabs = {}
        self._init_dashboard_tab()
        self._init_monitor_tab()
        self._init_scanner_tab()
        self._init_analyzer_tab()
        self._init_settings_tab()

        # Show Dashboard by default
        self.show_dashboard()

    # --- TAB INITIALIZATIONS ---

    def _init_dashboard_tab(self):
        tab = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.tabs["dashboard"] = tab
        
        # Grid layout
        tab.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Header
        lbl = ctk.CTkLabel(tab, text="Security Overview", font=ctk.CTkFont(size=24, weight="bold"))
        lbl.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 20))

        # Status card
        self.card_status = ctk.CTkFrame(tab, fg_color="#1E293B", height=100)
        self.card_status.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(self.card_status, text="SYSTEM STATUS", font=ctk.CTkFont(size=11, weight="bold")).pack(pady=(15, 5))
        self.lbl_system_status = ctk.CTkLabel(self.card_status, text="SECURE", text_color="#10B981", font=ctk.CTkFont(size=20, weight="bold"))
        self.lbl_system_status.pack(pady=(0, 15))

        # Logs card
        self.card_logs = ctk.CTkFrame(tab, fg_color="#1E293B", height=100)
        self.card_logs.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(self.card_logs, text="LOGS INDEXED", font=ctk.CTkFont(size=11, weight="bold")).pack(pady=(15, 5))
        self.lbl_logs_count = ctk.CTkLabel(self.card_logs, text="0", font=ctk.CTkFont(size=22, weight="bold"))
        self.lbl_logs_count.pack(pady=(0, 15))

        # Alerts card
        self.card_alerts = ctk.CTkFrame(tab, fg_color="#1E293B", height=100)
        self.card_alerts.grid(row=1, column=2, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(self.card_alerts, text="ACTIVE ALERTS", font=ctk.CTkFont(size=11, weight="bold")).pack(pady=(15, 5))
        self.lbl_alerts_count = ctk.CTkLabel(self.card_alerts, text="0", text_color="#EF4444", font=ctk.CTkFont(size=22, weight="bold"))
        self.lbl_alerts_count.pack(pady=(0, 15))

        # Recent Alerts List
        lbl_sec = ctk.CTkLabel(tab, text="Recent Security Threat Logs", font=ctk.CTkFont(size=16, weight="bold"))
        lbl_sec.grid(row=2, column=0, columnspan=3, sticky="w", pady=(20, 10))

        self.txt_alerts = ctk.CTkTextbox(tab, height=300)
        self.txt_alerts.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=10, pady=10)
        self.txt_alerts.configure(state="disabled")

    def _init_monitor_tab(self):
        tab = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.tabs["monitor"] = tab
        
        tab.grid_rowconfigure(2, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(tab, text="Real-Time Event Log Center", font=ctk.CTkFont(size=24, weight="bold"))
        lbl.grid(row=0, column=0, sticky="w", pady=(0, 5))

        # Filters and Search Panel
        filter_frame = ctk.CTkFrame(tab, fg_color="transparent")
        filter_frame.grid(row=1, column=0, sticky="ew", pady=10)
        filter_frame.grid_columnconfigure(0, weight=1)

        self.ent_log_search = ctk.CTkEntry(filter_frame, placeholder_text="Search logs by Process or PID...")
        self.ent_log_search.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.ent_log_search.bind("<KeyRelease>", lambda e: self.refresh_monitor_table())

        self.opt_log_filter = ctk.CTkOptionMenu(filter_frame, values=["All Logs", "Alerts Only"], command=lambda v: self.refresh_monitor_table())
        self.opt_log_filter.grid(row=0, column=1)

        # Style native Treeview to fit EDR Dark Theme
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.style.configure("Treeview", 
                             background="#1E293B", 
                             foreground="#E2E8F0", 
                             fieldbackground="#1E293B",
                             rowheight=26,
                             font=("Courier New" if sys.platform != "win32" else "Consolas", 10))
        
        self.style.map("Treeview", background=[("selected", "#3B82F6")])
        self.style.configure("Treeview.Heading", 
                             background="#0F172A", 
                             foreground="#F8FAFC", 
                             font=("Segoe UI", 10, "bold"))

        # Scrollable log table body using ttk.Treeview
        self.tree_frame = ctk.CTkFrame(tab, fg_color="transparent")
        self.tree_frame.grid(row=2, column=0, sticky="nsew", pady=(5, 10))
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(self.tree_frame, columns=("Timestamp", "Image", "PID", "Status"), show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Define columns headings
        self.tree.heading("Timestamp", text="Timestamp", anchor="w")
        self.tree.heading("Image", text="Process Image Path / Alert Summary", anchor="w")
        self.tree.heading("PID", text="PID / Detail", anchor="w")
        self.tree.heading("Status", text="Status", anchor="w")

        # Define columns dimensions
        self.tree.column("Timestamp", width=180, minwidth=150, stretch=False)
        self.tree.column("Image", width=420, minwidth=250, stretch=True)
        self.tree.column("PID", width=120, minwidth=80, stretch=False)
        self.tree.column("Status", width=110, minwidth=80, stretch=False)

        # Treeview Scrollbar
        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

    def refresh_monitor_table(self):
        """Fetches logs or alerts with search/filter queries and updates Treeview safely."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        search_query = self.ent_log_search.get().strip()
        filter_mode = self.opt_log_filter.get()

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()

        if filter_mode == "Alerts Only":
            if search_query:
                cursor.execute(
                    "SELECT timestamp, type, description, score as pid_placeholder FROM alerts WHERE description LIKE ? OR type LIKE ? ORDER BY id DESC LIMIT 100",
                    (f"%{search_query}%", f"%{search_query}%")
                )
            else:
                cursor.execute("SELECT timestamp, type, description, score as pid_placeholder FROM alerts ORDER BY id DESC LIMIT 100")
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                self.tree.insert("", "end", values=(
                    row['timestamp'],
                    row['description'],
                    f"Risk: {row['pid_placeholder']}",
                    "THREAT"
                ))
        else:
            if search_query:
                cursor.execute(
                    "SELECT return_date_time, return_image, return_id FROM logindexer WHERE return_image LIKE ? OR return_id LIKE ? ORDER BY id DESC LIMIT 100",
                    (f"%{search_query}%", f"%{search_query}%")
                )
            else:
                cursor.execute("SELECT return_date_time, return_image, return_id FROM logindexer ORDER BY id DESC LIMIT 100")
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                full_path = row['return_image']
                base_name = full_path.split('\\')[-1] if '\\' in full_path else full_path.split('/')[-1]
                
                is_suspicious = any(trg.lower() in full_path.lower() for trg in ["temp", "cerber", "locky"])
                status_text = "SUSPICIOUS" if is_suspicious else "INFO"
                
                self.tree.insert("", "end", values=(
                    row['return_date_time'],
                    base_name,
                    row['return_id'],
                    status_text
                ))

    def _init_scanner_tab(self):
        tab = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.tabs["scanner"] = tab
        
        tab.grid_rowconfigure(4, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(tab, text="Ransomware Extension Scanner & Watchdog", font=ctk.CTkFont(size=24, weight="bold"))
        lbl.grid(row=0, column=0, sticky="w", pady=(0, 5))

        sub = ctk.CTkLabel(tab, text="On-demand search of a target directory combined with real-time, background watchdog folder protection.", font=ctk.CTkFont(size=13, slant="italic"))
        sub.grid(row=1, column=0, sticky="w", pady=(0, 15))

        # Directory selector layout
        dir_frame = ctk.CTkFrame(tab, fg_color="transparent")
        dir_frame.grid(row=2, column=0, sticky="ew", pady=10)
        dir_frame.grid_columnconfigure(0, weight=1)

        self.ent_dir = ctk.CTkEntry(dir_frame, placeholder_text="Select target folder to scan or monitor...")
        self.ent_dir.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        btn_browse = ctk.CTkButton(dir_frame, text="Browse Folder", width=120, command=self.browse_folder)
        btn_browse.grid(row=0, column=1)

        # Control Panel
        control_frame = ctk.CTkFrame(tab, fg_color="transparent")
        control_frame.grid(row=3, column=0, sticky="ew", pady=10)

        self.btn_start_scan = ctk.CTkButton(control_frame, text="Start Manual Scan", fg_color="#10B981", hover_color="#059669", command=self.start_file_scan)
        self.btn_start_scan.grid(row=0, column=0, padx=(0, 10))

        self.btn_stop_scan = ctk.CTkButton(control_frame, text="Cancel Scan", fg_color="#EF4444", hover_color="#DC2626", command=self.stop_file_scan, state="disabled")
        self.btn_stop_scan.grid(row=0, column=1, padx=(0, 20))

        self.lbl_scan_progress = ctk.CTkLabel(control_frame, text="Ready", font=ctk.CTkFont(size=12))
        self.lbl_scan_progress.grid(row=0, column=2)

        # Log details textbox
        self.txt_scan_log = ctk.CTkTextbox(tab, height=200)
        self.txt_scan_log.grid(row=4, column=0, sticky="nsew", pady=10)
        self.txt_scan_log.configure(state="disabled")

        # Continuous Protection watchdog Status Card
        self.watchdog_frame = ctk.CTkFrame(tab, fg_color="#1E293B")
        self.watchdog_frame.grid(row=5, column=0, sticky="ew", pady=(10, 5), padx=5)
        
        ctk.CTkLabel(self.watchdog_frame, text="ALWAYS-ON BACKGROUND PROTECTION", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        self.lbl_watchdog_status = ctk.CTkLabel(self.watchdog_frame, text="Active Status: Monitoring project folder (.)", text_color="#10B981", font=ctk.CTkFont(size=12, slant="italic"))
        self.lbl_watchdog_status.pack(anchor="w", padx=15, pady=(0, 10))
        
        self.btn_update_watchdog = ctk.CTkButton(self.watchdog_frame, text="Apply Watchdog to Selected Folder", command=self.update_watchdog_path)
        self.btn_update_watchdog.pack(anchor="w", padx=15, pady=(0, 15))

    def _init_analyzer_tab(self):
        tab = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.tabs["analyzer"] = tab
        
        tab.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(tab, text="Threat Intelligence & MITRE ATT&CK Dashboard", font=ctk.CTkFont(size=24, weight="bold"))
        lbl.grid(row=0, column=0, sticky="w", pady=(0, 5))

        sub = ctk.CTkLabel(tab, text="Vanguard real-time sequence classification, behavior explanations, and vulnerability CVE references.", font=ctk.CTkFont(size=13, slant="italic"))
        sub.grid(row=1, column=0, sticky="w", pady=(0, 10))

        # Real-time dashboard panel
        intel_panel = ctk.CTkFrame(tab, fg_color="#1E293B", height=150)
        intel_panel.grid(row=2, column=0, sticky="ew", pady=10, padx=5)
        
        ctk.CTkLabel(intel_panel, text="LIVE EDR ENGINE MONITOR", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        # Grid inside panel
        stat_frame = ctk.CTkFrame(intel_panel, fg_color="transparent")
        stat_frame.pack(fill="x", padx=15, pady=(5, 10))
        stat_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Score status
        self.lbl_live_score = ctk.CTkLabel(stat_frame, text="Live Threat Level: 0.05", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_live_score.grid(row=0, column=0, sticky="w")
        
        # MITRE ID
        self.lbl_live_mitre = ctk.CTkLabel(stat_frame, text="Active MITRE Tactic: N/A", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_live_mitre.grid(row=0, column=1, sticky="w")

        # CVEs
        self.lbl_live_cves = ctk.CTkLabel(stat_frame, text="Referenced CVEs: N/A", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_live_cves.grid(row=0, column=2, sticky="w")

        # Explanation box
        self.lbl_live_expl = ctk.CTkLabel(intel_panel, text="Verdict: Normal benign background behavior (Active Monitoring).", wraplength=800, justify="left", font=ctk.CTkFont(size=12, slant="italic"))
        self.lbl_live_expl.pack(anchor="w", padx=15, pady=(0, 15))

        # Manual sandbox divider
        ctk.CTkLabel(tab, text="Manual Analysis Sandbox (Research & Grading Demo)", font=ctk.CTkFont(size=15, weight="bold")).grid(row=3, column=0, sticky="w", pady=(15, 5))

        # File selection
        file_frame = ctk.CTkFrame(tab, fg_color="transparent")
        file_frame.grid(row=4, column=0, sticky="ew", pady=5)
        file_frame.grid_columnconfigure(0, weight=1)

        self.ent_xml = ctk.CTkEntry(file_frame, placeholder_text="Select api.xml behavior log file...")
        self.ent_xml.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        btn_browse_xml = ctk.CTkButton(file_frame, text="Browse XML", width=120, command=self.browse_xml_file)
        btn_browse_xml.grid(row=0, column=1)

        # Analyze button
        self.btn_run_analysis = ctk.CTkButton(tab, text="Analyze Sandbox Log", fg_color="#3B82F6", hover_color="#2563EB", command=self.run_ml_analysis)
        self.btn_run_analysis.grid(row=5, column=0, sticky="w", pady=10)

    def _init_settings_tab(self):
        tab = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.tabs["settings"] = tab
        
        tab.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(tab, text="Settings & Database Administration", font=ctk.CTkFont(size=24, weight="bold"))
        lbl.grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Central server configuration
        server_card = ctk.CTkFrame(tab, fg_color="#1E293B")
        server_card.grid(row=1, column=0, sticky="ew", pady=10, padx=5)
        
        ctk.CTkLabel(server_card, text="Central Server Configuration", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(15, 5))
        
        url_frame = ctk.CTkFrame(server_card, fg_color="transparent")
        url_frame.pack(fill="x", padx=20, pady=(5, 15))
        
        self.ent_server_url = ctk.CTkEntry(url_frame, width=300)
        self.ent_server_url.insert(0, self.server_url)
        self.ent_server_url.grid(row=0, column=0, padx=(0, 10))
        
        btn_save_url = ctk.CTkButton(url_frame, text="Update Server URL", command=self.update_server_url)
        btn_save_url.grid(row=0, column=1)

        # Database Management card
        db_card = ctk.CTkFrame(tab, fg_color="#1E293B")
        db_card.grid(row=2, column=0, sticky="ew", pady=10, padx=5)
        
        ctk.CTkLabel(db_card, text="Database Administration", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))
        
        btn_clear = ctk.CTkButton(db_card, text="Reset & Truncate Tables", fg_color="#EF4444", hover_color="#DC2626", command=self.confirm_database_clear)
        btn_clear.pack(anchor="w", padx=20, pady=(0, 20))

        # Information card
        info_card = ctk.CTkFrame(tab, fg_color="#1E293B")
        info_card.grid(row=3, column=0, sticky="ew", pady=10, padx=5)
        ctk.CTkLabel(info_card, text="System Information", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))
        
        info_text = f"Operating System: {sys.platform}\nLocal Database Path: {os.path.abspath(self.db_path)}\nPython Interpreter: {sys.version.split()[0]}"
        ctk.CTkLabel(info_card, text=info_text, justify="left", font=ctk.CTkFont(family="Courier", size=12)).pack(anchor="w", padx=20, pady=(0, 20))

    # --- TAB NAVIGATION CONTROLLER ---

    def hide_all_tabs(self):
        for tab in self.tabs.values():
            tab.grid_forget()

    def show_dashboard(self):
        self.hide_all_tabs()
        self.update_dashboard_stats()
        self.tabs["dashboard"].grid(row=0, column=0, sticky="nsew")

    def show_monitor(self):
        self.hide_all_tabs()
        self.refresh_monitor_table()
        self.tabs["monitor"].grid(row=0, column=0, sticky="nsew")

    def show_scanner(self):
        self.hide_all_tabs()
        self.tabs["scanner"].grid(row=0, column=0, sticky="nsew")

    def show_analyzer(self):
        self.hide_all_tabs()
        self.tabs["analyzer"].grid(row=0, column=0, sticky="nsew")

    def show_settings(self):
        self.hide_all_tabs()
        self.tabs["settings"].grid(row=0, column=0, sticky="nsew")

    # --- FUNCTIONALITY ACTIONS ---

    def start_sysmon_monitor(self):
        """Launches background Sysmon logging monitor."""
        self.sysmon_monitor = SysmonMonitor(
            db_path=self.db_path,
            event_callback=self.on_sysmon_event,
            alert_callback=self.on_sysmon_alert
        )
        self.sysmon_monitor.start()

    def start_sync_client(self):
        """Launches remote server log syncer."""
        self.sync_client = SyncClient(
            db_path=self.db_path,
            server_url=self.server_url
        )
        self.sync_client.start()

    def start_file_watchdog(self, watch_path):
        """Starts background always-on continuous file monitor thread."""
        if self.watchdog_monitor:
            self.watchdog_monitor.stop_monitor()
            
        self.watchdog_monitor = ContinuousRansomwareMonitor(
            watch_dir=watch_path,
            db_path=self.db_path,
            alert_callback=self.on_sysmon_alert
        )
        self.watchdog_monitor.start()

    def start_signature_updater(self):
        """Starts background dynamic signatures database updater (runs every 4 hours)."""
        self.signature_updater = SignatureDatabaseUpdater(interval_hours=4)
        self.signature_updater.start()

    def update_watchdog_path(self):
        folder = self.ent_dir.get().strip()
        if not folder:
            messagebox.showerror("Error", "Please select or type a valid folder first.")
            return
            
        self.start_file_watchdog(folder)
        self.lbl_watchdog_status.configure(text=f"Active Status: Monitoring {folder}", text_color="#10B981")
        messagebox.showinfo("Watchdog Updated", f"Continuous file protection is now active on:\n{folder}")

    def update_server_url(self):
        new_url = self.ent_server_url.get().strip()
        if new_url:
            self.server_url = new_url
            if self.sync_client:
                self.sync_client.stop()
            self.start_sync_client()
            messagebox.showinfo("Success", f"Sync server URL updated to: {new_url}")

    def update_sync_status_label(self):
        """Periodically runs to check if connection to server is active."""
        if self.sync_client:
            try:
                import urllib.request
                req = urllib.request.Request(self.server_url, method="GET")
                with urllib.request.urlopen(req, timeout=1.5) as r:
                    if r.status == 200:
                        self.sync_dot.configure(text_color="#10B981")
                        self.sync_text.configure(text="Sync Server Online")
                    else:
                        raise Exception
            except Exception:
                self.sync_dot.configure(text_color="#EF4444")
                self.sync_text.configure(text="Sync Server Offline")
        
        self.after(5000, self.update_sync_status_label)

    def run_background_ml_classification(self):
        """Periodically runs ML sequence analysis on the sliding window of live database logs."""
        try:
            logs = fetch_recent_logs(limit=40, db_path=self.db_path)
            
            if logs:
                api_sequence = self.ml_analyzer.map_sysmon_logs_to_apis(logs)
                res = self.ml_analyzer.analyze_sequence(api_sequence)
                
                # Update widgets thread-safely
                self.lbl_live_score.configure(text=f"Live Threat Level: {res['score']:.4f}")
                self.lbl_live_mitre.configure(text=f"Active MITRE Tactic: {res['mitre_id']}")
                
                cves_text = ", ".join(res['cves']) if res['cves'] else "N/A"
                self.lbl_live_cves.configure(text=f"Referenced CVEs: {cves_text}")
                
                self.lbl_live_expl.configure(text=f"Verdict: {res['label']} ({res['method']}).\n{res['explanation']}")
                
                if res['label'] == "Malicious":
                    self.lbl_live_score.configure(text_color="#EF4444")
                    self.lbl_live_mitre.configure(text_color="#EF4444")
                    self.lbl_live_cves.configure(text_color="#EF4444")
                    self.lbl_live_expl.configure(text_color="#EF4444")
                    
                    # 1. Look up process causing sequence and REMEDIATE it!
                    malicious_image = "Unknown"
                    malicious_pid = "N/A"
                    for log in reversed(logs):
                        img_lower = log.get('return_image', '').lower()
                        if "temp" in img_lower or "cerber" in img_lower or "locky" in img_lower:
                            malicious_image = log.get('return_image', 'Unknown')
                            malicious_pid = log.get('return_id', 'N/A')
                            break
                            
                    # Active Block & Cleanup
                    remediate_summary = remediate_malicious_process(malicious_image, malicious_pid, self.db_path, self.on_sysmon_alert)
                    
                    recent_alerts = fetch_recent_alerts(limit=5, db_path=self.db_path)
                    duplicate = any(res['method'] in alert['description'] for alert in recent_alerts)
                    
                    if not duplicate:
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        insert_alert(
                            "ML Threat Detection", 
                            f"Background ML engine detected threat ({res['method']}). CVE: {cves_text}. Mitigation: {remediate_summary}", 
                            5, 
                            timestamp, 
                            self.db_path
                        )
                        self.update_dashboard_stats()
                        self.refresh_monitor_table()
                        self.lbl_system_status.configure(text="THREATS DETECTED", text_color="#EF4444")
                else:
                    self.lbl_live_score.configure(text_color="#10B981")
                    self.lbl_live_mitre.configure(text_color="#94A3B8")
                    self.lbl_live_cves.configure(text_color="#94A3B8")
                    self.lbl_live_expl.configure(text_color="#94A3B8")
        except Exception as e:
            print(f"Background ML classification error: {e}")
            
        self.after(8000, self.run_background_ml_classification)

    # --- THREAD-SAFE CALLBACK WRAPPERS ---

    def on_sysmon_event(self, image_path, pid, timestamp):
        """Callback when new Sysmon log is captured. Scheduled on Main Thread."""
        self.after(0, self._on_sysmon_event_main_thread, image_path, pid, timestamp)

    def _on_sysmon_event_main_thread(self, image_path, pid, timestamp):
        self.update_dashboard_stats()
        self.refresh_monitor_table()

    def on_sysmon_alert(self, description, score, timestamp):
        """Callback when real-time correlation alert triggers. Scheduled on Main Thread."""
        self.after(0, self._on_sysmon_alert_main_thread, description, score, timestamp)

    def _on_sysmon_alert_main_thread(self, description, score, timestamp):
        self.update_dashboard_stats()
        self.refresh_monitor_table()
        self.lbl_system_status.configure(text="THREATS DETECTED", text_color="#EF4444")
        messagebox.showwarning("Incident Response Intercept", f"Vanguard Remediation Engaged!\n\n{description}")

    # --- SCANNER THREAD-SAFE CALLBACKS ---

    def on_scan_progress(self, scanned_count, threat_count):
        self.after(0, self._on_scan_progress_main_thread, scanned_count, threat_count)

    def _on_scan_progress_main_thread(self, scanned_count, threat_count):
        self.lbl_scan_progress.configure(text=f"Scanned: {scanned_count} files | Threats: {threat_count}")

    def on_scan_threat_alert(self, description, score, timestamp):
        self.after(0, self._on_scan_threat_alert_main_thread, description, score, timestamp)

    def _on_scan_threat_alert_main_thread(self, description, score, timestamp):
        self.txt_scan_log.configure(state="normal")
        self.txt_scan_log.insert("end", f"[MITIGATED] {description}\n")
        self.txt_scan_log.configure(state="disabled")
        self.update_dashboard_stats()

    def on_scan_completed(self, scanned_count, threat_count, status_message):
        self.after(0, self._on_scan_completed_main_thread, scanned_count, threat_count, status_message)

    def _on_scan_completed_main_thread(self, scanned_count, threat_count, status_message):
        self.btn_start_scan.configure(state="normal")
        self.btn_stop_scan.configure(state="disabled")
        self.lbl_scan_progress.configure(text="Scan completed.")
        
        self.txt_scan_log.configure(state="normal")
        self.txt_scan_log.insert("end", f"\n--- SCAN & REMEDIATION RESULTS ---\n{status_message}\nTotal files processed: {scanned_count}\nThreat files deleted: {threat_count}\n")
        self.txt_scan_log.configure(state="disabled")
        
        if threat_count > 0:
            messagebox.showwarning("Scan Complete", f"Scan complete. Found and deleted {threat_count} potential ransomware files!\nCheck logs for details.")
        else:
            messagebox.showinfo("Scan Complete", "Scan complete. No threat extensions detected.")

    def update_dashboard_stats(self):
        """Refreshes cards values with DB queries."""
        try:
            logs = fetch_recent_logs(db_path=self.db_path)
            alerts = fetch_recent_alerts(db_path=self.db_path)
            
            self.lbl_logs_count.configure(text=str(len(logs)))
            self.lbl_alerts_count.configure(text=str(len(alerts)))
            
            if len(alerts) == 0:
                self.lbl_system_status.configure(text="SECURE", text_color="#10B981")
                
            self.txt_alerts.configure(state="normal")
            self.txt_alerts.delete("1.0", "end")
            for alert in alerts:
                line = f"● [{alert['timestamp']}] RISK: {alert['score']}/5 | {alert['description']}\n"
                self.txt_alerts.insert("end", line)
            self.txt_alerts.configure(state="disabled")
        except Exception as e:
            print(f"Error updating dashboard: {e}")

    # --- SCANNER METHODS ---

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.ent_dir.delete(0, tk.END)
            self.ent_dir.insert(0, folder)

    def start_file_scan(self):
        target = self.ent_dir.get()
        if not target:
            messagebox.showerror("Error", "Please select a directory to scan.")
            return
            
        self.btn_start_scan.configure(state="disabled")
        self.btn_stop_scan.configure(state="normal")
        self.lbl_scan_progress.configure(text="Scan in progress...")
        
        self.txt_scan_log.configure(state="normal")
        self.txt_scan_log.delete("1.0", "end")
        self.txt_scan_log.insert("end", f"Starting recursive scan & quarantine on: {target}\n")
        self.txt_scan_log.configure(state="disabled")

        self.active_scanner = ExtensionScanner(
            target_dir=target,
            db_path=self.db_path,
            progress_callback=self.on_scan_progress,
            result_callback=self.on_scan_completed,
            alert_callback=self.on_scan_threat_alert
        )
        self.active_scanner.start()

    def stop_file_scan(self):
        if self.active_scanner:
            self.active_scanner.cancel()
            self.lbl_scan_progress.configure(text="Cancelling...")

    # --- ANALYZER METHODS ---

    def browse_xml_file(self):
        file = filedialog.askopenfilename(filetypes=[("XML Files", "*.xml")])
        if file:
            self.ent_xml.delete(0, tk.END)
            self.ent_xml.insert(0, file)

    def run_ml_analysis(self):
        xml_path = self.ent_xml.get()
        if not xml_path:
            messagebox.showerror("Error", "Please select an XML log file to analyze.")
            return
            
        apis = self.ml_analyzer.parse_api_xml(xml_path)
        if not apis:
            messagebox.showerror("Error", f"Failed to extract API calls from {xml_path}")
            return

        api_sequence = self.ml_analyzer.map_apis_to_indices(apis)
        res = self.ml_analyzer.analyze_sequence(api_sequence)
        
        self.lbl_live_score.configure(text=f"Live Threat Level: {res['score']:.4f}")
        self.lbl_live_mitre.configure(text=f"Active MITRE Tactic: {res['mitre_id']}")
        
        cves_text = ", ".join(res['cves']) if res['cves'] else "N/A"
        self.lbl_live_cves.configure(text=f"Referenced CVEs: {cves_text}")
        self.lbl_live_expl.configure(text=f"Verdict: {res['label']} ({res['method']}).\n{res['explanation']}")
        
        if res['label'] == "Malicious":
            self.lbl_live_score.configure(text_color="#EF4444")
            self.lbl_live_mitre.configure(text_color="#EF4444")
            self.lbl_live_cves.configure(text_color="#EF4444")
            self.lbl_live_expl.configure(text_color="#EF4444")
            
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            insert_alert("ML Sandbox Threat", f"Manual sandbox run detected threat sequence ({res['method']}). CVE: {cves_text}", 5, timestamp, self.db_path)
            self.update_dashboard_stats()
            self.refresh_monitor_table()
            
            messagebox.showerror("Ransomware Intrusion", f"Malware Activity Detected via API Behavior Analysis!\nScore: {res['score']:.4f}\nMethod: {res['method']}")
        else:
            self.lbl_live_score.configure(text_color="#10B981")
            self.lbl_live_mitre.configure(text_color="#94A3B8")
            self.lbl_live_cves.configure(text_color="#94A3B8")
            self.lbl_live_expl.configure(text_color="#94A3B8")
            messagebox.showinfo("Analysis Safe", "API Sequence Behavior is classified as Benign.")

    # --- SETTINGS / DB ADMIN METHODS ---

    def confirm_database_clear(self):
        ans = messagebox.askyesno("Confirm Clear", "Are you sure you want to delete all stored sysmon logs and alert history? This cannot be undone.")
        if ans:
            clear_all_data(db_path=self.db_path)
            self.update_dashboard_stats()
            self.refresh_monitor_table()
            messagebox.showinfo("Success", "Database tables truncated successfully.")

    def on_closing(self):
        if self.sysmon_monitor:
            self.sysmon_monitor.stop()
        if self.sync_client:
            self.sync_client.stop()
        if self.watchdog_monitor:
            self.watchdog_monitor.stop_monitor()
        if self.signature_updater:
            self.signature_updater.stop_updater()
        self.destroy()

if __name__ == "__main__":
    app = EDRApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
