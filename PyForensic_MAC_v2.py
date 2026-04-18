import sys
import os
import subprocess
from datetime import datetime, timedelta
import subprocess
import json
import re
import psutil
import glob
import sqlite3
import plistlib
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QListWidget, QStackedWidget,
                             QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import shutil
import tempfile
from datetime import datetime, timedelta

def webkit_to_utc(timestamp):
    if not timestamp or timestamp == 0: return "N/A"
    # Chrome/WebKit: microseconds since 1601-01-01
    return (datetime(1601, 1, 1) + timedelta(microseconds=timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')

def mac_to_utc(timestamp):
    if not timestamp or timestamp == 0: return "N/A"
    # Mac Absolute: seconds since 2001-01-01
    return (datetime(2001, 1, 1) + timedelta(seconds=timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')

class ForensicModule(QWidget):
    def __init__(self, name):
        super().__init__()
        self.name = name
        layout = QVBoxLayout()

        # Header
        header_layout = QHBoxLayout()
        self.label = QLabel(f"Analysis: {name}")
        self.label.setFont(QFont("Arial", 14, QFont.Weight.Bold))

        self.refresh_btn = QPushButton("Run Analysis")
        self.refresh_btn.clicked.connect(self.populate_data)

        export_btn = QPushButton("Export CSV")
        export_btn.clicked.connect(self.export_data)

        header_layout.addWidget(self.label)
        header_layout.addStretch()
        header_layout.addWidget(self.refresh_btn)
        header_layout.addWidget(export_btn)

        self.table = QTableWidget()
        self.table.setStyleSheet("background-color: #2b2b2b; color: #ffffff; gridline-color: #444;")
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        layout.addLayout(header_layout)
        layout.addWidget(self.table)
        self.setLayout(layout)

    def update_table(self, headers, data):
        self.table.setRowCount(0)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        for row_data in data:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, value in enumerate(row_data):
                self.table.setItem(row, col, QTableWidgetItem(str(value)))

    def populate_data(self):
        if self.name == "System Info":
            self.get_system_info()
        elif self.name == "Running Processes":
            self.get_processes()
        elif self.name == "Internet History":
            self.get_internet_history()
        elif self.name == "MRU (Recent Items)":
            self.get_mru()
        elif self.name == "Users & Groups":
            self.get_users()
        elif self.name == "Installed Apps":
            self.get_apps()

    # --- New Forensic Methods ---

    def get_internet_history(self):
        """Copies DBs to Temp to avoid locks and parses History + Downloads + Searches"""
        self.table.setRowCount(0)
        all_data = []

        # Define targets: (Source Path, Browser Type, Timestamp Func)
        targets = [
            (os.path.expanduser("~/Library/Safari/History.db"), "Safari", mac_to_utc),
            (os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History"), "Chrome", webkit_to_utc)
        ]

        for db_path, browser, time_func in targets:
            if not os.path.exists(db_path):
                continue

            # 1. Create a temp copy to bypass "Locked" or "Permission" issues during active use
            temp_dir = tempfile.gettempdir()
            temp_db = os.path.join(temp_dir, f"forensic_{browser}.db")

            try:
                shutil.copy2(db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                # --- PART A: WEB VISITS & SEARCHES ---
                if browser == "Chrome":
                    # Chrome has a specific table for search terms
                    query = """
                            SELECT urls.last_visit_time, urls.title, urls.url, keyword_search_terms.term
                            FROM urls
                                     LEFT JOIN keyword_search_terms ON urls.id = keyword_search_terms.url_id
                            WHERE urls.last_visit_time > 0
                            ORDER BY urls.last_visit_time DESC LIMIT 100 \
                            """
                else:
                    # Safari search terms are usually embedded in the URL
                    query = """
                            SELECT visit_time, title, url, NULL
                            FROM history_visits
                                     INNER JOIN history_items ON history_items.id = history_visits.history_item
                            ORDER BY visit_time DESC LIMIT 100 \
                            """

                cursor.execute(query)
                for row in cursor.fetchall():
                    search_term = row[3] if row[3] else ("Search Detected" if "search?" in row[2] else "N/A")
                    all_data.append([time_func(row[0]), row[2],browser, "Visit/Search", search_term, row[1][:50]])

                # --- PART B: DOWNLOADS ---
                if browser == "Chrome":
                    dl_query = "SELECT start_time, target_path, tab_url FROM downloads"
                else:
                    # Modern Safari stores downloads in History.db
                    dl_query = "SELECT download_time, destination_path, source_url FROM downloads"

                try:
                    cursor.execute(dl_query)
                    for row in cursor.fetchall():
                        file_name = os.path.basename(row[1]) if row[1] else "Unknown"
                        all_data.append([time_func(row[0]), row[2],browser, "DOWNLOAD", file_name, "N/A"] )
                except sqlite3.Error:
                    pass  # Some older Safari DBs might not have the downloads table

                conn.close()
                os.remove(temp_db)  # Cleanup

            except Exception as e:
                all_data.append(["ERROR", browser, "Access Denied", "Check FDA", str(e), "N/A"])

        # Sort all combined records by timestamp descending
        all_data.sort(key=lambda x: x[0], reverse=True)

        self.update_table(
            ["Timestamp (UTC)", "Source", "Type", "Detail/Search", "Title/File", "URL/Path"],
            all_data
        )
    def get_mru(self):
        """Parses Finder Recent Folders (Reliable on modern macOS)"""
        path = os.path.expanduser("~/Library/Preferences/com.apple.finder.plist")
        if not os.path.exists(path):
            self.update_table(["Status"], [["Finder preferences not found"]])
            return

        try:
            with open(path, 'rb') as f:
                pl = plistlib.load(f)
                # Modern Finder stores recent folders here
                recent_folders = pl.get('FXRecentFolders', [])
                data = []
                for item in recent_folders:
                    name = item.get('name')
                    # Data is often stored in a 'file-bookmark' blob which is hard to parse
                    # simply, but 'name' is usually available.
                    if name:
                        data.append([name, "Folder"])

                if not data:
                    data = [["No recent folders found in plist", "N/A"]]

                self.update_table(["Item Name", "Type"], data)
        except Exception as e:
            self.update_table(["Error"], [[f"Could not parse Finder Plist: {str(e)}"]])


    def get_unified_logs(self):
        """Queries the Apple Unified Log for recent significant events (last 1 hour)"""
        try:
            # Filtering for interesting events like logins or process starts
            cmd = ["log", "show", "--last", "1h", "--style", "json", "--predicate",
                   'eventMessage contains "login" OR eventMessage contains "auth"']
            output = subprocess.check_output(cmd).decode()
            log_data = json.loads(output)

            data = []
            for entry in log_data:
                data.append([entry.get('timestamp'), entry.get('processImagePath'), entry.get('eventMessage')])
            self.update_table(["Timestamp", "Process", "Message"], data)
        except Exception as e:
            self.update_table(["Error"], [[f"Unified Log requires sudo or FDA: {str(e)}"]])

    def get_network_info(self):
        """Active connections and Wireless Profile history"""
        data = []
        # 1. Active Connections (lsof)
        try:
            net_cmd = ["lsof", "-i", "-n", "-P"]
            net_out = subprocess.check_output(net_cmd).decode().split('\n')
            for line in net_out[1:30]:  # Limit for performance
                parts = re.split(r'\s+', line)
                if len(parts) > 8:
                    data.append(["ACTIVE", parts[0], parts[8], parts[7]])
        except:
            pass

        # 2. Wireless History (Known Networks)
        try:
            wifi_cmd = ["networksetup", "-listallhardwareports"]
            # Typically en0 is Wi-Fi
            wifi_out = subprocess.check_output(
                ["networksetup", "-listpreferredwirelessnetworks", "en0"]).decode().split('\n')
            for ssid in wifi_out[1:]:
                if ssid.strip():
                    data.append(["WIFI-HISTORY", "en0", ssid.strip(), "N/A"])
        except:
            pass

        self.update_table(["Type", "Process/Interface", "Detail", "State"], data)

    def get_usb_usage_detailed(self):
        """Advanced USB history via System Profiler"""
        try:
            cmd = ["system_profiler", "SPUSBDataType", "-json"]
            output = json.loads(subprocess.check_output(cmd).decode())
            data = []

            # Recursive function to find USB devices in the JSON tree
            def parse_usb(items):
                for item in items:
                    name = item.get('_name', 'Unknown')
                    serial = item.get('serial_num', 'N/A')
                    manufacturer = item.get('manufacturer', 'N/A')
                    data.append([name, manufacturer, serial])
                    if 'items' in item:
                        parse_usb(item['items'])

            for controller in output.get('SPUSBDataType', []):
                if 'items' in controller:
                    parse_usb(controller['items'])

            self.update_table(["Device Name", "Manufacturer", "Serial Number"], data)
        except:
            self.update_table(["Error"], [["Could not parse USB JSON"]])

    def get_users_with_groups(self):
        """Lists users and the groups they belong to"""
        try:
            user_list = subprocess.check_output(["dscl", ".", "-list", "/Users"]).decode().split('\n')
            data = []
            for u in user_list:
                if u and not u.startswith('_'):
                    # Get groups for this user
                    groups = subprocess.check_output(["id", "-Gn", u]).decode().strip()
                    data.append([u, groups])
            self.update_table(["Username", "Groups"], data)
        except:
            pass

    def get_spotlight_analysis(self):
        """Analyzes recent Spotlight metadata for the Downloads folder"""
        try:
            path = os.path.expanduser("~/Downloads")
            # mdfind -last 1d: find files modified in last day
            cmd = ["mdfind", "-onlyin", path, "((kMDItemFSContentChangeDate >= $time.now(-3600)))"]
            files = subprocess.check_output(cmd).decode().split('\n')
            data = []
            for f in files:
                if f:
                    # Get specific metadata (Creation date, where-froms)
                    meta = subprocess.check_output(
                        ["mdls", "-name", "kMDItemWhereFroms", "-name", "kMDItemContentCreationDate", f]).decode()
                    data.append([os.path.basename(f), meta.replace('\n', ' ')])
            self.update_table(["File", "Metadata (Source/Created)"], data)
        except:
            self.update_table(["Status"], [["Spotlight query failed or folder empty"]])

    def get_persistence_items(self):
        """Combines LaunchDaemons and LaunchAgents (System & User)"""
        paths = [
            "/Library/LaunchDaemons/*.plist",
            "/Library/LaunchAgents/*.plist",
            os.path.expanduser("~/Library/LaunchAgents/*.plist"),
            "/System/Library/LaunchDaemons/*.plist",
        ]
        data = []
        for path_pattern in paths:
            for filepath in glob.glob(path_pattern):
                try:
                    with open(filepath, 'rb') as f:
                        pl = plistlib.load(f)
                        label = pl.get('Label', 'No Label')
                        program = pl.get('Program') or pl.get('ProgramArguments', ['N/A'])[0]
                        data.append([os.path.basename(filepath), label, program, filepath])
                except:
                    data.append([os.path.basename(filepath), "Access Denied", "N/A", filepath])

        self.update_table(["Filename", "Label", "Execution Path", "Location"], data)

    def get_global_preferences(self):
        """Parses .GlobalPreferences.plist for system-wide settings"""
        path = os.path.expanduser("~/Library/Preferences/.GlobalPreferences.plist")
        data = []
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    pl = plistlib.load(f)
                    for key, value in pl.items():
                        # Filter for common forensic interests
                        if any(x in key for x in ['Language', 'Locale', 'Country', 'AppleID']):
                            data.append([key, str(value)])
            except:
                data.append(["Error", "Could not parse plist"])

        self.update_table(["Preference Key", "Value"], data)

    def get_fsevents_status(self):
        """Checks for File System Event Logs (FSEvents)"""
        fsevents_path = "/.fseventsd/"
        data = []
        if os.path.exists(fsevents_path):
            try:
                files = os.listdir(fsevents_path)
                for f in files:
                    finfo = os.stat(os.path.join(fsevents_path, f))
                    data.append([f, f"{finfo.st_size} bytes", "Gzipped Log"])
            except PermissionError:
                data.append(["Root Access Required", "N/A", "Please run with sudo/FDA to see log list"])

        self.update_table(["Log Chunk", "Size", "Type"], data)

    def get_messages(self):
        """Parses iMessage/SMS database (chat.db)"""
        db_path = os.path.expanduser("~/Library/Messages/chat.db")
        temp_db = os.path.join(tempfile.gettempdir(), "forensic_chat.db")
        data = []

        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                # Query joins messages with handle (sender)
                query = """
                        SELECT datetime(message.date / 1000000000 + 978307200, 'unixepoch') as date,
                    handle.id,
                    message.text
                        FROM message
                            LEFT JOIN handle \
                        ON message.handle_id = handle.ROWID
                        WHERE message.text IS NOT NULL
                        ORDER BY date DESC LIMIT 100 \
                        """
                cursor.execute(query)
                for row in cursor.fetchall():
                    data.append([row[0], row[1], row[2]])
                conn.close()
                os.remove(temp_db)
            except Exception as e:
                data.append(["N/A", "Error", str(e)])
        else:
            data.append(["N/A", "Not Found", "chat.db missing or restricted"])

        self.update_table(["Timestamp (UTC)", "Sender/Receiver", "Message Content"], data)
    def get_keychain_metadata(self):
        """Lists Keychain files and security settings"""
        paths = [
            os.path.expanduser("~/Library/Keychains"),
            "/Library/Keychains"
        ]
        data = []
        for p in paths:
            if os.path.exists(p):
                for f in os.listdir(p):
                    if f.endswith(".keychain") or f.endswith(".keychain-db"):
                        finfo = os.stat(os.path.join(p, f))
                        data.append([f, p, datetime.fromtimestamp(finfo.st_mtime).strftime('%Y-%m-%d')])
        self.update_table(["Keychain File", "Location", "Last Modified"], data)

    # Update populate_data router
    def populate_data(self):
        mapping = {
            "System Info": self.get_system_info,
            "Running Processes": self.get_processes,
            "Internet History": self.get_internet_history,
            "MRU (Recent Items)":self.get_mru,
            "Unified Logs": self.get_unified_logs,
            "Network & WiFi": self.get_network_info,
            "USB History": self.get_usb_usage_detailed,
            "Users & Groups": self.get_users_with_groups,
            "Installed Apps": self.get_apps,
            "Persistence Items": self.get_persistence_items,
            "Global Preferences": self.get_global_preferences,
            "FSEvents Status": self.get_fsevents_status,
            "Messages (iMessage)": self.get_messages,
            "Spotlight Analysis": self.get_spotlight_analysis,
            "Keychain Info": self.get_keychain_metadata
        }
        if self.name in mapping:
            mapping[self.name]()
    def get_apps(self):
        """Lists applications in the main Applications folder"""
        app_dir = "/Applications"
        data = []
        for item in os.listdir(app_dir):
            if item.endswith(".app"):
                data.append([item, app_dir])
        self.update_table(["App Name", "Path"], data)

    def get_system_info(self):
        cmd = ["system_profiler", "SPHardwareDataType"]
        result = subprocess.check_output(cmd).decode().split('\n')
        data = [[line.split(':')[0].strip(), line.split(':')[-1].strip()] for line in result if ':' in line]
        self.update_table(["Property", "Value"], data)

    def get_processes(self):
        data = [[p.info['pid'], p.info['name'], p.info['username']] for p in
                psutil.process_iter(['pid', 'name', 'username'])]
        self.update_table(["PID", "Name", "User"], data)

    def export_data(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "CSV Files (*.csv)")
        if path:
            import csv
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                headers = [self.table.horizontalHeaderItem(i).text() for i in range(self.table.columnCount())]
                writer.writerow(headers)
                for row in range(self.table.rowCount()):
                    writer.writerow([self.table.item(row, col).text() for col in range(self.table.columnCount())])


class PyForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyForensic for MacOS")
        self.resize(1200, 800)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        # Title Bar
        title_bar = QWidget()
        title_bar.setFixedHeight(50)
        title_bar.setStyleSheet("background-color: #36404A; color: white;")
        t_layout = QHBoxLayout(title_bar)
        lbl = QLabel("PyForensic for MacOS")
        lbl.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        t_layout.addWidget(lbl, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_bar)

        # Body
        body = QHBoxLayout()
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(200)
        items = [
            "System Info", "Running Processes", "Internet History",
            "Persistence Items", "Global Preferences", "FSEvents Status",
            "Messages (iMessage)", "Unified Logs", "Network & WiFi",
            "USB History", "Users & Groups", "Spotlight Analysis"
        ]
        self.sidebar.addItems(items)
        self.sidebar.setFont(QFont("Arial", 16, QFont.Weight.Normal))
        self.sidebar.setStyleSheet("background-color: #3c3f41; color: white;")

        self.stack = QStackedWidget()
        for item in items:
            self.stack.addWidget(ForensicModule(item))

        self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)
        body.addWidget(self.sidebar)
        body.addWidget(self.stack)
        layout.addLayout(body)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = PyForensicApp()
    ex.show()
    sys.exit(app.exec())