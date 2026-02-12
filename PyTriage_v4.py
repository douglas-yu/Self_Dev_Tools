"""
Python PyQt5 GUI for local forensic triage on Windows.

Enhancements:
- Fix services enumeration to skip services that trigger QueryServiceConfig2W
  ("The system cannot find the file specified") instead of crashing.
- Add triage functions:
    * Network connections info
    * User pictures (thumbnails in top panel, large image in bottom panel)
    * Documents list (PDF, Word, Excel, PowerPoint, TXT, LOG)
- Resize main window larger and scale fonts by 1.5x.

Dependencies:
    pip install pyqt5 psutil python-registry

Run:
    python forensic_triage_gui.py
"""

import sys
import os
import csv
import subprocess
import platform
import socket
import tempfile
import shutil
import sqlite3
from datetime import datetime, timedelta

import psutil

try:
    import winreg  # Windows-only
except ImportError:
    winreg = None

from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QSplitter,
    QMessageBox,
    QFileDialog,
    QLabel,
    QHeaderView,
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QStackedWidget,
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QPixmap, QIcon


class TriageMainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Local Forensic Triage")
        # Larger window
        self.resize(1800, 1000)

        self._build_ui()

    def _build_ui(self):
        splitter = QSplitter()
        splitter.setOrientation(Qt.Horizontal)

        # -----------------------
        # Left panel (buttons)
        # -----------------------
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(5, 5, 5, 5)
        left_layout.setSpacing(4)

        title_label = QLabel("Triage Functions")
        title_label.setStyleSheet("font-weight: bold;")
        left_layout.addWidget(title_label)

        buttons = [
            ("System Information", self.run_system_info),
            ("Processes", self.run_processes),
            ("Services", self.run_services),
            ("Scheduled Tasks", self.run_scheduled_tasks),
            ("Autoruns", self.run_autoruns),
            ("Network Connections", self.run_network_connections),
            ("Internet History (URLs & Time)", self.run_internet_history),
            ("Registry Hive Analysis (Offline)", self.run_registry_analysis),
            ("USB Connection Details", self.run_usb_history),
            ("Prefetch Files", self.run_prefetch),
            ("Shimcache (stub)", self.run_shimcache_stub),
            ("Users && Groups", self.run_users_and_groups),
            ("User Pictures", self.run_user_pictures),
            ("Documents List", self.run_documents_list),
        ]

        for label, handler in buttons:
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            left_layout.addWidget(btn)

        left_layout.addStretch(1)

        # -----------------------
        # Right panel (stack: table view / picture view)
        # -----------------------
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(5, 5, 5, 5)

        self.status_label = QLabel("Ready.")
        self.status_label.setStyleSheet("font-weight: bold;")

        self.stack = QStackedWidget()

        # --- Page 0: table view (grid results + export) ---
        table_page = QWidget()
        tp_layout = QVBoxLayout(table_page)
        tp_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(0)
        self.table.setRowCount(0)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setSortingEnabled(True)

        export_btn = QPushButton("Export Current Result to CSV")
        export_btn.clicked.connect(self.export_current_table)

        tp_layout.addWidget(self.table)
        tp_layout.addWidget(export_btn)

        # --- Page 1: picture view (thumbnails top, large image bottom) ---
        pictures_page = QWidget()
        pp_layout = QVBoxLayout(pictures_page)
        pp_layout.setContentsMargins(0, 0, 0, 0)

        self.thumbnail_list = QListWidget()
        self.thumbnail_list.setViewMode(QListWidget.IconMode)
        self.thumbnail_list.setIconSize(QSize(96, 96))
        self.thumbnail_list.setResizeMode(QListWidget.Adjust)
        self.thumbnail_list.setMovement(QListWidget.Static)
        self.thumbnail_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.thumbnail_list.itemSelectionChanged.connect(self.show_selected_picture)

        self.image_label = QLabel("Selected image will appear here.")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setMinimumHeight(250)
        self.image_label.setStyleSheet("border: 1px solid #888;")

        pp_layout.addWidget(self.thumbnail_list, stretch=1)
        pp_layout.addWidget(self.image_label, stretch=2)

        # Add pages to stack
        self.stack.addWidget(table_page)     # index 0
        self.stack.addWidget(pictures_page)  # index 1

        right_layout.addWidget(self.status_label)
        right_layout.addWidget(self.stack)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(1, 4)

        self.setCentralWidget(splitter)

        # start in table mode
        self.show_table_mode()

    # ---------------------------
    # View mode helpers
    # ---------------------------
    def show_table_mode(self):
        self.stack.setCurrentIndex(0)

    def show_pictures_mode(self):
        self.stack.setCurrentIndex(1)

    # ---------------------------
    # Generic helpers
    # ---------------------------
    def set_status(self, text: str):
        self.status_label.setText(text)

    def show_error(self, title: str, message: str):
        QMessageBox.critical(self, title, message)

    def populate_table(self, columns, rows):
        """
        columns: list of column names
        rows: list of dicts or sequences
        """
        self.show_table_mode()
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.table.setColumnCount(len(columns))
        self.table.setRowCount(len(rows))
        self.table.setHorizontalHeaderLabels(columns)

        for r_idx, row in enumerate(rows):
            if isinstance(row, dict):
                for c_idx, col in enumerate(columns):
                    value = row.get(col, "")
                    self.table.setItem(r_idx, c_idx, QTableWidgetItem(str(value)))
            else:
                for c_idx, value in enumerate(row):
                    if c_idx >= len(columns):
                        break
                    self.table.setItem(r_idx, c_idx, QTableWidgetItem(str(value)))

        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)

    def export_current_table(self):
        self.show_table_mode()
        if self.table.rowCount() == 0 or self.table.columnCount() == 0:
            QMessageBox.information(self, "Export", "No data to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save CSV",
            f"triage_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                headers = [
                    self.table.horizontalHeaderItem(i).text()
                    for i in range(self.table.columnCount())
                ]
                writer.writerow(headers)
                for r in range(self.table.rowCount()):
                    row = []
                    for c in range(self.table.columnCount()):
                        item = self.table.item(r, c)
                        row.append(item.text() if item else "")
                    writer.writerow(row)
            QMessageBox.information(self, "Export", f"Exported to {path}")
        except Exception as e:
            self.show_error("Export Error", str(e))

    # ---------------------------
    # Core triage functions
    # ---------------------------
    def run_system_info(self):
        try:
            self.set_status("Collecting system information...")
            cols = ["Key", "Value"]
            data = []

            data.append(("Hostname", socket.gethostname()))
            data.append(("Platform", platform.platform()))
            data.append(("System", platform.system()))
            data.append(("Release", platform.release()))
            data.append(("Version", platform.version()))
            data.append(("Architecture", " ".join(platform.architecture())))
            data.append(("Processor", platform.processor()))
            data.append(("CPU Count (logical)", psutil.cpu_count(logical=True)))
            data.append(("CPU Count (physical)", psutil.cpu_count(logical=False)))
            vm = psutil.virtual_memory()
            data.append(("RAM Total (GB)", round(vm.total / (1024 ** 3), 2)))
            data.append(("RAM Used (GB)", round(vm.used / (1024 ** 3), 2)))
            data.append(("RAM Percent", vm.percent))

            self.populate_table(cols, data)
            self.set_status("System information collected.")
        except Exception as e:
            self.show_error("System Info Error", str(e))

    def run_processes(self):
        try:
            self.set_status("Enumerating processes...")
            cols = ["PID", "Name", "Username", "Create Time", "Exe", "Cmdline"]
            rows = []

            for p in psutil.process_iter(
                ["pid", "name", "username", "create_time", "exe", "cmdline"]
            ):
                info = p.info
                try:
                    create_time = (
                        datetime.fromtimestamp(info.get("create_time", 0)).isoformat()
                        if info.get("create_time")
                        else ""
                    )
                except Exception:
                    create_time = ""

                rows.append(
                    [
                        info.get("pid", ""),
                        info.get("name", ""),
                        info.get("username", ""),
                        create_time,
                        info.get("exe", ""),
                        " ".join(info.get("cmdline", []) or []),
                    ]
                )

            self.populate_table(cols, rows)
            self.set_status(f"Processes enumerated: {len(rows)}")
        except Exception as e:
            self.show_error("Processes Error", str(e))

    def run_services(self):
        """
        Robust services enumeration.
        Skips services that trigger QueryServiceConfig2W / "system cannot find file"
        errors instead of crashing.
        """
        if not hasattr(psutil, "win_service_iter"):
            self.show_error(
                "Services",
                "Service enumeration is only supported on Windows.",
            )
            return

        try:
            self.set_status("Enumerating Windows services...")
            cols = ["Name", "Display Name", "Status", "Start Type", "BinPath", "Error"]
            rows = []

            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    rows.append(
                        [
                            info.get("name", ""),
                            info.get("display_name", ""),
                            info.get("status", ""),
                            info.get("start_type", ""),
                            info.get("binpath", ""),
                            "",
                        ]
                    )
                except Exception as e:
                    rows.append(
                        [
                            getattr(svc, "name", lambda: "")(),
                            getattr(svc, "display_name", lambda: "")(),
                            "",
                            "",
                            "",
                            str(e),
                        ]
                    )

            self.populate_table(cols, rows)
            self.set_status(f"Services enumerated (including errors): {len(rows)}")
        except Exception as e:
            self.show_error("Services Error", str(e))

    def run_scheduled_tasks(self):
        if platform.system().lower() != "windows":
            self.show_error(
                "Scheduled Tasks",
                "Scheduled tasks enumeration is only supported on Windows.",
            )
            return

        try:
            self.set_status("Enumerating scheduled tasks via schtasks...")
            proc = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                errors="ignore",
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr or "schtasks failed")

            lines = proc.stdout.splitlines()
            reader = csv.reader(lines)
            rows = list(reader)
            if not rows:
                self.populate_table([], [])
                self.set_status("No scheduled tasks found (or parsing failed).")
                return

            header = rows[0]
            data_rows = rows[1:]
            self.populate_table(header, data_rows)
            self.set_status(f"Scheduled tasks enumerated: {len(data_rows)}")
        except Exception as e:
            self.show_error("Scheduled Tasks Error", str(e))

    def run_autoruns(self):
        if platform.system().lower() != "windows" or winreg is None:
            self.show_error(
                "Autoruns",
                "Autoruns via Registry is only supported on Windows.",
            )
            return

        self.set_status("Collecting autorun entries from Run keys...")

        run_keys = [
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
        ]

        rows = []
        cols = ["Hive", "Key", "Value Name", "Command"]

        try:
            for hive, key_path in run_keys:
                try:
                    with winreg.OpenKey(hive, key_path) as k:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(k, i)
                                hive_name = (
                                    "HKLM"
                                    if hive == winreg.HKEY_LOCAL_MACHINE
                                    else "HKCU"
                                )
                                rows.append([hive_name, key_path, name, value])
                                i += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    continue

            self.populate_table(cols, rows)
            self.set_status(f"Autorun entries found: {len(rows)}")
        except Exception as e:
            self.show_error("Autoruns Error", str(e))

    # ---------------------------
    # Network connections
    # ---------------------------
    def run_network_connections(self):
        self.set_status("Collecting network connections (inet)...")
        cols = [
            "FD",
            "Family",
            "Type",
            "Local Address",
            "Local Port",
            "Remote Address",
            "Remote Port",
            "Status",
            "PID",
            "Process Name",
        ]
        rows = []

        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                try:
                    family = str(c.family).split(".")[-1]
                    typ = str(c.type).split(".")[-1]
                    laddr_ip, laddr_port = ("", 0)
                    raddr_ip, raddr_port = ("", 0)

                    if c.laddr:
                        laddr_ip = c.laddr.ip if hasattr(c.laddr, "ip") else c.laddr[0]
                        laddr_port = c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]
                    if c.raddr:
                        raddr_ip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
                        raddr_port = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]

                    pid = c.pid or 0
                    pname = ""
                    if pid:
                        try:
                            pname = psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pname = ""

                    rows.append(
                        [
                            c.fd,
                            family,
                            typ,
                            laddr_ip,
                            laddr_port,
                            raddr_ip,
                            raddr_port,
                            c.status,
                            pid,
                            pname,
                        ]
                    )
                except Exception:
                    continue

            self.populate_table(cols, rows)
            self.set_status(f"Network connections collected: {len(rows)}")
        except Exception as e:
            self.show_error("Network Connections Error", str(e))

    # ---------------------------
    # Internet history (Chrome / Edge)
    # ---------------------------
    @staticmethod
    def chrome_history_paths():
        """Return (browser, path) tuples for known Chromium history DBs."""
        paths = []
        local_app_data = os.environ.get("LOCALAPPDATA")

        if local_app_data:
            chrome_hist = os.path.join(
                local_app_data, "Google", "Chrome", "User Data", "Default", "History"
            )
            if os.path.exists(chrome_hist):
                paths.append(("Chrome", chrome_hist))

            edge_hist = os.path.join(
                local_app_data,
                "Microsoft",
                "Edge",
                "User Data",
                "Default",
                "History",
            )
            if os.path.exists(edge_hist):
                paths.append(("Edge", edge_hist))

        return paths

    @staticmethod
    def chrome_time_to_iso(chrome_ts):
        """
        Convert Chrome/WebKit timestamp (microseconds since 1601-01-01 UTC)
        to ISO8601 string.
        """
        if not chrome_ts:
            return ""
        try:
            epoch_start = datetime(1601, 1, 1)
            dt = epoch_start + timedelta(microseconds=chrome_ts)
            return dt.isoformat() + "Z"
        except Exception:
            return str(chrome_ts)

    def run_internet_history(self):
        if platform.system().lower() != "windows":
            self.show_error(
                "Internet History",
                "This implementation is tailored for Windows Chrome/Edge profiles.",
            )
            return

        try:
            self.set_status("Collecting internet history (Chrome/Edge)...")
            cols = ["Browser", "URL", "Title", "Visit Time (UTC)"]
            rows = []

            for browser, hist_path in self.chrome_history_paths():
                try:
                    temp_dir = tempfile.mkdtemp(prefix="triage_hist_")
                    temp_db = os.path.join(temp_dir, f"{browser}_History")
                    shutil.copy2(hist_path, temp_db)

                    conn = sqlite3.connect(temp_db)
                    cur = conn.cursor()
                    cur.execute(
                        """
                        SELECT url, title, last_visit_time
                        FROM urls
                        ORDER BY last_visit_time DESC
                        LIMIT 2000
                        """
                    )
                    for url, title, ts in cur.fetchall():
                        rows.append(
                            [
                                browser,
                                url,
                                title,
                                self.chrome_time_to_iso(ts),
                            ]
                        )

                    conn.close()
                except Exception as e:
                    rows.append(
                        [
                            browser,
                            f"[Error reading history DB: {e}]",
                            "",
                            "",
                        ]
                    )
                finally:
                    try:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    except Exception:
                        pass

            self.populate_table(cols, rows)
            self.set_status(f"Internet history rows: {len(rows)}")
        except Exception as e:
            self.show_error("Internet History Error", str(e))

    # ---------------------------
    # Registry hive analysis (offline, python-registry)
    # ---------------------------
    def run_registry_analysis(self):
        if platform.system().lower() != "windows":
            self.show_error(
                "Registry Analysis",
                "Designed primarily for Windows offline hives.",
            )

        try:
            hive_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Registry Hive (e.g. SYSTEM, SOFTWARE)",
                "",
                "Registry Hives (*.dat *.hiv *.*)",
            )
            if not hive_path:
                return

            try:
                from Registry import Registry  # python-registry
            except ImportError:
                self.show_error(
                    "Registry Analysis",
                    "python-registry not installed. Install via:\n"
                    "  pip install python-registry",
                )
                return

            self.set_status(f"Parsing hive: {hive_path}")
            cols = ["Key Path", "Value Name", "Value Type", "Value Data"]
            rows = []

            def walk_key(key, limit=8000):
                stack = [key]
                while stack and len(rows) < limit:
                    k = stack.pop()
                    key_path = k.path()
                    for v in k.values():
                        try:
                            value_data = v.value()
                        except Exception:
                            value_data = "<unreadable>"

                        rows.append(
                            [
                                key_path,
                                v.name(),
                                v.value_type_str(),
                                str(value_data),
                            ]
                        )
                        if len(rows) >= limit:
                            break

                    for sub in k.subkeys():
                        stack.append(sub)

            try:
                reg = Registry.Registry(hive_path)
                walk_key(reg.root())
            except Exception as e:
                self.show_error("Registry Analysis Error", str(e))
                return

            self.populate_table(cols, rows)
            self.set_status(
                f"Registry hive parsed: {len(rows)} values (truncated to max 8000)."
            )
        except Exception as e:
            self.show_error("Registry Analysis Error", str(e))

    # ---------------------------
    # USB connection details
    # ---------------------------
    @staticmethod
    def _usb_parse_dev_class(dev_class: str):
        """
        Attempt to parse vendor/product/revision from a USBSTOR device class
        string such as 'Disk&Ven_VENDOR&Prod_PRODUCT&Rev_1.00'.
        """
        vendor = ""
        product = ""
        revision = ""

        parts = dev_class.split("&")
        for p in parts:
            up = p.upper()
            if up.startswith("VEN_"):
                vendor = p[4:]
            elif up.startswith("PROD_"):
                product = p[5:]
            elif up.startswith("REV_"):
                revision = p[4:]

        return vendor, product, revision

    @staticmethod
    def _winreg_key_lastwrite_utc(key) -> str:
        """
        Convert winreg.QueryInfoKey last_modified to ISO8601 UTC
        (Windows stores seconds since 1601-01-01).
        """
        try:
            _, _, last_modified = winreg.QueryInfoKey(key)
            base = datetime(1601, 1, 1)
            dt = base + timedelta(seconds=last_modified)
            return dt.isoformat() + "Z"
        except Exception:
            return ""

    def run_usb_history(self):
        if platform.system().lower() != "windows" or winreg is None:
            self.show_error(
                "USB Connection Details",
                "USB history via Registry is only supported on Windows.",
            )
            return

        self.set_status("Collecting USBSTOR-based USB connection details...")

        base_paths = [
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        ]
        rows = []
        cols = [
            "Device Class",
            "Instance",
            "Vendor",
            "Product",
            "Revision",
            "Serial (from Instance)",
            "Friendly Name",
            "Parent ID",
            "Service",
            "Key LastWrite (UTC)",
        ]

        try:
            for base_path in base_paths:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, base_path
                    ) as base_key:
                        i = 0
                        while True:
                            try:
                                dev_class = winreg.EnumKey(base_key, i)
                                i += 1
                            except OSError:
                                break

                            dev_class_path = f"{base_path}\\{dev_class}"
                            try:
                                with winreg.OpenKey(
                                    winreg.HKEY_LOCAL_MACHINE, dev_class_path
                                ) as class_key:
                                    j = 0
                                    while True:
                                        try:
                                            instance = winreg.EnumKey(class_key, j)
                                            j += 1
                                        except OSError:
                                            break

                                        instance_path = f"{dev_class_path}\\{instance}"
                                        try:
                                            with winreg.OpenKey(
                                                winreg.HKEY_LOCAL_MACHINE,
                                                instance_path,
                                            ) as inst_key:
                                                vendor, product, revision = (
                                                    self._usb_parse_dev_class(dev_class)
                                                )

                                                serial = instance.split("&")[0]

                                                try:
                                                    friendly, _ = winreg.QueryValueEx(
                                                        inst_key, "FriendlyName"
                                                    )
                                                except FileNotFoundError:
                                                    friendly = ""
                                                try:
                                                    parent, _ = winreg.QueryValueEx(
                                                        inst_key, "ParentIdPrefix"
                                                    )
                                                except FileNotFoundError:
                                                    parent = ""
                                                try:
                                                    service, _ = winreg.QueryValueEx(
                                                        inst_key, "Service"
                                                    )
                                                except FileNotFoundError:
                                                    service = ""

                                                lastwrite = self._winreg_key_lastwrite_utc(
                                                    inst_key
                                                )

                                                rows.append(
                                                    [
                                                        dev_class,
                                                        instance,
                                                        vendor,
                                                        product,
                                                        revision,
                                                        serial,
                                                        friendly,
                                                        parent,
                                                        service,
                                                        lastwrite,
                                                    ]
                                                )
                                        except FileNotFoundError:
                                            continue
                            except FileNotFoundError:
                                continue
                except FileNotFoundError:
                    continue

            self.populate_table(cols, rows)
            self.set_status(f"USBSTOR records found: {len(rows)}")
        except Exception as e:
            self.show_error("USB History Error", str(e))

    # ---------------------------
    # Prefetch
    # ---------------------------
    def run_prefetch(self):
        if platform.system().lower() != "windows":
            self.show_error(
                "Prefetch",
                "Prefetch directory is only standard on Windows.",
            )
            return

        prefetch_dir = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "Prefetch",
        )
        self.set_status(f"Listing Prefetch files in: {prefetch_dir}")

        cols = ["Filename", "Size (KB)", "Modified Time", "Full Path"]
        rows = []
        try:
            if not os.path.isdir(prefetch_dir):
                self.show_error(
                    "Prefetch", f"Prefetch directory not found: {prefetch_dir}"
                )
                return

            for name in os.listdir(prefetch_dir):
                full_path = os.path.join(prefetch_dir, name)
                if not os.path.isfile(full_path):
                    continue
                stat = os.stat(full_path)
                size_kb = round(stat.st_size / 1024, 2)
                mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
                rows.append([name, size_kb, mtime, full_path])

            self.populate_table(cols, rows)
            self.set_status(f"Prefetch files listed: {len(rows)}")
        except Exception as e:
            self.show_error("Prefetch Error", str(e))

    # ---------------------------
    # Shimcache stub
    # ---------------------------
    def run_shimcache_stub(self):
        """
        Placeholder for Shimcache (AppCompatCache) parsing.
        Typically requires parsing SYSTEM hive; integrate your own parser here.
        """
        self.set_status("Shimcache stub - connect to your AppCompatCache parser.")
        cols = ["Path", "Last Modified", "Execution Flag", "Source"]
        rows = [
            [r"C:\Example\malware.exe", "2020-01-01T00:00:00Z", "Unknown", "Stub"],
        ]
        self.populate_table(cols, rows)

    # ---------------------------
    # Users & Groups (local)
    # ---------------------------
    def run_users_and_groups(self):
        if platform.system().lower() != "windows":
            self.show_error(
                "Users & Groups",
                "This implementation uses 'net' commands (Windows only).",
            )
            return

        self.set_status("Collecting local users and groups via 'net' commands...")
        cols = ["Type", "Name"]
        rows = []

        def parse_net_list(cmd, type_label):
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    errors="ignore",
                )
                if proc.returncode != 0:
                    return []

                lines = proc.stdout.splitlines()
                data_started = False
                names = []
                for line in lines:
                    if "----" in line:
                        data_started = True
                        continue
                    if not data_started:
                        continue
                    if "The command completed successfully." in line:
                        break
                    parts = [p.strip() for p in line.split() if p.strip()]
                    names.extend(parts)
                return [[type_label, name] for name in names]
            except Exception:
                return []

        rows.extend(parse_net_list(["net", "user"], "User"))
        rows.extend(parse_net_list(["net", "localgroup"], "Group"))

        self.populate_table(cols, rows)
        self.set_status(f"Users & groups entries: {len(rows)}")

    # ---------------------------
    # User pictures (thumbnails top, large image bottom)
    # ---------------------------
    def run_user_pictures(self):
        """
        Load images from the user's Pictures folders and show:
        - Thumbnails in the top panel (icon grid)
        - Large selected image in the bottom panel
        """
        self.show_pictures_mode()
        self.set_status("Loading user pictures...")
        self.thumbnail_list.clear()
        self.image_label.clear()
        self.image_label.setText("Selected image will appear here.")

        user_profile = os.environ.get("USERPROFILE", "")
        bases = []
        if user_profile:
            bases.append(os.path.join(user_profile, "Pictures"))
            bases.append(os.path.join(user_profile, "My Pictures"))

        exts = {".jpg", ".jpeg", ".png", ".bmp", ".gif"}
        max_images = 500
        count = 0

        for base in bases:
            if not base or not os.path.isdir(base):
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    if count >= max_images:
                        break
                    ext = os.path.splitext(name)[1].lower()
                    if ext not in exts:
                        continue
                    full_path = os.path.join(root, name)
                    pixmap = QPixmap(full_path)
                    if pixmap.isNull():
                        continue
                    thumb = pixmap.scaled(
                        self.thumbnail_list.iconSize(),
                        Qt.KeepAspectRatio,
                        Qt.SmoothTransformation,
                    )
                    item = QListWidgetItem(QIcon(thumb), name)
                    item.setData(Qt.UserRole, full_path)
                    self.thumbnail_list.addItem(item)
                    count += 1
                if count >= max_images:
                    break
            if count >= max_images:
                break

        self.set_status(f"Loaded {count} picture thumbnails.")

    def show_selected_picture(self):
        """
        Show full-size version of the selected thumbnail in the bottom panel.
        """
        if self.stack.currentIndex() != 1:
            return

        item = self.thumbnail_list.currentItem()
        if not item:
            return
        path = item.data(Qt.UserRole)
        if not path or not os.path.exists(path):
            self.image_label.setText("Image not found.")
            self.image_label.setPixmap(QPixmap())
            return

        pixmap = QPixmap(path)
        if pixmap.isNull():
            self.image_label.setText("Unable to load image.")
            self.image_label.setPixmap(QPixmap())
            return

        label_size = self.image_label.size()
        if label_size.width() <= 0 or label_size.height() <= 0:
            scaled = pixmap
        else:
            scaled = pixmap.scaled(
                label_size, Qt.KeepAspectRatio, Qt.SmoothTransformation
            )

        self.image_label.setPixmap(scaled)
        self.image_label.setText("")

    # ---------------------------
    # Documents list
    # ---------------------------
    def run_documents_list(self):
        """
        List documents under common user folders (Documents, Desktop, Downloads):
        PDF, Word, Excel, PowerPoint, TXT, LOG.
        """
        self.set_status("Collecting documents from user profile...")
        cols = ["Filename", "Extension", "Size (KB)", "Modified Time", "Full Path"]
        rows = []

        user_profile = os.environ.get("USERPROFILE", "")
        bases = []
        if user_profile:
            bases.append(os.path.join(user_profile, "Documents"))
            bases.append(os.path.join(user_profile, "Desktop"))
            bases.append(os.path.join(user_profile, "Downloads"))

        exts = {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".txt",
            ".log",
        }
        max_files = 10000
        count = 0

        try:
            for base in bases:
                if not base or not os.path.isdir(base):
                    continue
                for root, _, files in os.walk(base):
                    for name in files:
                        if count >= max_files:
                            break
                        ext = os.path.splitext(name)[1].lower()
                        if ext not in exts:
                            continue
                        full_path = os.path.join(root, name)
                        try:
                            st = os.stat(full_path)
                        except Exception:
                            continue
                        size_kb = round(st.st_size / 1024, 2)
                        mtime = datetime.fromtimestamp(st.st_mtime).isoformat()
                        rows.append([name, ext, size_kb, mtime, full_path])
                        count += 1
                    if count >= max_files:
                        break
                if count >= max_files:
                    break

            self.populate_table(cols, rows)
            self.set_status(f"Documents listed: {len(rows)} (max {max_files})")
        except Exception as e:
            self.show_error("Documents List Error", str(e))


def main():
    app = QApplication(sys.argv)

    # Scale global font by 1.5x
    font = app.font()
    size = font.pointSizeF()
    if size <= 0:
        size = 10
    font.setPointSizeF(size * 1.2)
    app.setFont(font)

    win = TriageMainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
