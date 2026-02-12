import sys
import sqlite3
import threading
from queue import Queue, Empty
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from datetime import datetime
import csv

import requests
from bs4 import BeautifulSoup

from PyQt6.QtCore import (
    Qt,
    QObject,
    pyqtSignal,
    QThread,
    QPoint,
)
from PyQt6.QtGui import (
    QStandardItemModel,
    QStandardItem,
    QColor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QSplitter,
    QTreeView,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTabWidget,
    QTextEdit,
    QMessageBox,
    QCheckBox,
    QMenu,
    QAbstractItemView,
    QComboBox,
)

# -------------------------------------------------
# Data Model
# -------------------------------------------------

class ScanResult:
    def __init__(self, url, method, status_code, request_raw, response_raw, vulns):
        self.url = url
        self.method = method
        self.status_code = status_code
        self.request_raw = request_raw
        self.response_raw = response_raw
        self.vulns = vulns  # list[str]

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "vulnerabilities": self.vulns,
        }

# -------------------------------------------------
# SQLite Persistence
# -------------------------------------------------

class DatabaseManager:
    def __init__(self, filename="scan_results.db"):
        self.conn = sqlite3.connect(filename)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                method TEXT,
                status_code INTEGER,
                has_vuln INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS page_details (
                page_id INTEGER PRIMARY KEY,
                request_raw TEXT,
                response_raw TEXT,
                FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE CASCADE
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER,
                description TEXT,
                FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE CASCADE
            )
            """
        )
        self.conn.commit()

    def save_result(self, result: ScanResult):
        cur = self.conn.cursor()
        has_vuln = 1 if result.vulns else 0

        cur.execute(
            """
            INSERT OR IGNORE INTO pages (url, method, status_code, has_vuln)
            VALUES (?, ?, ?, ?)
            """,
            (result.url, result.method, result.status_code, has_vuln),
        )
        cur.execute(
            """
            UPDATE pages
            SET method = ?, status_code = ?, has_vuln = ?
            WHERE url = ?
            """,
            (result.method, result.status_code, has_vuln, result.url),
        )

        cur.execute("SELECT id FROM pages WHERE url = ?", (result.url,))
        row = cur.fetchone()
        if not row:
            self.conn.commit()
            return
        page_id = row[0]

        cur.execute(
            """
            INSERT OR REPLACE INTO page_details (page_id, request_raw, response_raw)
            VALUES (?, ?, ?)
            """,
            (page_id, result.request_raw, result.response_raw),
        )

        cur.execute("DELETE FROM vulnerabilities WHERE page_id = ?", (page_id,))
        for v in result.vulns:
            cur.execute(
                "INSERT INTO vulnerabilities (page_id, description) VALUES (?, ?)",
                (page_id, v),
            )

        self.conn.commit()

    def close(self):
        self.conn.close()

# -------------------------------------------------
# Scanner Worker (QThread + internal worker threads)
# -------------------------------------------------

class ScannerWorker(QObject):
    progress = pyqtSignal(str)
    url_discovered = pyqtSignal(str)
    scan_result = pyqtSignal(object)  # ScanResult
    finished = pyqtSignal()

    def __init__(
        self,
        start_url,
        max_depth=2,
        timeout=5,
        allowed_domains=None,
        ignore_patterns=None,
        max_workers=5,
        max_active_tests=20,
    ):
        super().__init__()
        self.start_url = start_url
        self.max_depth = max_depth
        self.timeout = timeout
        self.max_workers = max_workers
        self.max_active_tests = max_active_tests

        self.stop_flag = False
        self.session = requests.Session()
        self.visited = set()
        self.active_tests_run = 0

        parsed = urlparse(start_url)
        default_domain = parsed.netloc
        self.allowed_domains = allowed_domains or [default_domain]
        if default_domain not in self.allowed_domains:
            self.allowed_domains.append(default_domain)

        self.ignore_patterns = ignore_patterns or []

        # queue reference for cancellation
        self.queue = None

    def stop(self):
        self.stop_flag = True
        # Drain queue so q.join() can finish quickly
        if self.queue is not None:
            try:
                while True:
                    try:
                        _item = self.queue.get_nowait()
                        self.queue.task_done()
                    except Empty:
                        break
            except Exception:
                pass

    def log(self, msg: str):
        self.progress.emit(msg)

    # ---------------------------
    # Passive vulnerability checks
    # ---------------------------
    def passive_checks(self, url, method, req, resp):
        vulns = []
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "pg_query()",
        ]
        lower_body = resp.text.lower()

        if any(err in lower_body for err in sql_errors):
            vulns.append("Possible SQL Injection (SQL error in response)")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for k, vs in qs.items():
            for v in vs:
                if v and v in resp.text:
                    vulns.append(f"Possible reflected XSS on parameter '{k}'")

        cmd_indicators = ["root:x:0:0:", "uid=0(", "bin/sh", "bin/bash"]
        if any(ind in lower_body for ind in cmd_indicators):
            vulns.append("Possible Command Injection (OS output patterns found)")

        if "../" in parsed.path or "%2e%2e%2f" in parsed.path.lower():
            if "root:x:0:0:" in lower_body or "[extensions]" in lower_body:
                vulns.append("Possible Path Traversal")

        ssrf_keywords = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"]
        if any(k in url for k in ssrf_keywords):
            vulns.append("Possible SSRF (URL targets internal/metadata host)")

        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            cookies = set_cookie.split(",")
            for c in cookies:
                if "session" in c.lower():
                    if "httponly" not in c.lower():
                        vulns.append("Weak Session Management (session cookie missing HttpOnly)")
                    if "secure" not in c.lower() and parsed.scheme == "https":
                        vulns.append("Weak Session Management (session cookie missing Secure)")

        try:
            if "text/html" in resp.headers.get("Content-Type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form")
                for form in forms:
                    method_attr = form.get("method", "get").lower()
                    if method_attr == "post":
                        inputs = form.find_all("input")
                        has_token = any(
                            "csrf" in (inp.get("name", "").lower())
                            or "token" in (inp.get("name", "").lower())
                            for inp in inputs
                        )
                        if not has_token:
                            vulns.append("Possible CSRF (POST form without CSRF token field)")
                            break
        except Exception:
            pass

        return sorted(set(vulns))

    # ---------------------------
    # Active tests on query parameters
    # ---------------------------
    def run_active_tests(self, url):
        vulns = []
        if self.active_tests_run >= self.max_active_tests:
            return vulns

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return vulns

        base_params = {k: v[:] for k, v in qs.items()}

        payload_sets = {
            "SQLi": ["' OR '1'='1", "\" OR \"1\"=\"1"],
            "XSS": ['<script>alert(1)</script>'],
            "CMD": [';id', '&&id'],
            "Traversal": ['../../../../etc/passwd'],
        }

        for param in list(base_params.keys()):
            for category, payloads in payload_sets.items():
                for payload in payloads:
                    if self.active_tests_run >= self.max_active_tests or self.stop_flag:
                        return sorted(set(vulns))

                    new_params = {k: v[:] for k, v in base_params.items()}
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    mutated = parsed._replace(query=new_query)
                    test_url = urlunparse(mutated)

                    if any(p in test_url for p in self.ignore_patterns):
                        continue

                    try:
                        self.log(f"Active test [{category}] param={param} on {test_url}")
                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                        self.active_tests_run += 1
                    except Exception as e:
                        self.log(f"Active test error on {test_url}: {e}")
                        continue

                    test_vulns = self.passive_checks(test_url, "GET", resp.request, resp)
                    for tv in test_vulns:
                        vulns.append(f"{tv} (active test param={param}, payload={category})")

        return sorted(set(vulns))

    # ---------------------------
    # Single URL processing
    # ---------------------------
    def process_url(self, url, depth, queue_obj: Queue):
        if self.stop_flag:
            return
        if depth > self.max_depth:
            return

        if url in self.visited:
            return
        self.visited.add(url)

        if any(pat in url for pat in self.ignore_patterns):
            self.log(f"Skipping (ignore pattern): {url}")
            return

        self.log(f"Crawling: {url}")
        self.url_discovered.emit(url)

        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
        except Exception as e:
            self.log(f"Error requesting {url}: {e}")
            return

        passive_vulns = self.passive_checks(url, "GET", resp.request, resp)
        active_vulns = self.run_active_tests(url)
        all_vulns = sorted(set(passive_vulns + active_vulns))

        result = self.build_result(url, "GET", resp.request, resp, all_vulns)
        self.scan_result.emit(result)

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type and depth < self.max_depth and not self.stop_flag:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    link = a["href"]
                    absolute = urljoin(url, link)
                    parsed_link = urlparse(absolute)

                    if parsed_link.netloc not in self.allowed_domains:
                        continue

                    full_url = urlunparse(parsed_link)

                    if any(p in full_url for p in self.ignore_patterns):
                        continue

                    if full_url not in self.visited:
                        queue_obj.put((full_url, depth + 1))
            except Exception as e:
                self.log(f"Error parsing HTML at {url}: {e}")

    def build_result(self, url, method, req, resp, vulns):
        req_headers = "\r\n".join(f"{k}: {v}" for k, v in req.headers.items())
        request_line = f"{req.method} {req.path_url} HTTP/1.1"
        if req.body:
            if isinstance(req.body, bytes):
                body = req.body.decode(errors="replace")
            else:
                body = str(req.body)
        else:
            body = ""
        request_raw = f"{request_line}\r\n{req_headers}\r\n\r\n{body}"

        status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"
        resp_headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        response_raw = f"{status_line}\r\n{resp_headers}\r\n\r\n{resp.text}"

        return ScanResult(
            url=url,
            method=method,
            status_code=resp.status_code,
            request_raw=request_raw,
            response_raw=response_raw,
            vulns=vulns,
        )

    def run(self):
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.log(f"Starting scan at {self.start_url}")
        q = Queue()
        self.queue = q  # allow stop() to drain
        q.put((self.start_url, 0))

        def worker():
            while not self.stop_flag:
                try:
                    url, depth = q.get(timeout=0.5)
                except Empty:
                    break
                try:
                    self.process_url(url, depth, q)
                finally:
                    q.task_done()

        threads = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=worker, daemon=True)
            threads.append(t)
            t.start()

        q.join()
        self.log("Scan finished.")
        self.finished.emit()

# -------------------------------------------------
# Main Window / GUI
# -------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Web Application Scanner")
        self.resize(1500, 900)

        self.db = DatabaseManager()

        self.scanner_thread = None
        self.scanner_worker = None

        self.all_results = []
        self.scan_results_by_row = {}
        self.vuln_results = []
        self.vuln_results_by_row = {}
        self.exploit_results = []
        self.exploit_results_by_row = {}

        self.tree_filter_prefix = None

        self.manual_session = requests.Session()

        self._build_ui()

    # ---------------------------
    # UI construction
    # ---------------------------

    def _build_ui(self):
        central = QWidget()
        main_layout = QVBoxLayout()
        central.setLayout(main_layout)
        self.setCentralWidget(central)

        # Top title bar
        title_widget = QWidget()
        title_layout = QHBoxLayout()
        title_widget.setLayout(title_layout)
        title_widget.setStyleSheet("background-color: rgb(30, 30, 30);")

        title_layout.addStretch()
        title_label = QLabel("Web Application Scanner")
        title_label.setStyleSheet("font-size: 20px; font-weight:bold;color: rgb(255, 255, 255)")


        title_layout.addWidget(title_label)
        title_layout.addStretch()

        right_label = QLabel("GM ISRM Inside Risk Tool")
        right_label.setStyleSheet("font-size: 14px; font-weight: bold;color: white")
        title_layout.addWidget(right_label)

        main_layout.addWidget(title_widget)

        # Top controls
        controls_widget = QWidget()
        controls_layout = QHBoxLayout()
        controls_widget.setLayout(controls_layout)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com/")

        self.max_depth_edit = QLineEdit("2")
        self.max_depth_edit.setFixedWidth(40)

        self.allowed_domains_edit = QLineEdit()
        self.allowed_domains_edit.setPlaceholderText("allowed domains (comma-separated, optional)")

        self.ignore_patterns_edit = QLineEdit()
        self.ignore_patterns_edit.setPlaceholderText("ignore URL patterns (comma-separated, optional)")

        self.status_filter_edit = QLineEdit()
        self.status_filter_edit.setPlaceholderText("Status (e.g. 200, 4xx, 5xx)")
        self.status_filter_edit.setFixedWidth(120)

        self.vuln_only_checkbox = QCheckBox("Vulns only")

        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        controls_layout.addWidget(QLabel("Start URL:"))
        controls_layout.addWidget(self.url_edit)
        controls_layout.addWidget(QLabel("Depth:"))
        controls_layout.addWidget(self.max_depth_edit)
        controls_layout.addWidget(self.allowed_domains_edit)
        controls_layout.addWidget(self.ignore_patterns_edit)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.status_filter_edit)
        controls_layout.addWidget(self.vuln_only_checkbox)
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)

        main_layout.addWidget(controls_widget)

        # Main tabs
        self.main_tabs = QTabWidget()
        main_layout.addWidget(self.main_tabs)

        self._build_scan_tab()
        self._build_vuln_tab()
        self._build_exploit_tab()
        self._build_manual_tab()

        # Connect signals
        self.start_button.clicked.connect(self.on_start)
        self.stop_button.clicked.connect(self.on_stop)
        self.status_filter_edit.textChanged.connect(self.apply_scan_filters)
        self.vuln_only_checkbox.stateChanged.connect(self.apply_scan_filters)

    def _build_scan_tab(self):
        scan_tab = QWidget()
        layout = QVBoxLayout()
        scan_tab.setLayout(layout)

        # Horizontal splitter: tree + table
        hsplitter = QSplitter(Qt.Orientation.Horizontal)

        self.tree_model = QStandardItemModel()
        self.tree_model.setHorizontalHeaderLabels(["Discovered URLs"])
        self.tree_root = self.tree_model.invisibleRootItem()

        self.tree_view = QTreeView()
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setHeaderHidden(False)

        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(4)
        self.scan_table.setHorizontalHeaderLabels(["URL", "Method", "Status", "Vulnerabilities"])
        header = self.scan_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.scan_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.scan_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.scan_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.scan_table.customContextMenuRequested.connect(self.on_scan_table_context_menu)
        self.scan_table.cellClicked.connect(self.on_scan_table_clicked)

        hsplitter.addWidget(self.tree_view)
        hsplitter.addWidget(self.scan_table)
        hsplitter.setStretchFactor(0, 1)
        hsplitter.setStretchFactor(1, 2)

        # Vertical splitter: (tree+table) + scan log (adjustable)
        vsplitter = QSplitter(Qt.Orientation.Vertical)

        vsplitter.addWidget(hsplitter)

        log_widget = QWidget()
        log_layout = QVBoxLayout()
        log_widget.setLayout(log_layout)
        log_layout.addWidget(QLabel("Scan Log:"))
        self.scan_log_text = QTextEdit()
        self.scan_log_text.setReadOnly(True)
        log_layout.addWidget(self.scan_log_text)

        vsplitter.addWidget(log_widget)
        vsplitter.setStretchFactor(0, 3)
        vsplitter.setStretchFactor(1, 1)

        layout.addWidget(vsplitter)

        self.main_tabs.addTab(scan_tab, "Scan")

        self.tree_view.selectionModel().currentChanged.connect(self.on_tree_selection_changed)

    def _build_vuln_tab(self):
        vuln_tab = QWidget()
        layout = QVBoxLayout()
        vuln_tab.setLayout(layout)

        top_bar = QHBoxLayout()
        self.vuln_export_button = QPushButton("Export Vulnerabilities (CSV)")
        self.vuln_export_button.clicked.connect(self.export_vulnerabilities_csv)
        top_bar.addWidget(self.vuln_export_button)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(3)
        self.vuln_table.setHorizontalHeaderLabels(["URL", "Status", "Vulnerabilities"])
        header = self.vuln_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.vuln_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.vuln_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.vuln_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.vuln_table.customContextMenuRequested.connect(self.on_vuln_table_context_menu)
        self.vuln_table.cellClicked.connect(self.on_vuln_table_clicked)

        self.vuln_detail_tabs = QTabWidget()
        self.vuln_request_text = QTextEdit()
        self.vuln_request_text.setReadOnly(True)
        self.vuln_response_text = QTextEdit()
        self.vuln_response_text.setReadOnly(True)
        self.vuln_detail_tabs.addTab(self.vuln_request_text, "Raw Request")
        self.vuln_detail_tabs.addTab(self.vuln_response_text, "Raw Response")

        splitter.addWidget(self.vuln_table)
        splitter.addWidget(self.vuln_detail_tabs)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)
        self.main_tabs.addTab(vuln_tab, "Vulnerabilities")

    def _build_exploit_tab(self):
        exploit_tab = QWidget()
        layout = QVBoxLayout()
        exploit_tab.setLayout(layout)

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Exploit type:"))

        self.exploit_type_combo = QComboBox()
        self.exploit_type_combo.addItems([
            "SQL Injection",
            "XSS",
            "Command Injection",
            "Path Traversal",
            "SSRF",
            "CSRF Test",
            "File Upload Test",
        ])
        controls_layout.addWidget(self.exploit_type_combo)

        self.exploit_run_button = QPushButton("Run Exploit on Selected")
        self.exploit_run_button.clicked.connect(self.on_exploit_run_clicked)
        controls_layout.addWidget(self.exploit_run_button)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        self.exploit_table = QTableWidget()
        self.exploit_table.setColumnCount(3)
        self.exploit_table.setHorizontalHeaderLabels(["URL", "Status", "Vulnerabilities"])
        header = self.exploit_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.exploit_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.exploit_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.exploit_table.cellClicked.connect(self.on_exploit_table_clicked)

        layout.addWidget(self.exploit_table)

        self.exploit_detail_tabs = QTabWidget()
        self.exploit_request_text = QTextEdit()
        self.exploit_request_text.setReadOnly(True)
        self.exploit_response_text = QTextEdit()
        self.exploit_response_text.setReadOnly(True)
        self.exploit_detail_tabs.addTab(self.exploit_request_text, "Raw Request")
        self.exploit_detail_tabs.addTab(self.exploit_response_text, "Raw Response")

        layout.addWidget(self.exploit_detail_tabs)
        self.main_tabs.addTab(exploit_tab, "Exploit")

    def _build_manual_tab(self):
        manual_tab = QWidget()
        layout = QHBoxLayout()
        manual_tab.setLayout(layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)

        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL:"))
        self.manual_url_edit = QLineEdit()
        url_layout.addWidget(self.manual_url_edit)
        left_layout.addLayout(url_layout)

        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Method:"))
        self.manual_method_combo = QComboBox()
        self.manual_method_combo.addItems(["GET", "POST"])
        method_layout.addWidget(self.manual_method_combo)
        left_layout.addLayout(method_layout)

        left_layout.addWidget(QLabel("Headers:"))
        self.manual_headers_edit = QTextEdit()
        left_layout.addWidget(self.manual_headers_edit)

        left_layout.addWidget(QLabel("Body:"))
        self.manual_body_edit = QTextEdit()
        left_layout.addWidget(self.manual_body_edit)

        self.manual_send_button = QPushButton("Send Request")
        self.manual_send_button.clicked.connect(self.on_manual_send)
        left_layout.addWidget(self.manual_send_button)

        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)

        right_layout.addWidget(QLabel("Response:"))
        self.manual_response_text = QTextEdit()
        self.manual_response_text.setReadOnly(True)
        right_layout.addWidget(self.manual_response_text)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter)
        self.main_tabs.addTab(manual_tab, "Manual Test")

    # ---------------------------
    # Logging helper
    # ---------------------------

    def log(self, msg: str):
        if hasattr(self, "scan_log_text") and self.scan_log_text is not None:
            self.scan_log_text.append(msg)

    # ---------------------------
    # Scan control
    # ---------------------------

    def on_start(self):
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a start URL.")
            return

        parsed = urlparse(url)
        if not parsed.scheme:
            url = "http://" + url

        try:
            max_depth = int(self.max_depth_edit.text().strip())
            if max_depth < 0:
                max_depth = 0
        except Exception:
            max_depth = 2

        allowed_domains_text = self.allowed_domains_edit.text().strip()
        if allowed_domains_text:
            allowed_domains = [d.strip() for d in allowed_domains_text.split(",") if d.strip()]
        else:
            allowed_domains = None

        ignore_text = self.ignore_patterns_edit.text().strip()
        if ignore_text:
            ignore_patterns = [p.strip() for p in ignore_text.split(",") if p.strip()]
        else:
            ignore_patterns = []

        # Reset state
        self.tree_model.removeRows(0, self.tree_model.rowCount())
        self.scan_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        self.exploit_table.setRowCount(0)
        self.vuln_request_text.clear()
        self.vuln_response_text.clear()
        self.exploit_request_text.clear()
        self.exploit_response_text.clear()
        self.manual_url_edit.clear()
        self.manual_headers_edit.clear()
        self.manual_body_edit.clear()
        self.manual_response_text.clear()
        self.scan_log_text.clear()

        self.all_results.clear()
        self.scan_results_by_row.clear()
        self.vuln_results.clear()
        self.vuln_results_by_row.clear()
        self.exploit_results.clear()
        self.exploit_results_by_row.clear()
        self.tree_filter_prefix = None

        self.scanner_worker = ScannerWorker(
            url,
            max_depth=max_depth,
            timeout=5,
            allowed_domains=allowed_domains,
            ignore_patterns=ignore_patterns,
            max_workers=5,
            max_active_tests=20,
        )
        self.scanner_thread = QThread()
        self.scanner_worker.moveToThread(self.scanner_thread)

        self.scanner_thread.started.connect(self.scanner_worker.run)
        self.scanner_worker.progress.connect(self.on_worker_progress)
        self.scanner_worker.url_discovered.connect(self.on_url_discovered)
        self.scanner_worker.scan_result.connect(self.on_scan_result)
        self.scanner_worker.finished.connect(self.on_worker_finished)

        self.scanner_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.log(f"Scan started for {url} (depth={max_depth})")

    def on_stop(self):
        if self.scanner_worker:
            self.scanner_worker.stop()
            self.log("Stop requested by user.")

    def on_worker_progress(self, msg: str):
        self.log(msg)

    def on_worker_finished(self):
        self.log("Worker thread finished.")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.scanner_thread:
            self.scanner_thread.quit()
            self.scanner_thread.wait()
            self.scanner_thread = None
        self.scanner_worker = None

    # ---------------------------
    # URL tree
    # ---------------------------

    def on_url_discovered(self, url: str):
        parsed = urlparse(url)
        path = parsed.path or "/"
        segments = [seg for seg in path.split("/") if seg] or ["/"]
        current_parent = self.tree_root
        prefix = f"{parsed.scheme}://{parsed.netloc}"
        accumulated = prefix
        for seg in segments:
            accumulated = urljoin(accumulated + "/", seg)
            child = self._find_child(current_parent, accumulated)
            if child is None:
                child = QStandardItem(accumulated)
                current_parent.appendRow(child)
            current_parent = child

    def _find_child(self, parent_item, url: str):
        for row in range(parent_item.rowCount()):
            child = parent_item.child(row, 0)
            if child.text() == url:
                return child
        return None

    def on_tree_selection_changed(self, current, previous):
        item = self.tree_model.itemFromIndex(current)
        if item is None:
            self.tree_filter_prefix = None
        else:
            self.tree_filter_prefix = item.text()
        self.apply_scan_filters()

    # ---------------------------
    # Scan table
    # ---------------------------

    def on_scan_result(self, result: ScanResult):
        self.all_results.append(result)
        self.db.save_result(result)
        self.apply_scan_filters()

    def apply_scan_filters(self):
        status_filter = self.status_filter_edit.text().strip()
        vuln_only = self.vuln_only_checkbox.isChecked()
        prefix = self.tree_filter_prefix

        self.scan_table.setRowCount(0)
        self.scan_results_by_row.clear()

        def status_matches(code, filt):
            if not filt:
                return True
            filt = filt.lower()
            try:
                if filt.endswith("xx") and len(filt) == 3 and filt[0].isdigit():
                    base = int(filt[0]) * 100
                    return base <= code < base + 100
                else:
                    return code == int(filt)
            except Exception:
                return True

        row_index = 0
        for res in self.all_results:
            if vuln_only and not res.vulns:
                continue
            if not status_matches(res.status_code, status_filter):
                continue
            if prefix and not res.url.startswith(prefix):
                continue

            self.scan_table.insertRow(row_index)
            url_item = QTableWidgetItem(res.url)
            method_item = QTableWidgetItem(res.method)
            status_item = QTableWidgetItem(str(res.status_code))
            vulns_text = "; ".join(res.vulns) if res.vulns else ""
            vulns_item = QTableWidgetItem(vulns_text)
            if res.vulns:
                vulns_item.setForeground(QColor("red"))

            self.scan_table.setItem(row_index, 0, url_item)
            self.scan_table.setItem(row_index, 1, method_item)
            self.scan_table.setItem(row_index, 2, status_item)
            self.scan_table.setItem(row_index, 3, vulns_item)

            self.scan_results_by_row[row_index] = res
            row_index += 1

    def on_scan_table_clicked(self, row, column):
        # No request/response panel in Scan tab
        pass

    def on_scan_table_context_menu(self, pos: QPoint):
        row = self.scan_table.rowAt(pos.y())
        if row < 0:
            return
        result = self.scan_results_by_row.get(row)
        if not result:
            return

        menu = QMenu(self)
        send_action = menu.addAction("Send to Vulnerabilities tab")
        action = menu.exec(self.scan_table.viewport().mapToGlobal(pos))
        if action == send_action:
            self.add_to_vuln_tab(result)

    # ---------------------------
    # Vulnerability tab
    # ---------------------------

    def add_to_vuln_tab(self, result: ScanResult):
        for existing in self.vuln_results:
            if existing.url == result.url:
                self.main_tabs.setCurrentIndex(1)
                return

        self.vuln_results.append(result)
        row_index = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row_index)

        url_item = QTableWidgetItem(result.url)
        status_item = QTableWidgetItem(str(result.status_code))
        vulns_text = "; ".join(result.vulns) if result.vulns else ""
        vulns_item = QTableWidgetItem(vulns_text)
        if result.vulns:
            vulns_item.setForeground(QColor("red"))

        self.vuln_table.setItem(row_index, 0, url_item)
        self.vuln_table.setItem(row_index, 1, status_item)
        self.vuln_table.setItem(row_index, 2, vulns_item)

        self.vuln_results_by_row[row_index] = result
        self.main_tabs.setCurrentIndex(1)

    def on_vuln_table_clicked(self, row, column):
        result = self.vuln_results_by_row.get(row)
        if not result:
            return
        self.vuln_request_text.setPlainText(result.request_raw)
        self.vuln_response_text.setPlainText(result.response_raw)

    def on_vuln_table_context_menu(self, pos: QPoint):
        row = self.vuln_table.rowAt(pos.y())
        if row < 0:
            return
        result = self.vuln_results_by_row.get(row)
        if not result:
            return

        menu = QMenu(self)
        send_exploit = menu.addAction("Send to Exploit tab")
        send_manual = menu.addAction("Send to Manual Test tab")
        action = menu.exec(self.vuln_table.viewport().mapToGlobal(pos))
        if action == send_exploit:
            self.add_to_exploit_tab(result)
        elif action == send_manual:
            self.add_to_manual_tab(result)

    def export_vulnerabilities_csv(self):
        if not self.vuln_results:
            self.log("No vulnerabilities to export.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerabilities_{ts}.csv"
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Method", "Status", "Vulnerabilities"])
                for res in self.vuln_results:
                    writer.writerow([
                        res.url,
                        res.method,
                        res.status_code,
                        "; ".join(res.vulns),
                    ])
            self.log(f"Vulnerabilities exported to {filename}")
        except Exception as e:
            self.log(f"Error exporting CSV: {e}")

    # ---------------------------
    # Exploit tab
    # ---------------------------

    def add_to_exploit_tab(self, result: ScanResult):
        for existing in self.exploit_results:
            if existing.url == result.url:
                self.main_tabs.setCurrentIndex(2)
                return

        self.exploit_results.append(result)
        row_index = self.exploit_table.rowCount()
        self.exploit_table.insertRow(row_index)

        url_item = QTableWidgetItem(result.url)
        status_item = QTableWidgetItem(str(result.status_code))
        vulns_text = "; ".join(result.vulns) if result.vulns else ""
        vulns_item = QTableWidgetItem(vulns_text)
        if result.vulns:
            vulns_item.setForeground(QColor("red"))

        self.exploit_table.setItem(row_index, 0, url_item)
        self.exploit_table.setItem(row_index, 1, status_item)
        self.exploit_table.setItem(row_index, 2, vulns_item)

        self.exploit_results_by_row[row_index] = result
        self.main_tabs.setCurrentIndex(2)

    def on_exploit_table_clicked(self, row, column):
        result = self.exploit_results_by_row.get(row)
        if not result:
            return
        self.exploit_request_text.setPlainText(result.request_raw)
        self.exploit_response_text.setPlainText(result.response_raw)

    def on_exploit_run_clicked(self):
        row = self.exploit_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Exploit", "Please select a URL in the Exploit tab.")
            return
        result = self.exploit_results_by_row.get(row)
        if not result:
            return
        self.run_exploit_on_result(result)

    def run_exploit_on_result(self, result: ScanResult):
        exploit_type = self.exploit_type_combo.currentText()
        url = result.url

        payload_map = {
            "SQL Injection": ["' OR '1'='1", "\" OR \"1\"=\"1"],
            "XSS": ['<script>alert(1)</script>'],
            "Command Injection": [';id', '&&id'],
            "Path Traversal": ['../../../../etc/passwd'],
            "SSRF": ['http://127.0.0.1'],
            "CSRF Test": ['csrf_test'],
            "File Upload Test": ['file_upload_test'],
        }

        payloads = payload_map.get(exploit_type, [])
        if not payloads:
            QMessageBox.warning(self, "Exploit", f"No payloads defined for {exploit_type}.")
            return

        payload = payloads[0]

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            key = next(iter(qs.keys()))
            qs[key] = [payload]
        else:
            qs["test"] = [payload]

        new_query = urlencode(qs, doseq=True)
        mutated = parsed._replace(query=new_query)
        test_url = urlunparse(mutated)

        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        try:
            resp = self.manual_session.get(test_url, timeout=10, verify=False)
        except Exception as e:
            QMessageBox.warning(self, "Exploit Error", f"Error sending exploit request:\n{e}")
            return

        req = resp.request
        req_headers = "\r\n".join(f"{k}: {v}" for k, v in req.headers.items())
        request_line = f"{req.method} {req.path_url} HTTP/1.1"
        if req.body:
            if isinstance(req.body, bytes):
                body = req.body.decode(errors="replace")
            else:
                body = str(req.body)
        else:
            body = ""
        request_raw = f"{request_line}\r\n{req_headers}\r\n\r\n{body}"

        status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"
        resp_headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        response_raw = f"{status_line}\r\n{resp_headers}\r\n\r\n{resp.text}"

        self.exploit_request_text.setPlainText(request_raw)
        self.exploit_response_text.setPlainText(response_raw)
        self.log(f"Exploit [{exploit_type}] executed on {test_url} (status {resp.status_code})")

    # ---------------------------
    # Manual test tab
    # ---------------------------

    def add_to_manual_tab(self, result: ScanResult):
        self.main_tabs.setCurrentIndex(3)

        self.manual_url_edit.setText(result.url)

        raw = result.request_raw or ""
        parts = raw.split("\r\n\r\n", 1)
        head = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        lines = head.split("\r\n")
        method = "GET"
        headers_lines = []
        if lines:
            try:
                first = lines[0]
                method = first.split()[0]
            except Exception:
                method = "GET"
            headers_lines = lines[1:]

        idx = self.manual_method_combo.findText(method.upper())
        if idx >= 0:
            self.manual_method_combo.setCurrentIndex(idx)
        else:
            self.manual_method_combo.setCurrentIndex(0)

        self.manual_headers_edit.setPlainText("\r\n".join(headers_lines))
        self.manual_body_edit.setPlainText(body)
        self.manual_response_text.clear()

    def on_manual_send(self):
        url = self.manual_url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Manual Test", "URL is empty.")
            return

        method = self.manual_method_combo.currentText().upper()
        headers_text = self.manual_headers_edit.toPlainText()
        body = self.manual_body_edit.toPlainText()

        headers = {}
        for line in headers_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        try:
            if method == "POST":
                resp = self.manual_session.post(url, headers=headers, data=body, timeout=15, verify=False)
            else:
                resp = self.manual_session.get(url, headers=headers, timeout=15, verify=False)
        except Exception as e:
            QMessageBox.warning(self, "Manual Test Error", f"Error sending request:\n{e}")
            return

        status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"
        resp_headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        response_raw = f"{status_line}\r\n{resp_headers}\r\n\r\n{resp.text}"
        self.manual_response_text.setPlainText(response_raw)
        self.log(f"Manual request {method} {url} -> {resp.status_code}")

    # ---------------------------
    # Cleanup / Quit
    # ---------------------------

    def closeEvent(self, event):
        try:
            if self.scanner_worker:
                self.scanner_worker.stop()
            if self.scanner_thread:
                self.scanner_thread.quit()
                self.scanner_thread.wait()
        finally:
            self.db.close()
        super().closeEvent(event)

def main():
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()