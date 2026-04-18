#!/usr/bin/env python3
"""
MacOS Forensics Lab — RECON Lab-inspired forensic analysis tool
Requires: pip install PyQt6
Run:      python3 macos_forensics_lab.py
"""

import sys
import os
import json
import sqlite3
import plistlib
import subprocess
import platform
import hashlib
import datetime
import threading
import glob
import re
import csv
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QPushButton, QProgressBar, QStatusBar, QTabWidget,
    QFileDialog, QMessageBox, QHeaderView, QFrame, QScrollArea,
    QGroupBox, QCheckBox, QLineEdit, QComboBox, QSizePolicy,
    QDialog, QDialogButtonBox, QPlainTextEdit, QToolBar, QMenuBar,
    QMenu, QAbstractItemView, QSplashScreen
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex, pyqtSlot
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QPixmap, QPainter, QIcon,
    QAction, QKeySequence, QBrush, QLinearGradient
)


# ─── Color Palette (Dark forensics theme) ─────────────────────────────────────
COLORS = {
    "bg_primary":     "#0D1117",
    "bg_secondary":   "#161B22",
    "bg_tertiary":    "#21262D",
    "bg_panel":       "#1C2128",
    "accent_blue":    "#58A6FF",
    "accent_green":   "#3FB950",
    "accent_orange":  "#F78166",
    "accent_yellow":  "#E3B341",
    "accent_purple":  "#BC8CFF",
    "accent_teal":    "#39D353",
    "text_primary":   "#E6EDF3",
    "text_secondary": "#8B949E",
    "text_muted":     "#484F58",
    "border":         "#30363D",
    "border_active":  "#58A6FF",
    "red":            "#F85149",
    "header_bg":      "#010409",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {COLORS["bg_primary"]};
    color: {COLORS["text_primary"]};
    font-family: "SF Mono", "Menlo", "Monaco", "Courier New", monospace;
    font-size: 13px;
}}
QMenuBar {{
    background-color: {COLORS["header_bg"]};
    color: {COLORS["text_primary"]};
    border-bottom: 1px solid {COLORS["border"]};
    padding: 2px;
}}
QMenuBar::item:selected {{
    background-color: {COLORS["bg_tertiary"]};
    border-radius: 4px;
}}
QMenu {{
    background-color: {COLORS["bg_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item:selected {{
    background-color: {COLORS["bg_tertiary"]};
    border-radius: 4px;
}}
QToolBar {{
    background-color: {COLORS["bg_secondary"]};
    border-bottom: 1px solid {COLORS["border"]};
    padding: 4px 8px;
    spacing: 6px;
}}
QSplitter::handle {{
    background-color: {COLORS["border"]};
    width: 1px;
}}
QTreeWidget {{
    background-color: {COLORS["bg_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    color: {COLORS["text_primary"]};
    alternate-background-color: {COLORS["bg_panel"]};
    selection-background-color: {COLORS["bg_tertiary"]};
    selection-color: {COLORS["accent_blue"]};
    outline: none;
}}
QTreeWidget::item {{
    padding: 3px 4px;
    border-radius: 3px;
}}
QTreeWidget::item:hover {{
    background-color: {COLORS["bg_tertiary"]};
}}
QTreeWidget::item:selected {{
    background-color: {COLORS["bg_panel"]};
    color: {COLORS["accent_blue"]};
    border-left: 2px solid {COLORS["accent_blue"]};
}}
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {{
    color: {COLORS["text_secondary"]};
}}
QTableWidget {{
    background-color: {COLORS["bg_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    gridline-color: {COLORS["border"]};
    selection-background-color: {COLORS["bg_panel"]};
    selection-color: {COLORS["text_primary"]};
    alternate-background-color: {COLORS["bg_panel"]};
    outline: none;
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["accent_blue"]};
}}
QHeaderView::section {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text_secondary"]};
    border: none;
    border-bottom: 1px solid {COLORS["border"]};
    border-right: 1px solid {COLORS["border"]};
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QTabWidget::pane {{
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    background-color: {COLORS["bg_secondary"]};
    top: -1px;
}}
QTabBar::tab {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-bottom: none;
    padding: 6px 16px;
    margin-right: 2px;
    border-radius: 6px 6px 0 0;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background-color: {COLORS["bg_secondary"]};
    color: {COLORS["accent_blue"]};
    border-bottom: 2px solid {COLORS["accent_blue"]};
}}
QTabBar::tab:hover {{
    color: {COLORS["text_primary"]};
}}
QPushButton {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {COLORS["bg_panel"]};
    border-color: {COLORS["accent_blue"]};
    color: {COLORS["accent_blue"]};
}}
QPushButton:pressed {{
    background-color: {COLORS["bg_primary"]};
}}
QPushButton#primary {{
    background-color: #1F6FEB;
    color: white;
    border-color: #1F6FEB;
    font-weight: 600;
}}
QPushButton#primary:hover {{
    background-color: #388BFD;
    border-color: #388BFD;
}}
QPushButton#danger {{
    background-color: #6E1A1A;
    color: {COLORS["red"]};
    border-color: {COLORS["red"]};
}}
QPushButton#success {{
    background-color: #1A4A1A;
    color: {COLORS["accent_green"]};
    border-color: {COLORS["accent_green"]};
}}
QLineEdit, QComboBox {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    selection-background-color: {COLORS["accent_blue"]};
}}
QLineEdit:focus, QComboBox:focus {{
    border-color: {COLORS["accent_blue"]};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QTextEdit, QPlainTextEdit {{
    background-color: {COLORS["bg_secondary"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 8px;
    font-family: "SF Mono", "Menlo", monospace;
    font-size: 12px;
    selection-background-color: {COLORS["accent_blue"]};
}}
QProgressBar {{
    background-color: {COLORS["bg_tertiary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    text-align: center;
    color: {COLORS["text_primary"]};
    font-size: 11px;
    height: 14px;
}}
QProgressBar::chunk {{
    background-color: {COLORS["accent_blue"]};
    border-radius: 3px;
}}
QScrollBar:vertical {{
    background: {COLORS["bg_tertiary"]};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {COLORS["text_muted"]};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar:horizontal {{
    background: {COLORS["bg_tertiary"]};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {COLORS["text_muted"]};
    border-radius: 4px;
    min-width: 20px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}
QGroupBox {{
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    margin-top: 12px;
    padding: 8px;
    color: {COLORS["text_secondary"]};
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {COLORS["text_secondary"]};
}}
QCheckBox {{
    color: {COLORS["text_primary"]};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {COLORS["border"]};
    border-radius: 3px;
    background-color: {COLORS["bg_tertiary"]};
}}
QCheckBox::indicator:checked {{
    background-color: {COLORS["accent_blue"]};
    border-color: {COLORS["accent_blue"]};
}}
QStatusBar {{
    background-color: {COLORS["header_bg"]};
    border-top: 1px solid {COLORS["border"]};
    color: {COLORS["text_secondary"]};
    font-size: 11px;
}}
QLabel#sectionTitle {{
    color: {COLORS["text_secondary"]};
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
QFrame#divider {{
    background-color: {COLORS["border"]};
    max-height: 1px;
}}
"""


# ─── Forensic Artifact Collectors ─────────────────────────────────────────────

class ForensicResult:
    def __init__(self, category: str, artifact: str, data: list, columns: list, raw: str = ""):
        self.category = category
        self.artifact = artifact
        self.data = data        # list of row dicts
        self.columns = columns  # ordered column names
        self.raw = raw
        self.timestamp = datetime.datetime.now().isoformat()
        self.count = len(data)


class MacOSCollector:
    """Collects macOS forensic artifacts natively."""

    def __init__(self, target_path: str = "/"):
        self.target = target_path
        self.home = str(Path.home())
        self.username = os.getenv("USER", "unknown")

    def _run(self, cmd: list) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return r.stdout.strip()
        except Exception as e:
            return f"[Error: {e}]"

    def _plist_read(self, path: str) -> Optional[dict]:
        try:
            with open(path, "rb") as f:
                return plistlib.load(f)
        except Exception:
            return None

    def _sqlite_query(self, db_path: str, query: str) -> list:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(query)
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            return [{"error": str(e)}]

    # ── System Info ────────────────────────────────────────────────────────────
    def collect_system_info(self) -> ForensicResult:
        info = []
        checks = [
            ("OS Version",       ["sw_vers", "-productVersion"]),
            ("Build Version",    ["sw_vers", "-buildVersion"]),
            ("Product Name",     ["sw_vers", "-productName"]),
            ("Kernel Version",   ["uname", "-r"]),
            ("Hostname",         ["hostname"]),
            ("Architecture",     ["uname", "-m"]),
            ("Boot Time",        ["sysctl", "-n", "kern.boottime"]),
            ("System UUID",      ["system_profiler", "SPHardwareDataType"]),
        ]
        for name, cmd in checks:
            val = self._run(cmd)
            info.append({"Property": name, "Value": val[:200] if val else "N/A"})

        # Add Python platform info as fallback
        info.insert(0, {"Property": "Python Platform", "Value": platform.platform()})
        info.insert(1, {"Property": "Processor",       "Value": platform.processor() or "Unknown"})

        return ForensicResult("System", "System Information", info, ["Property", "Value"])

    # ── Users ──────────────────────────────────────────────────────────────────
    def collect_users(self) -> ForensicResult:
        rows = []
        out = self._run(["dscl", ".", "list", "/Users"])
        for u in out.splitlines():
            if u.startswith("_") or u in ("daemon", "nobody"):
                continue
            home = self._run(["dscl", ".", "read", f"/Users/{u}", "NFSHomeDirectory"])
            shell = self._run(["dscl", ".", "read", f"/Users/{u}", "UserShell"])
            uid = self._run(["dscl", ".", "read", f"/Users/{u}", "UniqueID"])
            rows.append({
                "Username": u,
                "Home":  home.replace("NFSHomeDirectory: ", "").strip(),
                "Shell": shell.replace("UserShell: ", "").strip(),
                "UID":   uid.replace("UniqueID: ", "").strip(),
            })
        if not rows:
            rows.append({"Username": self.username, "Home": self.home,
                         "Shell": os.environ.get("SHELL",""), "UID": str(os.getuid())})
        return ForensicResult("System", "User Accounts", rows, ["Username", "Home", "Shell", "UID"])

    # ── Installed Applications ─────────────────────────────────────────────────
    def collect_applications(self) -> ForensicResult:
        rows = []
        dirs = ["/Applications", f"{self.home}/Applications"]
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for app in glob.glob(f"{d}/*.app"):
                info_plist = os.path.join(app, "Contents", "Info.plist")
                p = self._plist_read(info_plist) or {}
                rows.append({
                    "Name":    p.get("CFBundleDisplayName") or p.get("CFBundleName") or os.path.basename(app),
                    "Version": p.get("CFBundleShortVersionString", ""),
                    "Bundle":  p.get("CFBundleIdentifier", ""),
                    "Path":    app,
                    "Location": d,
                })
        rows.sort(key=lambda x: x["Name"].lower())
        return ForensicResult("System", "Installed Applications", rows,
                              ["Name", "Version", "Bundle", "Location"])

    # ── Launch Agents / Daemons (Persistence) ─────────────────────────────────
    def collect_launch_agents(self) -> ForensicResult:
        rows = []
        dirs = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            f"{self.home}/Library/LaunchAgents",
        ]
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for f in glob.glob(f"{d}/*.plist"):
                p = self._plist_read(f) or {}
                prog = p.get("Program") or (p.get("ProgramArguments") or [""])[0]
                rows.append({
                    "Label":    p.get("Label", os.path.basename(f)),
                    "Program":  prog,
                    "RunAtLoad":str(p.get("RunAtLoad", False)),
                    "Type":     os.path.basename(d),
                    "Path":     f,
                })
        return ForensicResult("Persistence", "Launch Agents & Daemons", rows,
                              ["Label", "Program", "RunAtLoad", "Type"])

    # ── Login Items ────────────────────────────────────────────────────────────
    def collect_login_items(self) -> ForensicResult:
        rows = []
        plist_path = f"{self.home}/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
        sflt_path  = "/var/db/com.apple.xpc.launchd/loginitems.501.btm"
        # Try sfltool
        out = self._run(["sfltool", "dumpbtm"])
        if out and "Error" not in out:
            for line in out.splitlines():
                if ".app" in line or "executable" in line.lower():
                    rows.append({"Item": line.strip(), "Source": "sfltool"})
        # Fallback: parse plist
        if not rows:
            p = self._plist_read(plist_path)
            if p and isinstance(p, dict):
                for key, val in p.items():
                    rows.append({"Item": str(key), "Source": "backgrounditems.btm"})
        if not rows:
            rows.append({"Item": "(No login items found or permission denied)", "Source": ""})
        return ForensicResult("Persistence", "Login Items", rows, ["Item", "Source"])

    # ── Browser History (Safari) ───────────────────────────────────────────────
    def collect_safari_history(self) -> ForensicResult:
        db_orig = f"{self.home}/Library/Safari/History.db"

        # ── Existence / permission check ──────────────────────────────────────
        if not os.path.exists(db_orig):
            return ForensicResult("Web Activity", "Safari History",
                [{"Title": "Safari History.db not found — Safari may never have been used",
                  "URL": db_orig, "Visit Time": "", "Load OK": "", "Visit Count": ""}],
                ["Title", "URL", "Visit Time", "Load OK", "Visit Count"])

        if not os.access(db_orig, os.R_OK):
            return ForensicResult("Web Activity", "Safari History",
                [{"Title": "Permission denied — grant Full Disk Access to Terminal in "
                           "System Settings → Privacy & Security → Full Disk Access",
                  "URL": db_orig, "Visit Time": "", "Load OK": "", "Visit Count": ""}],
                ["Title", "URL", "Visit Time", "Load OK", "Visit Count"])

        # ── Copy DB + WAL/SHM files to temp dir to bypass Safari's file lock ──
        tmp_dir = tempfile.mkdtemp(prefix="safari_forensics_")
        tmp_db  = os.path.join(tmp_dir, "History.db")
        clean   = []
        error_msg = ""
        try:
            shutil.copy2(db_orig, tmp_db)
            # Also copy WAL and SHM so SQLite can reconstruct a consistent snapshot
            for suffix in ("-wal", "-shm"):
                src = db_orig + suffix
                if os.path.exists(src):
                    shutil.copy2(src, tmp_db + suffix)

            # ── Try the full join query first ──────────────────────────────────
            rows = self._sqlite_query(tmp_db, """
                SELECT
                    hi.id,
                    hi.title,
                    hv.url,
                    datetime(hi.visit_time + 978307200, 'unixepoch', 'localtime') AS visit_time,
                    hi.load_successful,
                    hv.visit_count
                FROM history_visits  hi
                JOIN history_items   hv ON hi.history_item = hv.id
                ORDER BY hi.visit_time DESC
                LIMIT 500
            """)

            # ── If join fails (schema varies), fall back to history_items only ─
            if not rows or (len(rows) == 1 and "error" in rows[0]):
                error_msg = rows[0].get("error", "") if rows else "empty result"
                rows = self._sqlite_query(tmp_db, """
                    SELECT
                        id,
                        url,
                        title,
                        visit_count,
                        datetime(last_visit_time + 978307200, 'unixepoch', 'localtime') AS visit_time,
                        1 AS load_successful
                    FROM history_items
                    ORDER BY last_visit_time DESC
                    LIMIT 500
                """)

            # ── If both queries fail, surface the real error ───────────────────
            if not rows or (len(rows) == 1 and "error" in rows[0]):
                err = rows[0].get("error", "Unknown error") if rows else "No rows returned"
                return ForensicResult("Web Activity", "Safari History",
                    [{"Title": f"DB query failed: {err}  |  fallback error: {error_msg}",
                      "URL": db_orig, "Visit Time": "", "Load OK": "", "Visit Count": ""}],
                    ["Title", "URL", "Visit Time", "Load OK", "Visit Count"])

            for r in rows:
                clean.append({
                    "Visit Time": r.get("visit_time") or "",
                    "URL": r.get("url")   or "",
                    "Title": r.get("title") or "",
                    "Load OK":     "Yes" if r.get("load_successful") else "No",
                    "Visit Count": str(r.get("visit_count") or ""),
                })

        except Exception as exc:
            clean = [{"Title": f"Unexpected error: {exc}", "URL": db_orig,
                      "Visit Time": "", "Load OK": "", "Visit Count": ""}]
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return ForensicResult("Web Activity", "Safari History", clean,
                              ["Visit Time", "URL", "Title", "Load OK", "Visit Count"])

    # ── Browser History (Chrome) ───────────────────────────────────────────────
    def collect_chrome_history(self) -> ForensicResult:
        db = f"{self.home}/Library/Application Support/Google/Chrome/Default/History"
        if not os.path.exists(db):
            return ForensicResult("Web Activity", "Chrome History",
                                  [{"Note": "Chrome not found"}], ["Note"])
        # Copy to temp to avoid lock
        tmp = tempfile.mktemp(suffix=".db")
        shutil.copy2(db, tmp)
        rows = self._sqlite_query(tmp, """
            SELECT title, url,
                   datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime') as last_visit,
                   visit_count
            FROM urls ORDER BY last_visit_time DESC LIMIT 500
        """)
        os.unlink(tmp)
        clean = []
        for r in rows:
            clean.append({
                "Last Visit": r.get("last_visit", ""),
                "URL":        r.get("url", ""),
                "Title": r.get("title", ""),
                "Count":      str(r.get("visit_count", "")),
            })
        return ForensicResult("Web Activity", "Chrome History", clean,
                              ["Last Visit", "URL", "Title", "Count"])

    # ── Downloads ─────────────────────────────────────────────────────────────
    def collect_downloads(self) -> ForensicResult:
        rows = []
        downloads_dir = f"{self.home}/Downloads"
        if os.path.isdir(downloads_dir):
            for entry in sorted(os.scandir(downloads_dir), key=lambda e: e.stat().st_mtime, reverse=True):
                st = entry.stat()
                rows.append({
                    "Filename": entry.name,
                    "Size":     self._human_size(st.st_size),
                    "Modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "Created":  datetime.datetime.fromtimestamp(st.st_birthtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "Path":     entry.path,
                })
        return ForensicResult("File Activity", "Downloads Folder", rows,
                              ["Filename", "Size", "Modified", "Created"])

    # ── Recent Items ──────────────────────────────────────────────────────────
    def collect_recent_items(self) -> ForensicResult:
        """
        Collects recently accessed files, applications, and servers from multiple
        macOS sources:

        1. SharedFileLists (.sfl2) — binary plists in
              ~/Library/Application Support/com.apple.sharedfilelist/
           Each .sfl2 file is a binary plist; we convert to XML via `plutil -convert xml1`
           then parse with plistlib. The "items" array inside contains bookmark blobs
           from which we extract the CFURLString (the resolved path).

        2. com.apple.recentitems.plist  (~/Library/Preferences/)
           Stores per-app recent documents under keys like
           "RecentDocuments", "RecentApplications", "RecentServers".
           Each value is a dict with "CustomListItems" → list of {"Name":…,"Alias":…}.

        3. Per-app NSDocument recent file lists stored under
              ~/Library/Preferences/<bundle-id>.plist
           under the key "NSRecentDocumentRecords" or "recentDocuments".
        """
        APPLE_EPOCH = 978307200
        rows = []
        cols = ["Name", "Path", "Kind", "Last Used", "Source File"]

        def _sfl2_parse(sfl2_path: str, kind: str):
            """Convert sfl2 → XML plist in temp file, then walk items."""
            tmp = tempfile.mktemp(suffix=".plist")
            try:
                ret = subprocess.run(
                    ["plutil", "-convert", "xml1", "-o", tmp, sfl2_path],
                    capture_output=True, timeout=10
                )
                if ret.returncode != 0:
                    return
                with open(tmp, "rb") as f:
                    data = plistlib.load(f)

                items = data.get("items", [])
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("Name") or item.get("name") or ""
                    # bookmark blob → extract embedded UTF-8 path
                    path = ""
                    bm = item.get("Bookmark") or item.get("bookmark") or b""
                    if isinstance(bm, bytes) and len(bm) > 16:
                        # Apple bookmark binary format: scan for null-terminated
                        # UTF-8 strings that look like absolute paths
                        decoded = bm.decode("utf-8", errors="replace")
                        # paths start with /
                        for segment in decoded.split("\x00"):
                            segment = segment.strip()
                            if segment.startswith("/") and len(segment) > 2:
                                path = segment
                                break
                        if not path:
                            # fallback: regex
                            m = re.search(r"(/(?:Users|Volumes|Applications|private)[^\x00\x01-\x1f]+)", decoded)
                            if m:
                                path = m.group(1)
                    if not name and path:
                        name = os.path.basename(path)
                    if name or path:
                        rows.append({
                            "Name":      name,
                            "Path":      path,
                            "Kind":      kind,
                            "Last Used": "",
                            "Source File": os.path.basename(sfl2_path),
                        })
            except Exception:
                pass
            finally:
                try: os.unlink(tmp)
                except Exception: pass

        # ── 1. All .sfl2 files ────────────────────────────────────────────────
        sfl_base = f"{self.home}/Library/Application Support/com.apple.sharedfilelist"
        sfl_map = {
            "com.apple.LSSharedFileList.RecentDocuments.sfl2":    "Recent Document",
            "com.apple.LSSharedFileList.RecentApplications.sfl2": "Recent Application",
            "com.apple.LSSharedFileList.RecentServers.sfl2":      "Recent Server",
            "com.apple.LSSharedFileList.RecentHosts.sfl2":        "Recent Host",
            "com.apple.LSSharedFileList.FavoriteItems.sfl2":      "Favourite",
            "com.apple.LSSharedFileList.FavoriteVolumes.sfl2":    "Favourite Volume",
        }
        if os.path.isdir(sfl_base):
            for fname, kind in sfl_map.items():
                full = os.path.join(sfl_base, fname)
                if os.path.exists(full):
                    _sfl2_parse(full, kind)
            # Also grab any other .sfl2 files
            for f in glob.glob(f"{sfl_base}/**/*.sfl2", recursive=True):
                base = os.path.basename(f)
                if base not in sfl_map:
                    _sfl2_parse(f, "Recent Item")

        # ── 2. com.apple.recentitems.plist ───────────────────────────────────
        ri_plist = f"{self.home}/Library/Preferences/com.apple.recentitems.plist"
        p = self._plist_read(ri_plist)
        if p:
            section_map = {
                "RecentDocuments":    "Recent Document",
                "RecentApplications": "Recent Application",
                "RecentServers":      "Recent Server",
            }
            for section, kind in section_map.items():
                sec = p.get(section, {})
                if not isinstance(sec, dict):
                    continue
                items = sec.get("CustomListItems") or []
                for item in items[:30]:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("Name") or ""
                    # Alias blob also encodes the original path; skip deep decode
                    rows.append({
                        "Name":       name,
                        "Path":       "",
                        "Kind":       kind,
                        "Last Used":  "",
                        "Source File": "com.apple.recentitems.plist",
                    })

        # ── 3. Per-app recent docs via defaults (safe, no sudo needed) ────────
        out = self._run(["defaults", "read", "com.apple.finder", "FXRecentFolders"])
        if out and "does not exist" not in out:
            for line in out.splitlines():
                m = re.search(r'"?name"?\s*=\s*"([^"]+)"', line)
                if m:
                    rows.append({"Name": m.group(1), "Path": "", "Kind": "Finder Recent Folder",
                                 "Last Used": "", "Source File": "com.apple.finder defaults"})

        # ── 4. Dock recent apps (~/Library/Preferences/com.apple.dock.plist) ─
        dock = self._plist_read(f"{self.home}/Library/Preferences/com.apple.dock.plist")
        if dock:
            for item in dock.get("recent-apps", []):
                if not isinstance(item, dict):
                    continue
                tile = item.get("tile-data", {})
                label = tile.get("file-label") or tile.get("file-data", {}).get("_CFURLString", "")
                if label:
                    rows.append({"Name": label, "Path": "", "Kind": "Dock Recent App",
                                 "Last Used": "", "Source File": "com.apple.dock.plist"})

        if not rows:
            rows.append({
                "Name": "No recent items found — grant Full Disk Access to Terminal",
                "Path": "", "Kind": "", "Last Used": "", "Source File": "",
            })

        return ForensicResult("File Activity", "Recent Items", rows, cols)

    # ── Shell History ──────────────────────────────────────────────────────────
    def collect_shell_history(self) -> ForensicResult:
        rows = []
        files = [
            (f"{self.home}/.zsh_history",  "zsh"),
            (f"{self.home}/.bash_history", "bash"),
            (f"{self.home}/.fish/fish_history", "fish"),
        ]
        for path, shell in files:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", errors="replace") as f:
                    lines = f.readlines()[-500:]
                for line in reversed(lines):
                    line = line.strip()
                    # zsh format: ": timestamp:elapsed;command"
                    if shell == "zsh" and line.startswith(":"):
                        parts = line.split(";", 1)
                        cmd = parts[1] if len(parts) > 1 else line
                        ts_part = parts[0].split(":")[1] if ":" in parts[0] else ""
                        try:
                            ts = datetime.datetime.fromtimestamp(int(ts_part)).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            ts = ""
                        rows.append({"Command": cmd, "Timestamp": ts, "Shell": shell})
                    elif line:
                        rows.append({"Command": line, "Timestamp": "", "Shell": shell})
            except Exception:
                pass
        return ForensicResult("User Activity", "Shell History", rows,
                              ["Timestamp", "Command", "Shell"])

    # ── Network Connections ────────────────────────────────────────────────────
    def collect_network(self) -> ForensicResult:
        rows = []
        out = self._run(["netstat", "-an", "-p", "tcp"])
        for line in out.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 6:
                rows.append({
                    "Protocol": parts[0],
                    "Local":    parts[3],
                    "Foreign":  parts[4],
                    "State":    parts[5] if len(parts) > 5 else "",
                })
        return ForensicResult("Network", "Active Connections", rows,
                              ["Protocol", "Local", "Foreign", "State"])

    # ── Wi-Fi Networks ─────────────────────────────────────────────────────────
    def collect_wifi(self) -> ForensicResult:
        """
        Parse known Wi-Fi networks from the Airport preferences plist.

        macOS stores Wi-Fi history in:
          /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist
          (requires sudo or Full Disk Access)

        The plist schema changed across OS versions:
          • macOS ≤ 12 (Monterey): KnownNetworks keys are BSSIDs
          • macOS 13+ (Ventura/Sonoma): KnownNetworks keys are SSID strings;
            per-network BSSIDs live inside a nested "NetworkBSSIDList" or
            "BSSIDList" array of dicts.

        Timestamps use the Apple/Mac absolute reference epoch:
          January 1, 2001 00:00:00 UTC  →  add 978307200 to get Unix epoch.
        """
        APPLE_EPOCH_OFFSET = 978307200  # seconds between 1970-01-01 and 2001-01-01

        def _apple_ts(val) -> str:
            """Convert an Apple-epoch float/int or datetime to readable string."""
            if val is None:
                return ""
            if isinstance(val, datetime.datetime):
                return val.strftime("%Y-%m-%d %H:%M:%S")
            try:
                unix_ts = float(val) + APPLE_EPOCH_OFFSET
                return datetime.datetime.utcfromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                return str(val)

        def _bool_str(val) -> str:
            if val is None:
                return ""
            return "Yes" if val else "No"

        def _security_label(raw: str) -> str:
            """Map internal security type codes to human-readable labels."""
            mapping = {
                "WPA2":           "WPA2 Personal",
                "WPA2E":          "WPA2 Enterprise",
                "WPA3":           "WPA3 Personal",
                "WPA3E":          "WPA3 Enterprise",
                "WPA3T":          "WPA3 Transition",
                "WPA":            "WPA Personal",
                "WPAE":           "WPA Enterprise",
                "WEP":            "WEP",
                "Open":           "Open (No Security)",
                "None":           "Open (No Security)",
                "":               "Unknown",
            }
            return mapping.get(raw, raw)

        rows = []
        cols = ["SSID", "BSSID(s)", "Security", "Last Joined", "Added", "Auto-Join",
                "Personal Hotspot", "Channel", "Band", "Hidden", "Disabled", "Source"]

        # ── Candidate plist paths (sudo expands access; user copy is a fallback) ─
        plist_candidates = [
            "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
            f"{self.home}/Library/Preferences/com.apple.airport.preferences.plist",
        ]

        p = None
        source_path = ""
        for candidate in plist_candidates:
            p = self._plist_read(candidate)
            if p:
                source_path = candidate
                break

        if p:
            known = p.get("KnownNetworks", {})
            for key, net in known.items():
                if not isinstance(net, dict):
                    continue

                # ── SSID ──────────────────────────────────────────────────────
                # macOS 13+: key itself is the SSID string
                # macOS ≤12:  key is a BSSID; SSID is inside net dict
                ssid = (net.get("SSIDString")
                        or net.get("SSID_STR")
                        or (key if ":" not in key else ""))
                if not ssid:
                    # Try decoding bytes SSID
                    raw_ssid = net.get("SSID")
                    if isinstance(raw_ssid, bytes):
                        try:
                            ssid = raw_ssid.decode("utf-8", errors="replace")
                        except Exception:
                            ssid = raw_ssid.hex()
                    else:
                        ssid = str(key)

                # ── BSSID(s) ──────────────────────────────────────────────────
                bssid_parts = []
                # macOS ≤12: key IS the BSSID
                if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", key):
                    bssid_parts.append(key.upper())
                # macOS 13+: nested list of BSSID dicts
                for blist_key in ("NetworkBSSIDList", "BSSIDList", "BSSIDs"):
                    blist = net.get(blist_key, [])
                    if isinstance(blist, list):
                        for b in blist:
                            if isinstance(b, dict):
                                bv = b.get("BSSID") or b.get("BSSIDString") or ""
                            else:
                                bv = str(b)
                            bv = bv.strip().upper()
                            if bv and bv not in bssid_parts:
                                bssid_parts.append(bv)
                    elif isinstance(blist, str) and blist:
                        bssid_parts.append(blist.upper())
                bssid_str = ", ".join(bssid_parts) if bssid_parts else ""

                # ── Security ──────────────────────────────────────────────────
                sec_raw = (net.get("SecurityType")
                           or net.get("SecurityMode")
                           or net.get("80211SecurityType")
                           or "")
                security = _security_label(str(sec_raw))

                # ── Timestamps ────────────────────────────────────────────────
                last_joined = _apple_ts(net.get("LastConnected")
                                        or net.get("LastJoined")
                                        or net.get("LastAutoJoined"))
                added_at    = _apple_ts(net.get("AddedAt")
                                        or net.get("AddedTime"))

                # ── Flags ─────────────────────────────────────────────────────
                auto_join   = _bool_str(net.get("AutoJoin"))
                hotspot     = _bool_str(net.get("PersonalHotspot")
                                        or net.get("IsPersonalHotspot"))
                hidden      = _bool_str(net.get("Hidden")
                                        or net.get("ClosedNetwork"))
                disabled    = _bool_str(net.get("Disabled"))

                # ── Channel / Band ─────────────────────────────────────────────
                channel = str(net.get("Channel") or net.get("ChannelHistory", [{}])[0].get("Channel", "")
                              if net.get("ChannelHistory") else net.get("Channel", ""))
                band_raw = net.get("NetworkBand") or net.get("Band") or ""
                band_map = {"2":  "2.4 GHz", "5":  "5 GHz",
                            "6":  "6 GHz",   "60": "60 GHz",
                            "2.4 GHz": "2.4 GHz", "5 GHz": "5 GHz",
                            "6 GHz": "6 GHz"}
                band = band_map.get(str(band_raw), str(band_raw))

                rows.append({
                    "SSID":             ssid,
                    "BSSID(s)":         bssid_str,
                    "Security":         security,
                    "Last Joined":      last_joined,
                    "Added":            added_at,
                    "Auto-Join":        auto_join,
                    "Personal Hotspot": hotspot,
                    "Channel":          channel,
                    "Band":             band,
                    "Hidden":           hidden,
                    "Disabled":         disabled,
                    "Source":           source_path,
                })

        # ── Fallback: networksetup (no sudo needed, but less detail) ──────────
        if not rows:
            for iface in ("en0", "en1", "en2"):
                out = self._run(["networksetup", "-listpreferredwirelessnetworks", iface])
                if "Error" in out or not out.strip():
                    continue
                for line in out.splitlines()[1:]:
                    ssid = line.strip()
                    if ssid:
                        rows.append({
                            "SSID":             ssid,
                            "BSSID(s)":         "",
                            "Security":         "",
                            "Last Joined":      "",
                            "Added":            "",
                            "Auto-Join":        "",
                            "Personal Hotspot": "",
                            "Channel":          "",
                            "Band":             "",
                            "Hidden":           "",
                            "Disabled":         "",
                            "Source":           f"networksetup {iface}",
                        })
                if rows:
                    break

        # ── Still nothing: explain why ─────────────────────────────────────────
        if not rows:
            rows.append({
                "SSID":             "No Wi-Fi records found",
                "BSSID(s)":         "",
                "Security":         "",
                "Last Joined":      "",
                "Added":            "",
                "Auto-Join":        "",
                "Personal Hotspot": "",
                "Channel":          "",
                "Band":             "",
                "Hidden":           "",
                "Disabled":         "",
                "Source":           "Grant Full Disk Access to Terminal in "
                                    "System Settings → Privacy & Security",
            })

        return ForensicResult("Network", "Known Wi-Fi Networks", rows, cols)

    # ── Spotlight Database ─────────────────────────────────────────────────────
    def collect_spotlight_shortcuts(self) -> ForensicResult:
        rows = []
        plist = f"{self.home}/Library/Application Support/com.apple.spotlight/com.apple.spotlight.shortcuts.plist"
        p = self._plist_read(plist)
        if p:
            for query, details in p.items():
                rows.append({
                    "Query":  query,
                    "Count":  str(details.get("DISPLAY_NAME", {}).get("count", "")),
                    "Last Used": str(details.get("lastUsed", "")),
                })
        if not rows:
            rows.append({"Query": "(No Spotlight shortcuts found)", "Count": "", "Last Used": ""})
        return ForensicResult("User Activity", "Spotlight Searches", rows,
                              ["Query", "Count", "Last Used"])

    # ── Running Processes ──────────────────────────────────────────────────────
    def collect_processes(self) -> ForensicResult:
        rows = []
        out = self._run(["ps", "aux"])
        for line in out.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                rows.append({
                    "User":    parts[0],
                    "PID":     parts[1],
                    "%CPU":    parts[2],
                    "%MEM":    parts[3],
                    "Started": parts[8],
                    "Command": parts[10],
                })
        return ForensicResult("System", "Running Processes", rows,
                              ["User", "PID", "%CPU", "%MEM", "Started", "Command"])

    # ── Cron Jobs ─────────────────────────────────────────────────────────────
    def collect_cron(self) -> ForensicResult:
        rows = []
        out = self._run(["crontab", "-l"])
        if out and "no crontab" not in out.lower() and "Error" not in out:
            for line in out.splitlines():
                if line.strip() and not line.startswith("#"):
                    rows.append({"Schedule": line.strip(), "User": self.username, "Source": "user crontab"})
        # System cron
        for f in glob.glob("/etc/cron*") + glob.glob("/var/cron/tabs/*"):
            if os.path.isfile(f):
                try:
                    with open(f) as fh:
                        for line in fh:
                            if line.strip() and not line.startswith("#"):
                                rows.append({"Schedule": line.strip(), "User": "system", "Source": f})
                except Exception:
                    pass
        if not rows:
            rows.append({"Schedule": "(No cron jobs found)", "User": "", "Source": ""})
        return ForensicResult("Persistence", "Cron Jobs", rows, ["Schedule", "User", "Source"])

    # ── File Hashing ───────────────────────────────────────────────────────────
    def hash_file(self, path: str) -> dict:
        result = {"Path": path, "MD5": "", "SHA1": "", "SHA256": "", "Size": "", "Error": ""}
        try:
            size = os.path.getsize(path)
            result["Size"] = self._human_size(size)
            if size > 500 * 1024 * 1024:
                result["Error"] = "File too large (>500MB)"
                return result
            with open(path, "rb") as f:
                data = f.read()
            result["MD5"]    = hashlib.md5(data).hexdigest()
            result["SHA1"]   = hashlib.sha1(data).hexdigest()
            result["SHA256"] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            result["Error"] = str(e)
        return result

    # ── System Logs ────────────────────────────────────────────────────────────
    def collect_unified_logs(self, predicate: str = "", limit: int = 200) -> ForensicResult:
        rows = []
        cmd = ["log", "show", "--last", "1h", "--style", "json"]
        if predicate:
            cmd += ["--predicate", predicate]
        out = self._run(cmd)
        try:
            entries = json.loads(out) if out.startswith("[") else []
            for e in entries[:limit]:
                rows.append({
                    "Timestamp":   e.get("timestamp", ""),
                    "Process":     e.get("processImagePath", "").split("/")[-1],
                    "Category":    e.get("category", ""),
                    "Message":     e.get("eventMessage", "")[:200],
                })
        except Exception:
            # Fallback: parse text log
            for line in out.splitlines()[:limit]:
                rows.append({"Timestamp": "", "Process": "", "Category": "", "Message": line})
        return ForensicResult("System", "Unified Logs (Last 1h)", rows,
                              ["Timestamp", "Process", "Category", "Message"])

    # ── Quarantine Events ──────────────────────────────────────────────────────
    def collect_quarantine(self) -> ForensicResult:
        db = f"{self.home}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        rows = self._sqlite_query(db, """
            SELECT LSQuarantineAgentName, LSQuarantineDataURLString,
                   LSQuarantineOriginURLString,
                   datetime(LSQuarantineTimeStamp + 978307200,'unixepoch','localtime') as timestamp,
                   LSQuarantineTypeNumber
            FROM LSQuarantineEvent
            ORDER BY LSQuarantineTimeStamp DESC LIMIT 300
        """)
        clean = []
        for r in rows:
            clean.append({
                "Agent":      r.get("LSQuarantineAgentName", ""),
                "File URL":   r.get("LSQuarantineDataURLString", ""),
                "Origin URL": r.get("LSQuarantineOriginURLString", ""),
                "Timestamp":  r.get("timestamp", ""),
                "Type":       str(r.get("LSQuarantineTypeNumber", "")),
            })
        if not clean:
            clean.append({"Agent": "No quarantine events or permission denied", "File URL": "",
                          "Origin URL": "", "Timestamp": "", "Type": ""})
        return ForensicResult("File Activity", "Quarantine Events", clean,
                              ["Timestamp", "Agent", "File URL", "Origin URL"])

    # ── USB / External Devices ─────────────────────────────────────────────────
    def collect_usb_devices(self) -> ForensicResult:
        rows = []
        out = self._run(["system_profiler", "SPUSBDataType", "-json"])
        try:
            data = json.loads(out)
            usb_items = data.get("SPUSBDataType", [])
            def flatten(items):
                for item in items:
                    rows.append({
                        "Name":           item.get("_name", ""),
                        "Manufacturer":   item.get("manufacturer", ""),
                        "Serial":         item.get("serial_num", ""),
                        "Vendor ID":      item.get("vendor_id", ""),
                        "Product ID":     item.get("product_id", ""),
                        "Speed":          item.get("device_speed", ""),
                    })
                    if "_items" in item:
                        flatten(item["_items"])
            flatten(usb_items)
        except Exception:
            out2 = self._run(["system_profiler", "SPUSBDataType"])
            for line in out2.splitlines():
                if ":" in line and not line.strip().startswith("USB"):
                    k, _, v = line.partition(":")
                    rows.append({"Name": k.strip(), "Manufacturer": "", "Serial": v.strip(),
                                 "Vendor ID": "", "Product ID": "", "Speed": ""})
        if not rows:
            rows.append({"Name": "No USB devices detected", "Manufacturer": "",
                         "Serial": "", "Vendor ID": "", "Product ID": "", "Speed": ""})
        return ForensicResult("Devices", "USB Devices", rows,
                              ["Name", "Manufacturer", "Serial", "Vendor ID", "Product ID", "Speed"])

    # ── Disk & Volume Info ────────────────────────────────────────────────────
    def collect_disks(self) -> ForensicResult:
        rows = []
        out = self._run(["diskutil", "list", "-plist"])
        try:
            p = plistlib.loads(out.encode() if isinstance(out, str) else out)
            for disk in p.get("AllDisksAndPartitions", []):
                rows.append({
                    "Device":     disk.get("DeviceIdentifier", ""),
                    "Content":    disk.get("Content", ""),
                    "Size":       self._human_size(disk.get("Size", 0)),
                    "Partitions": str(len(disk.get("Partitions", []))),
                    "MountPoint": disk.get("MountPoint", ""),
                })
                for part in disk.get("Partitions", []):
                    rows.append({
                        "Device":     "  " + part.get("DeviceIdentifier", ""),
                        "Content":    part.get("Content", ""),
                        "Size":       self._human_size(part.get("Size", 0)),
                        "Partitions": "",
                        "MountPoint": part.get("MountPoint", ""),
                    })
        except Exception:
            out2 = self._run(["df", "-h"])
            for line in out2.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    rows.append({"Device": parts[0], "Content": "", "Size": parts[1],
                                 "Partitions": "", "MountPoint": parts[5]})
        return ForensicResult("System", "Disks & Volumes", rows,
                              ["Device", "Content", "Size", "Partitions", "MountPoint"])

    # ── Preferences ───────────────────────────────────────────────────────────
    def collect_preferences(self) -> ForensicResult:
        """
        Reads key forensic-relevant preference plists from ~/Library/Preferences/.
        Parses each to a flat key=value table with source filename, key path,
        value, and type — useful for revealing app configs, privacy settings,
        and user behaviour patterns.
        """
        rows = []
        cols = ["Domain", "Key", "Value", "Type", "File"]

        TARGETS = [
            # Privacy & Security
            ("com.apple.security.plist",            "Security"),
            ("com.apple.TCC.plist",                 "TCC Privacy"),
            # Network & Location
            ("com.apple.locationd.plist",           "Location Services"),
            ("com.apple.airport.preferences.plist", "Wi-Fi / Airport"),
            # User behaviour
            ("com.apple.finder.plist",              "Finder"),
            ("com.apple.dock.plist",                "Dock"),
            ("com.apple.recentitems.plist",         "Recent Items"),
            ("com.apple.HIToolbox.plist",           "Input/HI"),
            ("com.apple.LaunchServices.plist",      "LaunchServices"),
            ("com.apple.loginwindow.plist",         "Login Window"),
            # Time & Locale
            ("com.apple.TimeZonePref.plist",        "TimeZone"),
            ("com.apple.screensaver.plist",         "Screensaver"),
            # iCloud / Apple ID
            ("MobileMeAccounts.plist",              "iCloud Accounts"),
            ("com.apple.icloud.fmfd.plist",         "Find My"),
        ]

        search_dirs = [
            f"{self.home}/Library/Preferences",
            "/Library/Preferences",
        ]

        def _flatten(obj, prefix="", depth=0):
            """Recursively flatten nested dicts/lists to dotted key=value pairs."""
            if depth > 6:
                yield prefix, repr(obj)[:200], type(obj).__name__
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full_key = f"{prefix}.{k}" if prefix else str(k)
                    yield from _flatten(v, full_key, depth + 1)
            elif isinstance(obj, list):
                for i, v in enumerate(obj[:20]):
                    yield from _flatten(v, f"{prefix}[{i}]", depth + 1)
            elif isinstance(obj, bytes):
                yield prefix, f"<bytes {len(obj)}B> {obj[:16].hex()}", "bytes"
            elif isinstance(obj, datetime.datetime):
                yield prefix, obj.strftime("%Y-%m-%d %H:%M:%S"), "datetime"
            else:
                yield prefix, str(obj)[:300], type(obj).__name__

        for fname, domain in TARGETS:
            for base_dir in search_dirs:
                fpath = os.path.join(base_dir, fname)
                if not os.path.exists(fpath):
                    continue
                p = self._plist_read(fpath)
                if not p or not isinstance(p, dict):
                    continue
                for key, val, typ in _flatten(p):
                    rows.append({
                        "Domain": domain,
                        "Key":    key,
                        "Value":  val,
                        "Type":   typ,
                        "File":   fpath,
                    })
                break   # found in first search_dir, skip second

        # Grab any remaining *.plist not in TARGETS list
        target_fnames = {t[0] for t in TARGETS}
        pref_dir = f"{self.home}/Library/Preferences"
        if os.path.isdir(pref_dir):
            for pf in sorted(glob.glob(f"{pref_dir}/*.plist"))[:40]:
                if os.path.basename(pf) in target_fnames:
                    continue
                p = self._plist_read(pf)
                if not p or not isinstance(p, dict):
                    continue
                for key, val, typ in list(_flatten(p))[:30]:
                    rows.append({
                        "Domain": os.path.basename(pf).replace(".plist", ""),
                        "Key":    key,
                        "Value":  val,
                        "Type":   typ,
                        "File":   pf,
                    })

        if not rows:
            rows.append({"Domain": "No preferences readable", "Key": "",
                         "Value": "", "Type": "", "File": ""})

        return ForensicResult("System", "Preferences", rows, cols)

    # ── FSEvents ──────────────────────────────────────────────────────────────
    def collect_fsevents(self) -> ForensicResult:
        """
        Parses the macOS FSEvents stream logs located at:
            <volume>/.fseventsd/

        FSEvents are stored as compressed binary log files. Each record
        contains a path and a bitmask of event flags (created, modified,
        removed, renamed, etc.).

        We parse using pure Python (no external tools) by reading the
        binary format: 8-byte magic + records of {flags:uint32, nodeid:uint64,
        path:null-terminated UTF-8}.

        Two log roots are checked:
          /  (boot volume)
          ~/  (user directory via .fseventsd if any)
        """
        import struct

        FSEVENTS_DIR = "/.fseventsd"
        MAGIC_V1 = b"1SLD"
        MAGIC_V2 = b"2SLD"

        FLAG_NAMES = {
            0x00000001: "Created",
            0x00000002: "Removed",
            0x00000004: "InodeMetaMod",
            0x00000008: "Renamed",
            0x00000010: "Modified",
            0x00000020: "Exchange",
            0x00000040: "FinderInfoMod",
            0x00000080: "FolderCreated",
            0x00000100: "PermissionChange",
            0x00000200: "XattrMod",
            0x00000400: "IsFile",
            0x00000800: "IsDir",
            0x00001000: "IsSymlink",
            0x00002000: "OwnEvent",
            0x00004000: "IsHardlink",
            0x00008000: "IsLastHardlink",
            0x00010000: "ItemCloned",
            0x01000000: "MustScanSubDirs",
            0x02000000: "UserDropped",
            0x04000000: "KernelDropped",
            0x08000000: "EventIDsWrapped",
            0x10000000: "HistoryDone",
            0x20000000: "RootChanged",
            0x40000000: "Mount",
            0x80000000: "Unmount",
        }

        def _flags_str(flags: int) -> str:
            return " | ".join(n for mask, n in FLAG_NAMES.items() if flags & mask) or hex(flags)

        def _parse_fsevents_file(fpath: str) -> list:
            """Return list of (path, flags_str, node_id) from one FSEvents log file."""
            records = []
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                if len(data) < 12:
                    return records

                magic = data[:4]
                if magic not in (MAGIC_V1, MAGIC_V2):
                    return records

                # Header: magic(4) + version?(4) + file_id?(4) = 12 bytes preamble
                offset = 12
                while offset < len(data) - 13:
                    try:
                        flags   = struct.unpack_from("<I", data, offset)[0]; offset += 4
                        node_id = struct.unpack_from("<Q", data, offset)[0]; offset += 8
                        # null-terminated path
                        end = data.index(b"\x00", offset)
                        path = data[offset:end].decode("utf-8", errors="replace")
                        offset = end + 1
                        records.append((path, _flags_str(flags), str(node_id)))
                    except (struct.error, ValueError):
                        break
            except Exception:
                pass
            return records

        rows = []
        cols = ["Path", "Event Flags", "Node ID", "Log File"]

        fseventsd = FSEVENTS_DIR
        limit_per_file = 300
        files_parsed = 0

        if os.path.isdir(fseventsd):
            log_files = sorted(
                [f for f in glob.glob(f"{fseventsd}/*")
                 if os.path.isfile(f) and not os.path.basename(f).startswith(".")],
                reverse=True  # newest first
            )[:10]  # cap at 10 log files

            for lf in log_files:
                recs = _parse_fsevents_file(lf)
                files_parsed += 1
                for path, flags, nid in recs[-limit_per_file:]:
                    rows.append({
                        "Path":       path,
                        "Event Flags": flags,
                        "Node ID":    nid,
                        "Log File":   os.path.basename(lf),
                    })

        if not rows:
            # Fallback: show the log file listing even if we can't parse content
            if os.path.isdir(fseventsd):
                for f in glob.glob(f"{fseventsd}/*"):
                    st = os.stat(f)
                    rows.append({
                        "Path":        f,
                        "Event Flags": f"(binary — {self._human_size(st.st_size)})",
                        "Node ID":     "",
                        "Log File":    os.path.basename(f),
                    })
                if not rows:
                    rows.append({"Path": "/.fseventsd exists but is empty",
                                 "Event Flags": "", "Node ID": "", "Log File": ""})
            else:
                rows.append({"Path": "/.fseventsd not accessible — requires sudo or Full Disk Access",
                             "Event Flags": "", "Node ID": "", "Log File": ""})

        return ForensicResult("File Activity", "FSEvents Log", rows, cols)

    # ── Messages (iMessage / SMS) ─────────────────────────────────────────────
    def collect_messages(self) -> ForensicResult:
        """
        Parses the Messages chat database at:
            ~/Library/Messages/chat.db

        Tables of interest:
          message   — individual messages (text, date, service, account)
          handle    — sender/recipient identifiers (phone / email)
          chat      — conversation threads
          attachment — file attachments

        Timestamps use Apple epoch (2001-01-01), stored as nanoseconds
        in macOS 10.13+ or seconds in earlier versions.  We detect which
        scale is in use by checking the magnitude of the date column.
        """
        APPLE_EPOCH = 978307200
        db_orig = f"{self.home}/Library/Messages/chat.db"

        if not os.path.exists(db_orig):
            return ForensicResult("Communications", "Messages (iMessage/SMS)",
                [{"Date": "", "Service": "", "From/To": "chat.db not found",
                  "Direction": "", "Text": "Messages app may not be configured on this Mac",
                  "Attachment": ""}],
                ["Date", "Service", "From/To", "Direction", "Text", "Attachment"])

        tmp_dir = tempfile.mkdtemp(prefix="messages_forensics_")
        tmp_db  = os.path.join(tmp_dir, "chat.db")
        rows = []
        cols = ["Date", "Service", "From/To", "Direction", "Text", "Attachment"]

        try:
            shutil.copy2(db_orig, tmp_db)
            for suf in ("-wal", "-shm"):
                src = db_orig + suf
                if os.path.exists(src):
                    shutil.copy2(src, tmp_db + suf)

            raw = self._sqlite_query(tmp_db, """
                SELECT
                    m.rowid,
                    m.date,
                    m.is_from_me,
                    m.service,
                    m.account,
                    m.text,
                    h.id          AS handle_id,
                    a.filename    AS attach_file,
                    a.mime_type   AS attach_mime
                FROM message m
                LEFT JOIN handle     h ON m.handle_id    = h.rowid
                LEFT JOIN message_attachment_join maj ON maj.message_id = m.rowid
                LEFT JOIN attachment a ON a.rowid = maj.attachment_id
                ORDER BY m.date DESC
                LIMIT 1000
            """)

            if not raw or (len(raw) == 1 and "error" in raw[0]):
                err = raw[0].get("error", "") if raw else "empty"
                rows = [{"Date": "", "Service": "", "From/To": f"Query error: {err}",
                         "Direction": "", "Text": "", "Attachment": ""}]
            else:
                for r in raw:
                    raw_date = r.get("date") or 0
                    # macOS 10.13+: date is in nanoseconds; earlier: seconds
                    if raw_date > 1e15:
                        unix_ts = raw_date / 1e9 + APPLE_EPOCH
                    else:
                        unix_ts = raw_date + APPLE_EPOCH
                    try:
                        ts = datetime.datetime.utcfromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        ts = str(raw_date)

                    direction  = "Sent" if r.get("is_from_me") else "Received"
                    handle     = r.get("handle_id") or r.get("account") or ""
                    text       = (r.get("text") or "").replace("\n", " ")[:300]
                    attach     = r.get("attach_file") or ""
                    if attach:
                        attach = attach.replace("~/", f"{self.home}/")
                        attach = f"{os.path.basename(attach)}  [{r.get('attach_mime','')}]"

                    rows.append({
                        "Date":      ts,
                        "Service":   r.get("service") or "",
                        "From/To":   handle,
                        "Direction": direction,
                        "Text":      text,
                        "Attachment": attach,
                    })
        except Exception as exc:
            rows = [{"Date": "", "Service": "", "From/To": f"Error: {exc}",
                     "Direction": "", "Text": "", "Attachment": ""}]
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return ForensicResult("Communications", "Messages (iMessage/SMS)", rows, cols)

    # ── AirDrop ───────────────────────────────────────────────────────────────
    def collect_airdrop(self) -> ForensicResult:
        """
        AirDrop forensic artifacts from multiple sources:

        1. Unified log — com.apple.sharing.airdrop subsystem captures
           discovered peers, transfer requests, and completions.
        2. com.apple.sharingd preferences plist (transfer history metadata).
        3. ~/Downloads/ — AirDrop received files land here; we flag items
           whose xattr com.apple.quarantine contains "AirDrop" as origin.
        4. AWDL syslog entries (Apple Wireless Direct Link) for device discovery.
        """
        rows = []
        cols = ["Timestamp", "Event", "Peer / File", "Direction", "Status", "Source"]
        APPLE_EPOCH = 978307200

        # ── 1. Unified log ────────────────────────────────────────────────────
        log_cmd = [
            "log", "show",
            "--predicate",
            '(subsystem == "com.apple.sharing.airdrop") OR '
            '(subsystem == "com.apple.sharingd") OR '
            '(process == "AirDropUIAgent") OR '
            '(eventMessage CONTAINS[c] "airdrop")',
            "--last", "30d",
            "--style", "json",
            "--info",
        ]
        out = self._run(log_cmd)
        try:
            entries = json.loads(out) if out.strip().startswith("[") else []
            for e in entries[:500]:
                msg = e.get("eventMessage", "")
                ts  = e.get("timestamp", "")
                proc = (e.get("processImagePath") or "").split("/")[-1]
                # Classify event type
                ev_type = "Info"
                if any(w in msg.lower() for w in ("send", "sent", "upload")):
                    ev_type = "Send"
                elif any(w in msg.lower() for w in ("receiv", "download", "accept")):
                    ev_type = "Receive"
                elif any(w in msg.lower() for w in ("discover", "found", "peer", "browser")):
                    ev_type = "Discovery"
                elif any(w in msg.lower() for w in ("declin", "cancel", "reject")):
                    ev_type = "Declined"
                rows.append({
                    "Timestamp": ts[:19] if ts else "",
                    "Event":     ev_type,
                    "Peer / File": msg[:200],
                    "Direction": "",
                    "Status":    proc,
                    "Source":    "Unified Log",
                })
        except Exception:
            # Non-JSON fallback
            for line in out.splitlines()[:300]:
                if line.strip():
                    rows.append({"Timestamp": "", "Event": "Log Line",
                                 "Peer / File": line.strip()[:200],
                                 "Direction": "", "Status": "", "Source": "Unified Log"})

        # ── 2. AirDrop received files in Downloads (xattr check) ──────────────
        downloads = f"{self.home}/Downloads"
        if os.path.isdir(downloads):
            for entry in os.scandir(downloads):
                # Check quarantine xattr for AirDrop origin
                xattr_out = self._run(
                    ["xattr", "-p", "com.apple.quarantine", entry.path])
                if "AirDrop" in xattr_out or "0003;" in xattr_out:
                    st = entry.stat()
                    ts = datetime.datetime.fromtimestamp(
                        st.st_birthtime).strftime("%Y-%m-%d %H:%M:%S")
                    rows.append({
                        "Timestamp": ts,
                        "Event":     "Received File",
                        "Peer / File": entry.name,
                        "Direction": "Inbound",
                        "Status":    self._human_size(st.st_size),
                        "Source":    "Downloads xattr",
                    })

        # ── 3. sharingd plist ─────────────────────────────────────────────────
        sharing_plist = f"{self.home}/Library/Preferences/com.apple.sharingd.plist"
        p = self._plist_read(sharing_plist)
        if p:
            for key, val in p.items():
                rows.append({
                    "Timestamp": "",
                    "Event":     "Pref",
                    "Peer / File": f"{key} = {str(val)[:150]}",
                    "Direction": "",
                    "Status":    "",
                    "Source":    "com.apple.sharingd.plist",
                })

        if not rows:
            rows.append({
                "Timestamp": "", "Event": "No AirDrop records found",
                "Peer / File": "Run with sudo or grant Full Disk Access for log access",
                "Direction": "", "Status": "", "Source": "",
            })

        return ForensicResult("Communications", "AirDrop Activity", rows, cols)

    # ── iCloud Sync Records ───────────────────────────────────────────────────
    def collect_icloud(self) -> ForensicResult:
        """
        iCloud forensic artefacts from:

        1. ~/Library/Mobile Documents/   — iCloud Drive synced file tree
           (lists all files currently or previously synced; metadata only).
        2. com.apple.bird (CloudDocs) database —
              ~/Library/Application Support/CloudDocs/session/db
           Stores sync status, upload/download timestamps, conflict records.
        3. MobileMeAccounts.plist — registered iCloud account identifiers.
        4. com.apple.icloud.fmfd.plist — Find My device registration.
        5. Unified log — com.apple.bird and com.apple.cloudd subsystems.
        """
        APPLE_EPOCH = 978307200
        rows = []
        cols = ["Item", "Status", "Account / Path", "Modified", "Size", "Source"]

        # ── 1. MobileMeAccounts.plist ─────────────────────────────────────────
        mme = f"{self.home}/Library/Preferences/MobileMeAccounts.plist"
        p   = self._plist_read(mme)
        if p:
            for acct in p.get("Accounts", []):
                if not isinstance(acct, dict):
                    continue
                rows.append({
                    "Item":    "Account",
                    "Status":  acct.get("AccountDescription", ""),
                    "Account / Path": acct.get("AccountID", ""),
                    "Modified": "",
                    "Size":    "",
                    "Source":  "MobileMeAccounts.plist",
                })
                for svc in acct.get("Services", []):
                    if isinstance(svc, dict):
                        rows.append({
                            "Item":    "  Service",
                            "Status":  str(svc.get("Enabled", "")),
                            "Account / Path": svc.get("ServiceType", ""),
                            "Modified": "",
                            "Size":    "",
                            "Source":  "MobileMeAccounts.plist",
                        })

        # ── 2. CloudDocs sync DB ──────────────────────────────────────────────
        cloud_db = f"{self.home}/Library/Application Support/CloudDocs/session/db"
        if os.path.exists(cloud_db):
            tmp_dir = tempfile.mkdtemp(prefix="icloud_forensics_")
            tmp_db  = os.path.join(tmp_dir, "db")
            try:
                shutil.copy2(cloud_db, tmp_db)
                # Try to discover tables first
                tables = self._sqlite_query(tmp_db,
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                table_names = [t.get("name","") for t in tables]

                for tname in table_names[:10]:
                    recs = self._sqlite_query(tmp_db,
                        f'SELECT * FROM "{tname}" LIMIT 100')
                    for rec in recs:
                        if "error" in rec:
                            continue
                        # Flatten first few interesting columns
                        vals = list(rec.values())
                        rows.append({
                            "Item":    tname,
                            "Status":  str(vals[1])[:100] if len(vals) > 1 else "",
                            "Account / Path": str(vals[2])[:200] if len(vals) > 2 else "",
                            "Modified": str(vals[3])[:30] if len(vals) > 3 else "",
                            "Size":    str(vals[4])[:20] if len(vals) > 4 else "",
                            "Source":  "CloudDocs/session/db",
                        })
            except Exception:
                pass
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        # ── 3. iCloud Drive file tree (Mobile Documents) ─────────────────────
        mobile_docs = f"{self.home}/Library/Mobile Documents"
        if os.path.isdir(mobile_docs):
            for container in sorted(os.scandir(mobile_docs), key=lambda e: e.name):
                if not container.is_dir():
                    continue
                app_name = container.name.replace("~", "/").split("/")[-1]
                try:
                    file_count = sum(1 for _ in os.scandir(container.path)
                                     if _.is_file())
                    total_size = sum(e.stat().st_size for e in
                                     os.scandir(container.path) if e.is_file())
                except Exception:
                    file_count, total_size = 0, 0

                rows.append({
                    "Item":    "iCloud Container",
                    "Status":  f"{file_count} files",
                    "Account / Path": container.path,
                    "Modified": "",
                    "Size":    self._human_size(total_size),
                    "Source":  "Mobile Documents",
                })
                # List files inside (up to 20 per container)
                try:
                    for entry in list(os.scandir(container.path))[:20]:
                        if entry.is_file():
                            st = entry.stat()
                            rows.append({
                                "Item":    f"  {app_name}/{entry.name}",
                                "Status":  "Synced",
                                "Account / Path": entry.path,
                                "Modified": datetime.datetime.fromtimestamp(
                                    st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                "Size":    self._human_size(st.st_size),
                                "Source":  "Mobile Documents",
                            })
                except Exception:
                    pass

        # ── 4. Unified log ────────────────────────────────────────────────────
        log_out = self._run([
            "log", "show",
            "--predicate",
            '(subsystem == "com.apple.bird") OR (subsystem == "com.apple.cloudd") OR '
            '(process == "bird") OR (process == "cloudd")',
            "--last", "7d", "--style", "json",
        ])
        try:
            entries = json.loads(log_out) if log_out.strip().startswith("[") else []
            for e in entries[:200]:
                rows.append({
                    "Item":    "Log Event",
                    "Status":  (e.get("processImagePath") or "").split("/")[-1],
                    "Account / Path": e.get("eventMessage", "")[:200],
                    "Modified": e.get("timestamp", "")[:19],
                    "Size":    "",
                    "Source":  "Unified Log (bird/cloudd)",
                })
        except Exception:
            pass

        if not rows:
            rows.append({"Item": "No iCloud records found",
                         "Status": "Grant Full Disk Access to Terminal",
                         "Account / Path": "", "Modified": "", "Size": "", "Source": ""})

        return ForensicResult("Cloud & Sync", "iCloud Sync Records", rows, cols)

    def _human_size(self, n: int) -> str:
        for unit in ["B","KB","MB","GB","TB"]:
            if abs(n) < 1024.0:
                return f"{n:.1f} {unit}"
            n /= 1024.0
        return f"{n:.1f} PB"


# ─── Worker Thread ─────────────────────────────────────────────────────────────

class CollectionWorker(QThread):
    progress    = pyqtSignal(int, str)
    result_ready= pyqtSignal(object)
    finished    = pyqtSignal()
    error       = pyqtSignal(str)

    def __init__(self, collector: MacOSCollector, tasks: list):
        super().__init__()
        self.collector = collector
        self.tasks = tasks

    def run(self):
        total = len(self.tasks)
        for i, (method_name, label) in enumerate(self.tasks):
            self.progress.emit(int((i / total) * 100), f"Collecting: {label}")
            try:
                method = getattr(self.collector, method_name)
                result = method()
                self.result_ready.emit(result)
            except Exception as e:
                self.error.emit(f"{label}: {e}")
        self.progress.emit(100, "Collection complete")
        self.finished.emit()


# ─── Artifact Tree Panel ───────────────────────────────────────────────────────

class ArtifactTree(QTreeWidget):
    artifact_selected = pyqtSignal(str)

    CATEGORIES = {
        "🖥  System": [
            "System Information", "User Accounts", "Running Processes",
            "Installed Applications", "Disks & Volumes", "Unified Logs (Last 1h)",
            "Preferences",
        ],
        "🔒  Persistence": [
            "Launch Agents & Daemons", "Login Items", "Cron Jobs"
        ],
        "🌐  Web Activity": [
            "Safari History", "Chrome History"
        ],
        "📁  File Activity": [
            "Downloads Folder", "Recent Items", "Quarantine Events",
            "FSEvents Log",
        ],
        "👤  User Activity": [
            "Shell History", "Spotlight Searches"
        ],
        "📡  Network": [
            "Active Connections", "Known Wi-Fi Networks"
        ],
        "🔌  Devices": [
            "USB Devices"
        ],
        "💬  Communications": [
            "Messages (iMessage/SMS)", "AirDrop Activity",
        ],
        "☁️  Cloud & Sync": [
            "iCloud Sync Records",
        ],
    }

    def __init__(self):
        super().__init__()
        self.setHeaderHidden(True)
        self.setAnimated(True)
        self.setIndentation(16)
        self._build()
        self.itemClicked.connect(self._on_click)
        self._results = {}

    def _build(self):
        self.clear()
        for cat, items in self.CATEGORIES.items():
            parent = QTreeWidgetItem(self, [cat])
            parent.setExpanded(True)
            f = parent.font(0)
            f.setPointSize(11)
            f.setBold(True)
            parent.setFont(0, f)
            parent.setForeground(0, QBrush(QColor(COLORS["text_secondary"])))
            for name in items:
                child = QTreeWidgetItem(parent, [f"  {name}"])
                child.setData(0, Qt.ItemDataRole.UserRole, name)
                child.setForeground(0, QBrush(QColor(COLORS["text_primary"])))

    def _on_click(self, item, _col):
        key = item.data(0, Qt.ItemDataRole.UserRole)
        if key:
            self.artifact_selected.emit(key)

    def mark_collected(self, artifact_name: str):
        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            cat = root.child(i)
            for j in range(cat.childCount()):
                child = cat.child(j)
                if child.data(0, Qt.ItemDataRole.UserRole) == artifact_name:
                    child.setForeground(0, QBrush(QColor(COLORS["accent_green"])))
                    child.setText(0, f"  ✓ {artifact_name}")
                    return


# ─── Result Table ──────────────────────────────────────────────────────────────

class ResultTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.setSortingEnabled(True)

    def load_result(self, result: ForensicResult):
        self.clear()
        self.setColumnCount(len(result.columns))
        self.setHorizontalHeaderLabels(result.columns)
        self.setRowCount(len(result.data))
        for row_idx, row in enumerate(result.data):
            for col_idx, col in enumerate(result.columns):
                val = str(row.get(col, ""))
                item = QTableWidgetItem(val)
                # Color coding
                if col in ("State",) and val == "ESTABLISHED":
                    item.setForeground(QBrush(QColor(COLORS["accent_green"])))
                elif col in ("State",) and "LISTEN" in val:
                    item.setForeground(QBrush(QColor(COLORS["accent_yellow"])))
                elif col in ("RunAtLoad",) and val == "True":
                    item.setForeground(QBrush(QColor(COLORS["accent_orange"])))
                self.setItem(row_idx, col_idx, item)
        self.resizeColumnsToContents()
        # Ensure last column stretches
        self.horizontalHeader().setStretchLastSection(True)


# ─── Detail / Hex Viewer ───────────────────────────────────────────────────────

class DetailPane(QTabWidget):
    def __init__(self):
        super().__init__()
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._json = QPlainTextEdit()
        self._json.setReadOnly(True)
        self.addTab(self._text, "Detail View")
        self.addTab(self._json, "JSON Export")

    def show_result(self, result: ForensicResult):
        # Detail
        lines = [
            f"Artifact:   {result.artifact}",
            f"Category:   {result.category}",
            f"Collected:  {result.timestamp}",
            f"Records:    {result.count}",
            "─" * 60,
        ]
        for i, row in enumerate(result.data[:50]):
            lines.append(f"\n[{i+1}]")
            for k, v in row.items():
                lines.append(f"  {k:<20} {v}")
        if result.count > 50:
            lines.append(f"\n... and {result.count - 50} more records")
        self._text.setPlainText("\n".join(lines))

        # JSON
        export = {
            "artifact":  result.artifact,
            "category":  result.category,
            "timestamp": result.timestamp,
            "count":     result.count,
            "data":      result.data[:200],
        }
        self._json.setPlainText(json.dumps(export, indent=2, default=str))


# ─── Hash Tool ────────────────────────────────────────────────────────────────

class HashTool(QWidget):
    def __init__(self, collector: MacOSCollector):
        super().__init__()
        self.collector = collector
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        top = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Enter file path or drag & drop...")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        hash_btn = QPushButton("Hash File")
        hash_btn.setObjectName("primary")
        hash_btn.clicked.connect(self._hash)
        top.addWidget(self.path_edit)
        top.addWidget(browse)
        top.addWidget(hash_btn)
        layout.addLayout(top)

        self.result_area = QPlainTextEdit()
        self.result_area.setReadOnly(True)
        self.result_area.setPlaceholderText("Hash results will appear here...")
        layout.addWidget(self.result_area)

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select File")
        if p:
            self.path_edit.setText(p)

    def _hash(self):
        path = self.path_edit.text().strip()
        if not path:
            return
        self.result_area.setPlainText("Computing hashes…")
        QApplication.processEvents()
        r = self.collector.hash_file(path)
        lines = [
            f"File:   {r['Path']}",
            f"Size:   {r['Size']}",
            f"",
            f"MD5:    {r['MD5']}",
            f"SHA1:   {r['SHA1']}",
            f"SHA256: {r['SHA256']}",
        ]
        if r["Error"]:
            lines.append(f"\nError: {r['Error']}")
        self.result_area.setPlainText("\n".join(lines))


# ─── Log Search ───────────────────────────────────────────────────────────────

class LogSearch(QWidget):
    def __init__(self, collector: MacOSCollector):
        super().__init__()
        self.collector = collector
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        row = QHBoxLayout()
        self.pred_edit = QLineEdit()
        self.pred_edit.setPlaceholderText('log predicate, e.g. process == "Safari" OR subsystem == "com.apple.network"')
        search_btn = QPushButton("Search Logs")
        search_btn.setObjectName("primary")
        search_btn.clicked.connect(self._search)
        row.addWidget(self.pred_edit)
        row.addWidget(search_btn)
        layout.addLayout(row)

        self.table = ResultTable()
        layout.addWidget(self.table)

    def _search(self):
        pred = self.pred_edit.text().strip()
        r = self.collector.collect_unified_logs(predicate=pred, limit=300)
        self.table.load_result(r)


# ─── SQLite Browser ───────────────────────────────────────────────────────────

class SQLiteBrowser(QWidget):
    def __init__(self, collector: MacOSCollector):
        super().__init__()
        self.collector = collector
        self.current_db = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        top = QHBoxLayout()
        self.db_path = QLineEdit()
        self.db_path.setPlaceholderText("Path to SQLite database...")
        browse = QPushButton("Open DB")
        browse.clicked.connect(self._open)
        top.addWidget(self.db_path)
        top.addWidget(browse)
        layout.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.table_list = QTreeWidget()
        self.table_list.setHeaderLabel("Tables")
        self.table_list.itemClicked.connect(self._on_table_click)
        splitter.addWidget(self.table_list)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setSpacing(6)
        rv.setContentsMargins(0, 0, 0, 0)

        qrow = QHBoxLayout()
        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText("SELECT * FROM table LIMIT 100")
        run_btn = QPushButton("Run Query")
        run_btn.setObjectName("primary")
        run_btn.clicked.connect(self._run_query)
        qrow.addWidget(self.query_edit)
        qrow.addWidget(run_btn)
        rv.addLayout(qrow)

        self.result_table = ResultTable()
        rv.addWidget(self.result_table)
        splitter.addWidget(right)
        splitter.setSizes([180, 620])
        layout.addWidget(splitter)

    def _open(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open SQLite DB", "",
                                            "SQLite Files (*.db *.sqlite *.sqlite3);;All Files (*)")
        if not p:
            return
        self.db_path.setText(p)
        self.current_db = p
        self.table_list.clear()
        try:
            conn = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            for (name,) in cur.fetchall():
                item = QTreeWidgetItem(self.table_list, [name])
                item.setData(0, Qt.ItemDataRole.UserRole, name)
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _on_table_click(self, item, _):
        table = item.data(0, Qt.ItemDataRole.UserRole)
        if table and self.current_db:
            self.query_edit.setText(f"SELECT * FROM \"{table}\" LIMIT 200")
            self._run_query()

    def _run_query(self):
        if not self.current_db:
            return
        q = self.query_edit.text().strip()
        if not q:
            return
        rows = self.collector._sqlite_query(self.current_db, q)
        if rows:
            cols = list(rows[0].keys())
            r = ForensicResult("SQLite", self.current_db, rows, cols)
            self.result_table.load_result(r)


# ─── Report Generator ─────────────────────────────────────────────────────────

class ReportGenerator(QWidget):
    def __init__(self, results_store: dict):
        super().__init__()
        self.results = results_store
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        hdr = QLabel("Generate Case Report")
        hdr.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 16px; font-weight: 600;")
        layout.addWidget(hdr)

        grp = QGroupBox("Report Options")
        gl = QVBoxLayout(grp)
        self.incl_system   = QCheckBox("System Information & Users")
        self.incl_persist  = QCheckBox("Persistence Mechanisms")
        self.incl_web      = QCheckBox("Web & Browser Activity")
        self.incl_files    = QCheckBox("File Activity & Quarantine")
        self.incl_network  = QCheckBox("Network Connections & Wi-Fi")
        self.incl_activity = QCheckBox("User Activity (Shell/Spotlight)")
        for cb in [self.incl_system, self.incl_persist, self.incl_web,
                   self.incl_files, self.incl_network, self.incl_activity]:
            cb.setChecked(True)
            gl.addWidget(cb)
        layout.addWidget(grp)

        row = QHBoxLayout()
        self.fmt_combo = QComboBox()
        self.fmt_combo.addItems(["JSON Report", "CSV Export", "Text Report"])
        export_btn = QPushButton("Export Report")
        export_btn.setObjectName("primary")
        export_btn.clicked.connect(self._export)
        row.addWidget(QLabel("Format:"))
        row.addWidget(self.fmt_combo)
        row.addStretch()
        row.addWidget(export_btn)
        layout.addLayout(row)

        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("Report preview will appear here after collection…")
        layout.addWidget(self.preview)
        self._refresh_preview()

    def _refresh_preview(self):
        if not self.results:
            return
        lines = [
            "MacOS FORENSICS LAB — CASE REPORT",
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"System:    {platform.node()}",
            f"User:      {os.getenv('USER')}",
            "=" * 60,
            f"Total Artifacts Collected: {len(self.results)}",
            "",
        ]
        for name, result in self.results.items():
            lines.append(f"\n[{result.category.upper()}] {name}")
            lines.append(f"  Records: {result.count}  |  Collected: {result.timestamp[:19]}")
        self.preview.setPlainText("\n".join(lines))

    def _export(self):
        fmt = self.fmt_combo.currentText()
        ext = {"JSON Report": "json", "CSV Export": "csv", "Text Report": "txt"}[fmt]
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", f"forensics_report_{datetime.date.today()}.{ext}",
            f"*.{ext}")
        if not path:
            return
        try:
            if fmt == "JSON Report":
                data = {}
                for name, r in self.results.items():
                    data[name] = {"category": r.category, "timestamp": r.timestamp,
                                  "count": r.count, "data": r.data[:500]}
                with open(path, "w") as f:
                    json.dump(data, f, indent=2, default=str)
            elif fmt == "CSV Export":
                with open(path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Artifact", "Category", "Timestamp"] + ["Key", "Value"])
                    for name, r in self.results.items():
                        for row in r.data:
                            for k, v in row.items():
                                writer.writerow([name, r.category, r.timestamp, k, v])
            else:
                lines = [
                    "MacOS FORENSICS LAB — FULL TEXT REPORT",
                    f"Generated: {datetime.datetime.now().isoformat()}",
                    "=" * 70,
                ]
                for name, r in self.results.items():
                    lines += ["", f"{'─'*70}", f"ARTIFACT: {name}", f"Category: {r.category}",
                              f"Collected: {r.timestamp}", f"Records: {r.count}", ""]
                    for row in r.data[:100]:
                        for k, v in row.items():
                            lines.append(f"  {k:<25} {v}")
                        lines.append("")
                with open(path, "w") as f:
                    f.write("\n".join(lines))
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{path}")
            self._refresh_preview()
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))


# ─── Header Widget ─────────────────────────────────────────────────────────────

class HeaderBar(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(56)
        self.setStyleSheet(f"background-color: {COLORS['header_bg']}; border-bottom: 1px solid {COLORS['border']};")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)

        icon_lbl = QLabel("🔬")
        icon_lbl.setStyleSheet("font-size: 22px;")
        layout.addWidget(icon_lbl)

        title = QLabel("MacOS Forensics Lab")
        title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 16px; font-weight: 700; letter-spacing: 0.5px;")
        layout.addWidget(title)

        version = QLabel("v1.0")
        version.setStyleSheet(f"color: {COLORS['accent_blue']}; font-size: 11px; margin-left: 4px; margin-top: 3px;")
        layout.addWidget(version)

        layout.addStretch()

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px;")
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(self.status_dot)
        layout.addWidget(self.status_label)

    def set_status(self, text: str, active: bool = False):
        color = COLORS["accent_green"] if active else COLORS["text_muted"]
        self.status_dot.setStyleSheet(f"color: {color}; font-size: 10px;")
        self.status_label.setText(text)


# ─── Main Window ───────────────────────────────────────────────────────────────

class ForensicsLab(QMainWindow):
    ALL_TASKS = [
        ("collect_system_info",         "System Information"),
        ("collect_users",               "User Accounts"),
        ("collect_processes",           "Running Processes"),
        ("collect_applications",        "Installed Applications"),
        ("collect_disks",               "Disks & Volumes"),
        ("collect_preferences",         "Preferences"),
        ("collect_launch_agents",       "Launch Agents & Daemons"),
        ("collect_login_items",         "Login Items"),
        ("collect_cron",                "Cron Jobs"),
        ("collect_safari_history",      "Safari History"),
        ("collect_chrome_history",      "Chrome History"),
        ("collect_downloads",           "Downloads Folder"),
        ("collect_recent_items",        "Recent Items"),
        ("collect_quarantine",          "Quarantine Events"),
        ("collect_fsevents",            "FSEvents Log"),
        ("collect_shell_history",       "Shell History"),
        ("collect_spotlight_shortcuts", "Spotlight Searches"),
        ("collect_network",             "Active Connections"),
        ("collect_wifi",                "Known Wi-Fi Networks"),
        ("collect_usb_devices",         "USB Devices"),
        ("collect_messages",            "Messages (iMessage/SMS)"),
        ("collect_airdrop",             "AirDrop Activity"),
        ("collect_icloud",              "iCloud Sync Records"),
    ]

    def __init__(self):
        super().__init__()
        self.results_store = {}
        self.collector = MacOSCollector()
        self.worker = None
        self.current_result = None

        self.setWindowTitle("MacOS Forensics Lab")
        self.setMinimumSize(1300, 800)
        self.resize(1440, 900)
        self.setStyleSheet(STYLESHEET)

        self._build_ui()
        self._build_menu()
        self._status_bar()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_vbox = QVBoxLayout(central)
        main_vbox.setContentsMargins(0, 0, 0, 0)
        main_vbox.setSpacing(0)

        # Header
        self.header = HeaderBar()
        main_vbox.addWidget(self.header)

        # Toolbar
        toolbar = self._build_toolbar()
        main_vbox.addWidget(toolbar)

        # Progress
        self.progress_widget = QWidget()
        self.progress_widget.setFixedHeight(60)
        pl = QHBoxLayout(self.progress_widget)
        pl.setContentsMargins(12, 4, 12, 4)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(12)
        self.progress_label = QLabel("Idle")
        self.progress_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; min-width: 220px;")
        pl.addWidget(self.progress_label)
        pl.addWidget(self.progress_bar)
        self.progress_widget.setStyleSheet(f"background-color: {COLORS['bg_secondary']}; border-bottom: 1px solid {COLORS['border']};")
        main_vbox.addWidget(self.progress_widget)

        # Body splitter
        body = QSplitter(Qt.Orientation.Horizontal)
        body.setHandleWidth(1)

        # Left panel: artifact tree
        left = QWidget()
        left.setMinimumWidth(220)
        left.setMaximumWidth(280)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(8, 8, 4, 8)
        lv.setSpacing(6)
        tree_lbl = QLabel("ARTIFACTS")
        tree_lbl.setObjectName("sectionTitle")
        lv.addWidget(tree_lbl)
        self.artifact_tree = ArtifactTree()
        self.artifact_tree.artifact_selected.connect(self._on_artifact_selected)
        lv.addWidget(self.artifact_tree)
        body.addWidget(left)

        # Center: tabs
        self.center_tabs = QTabWidget()

        # Tab 1: Results table + detail
        results_splitter = QSplitter(Qt.Orientation.Vertical)
        results_splitter.setHandleWidth(1)

        self.result_table = ResultTable()
        self.result_table.itemSelectionChanged.connect(self._on_row_selected)
        results_splitter.addWidget(self.result_table)

        self.detail_pane = DetailPane()
        self.detail_pane.setFixedHeight(220)
        results_splitter.addWidget(self.detail_pane)
        results_splitter.setSizes([500, 220])

        self.center_tabs.addTab(results_splitter, "📊  Results")

        # Tab 2: Hash Tool
        self.hash_tool = HashTool(self.collector)
        self.center_tabs.addTab(self.hash_tool, "🔑  File Hash")

        # Tab 3: Log Search
        self.log_search = LogSearch(self.collector)
        self.center_tabs.addTab(self.log_search, "📋  Log Search")

        # Tab 4: SQLite Browser
        self.sqlite_browser = SQLiteBrowser(self.collector)
        self.center_tabs.addTab(self.sqlite_browser, "🗄  SQLite Browser")

        # Tab 5: Report
        self.report_gen = ReportGenerator(self.results_store)
        self.center_tabs.addTab(self.report_gen, "📄  Report")

        body.addWidget(self.center_tabs)
        body.setSizes([250, 1190])
        main_vbox.addWidget(body)

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet(f"background-color: {COLORS['bg_secondary']}; border-bottom: 1px solid {COLORS['border']};")
        bar.setFixedHeight(44)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(6)

        self.collect_btn = QPushButton("⚡  Collect All Artifacts")
        self.collect_btn.setObjectName("primary")
        self.collect_btn.setFixedHeight(32)
        self.collect_btn.clicked.connect(self._collect_all)
        layout.addWidget(self.collect_btn)

        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setFixedHeight(32)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_collection)
        layout.addWidget(self.stop_btn)

        layout.addWidget(self._vline())

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search results…")
        self.search_edit.setFixedHeight(32)
        self.search_edit.setFixedWidth(200)
        self.search_edit.textChanged.connect(self._filter_table)
        layout.addWidget(self.search_edit)

        layout.addStretch()

        case_info = QLabel(f"Case:  |  Examiner: {os.getenv('USER','')}  |  {platform.node()}")
        case_info.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        layout.addWidget(case_info)

        export_btn = QPushButton("↓  Export CSV")
        export_btn.setFixedHeight(32)
        export_btn.clicked.connect(self._quick_export)
        layout.addWidget(export_btn)

        return bar

    def _vline(self) -> QFrame:
        f = QFrame()
        f.setFrameShape(QFrame.Shape.VLine)
        f.setStyleSheet(f"color: {COLORS['border']};")
        return f

    def _build_menu(self):
        mb = self.menuBar()
        # File
        fm = mb.addMenu("File")
        fm.addAction("New Case", QKeySequence.StandardKey.New)
        fm.addAction("Open Image…")
        fm.addSeparator()
        a = QAction("Collect All Artifacts", self)
        a.triggered.connect(self._collect_all)
        fm.addAction(a)
        fm.addSeparator()
        fm.addAction("Export JSON Report", self._export_json)
        fm.addAction("Export CSV", self._quick_export)
        fm.addSeparator()
        q = QAction("Quit", self)
        q.setShortcut(QKeySequence.StandardKey.Quit)
        q.triggered.connect(self.close)
        fm.addAction(q)
        # View
        vm = mb.addMenu("View")
        vm.addAction("Results")
        vm.addAction("File Hash Tool")
        vm.addAction("SQLite Browser")
        # Collect
        cm = mb.addMenu("Collect")
        for method, label in self.ALL_TASKS:
            a = QAction(label, self)
            a.triggered.connect(lambda checked, m=method, l=label: self._collect_single(m, l))
            cm.addAction(a)
        # Help
        hm = mb.addMenu("Help")
        hm.addAction("About", self._about)

    def _status_bar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_left  = QLabel(f"Platform: {platform.system()} {platform.release()}")
        self.status_right = QLabel("Records: 0")
        sb.addWidget(self.status_left)
        sb.addPermanentWidget(self.status_right)

    # ── Collection Logic ───────────────────────────────────────────────────────

    def _collect_all(self):
        if self.worker and self.worker.isRunning():
            return
        self._start_worker(self.ALL_TASKS)

    def _collect_single(self, method: str, label: str):
        self._start_worker([(method, label)])

    def _start_worker(self, tasks: list):
        self.collect_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.header.set_status("Collecting…", active=True)
        self.worker = CollectionWorker(self.collector, tasks)
        self.worker.progress.connect(self._on_progress)
        self.worker.result_ready.connect(self._on_result)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _stop_collection(self):
        if self.worker:
            self.worker.terminate()
        self._on_finished()

    # ── Signals ────────────────────────────────────────────────────────────────

    @pyqtSlot(int, str)
    def _on_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.progress_label.setText(msg)

    @pyqtSlot(object)
    def _on_result(self, result: ForensicResult):
        self.results_store[result.artifact] = result
        self.artifact_tree.mark_collected(result.artifact)
        self.status_right.setText(f"Artifacts: {len(self.results_store)}")
        self.statusBar().showMessage(f"Collected: {result.artifact} — {result.count} records", 3000)

    @pyqtSlot()
    def _on_finished(self):
        self.collect_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_label.setText(f"Complete — {len(self.results_store)} artifacts")
        self.header.set_status(f"Collection complete ({len(self.results_store)} artifacts)")
        self.report_gen._refresh_preview()

    @pyqtSlot(str)
    def _on_error(self, msg: str):
        self.statusBar().showMessage(f"⚠ {msg}", 5000)

    # ── UI Events ──────────────────────────────────────────────────────────────

    def _on_artifact_selected(self, name: str):
        result = self.results_store.get(name)
        if result:
            self.current_result = result
            self.result_table.load_result(result)
            self.detail_pane.show_result(result)
            self.center_tabs.setCurrentIndex(0)
            self.status_right.setText(f"Showing: {name} — {result.count} records")
        else:
            self.statusBar().showMessage(f"'{name}' not yet collected. Run collection first.", 3000)

    def _on_row_selected(self):
        if not self.current_result:
            return
        rows = self.result_table.selectedItems()
        if rows:
            row_idx = self.result_table.currentRow()
            if row_idx < len(self.current_result.data):
                d = self.current_result.data[row_idx]
                text = "\n".join(f"{k:<22} {v}" for k, v in d.items())
                # Show in status
                first_val = next(iter(d.values()), "")
                self.statusBar().showMessage(first_val[:120], 4000)

    def _filter_table(self, text: str):
        if not text:
            for r in range(self.result_table.rowCount()):
                self.result_table.setRowHidden(r, False)
            return
        text = text.lower()
        for r in range(self.result_table.rowCount()):
            visible = False
            for c in range(self.result_table.columnCount()):
                item = self.result_table.item(r, c)
                if item and text in item.text().lower():
                    visible = True
                    break
            self.result_table.setRowHidden(r, not visible)

    def _quick_export(self):
        if not self.current_result:
            QMessageBox.information(self, "No Data", "Select an artifact first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", f"{self.current_result.artifact}.csv", "*.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.current_result.columns)
                writer.writeheader()
                writer.writerows(self.current_result.data)
            self.statusBar().showMessage(f"Exported to {path}", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_json(self):
        self.center_tabs.setCurrentIndex(4)
        self.report_gen._export()

    def _about(self):
        QMessageBox.about(self, "About MacOS Forensics Lab",
            "MacOS Forensics Lab v1.1\n\n"
            "A RECON Lab-inspired forensic analysis tool for macOS.\n\n"
            "Artifact collectors (23):\n"
            "• System: info, users, processes, apps, disks, preferences\n"
            "• Persistence: launch agents/daemons, login items, cron jobs\n"
            "• Browser: Safari history, Chrome history\n"
            "• File activity: downloads, recent items, quarantine, FSEvents\n"
            "• User activity: shell history, Spotlight searches\n"
            "• Network: connections, Wi-Fi history\n"
            "• Devices: USB history\n"
            "• Communications: iMessage/SMS, AirDrop activity\n"
            "• Cloud: iCloud Drive sync, CloudDocs DB, MobileMeAccounts\n\n"
            "Built-in tools: File hasher · Log search · SQLite browser · Report generator\n\n"
            "Built with PyQt6. For educational/investigative use.")


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("MacOS Forensics Lab")
    app.setOrganizationName("ForensicsLab")

    # macOS dark mode hint
    app.setStyle("Fusion")

    # Splash
    splash_pix = QPixmap(400, 200)
    splash_pix.fill(QColor(COLORS["bg_primary"]))
    painter = QPainter(splash_pix)
    painter.setPen(QColor(COLORS["accent_blue"]))
    painter.setFont(QFont("Menlo", 18, QFont.Weight.Bold))
    painter.drawText(splash_pix.rect(), Qt.AlignmentFlag.AlignCenter, "🔬  MacOS Forensics Lab")
    painter.setPen(QColor(COLORS["text_secondary"]))
    painter.setFont(QFont("Menlo", 11))
    painter.drawText(0, 145, 400, 30, Qt.AlignmentFlag.AlignCenter, "Initializing…")
    painter.end()

    splash = QSplashScreen(splash_pix)
    splash.show()
    app.processEvents()

    window = ForensicsLab()

    QTimer.singleShot(1200, splash.close)
    QTimer.singleShot(1200, window.show)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()