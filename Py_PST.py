#!/usr/bin/env python3
"""
Email Forensics Tool - PST File Analyzer
Outlook-style GUI for email forensics investigation
Requires: pip install PyQt5 libratom extract-msg chardet
Optional PST support: pip install libpff-python
"""

import sys
import os
import json
import csv
import hashlib
import re
import email
import email.policy
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
import threading

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QTextEdit, QLabel, QPushButton, QLineEdit, QComboBox, QDateEdit,
    QMenuBar, QMenu, QAction, QFileDialog, QStatusBar, QProgressBar,
    QTabWidget, QGroupBox, QFormLayout, QCheckBox, QSpinBox,
    QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
    QFrame, QScrollArea, QSizePolicy, QHeaderView, QToolBar,
    QToolButton, QAbstractItemView, QMessageBox, QInputDialog,
    QStyleFactory, QShortcut
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QSortFilterProxyModel, QDate,
    QTimer, QSize, QRect, QPoint, QMimeData, QModelIndex
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QBrush,
    QPen, QLinearGradient, QKeySequence, QFontDatabase, QCursor,
    QTextDocument, QTextCursor
)

# ── Optional PST / MSG backend imports ────────────────────────────────────────
try:
    import extract_msg

    HAS_MSG = True
except ImportError:
    HAS_MSG = False

# PST backend priority: libratom (pure-Python, pip-installable) → pypff → python-pst
HAS_PST = False
PST_BACKEND = None
PST_INSTALL_MSG = (
    "No PST backend found.\n\n"
    "Install one of the following:\n\n"
    "  pip install libratom          ← recommended (pure Python)\n"
    "  pip install libpff-python     ← alternative (C extension)\n\n"
    "Then restart the application."
)

try:
    from libratom.lib.pff import PffArchive

    HAS_PST = True
    PST_BACKEND = "libratom"
except ImportError:
    pass

if not HAS_PST:
    try:
        import pypff as _pypff_test

        HAS_PST = True
        PST_BACKEND = "pypff"
    except ImportError:
        pass

# ── Color Palette ─────────────────────────────────────────────────────────────
COLORS = {
    "bg_dark": "#0F1117",
    "bg_mid": "#161B27",
    "bg_panel": "#1C2333",
    "bg_card": "#242D42",
    "bg_hover": "#2A3550",
    "accent": "#3B82F6",
    "accent_bright": "#60A5FA",
    "accent_dim": "#1E3A6E",
    "success": "#10B981",
    "warning": "#F59E0B",
    "danger": "#EF4444",
    "text_primary": "#E2E8F0",
    "text_secondary": "#94A3B8",
    "text_muted": "#475569",
    "border": "#2D3748",
    "border_bright": "#4A5568",
    "selected_bg": "#1E40AF",
    "unread_dot": "#60A5FA",
    "attachment": "#F59E0B",
    "header_bg": "#111827",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', sans-serif;
    font-size: 13px;
}}
QMenuBar {{
    background-color: {COLORS['header_bg']};
    color: {COLORS['text_primary']};
    border-bottom: 1px solid {COLORS['border']};
    padding: 2px 4px;
}}
QMenuBar::item:selected {{
    background-color: {COLORS['bg_hover']};
    border-radius: 4px;
}}
QMenu {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_bright']};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
    margin: 1px 4px;
}}
QMenu::item:selected {{
    background-color: {COLORS['accent_dim']};
    color: {COLORS['accent_bright']};
}}
QMenu::separator {{
    height: 1px;
    background: {COLORS['border']};
    margin: 4px 8px;
}}
QToolBar {{
    background-color: {COLORS['bg_mid']};
    border-bottom: 1px solid {COLORS['border']};
    spacing: 4px;
    padding: 4px 8px;
}}
QToolButton {{
    background: transparent;
    color: {COLORS['text_secondary']};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
}}
QToolButton:hover {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['text_primary']};
    border-color: {COLORS['border_bright']};
}}
QToolButton:pressed {{
    background-color: {COLORS['accent_dim']};
    color: {COLORS['accent_bright']};
}}
QSplitter::handle {{
    background-color: {COLORS['border']};
    width: 1px;
    height: 1px;
}}
QSplitter::handle:hover {{
    background-color: {COLORS['accent']};
}}
QTreeWidget {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: none;
    outline: none;
    font-size: 13px;
}}
QTreeWidget::item {{
    padding: 5px 4px;
    border-radius: 4px;
    margin: 1px 4px;
}}
QTreeWidget::item:hover {{
    background-color: {COLORS['bg_hover']};
}}
QTreeWidget::item:selected {{
    background-color: {COLORS['selected_bg']};
    color: white;
}}
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {{
    image: none;
}}
QTreeWidget::branch:open:has-children:!has-siblings,
QTreeWidget::branch:open:has-children:has-siblings {{
    image: none;
}}
QHeaderView::section {{
    background-color: {COLORS['header_bg']};
    color: {COLORS['text_secondary']};
    border: none;
    border-bottom: 1px solid {COLORS['border']};
    border-right: 1px solid {COLORS['border']};
    padding: 8px 10px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QTableWidget {{
    background-color: {COLORS['bg_mid']};
    color: {COLORS['text_primary']};
    border: none;
    outline: none;
    gridline-color: {COLORS['border']};
    alternate-background-color: {COLORS['bg_panel']};
    font-size: 13px;
    selection-background-color: {COLORS['selected_bg']};
}}
QTableWidget::item {{
    padding: 6px 10px;
    border: none;
}}
QTableWidget::item:hover {{
    background-color: {COLORS['bg_hover']};
}}
QTableWidget::item:selected {{
    background-color: {COLORS['selected_bg']};
    color: white;
}}
QTextEdit {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: none;
    font-size: 13px;
    padding: 12px;
    line-height: 1.6;
}}
QLineEdit {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 13px;
    selection-background-color: {COLORS['accent_dim']};
}}
QLineEdit:focus {{
    border-color: {COLORS['accent']};
    background-color: {COLORS['bg_hover']};
}}
QLineEdit::placeholder {{
    color: {COLORS['text_muted']};
}}
QComboBox {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
    min-width: 100px;
}}
QComboBox:hover {{
    border-color: {COLORS['border_bright']};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_bright']};
    selection-background-color: {COLORS['accent_dim']};
    border-radius: 4px;
    padding: 4px;
}}
QPushButton {{
    background-color: {COLORS['accent']};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: {COLORS['accent_bright']};
}}
QPushButton:pressed {{
    background-color: {COLORS['accent_dim']};
}}
QPushButton#secondary {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
}}
QPushButton#secondary:hover {{
    background-color: {COLORS['bg_hover']};
    border-color: {COLORS['border_bright']};
}}
QPushButton#danger {{
    background-color: {COLORS['danger']};
}}
QDateEdit {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}
QCheckBox {{
    color: {COLORS['text_primary']};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {COLORS['border_bright']};
    border-radius: 3px;
    background-color: {COLORS['bg_card']};
}}
QCheckBox::indicator:checked {{
    background-color: {COLORS['accent']};
    border-color: {COLORS['accent']};
}}
QLabel {{
    color: {COLORS['text_primary']};
    background: transparent;
}}
QLabel#muted {{
    color: {COLORS['text_muted']};
    font-size: 11px;
}}
QLabel#badge {{
    background-color: {COLORS['accent']};
    color: white;
    border-radius: 10px;
    padding: 1px 6px;
    font-size: 10px;
    font-weight: bold;
}}
QLabel#badge_warning {{
    background-color: {COLORS['warning']};
    color: {COLORS['bg_dark']};
    border-radius: 10px;
    padding: 1px 6px;
    font-size: 10px;
    font-weight: bold;
}}
QGroupBox {{
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: {COLORS['text_secondary']};
    font-size: 11px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 8px;
    color: {COLORS['text_secondary']};
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}}
QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    background-color: {COLORS['bg_panel']};
    border-radius: 6px;
}}
QTabBar::tab {{
    background-color: {COLORS['bg_mid']};
    color: {COLORS['text_muted']};
    border: 1px solid {COLORS['border']};
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-radius: 6px 6px 0 0;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['accent_bright']};
    border-color: {COLORS['border_bright']};
}}
QTabBar::tab:hover:!selected {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['text_primary']};
}}
QScrollBar:vertical {{
    background: {COLORS['bg_dark']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {COLORS['border_bright']};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {COLORS['accent']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar:horizontal {{
    background: {COLORS['bg_dark']};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {COLORS['border_bright']};
    border-radius: 4px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {COLORS['accent']};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}
QStatusBar {{
    background-color: {COLORS['header_bg']};
    color: {COLORS['text_muted']};
    border-top: 1px solid {COLORS['border']};
    font-size: 11px;
    padding: 2px 8px;
}}
QProgressBar {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {COLORS['accent']};
    border-radius: 4px;
}}
QFrame#separator {{
    background-color: {COLORS['border']};
    max-height: 1px;
}}
QDialog {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
}}
"""


# ── Data Model ────────────────────────────────────────────────────────────────
class EmailEntry:
    """Unified email entry representation"""

    def __init__(self):
        self.uid: str = ""
        self.subject: str = ""
        self.sender: str = ""
        self.sender_email: str = ""
        self.recipients: List[str] = []
        self.cc: List[str] = []
        self.bcc: List[str] = []
        self.date: Optional[datetime] = None
        self.body_text: str = ""
        self.body_html: str = ""
        self.attachments: List[Dict] = []
        self.headers: Dict[str, str] = {}
        self.folder: str = ""
        self.flags: Dict[str, bool] = {"read": True, "flagged": False, "replied": False}
        self.size_bytes: int = 0
        self.message_id: str = ""
        self.in_reply_to: str = ""
        self.x_mailer: str = ""
        self.x_originating_ip: str = ""
        self.importance: str = "Normal"
        self.raw_path: str = ""
        self.hash_md5: str = ""
        self.hash_sha256: str = ""

    def compute_hashes(self, raw: bytes):
        self.hash_md5 = hashlib.md5(raw).hexdigest()
        self.hash_sha256 = hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> Dict:
        return {
            "uid": self.uid,
            "subject": self.subject,
            "from": self.sender,
            "from_email": self.sender_email,
            "to": "; ".join(self.recipients),
            "cc": "; ".join(self.cc),
            "bcc": "; ".join(self.bcc),
            "date": self.date.isoformat() if self.date else "",
            "folder": self.folder,
            "size_bytes": self.size_bytes,
            "attachments": len(self.attachments),
            "message_id": self.message_id,
            "x_originating_ip": self.x_originating_ip,
            "x_mailer": self.x_mailer,
            "importance": self.importance,
            "md5": self.hash_md5,
            "sha256": self.hash_sha256,
            "body_text": self.body_text,
        }


# ── PST / MSG / EML Loader ────────────────────────────────────────────────────
def _safe_decode(val) -> str:
    """Safely decode bytes or return string value."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _extract_email_addr(text: str) -> str:
    """Extract bare email address from display string like 'Name <addr>'."""
    m = re.search(r'[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+', text or "")
    return m.group(0) if m else text


def _parse_eml_message(msg, entry: EmailEntry):
    """Populate EmailEntry fields from a stdlib email.message.Message object."""
    entry.subject = str(msg.get("Subject") or "")
    entry.sender = str(msg.get("From") or "")
    entry.sender_email = _extract_email_addr(entry.sender)
    entry.recipients = [r.strip() for r in str(msg.get("To") or "").split(",") if r.strip()]
    entry.cc = [r.strip() for r in str(msg.get("Cc") or "").split(",") if r.strip()]
    entry.bcc = [r.strip() for r in str(msg.get("Bcc") or "").split(",") if r.strip()]
    entry.message_id = str(msg.get("Message-ID") or "")
    entry.in_reply_to = str(msg.get("In-Reply-To") or "")
    entry.x_mailer = str(msg.get("X-Mailer") or "")
    entry.x_originating_ip = str(msg.get("X-Originating-IP") or "")
    entry.importance = str(msg.get("Importance") or "Normal")
    entry.headers = {k: str(v) for k, v in msg.items()}

    # Date parsing — try multiple strategies
    date_str = str(msg.get("Date") or "")
    if date_str:
        try:
            from email.utils import parsedate_to_datetime
            entry.date = parsedate_to_datetime(date_str)
        except Exception:
            try:
                import email.utils as eu
                t = eu.parsedate(date_str)
                if t:
                    entry.date = datetime(*t[:6])
            except Exception:
                entry.date = None

    # Body and attachments
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition") or "")
            if "attachment" in cd or part.get_filename():
                raw_att = part.get_payload(decode=True) or b""
                entry.attachments.append({
                    "name": part.get_filename() or "attachment",
                    "type": ct,
                    "size": len(raw_att),
                    "data": raw_att,
                })
            elif ct == "text/plain" and not entry.body_text:
                raw = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                entry.body_text = raw.decode(charset, errors="replace")
            elif ct == "text/html" and not entry.body_html:
                raw = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                entry.body_html = raw.decode(charset, errors="replace")
    else:
        raw = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        ct = msg.get_content_type()
        if ct == "text/html":
            entry.body_html = raw.decode(charset, errors="replace")
        else:
            entry.body_text = raw.decode(charset, errors="replace")


class MailLoader:
    """Multi-format email loader — EML (stdlib), MSG (extract-msg), PST (libratom or pypff)."""

    # ── EML ──────────────────────────────────────────────────────────────────
    @staticmethod
    def load_eml(path: str) -> Optional[EmailEntry]:
        try:
            with open(path, "rb") as f:
                raw = f.read()
            msg = email.message_from_bytes(raw)
            entry = EmailEntry()
            entry.uid = hashlib.md5(raw).hexdigest()[:12]
            entry.raw_path = path
            entry.compute_hashes(raw)
            entry.size_bytes = len(raw)
            _parse_eml_message(msg, entry)
            entry.folder = os.path.dirname(os.path.relpath(path)) or "Inbox"
            return entry
        except Exception as e:
            print(f"EML load error {path}: {e}")
            return None

    # ── MSG ──────────────────────────────────────────────────────────────────
    @staticmethod
    def load_msg(path: str) -> Optional[EmailEntry]:
        if not HAS_MSG:
            return None
        try:
            msg = extract_msg.openMsg(path)
            entry = EmailEntry()
            with open(path, "rb") as f:
                raw = f.read()
            entry.uid = hashlib.md5(raw).hexdigest()[:12]
            entry.raw_path = path
            entry.compute_hashes(raw)
            entry.size_bytes = len(raw)
            entry.subject = _safe_decode(msg.subject)
            entry.sender = _safe_decode(msg.sender)
            entry.sender_email = _extract_email_addr(entry.sender)

            # to / cc — extract_msg changed API over versions; handle both
            def _split_recips(val):
                if not val:
                    return []
                s = _safe_decode(val)
                return [r.strip() for r in re.split(r'[;,]', s) if r.strip()]

            entry.recipients = _split_recips(msg.to)
            entry.cc = _split_recips(msg.cc)
            entry.body_text = _safe_decode(msg.body)
            try:
                html = msg.htmlBody
                entry.body_html = html.decode("utf-8", errors="replace") if isinstance(html, bytes) else (html or "")
            except Exception:
                entry.body_html = ""
            entry.date = msg.date if hasattr(msg, "date") else None

            # Attachments
            for att in (msg.attachments or []):
                try:
                    name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
                    data = getattr(att, "data", None) or b""
                    entry.attachments.append({
                        "name": _safe_decode(name),
                        "type": "application/octet-stream",
                        "size": len(data),
                        "data": data,
                    })
                except Exception:
                    pass

            # Transport headers → parse for forensics fields
            try:
                hdrs_raw = _safe_decode(getattr(msg, "transportMessageHeaders", None) or "")
                if hdrs_raw:
                    import email as _em
                    hdr_msg = _em.message_from_string(hdrs_raw)
                    entry.headers = {k: str(v) for k, v in hdr_msg.items()}
                    entry.x_originating_ip = str(hdr_msg.get("X-Originating-IP") or "")
                    entry.x_mailer = str(hdr_msg.get("X-Mailer") or "")
                    entry.message_id = str(hdr_msg.get("Message-ID") or "")
                    entry.importance = str(hdr_msg.get("Importance") or "Normal")
            except Exception:
                pass

            entry.folder = "MSG Files"
            try:
                msg.close()
            except Exception:
                pass
            return entry
        except Exception as e:
            print(f"MSG load error {path}: {e}")
            return None

    # ── PST via libratom (primary) ────────────────────────────────────────────
    @staticmethod
    def load_pst_libratom(path: str, progress_cb=None) -> List[EmailEntry]:
        """Load PST using libratom (pure-Python, most reliable)."""
        from libratom.lib.pff import PffArchive
        entries = []
        with PffArchive(path) as archive:
            # Collect all messages with their folder paths
            def walk_folder(folder, folder_path):
                folder_name = getattr(folder, "name", None) or ""
                current_path = f"{folder_path}/{folder_name}".strip("/") if folder_name else folder_path

                # Messages in this folder
                for msg in folder.sub_messages:
                    try:
                        entry = _entry_from_libratom_msg(msg, current_path or "Root")
                        entries.append(entry)
                        if progress_cb and len(entries) % 20 == 0:
                            progress_cb(len(entries))
                    except Exception as e:
                        print(f"libratom msg error: {e}")

                # Recurse into sub-folders
                for sub in folder.sub_folders:
                    walk_folder(sub, current_path)

            root = archive.data.get_root_folder()
            for i in range(root.get_number_of_sub_folders()):
                walk_folder(root.get_sub_folder(i), "")

        return entries

    # ── PST via pypff (fallback) ──────────────────────────────────────────────
    @staticmethod
    def _load_pst_pypff_folder(folder, folder_path: str, entries: List[EmailEntry], progress_cb=None):
        import pypff
        n_msgs = folder.get_number_of_sub_messages()
        for i in range(n_msgs):
            try:
                msg = folder.get_sub_message(i)
                entry = _entry_from_pypff_msg(msg, folder_path)
                entries.append(entry)
                if progress_cb and len(entries) % 20 == 0:
                    progress_cb(len(entries))
            except Exception as e:
                print(f"pypff msg error [{folder_path}][{i}]: {e}")

        n_subs = folder.get_number_of_sub_folders()
        for i in range(n_subs):
            try:
                sub = folder.get_sub_folder(i)
                sub_name = sub.name or f"folder_{i}"
                MailLoader._load_pst_pypff_folder(
                    sub, f"{folder_path}/{sub_name}", entries, progress_cb
                )
            except Exception as e:
                print(f"pypff subfolder error: {e}")

    @staticmethod
    def load_pst_pypff(path: str, progress_cb=None) -> List[EmailEntry]:
        import pypff
        entries = []
        pst = pypff.file()
        pst.open(path)
        try:
            root = pst.get_root_folder()
            for i in range(root.get_number_of_sub_folders()):
                try:
                    folder = root.get_sub_folder(i)
                    MailLoader._load_pst_pypff_folder(
                        folder, folder.name or f"folder_{i}", entries, progress_cb
                    )
                except Exception as e:
                    print(f"pypff root folder error: {e}")
        finally:
            pst.close()
        return entries

    # ── Dispatcher ────────────────────────────────────────────────────────────
    @staticmethod
    def load_pst(path: str, progress_cb=None) -> List[EmailEntry]:
        """Try available PST backends in order of preference."""
        if not HAS_PST:
            raise RuntimeError(PST_INSTALL_MSG)

        last_err = None

        if PST_BACKEND == "libratom":
            try:
                return MailLoader.load_pst_libratom(path, progress_cb)
            except Exception as e:
                last_err = e
                print(f"libratom failed ({e}), trying pypff…")
                # fall through to pypff if available
                try:
                    import pypff  # noqa
                    return MailLoader.load_pst_pypff(path, progress_cb)
                except ImportError:
                    pass
                except Exception as e2:
                    last_err = e2

        elif PST_BACKEND == "pypff":
            try:
                return MailLoader.load_pst_pypff(path, progress_cb)
            except Exception as e:
                last_err = e

        raise RuntimeError(
            f"PST loading failed with backend '{PST_BACKEND}'.\n\nError: {last_err}\n\n"
            "Try: pip install libratom"
        )

    # ── Directory scan ────────────────────────────────────────────────────────
    @staticmethod
    def load_directory(path: str) -> List[EmailEntry]:
        entries = []
        for root, _, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""
                entry = None
                if ext == "eml":
                    entry = MailLoader.load_eml(fpath)
                elif ext == "msg" and HAS_MSG:
                    entry = MailLoader.load_msg(fpath)
                if entry:
                    entries.append(entry)
        return entries


# ── Per-message helpers ────────────────────────────────────────────────────────
def _entry_from_libratom_msg(msg, folder_path: str) -> EmailEntry:
    """Build EmailEntry from a libratom/PffArchive sub_message object."""
    entry = EmailEntry()

    # Basic identity
    uid_src = (getattr(msg, "identifier", None) or
               getattr(msg, "record_key", None) or
               f"{folder_path}_{id(msg)}")
    entry.uid = str(uid_src)
    entry.folder = folder_path

    # Fields — use getattr with fallback everywhere; libratom wraps pypff
    entry.subject = _safe_decode(getattr(msg, "subject", None))
    sender_name = _safe_decode(getattr(msg, "sender_name", None))
    sender_addr = _safe_decode(getattr(msg, "sender_email_address", None))
    entry.sender_email = sender_addr
    entry.sender = f"{sender_name} <{sender_addr}>" if sender_addr else sender_name

    entry.recipients = [_safe_decode(getattr(msg, "display_to", None) or "")]
    entry.cc = [_safe_decode(getattr(msg, "display_cc", None) or "")]

    # Body
    plain = getattr(msg, "plain_text_body", None)
    html = getattr(msg, "html_body", None)
    rtf = getattr(msg, "rtf_body", None)
    entry.body_text = _safe_decode(plain) if plain else ""
    entry.body_html = _safe_decode(html) if html else ""
    # RTF fallback for body_text
    if not entry.body_text and not entry.body_html and rtf:
        entry.body_text = f"[RTF body — {len(rtf)} bytes]"

    # Date
    for attr in ("delivery_time", "client_submit_time", "creation_time"):
        dt = getattr(msg, attr, None)
        if dt:
            entry.date = dt
            break

    # Transport headers → parse for forensics metadata
    hdrs_raw = _safe_decode(getattr(msg, "transport_message_headers", None))
    if hdrs_raw:
        try:
            import email as _em
            hdr_msg = _em.message_from_string(hdrs_raw)
            entry.headers = {k: str(v) for k, v in hdr_msg.items()}
            entry.x_originating_ip = str(hdr_msg.get("X-Originating-IP") or "")
            entry.x_mailer = str(hdr_msg.get("X-Mailer") or "")
            entry.message_id = str(hdr_msg.get("Message-ID") or "")
            entry.importance = str(hdr_msg.get("Importance") or "Normal")
        except Exception:
            entry.headers = {"Raw": hdrs_raw[:2000]}

    # Attachments
    n_att = 0
    try:
        n_att = msg.get_number_of_attachments()
    except Exception:
        pass
    for j in range(n_att):
        try:
            att = msg.get_attachment(j)
            att_name = _safe_decode(getattr(att, "name", None) or f"attachment_{j}")
            # read data safely
            att_data = b""
            try:
                size = att.get_size()
                if size and size > 0:
                    att_data = att.read_buffer(size)
            except Exception:
                pass
            entry.attachments.append({
                "name": att_name,
                "type": "application/octet-stream",
                "size": len(att_data),
                "data": att_data,
            })
        except Exception as e:
            print(f"attachment error: {e}")

    entry.size_bytes = (
            len(entry.body_text.encode("utf-8", errors="replace"))
            + len(entry.body_html.encode("utf-8", errors="replace"))
            + sum(a["size"] for a in entry.attachments)
    )
    return entry


def _entry_from_pypff_msg(msg, folder_path: str) -> EmailEntry:
    """Build EmailEntry from a raw pypff message object."""
    entry = EmailEntry()
    entry.uid = f"pypff_{folder_path}_{id(msg)}"
    entry.folder = folder_path
    entry.subject = _safe_decode(getattr(msg, "subject", None))

    sender_name = _safe_decode(getattr(msg, "sender_name", None))
    sender_addr = _safe_decode(getattr(msg, "sender_email_address", None))
    entry.sender_email = sender_addr
    entry.sender = f"{sender_name} <{sender_addr}>" if sender_addr else sender_name
    entry.recipients = [_safe_decode(getattr(msg, "display_to", None) or "")]
    entry.cc = [_safe_decode(getattr(msg, "display_cc", None) or "")]

    plain = getattr(msg, "plain_text_body", None)
    html = getattr(msg, "html_body", None)
    entry.body_text = _safe_decode(plain) if plain else ""
    entry.body_html = _safe_decode(html) if html else ""

    for attr in ("delivery_time", "client_submit_time", "creation_time"):
        dt = getattr(msg, attr, None)
        if dt:
            entry.date = dt
            break

    hdrs_raw = _safe_decode(getattr(msg, "transport_message_headers", None))
    if hdrs_raw:
        try:
            import email as _em
            hdr_msg = _em.message_from_string(hdrs_raw)
            entry.headers = {k: str(v) for k, v in hdr_msg.items()}
            entry.x_originating_ip = str(hdr_msg.get("X-Originating-IP") or "")
            entry.x_mailer = str(hdr_msg.get("X-Mailer") or "")
            entry.message_id = str(hdr_msg.get("Message-ID") or "")
        except Exception:
            pass

    n_att = 0
    try:
        n_att = msg.get_number_of_attachments()
    except Exception:
        pass
    for j in range(n_att):
        try:
            att = msg.get_attachment(j)
            att_name = _safe_decode(getattr(att, "name", None) or f"att_{j}")
            att_data = b""
            try:
                size = att.get_size()
                if size and size > 0:
                    att_data = att.read_buffer(size)
            except Exception:
                pass
            entry.attachments.append({
                "name": att_name,
                "type": "application/octet-stream",
                "size": len(att_data),
                "data": att_data,
            })
        except Exception:
            pass

    entry.size_bytes = (
            len(entry.body_text.encode("utf-8", errors="replace"))
            + sum(a["size"] for a in entry.attachments)
    )
    return entry


# ── Background Loader Thread ──────────────────────────────────────────────────
class LoaderThread(QThread):
    progress = pyqtSignal(int, str)
    entry_loaded = pyqtSignal(object)
    finished_loading = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._count = 0

    def run(self):
        try:
            ext = self.path.lower().rsplit(".", 1)[-1] if "." in self.path else ""

            if ext == "pst":
                if not HAS_PST:
                    self.error.emit(PST_INSTALL_MSG)
                    return
                self.progress.emit(0, "Opening PST archive…")

                def pst_progress(n):
                    self._count = n
                    self.progress.emit(0, f"Extracting emails… ({n} found so far)")

                try:
                    entries = MailLoader.load_pst(self.path, pst_progress)
                except Exception as e:
                    self.error.emit(
                        f"PST load failed:\n\n{e}\n\n"
                        f"Backend used: {PST_BACKEND}\n\n"
                        "Tip: pip install libratom"
                    )
                    return

                total = len(entries)
                self.progress.emit(50, f"Indexing {total} messages…")
                for i, entry in enumerate(entries):
                    self.entry_loaded.emit(entry)
                    if i % 25 == 0:
                        pct = 50 + int((i / max(total, 1)) * 50)
                        self.progress.emit(pct, f"Indexing {i}/{total}…")
                self.finished_loading.emit(total)
                return

            # Single EML
            if ext == "eml":
                self.progress.emit(10, "Loading EML…")
                entry = MailLoader.load_eml(self.path)
                if entry:
                    self.entry_loaded.emit(entry)
                    self.finished_loading.emit(1)
                else:
                    self.error.emit(f"Could not parse EML file:\n{self.path}")
                return

            # Single MSG
            if ext == "msg":
                if not HAS_MSG:
                    self.error.emit("extract-msg not installed.\n\nRun: pip install extract-msg")
                    return
                self.progress.emit(10, "Loading MSG…")
                entry = MailLoader.load_msg(self.path)
                if entry:
                    self.entry_loaded.emit(entry)
                    self.finished_loading.emit(1)
                else:
                    self.error.emit(f"Could not parse MSG file:\n{self.path}")
                return

            # Directory
            if os.path.isdir(self.path):
                self.progress.emit(0, "Scanning directory…")
                entries = MailLoader.load_directory(self.path)
                total = len(entries)
                for i, entry in enumerate(entries):
                    self.entry_loaded.emit(entry)
                    if i % 10 == 0:
                        pct = int((i / max(total, 1)) * 100)
                        self.progress.emit(pct, f"Loading {i}/{total} emails…")
                self.finished_loading.emit(total)
                return

            self.error.emit(f"Unsupported file type: .{ext}\n\nSupported: .pst, .eml, .msg, or a directory.")

        except Exception as e:
            import traceback
            self.error.emit(f"Unexpected error:\n\n{e}\n\n{traceback.format_exc()}")


# ── Email Header View ─────────────────────────────────────────────────────────
class EmailHeaderWidget(QWidget):
    """Renders Outlook-style email header"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {COLORS['bg_panel']}; border-bottom: 1px solid {COLORS['border']};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        self.lbl_subject = QLabel()
        self.lbl_subject.setStyleSheet(
            f"font-size: 17px; font-weight: 700; color: {COLORS['text_primary']}; background: transparent;")
        self.lbl_subject.setWordWrap(True)

        self.lbl_from = QLabel()
        self.lbl_from.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px; background: transparent;")
        self.lbl_to = QLabel()
        self.lbl_to.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px; background: transparent;")
        self.lbl_date = QLabel()
        self.lbl_date.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; background: transparent;")

        self.att_bar = QWidget()
        self.att_bar.setStyleSheet(f"background: transparent;")
        self.att_layout = QHBoxLayout(self.att_bar)
        self.att_layout.setContentsMargins(0, 4, 0, 0)
        self.att_layout.setSpacing(6)
        self.att_layout.addStretch()

        self.forensics_bar = QWidget()
        fb_layout = QHBoxLayout(self.forensics_bar)
        fb_layout.setContentsMargins(0, 4, 0, 0)
        fb_layout.setSpacing(8)
        self.lbl_ip = QLabel()
        self.lbl_ip.setStyleSheet(
            f"color: {COLORS['warning']}; font-size: 11px; font-family: 'Courier New', monospace; background: transparent;")
        self.lbl_hash = QLabel()
        self.lbl_hash.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; font-family: 'Courier New', monospace; background: transparent;")
        fb_layout.addWidget(self.lbl_ip)
        fb_layout.addStretch()
        fb_layout.addWidget(self.lbl_hash)

        layout.addWidget(self.lbl_subject)
        layout.addWidget(self.lbl_from)
        layout.addWidget(self.lbl_to)
        layout.addWidget(self.lbl_date)
        layout.addWidget(self.att_bar)
        layout.addWidget(self.forensics_bar)

    def load(self, entry: EmailEntry):
        self.lbl_subject.setText(entry.subject or "(No Subject)")
        self.lbl_from.setText(f"From: {entry.sender}")
        to_str = "; ".join(entry.recipients[:3])
        if len(entry.recipients) > 3:
            to_str += f"  +{len(entry.recipients) - 3} more"
        self.lbl_to.setText(f"To: {to_str}" + (f"   CC: {'; '.join(entry.cc[:2])}" if entry.cc else ""))
        date_str = entry.date.strftime("%A, %B %d %Y  %H:%M:%S %Z") if entry.date else "Unknown date"
        self.lbl_date.setText(f"📅  {date_str}   •   {entry.size_bytes:,} bytes")

        # Attachment pills
        for i in reversed(range(self.att_layout.count())):
            w = self.att_layout.itemAt(i).widget()
            if w:
                w.deleteLater()
        if entry.attachments:
            att_lbl = QLabel("📎 Attachments:")
            att_lbl.setStyleSheet(
                f"color: {COLORS['attachment']}; font-size: 11px; font-weight: 600; background: transparent;")
            self.att_layout.addWidget(att_lbl)
            for att in entry.attachments[:5]:
                pill = QLabel(f"  {att['name']} ({att['size']:,}b)  ")
                pill.setStyleSheet(f"""
                    background-color: {COLORS['bg_card']};
                    color: {COLORS['attachment']};
                    border: 1px solid {COLORS['attachment']};
                    border-radius: 10px;
                    padding: 2px 8px;
                    font-size: 11px;
                """)
                self.att_layout.addWidget(pill)
            self.att_layout.addStretch()

        # Forensics
        ip_str = f"🌐 Origin IP: {entry.x_originating_ip}" if entry.x_originating_ip and entry.x_originating_ip != "None" else ""
        self.lbl_ip.setText(ip_str)
        hash_str = f"MD5: {entry.hash_md5[:16]}…" if entry.hash_md5 else ""
        self.lbl_hash.setText(hash_str)

    def clear(self):
        self.lbl_subject.setText("")
        self.lbl_from.setText("")
        self.lbl_to.setText("")
        self.lbl_date.setText("")
        self.lbl_ip.setText("")
        self.lbl_hash.setText("")


# ── Metadata Panel ────────────────────────────────────────────────────────────
class MetadataPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        title = QLabel("METADATA")
        title.setStyleSheet(
            f"font-size: 10px; font-weight: 700; color: {COLORS['text_muted']}; letter-spacing: 1.5px; background: transparent;")
        layout.addWidget(title)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Field", "Value"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

    def load(self, entry: EmailEntry):
        fields = [
            ("UID", entry.uid),
            ("Subject", entry.subject),
            ("From", entry.sender),
            ("From Email", entry.sender_email),
            ("To", "; ".join(entry.recipients)),
            ("CC", "; ".join(entry.cc)),
            ("BCC", "; ".join(entry.bcc)),
            ("Date", entry.date.isoformat() if entry.date else ""),
            ("Message-ID", entry.message_id),
            ("In-Reply-To", entry.in_reply_to),
            ("X-Mailer", entry.x_mailer),
            ("X-Originating-IP", entry.x_originating_ip),
            ("Importance", entry.importance),
            ("Folder", entry.folder),
            ("Size (bytes)", str(entry.size_bytes)),
            ("Attachments", str(len(entry.attachments))),
            ("MD5", entry.hash_md5),
            ("SHA-256", entry.hash_sha256),
        ]
        self.table.setRowCount(len(fields))
        for row, (k, v) in enumerate(fields):
            ki = QTableWidgetItem(k)
            ki.setForeground(QColor(COLORS["text_secondary"]))
            ki.setFont(QFont("", 11, QFont.DemiBold))
            vi = QTableWidgetItem(v)
            vi.setForeground(QColor(COLORS["text_primary"]))
            self.table.setItem(row, 0, ki)
            self.table.setItem(row, 1, vi)
        self.table.resizeRowsToContents()

    def clear(self):
        self.table.setRowCount(0)


# ── Raw Headers Panel ─────────────────────────────────────────────────────────
class HeadersPanel(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 11))
        self.setStyleSheet(
            f"background-color: {COLORS['bg_dark']}; color: {COLORS['success']}; padding: 12px; font-family: 'Courier New', monospace; font-size: 11px;")

    def load(self, entry: EmailEntry):
        lines = []
        for k, v in entry.headers.items():
            lines.append(
                f'<span style="color:{COLORS["accent_bright"]}">{k}</span>: <span style="color:{COLORS["text_primary"]}">{v}</span>')
        self.setHtml("<br>".join(lines) if lines else "No headers available.")

    def clear_content(self):
        self.setPlainText("")


# ── Attachment Panel ──────────────────────────────────────────────────────────
class AttachmentPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        self.list = QListWidget()
        self.list.setStyleSheet(f"background: {COLORS['bg_dark']}; border: none;")
        self.list.itemDoubleClicked.connect(self._save_attachment)
        layout.addWidget(QLabel("Double-click to export attachment"))
        layout.addWidget(self.list)

        self._attachments = []

    def load(self, entry: EmailEntry):
        self.list.clear()
        self._attachments = entry.attachments
        for att in entry.attachments:
            icon = "📄" if "text" in att["type"] else "🖼️" if "image" in att["type"] else "📎"
            item = QListWidgetItem(f"{icon}  {att['name']}  ({att['size']:,} bytes)")
            item.setForeground(QColor(COLORS["attachment"]))
            self.list.addItem(item)

    def _save_attachment(self, item):
        idx = self.list.row(item)
        if 0 <= idx < len(self._attachments):
            att = self._attachments[idx]
            path, _ = QFileDialog.getSaveFileName(self, "Save Attachment", att["name"])
            if path and att.get("data"):
                with open(path, "wb") as f:
                    f.write(att["data"])
                QMessageBox.information(self, "Saved", f"Attachment saved to:\n{path}")

    def clear_content(self):
        self.list.clear()
        self._attachments = []


# ── Filter Bar ────────────────────────────────────────────────────────────────
class FilterBar(QWidget):
    filter_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {COLORS['bg_mid']}; border-bottom: 1px solid {COLORS['border']};")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(8)

        # Search
        search_icon = QLabel("🔍")
        search_icon.setStyleSheet("background: transparent; font-size: 14px;")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search subject, sender, body…")
        self.search.setMinimumWidth(220)
        self.search.textChanged.connect(self.filter_changed)

        # Sender filter
        self.sender_filter = QLineEdit()
        self.sender_filter.setPlaceholderText("Filter by sender…")
        self.sender_filter.setMaximumWidth(160)
        self.sender_filter.textChanged.connect(self.filter_changed)

        # Date range
        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate(2000, 1, 1))
        self.date_from.setMaximumWidth(110)
        self.date_from.dateChanged.connect(self.filter_changed)

        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        self.date_to.setMaximumWidth(110)
        self.date_to.dateChanged.connect(self.filter_changed)

        # Attachment filter
        self.has_att = QCheckBox("Has Attachments")
        self.has_att.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        self.has_att.stateChanged.connect(self.filter_changed)

        # Importance
        self.importance = QComboBox()
        self.importance.addItems(["All", "High", "Normal", "Low"])
        self.importance.setMaximumWidth(90)
        self.importance.currentIndexChanged.connect(self.filter_changed)

        # Reset
        self.btn_reset = QPushButton("✕ Reset")
        self.btn_reset.setObjectName("secondary")
        self.btn_reset.setMaximumWidth(70)
        self.btn_reset.clicked.connect(self.reset)

        layout.addWidget(search_icon)
        layout.addWidget(self.search)
        layout.addWidget(QLabel("|"))
        layout.addWidget(QLabel("From:"))
        layout.addWidget(self.sender_filter)
        layout.addWidget(QLabel("|"))
        layout.addWidget(QLabel("Date:"))
        layout.addWidget(self.date_from)
        layout.addWidget(QLabel("→"))
        layout.addWidget(self.date_to)
        layout.addWidget(QLabel("|"))
        layout.addWidget(self.has_att)
        layout.addWidget(QLabel("|"))
        layout.addWidget(QLabel("Priority:"))
        layout.addWidget(self.importance)
        layout.addWidget(self.btn_reset)
        layout.addStretch()

    def get_filters(self) -> Dict:
        return {
            "search": self.search.text().lower(),
            "sender": self.sender_filter.text().lower(),
            "date_from": self.date_from.date().toPyDate(),
            "date_to": self.date_to.date().toPyDate(),
            "has_att": self.has_att.isChecked(),
            "importance": self.importance.currentText(),
        }

    def reset(self):
        self.search.clear()
        self.sender_filter.clear()
        self.date_from.setDate(QDate(2000, 1, 1))
        self.date_to.setDate(QDate.currentDate())
        self.has_att.setChecked(False)
        self.importance.setCurrentIndex(0)


# ── Email List Widget ─────────────────────────────────────────────────────────
class EmailListWidget(QTableWidget):
    email_selected = pyqtSignal(object)

    COLS = ["", "Subject", "From", "Date", "Size", "Attachments"]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLS))
        self.setHorizontalHeaderLabels(self.COLS)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(36)

        hh = self.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed)
        self.setColumnWidth(0, 24)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.itemSelectionChanged.connect(self._on_select)

        self._entries: List[EmailEntry] = []
        self._filtered: List[EmailEntry] = []

    def load_entries(self, entries: List[EmailEntry]):
        self._entries = entries
        self.apply_filter({})

    def apply_filter(self, filters: Dict):
        self.setSortingEnabled(False)
        self.setRowCount(0)
        self._filtered = []

        for entry in self._entries:
            if not self._matches(entry, filters):
                continue
            self._filtered.append(entry)
            row = self.rowCount()
            self.insertRow(row)

            # Unread dot
            dot = QTableWidgetItem("●" if not entry.flags.get("read") else "")
            dot.setForeground(QColor(COLORS["unread_dot"]))
            dot.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 0, dot)

            subj = QTableWidgetItem(entry.subject or "(No Subject)")
            if not entry.flags.get("read"):
                f = subj.font();
                f.setBold(True);
                subj.setFont(f)
            self.setItem(row, 1, subj)

            sender_item = QTableWidgetItem(entry.sender_email or entry.sender)
            sender_item.setForeground(QColor(COLORS["text_secondary"]))
            self.setItem(row, 2, sender_item)

            date_str = entry.date.strftime("%Y-%m-%d %H:%M") if entry.date else ""
            date_item = QTableWidgetItem(date_str)
            date_item.setForeground(QColor(COLORS["text_muted"]))
            self.setItem(row, 3, date_item)

            size_item = QTableWidgetItem(
                f"{entry.size_bytes // 1024} KB" if entry.size_bytes >= 1024 else f"{entry.size_bytes} B")
            size_item.setForeground(QColor(COLORS["text_muted"]))
            self.setItem(row, 4, size_item)

            att_item = QTableWidgetItem(f"📎 {len(entry.attachments)}" if entry.attachments else "")
            att_item.setForeground(QColor(COLORS["attachment"]))
            att_item.setTextAlignment(Qt.AlignCenter)
            self.setItem(row, 5, att_item)

        self.setSortingEnabled(True)

    def _matches(self, entry: EmailEntry, filters: Dict) -> bool:
        if not filters:
            return True
        q = filters.get("search", "")
        if q and q not in (entry.subject or "").lower() \
                and q not in (entry.sender or "").lower() \
                and q not in (entry.body_text or "").lower():
            return False
        sf = filters.get("sender", "")
        if sf and sf not in (entry.sender or "").lower() and sf not in (entry.sender_email or "").lower():
            return False
        if entry.date:
            ed = entry.date.date() if hasattr(entry.date, 'date') else entry.date
            df = filters.get("date_from")
            dt_ = filters.get("date_to")
            if df and ed < df:
                return False
            if dt_ and ed > dt_:
                return False
        if filters.get("has_att") and not entry.attachments:
            return False
        imp = filters.get("importance", "All")
        if imp != "All" and entry.importance.lower() != imp.lower():
            return False
        return True

    def _on_select(self):
        rows = self.selectionModel().selectedRows()
        if rows:
            row = rows[0].row()
            if 0 <= row < len(self._filtered):
                self.email_selected.emit(self._filtered[row])

    def get_selected_entries(self) -> List[EmailEntry]:
        rows = set(idx.row() for idx in self.selectionModel().selectedRows())
        return [self._filtered[r] for r in sorted(rows) if r < len(self._filtered)]

    def _context_menu(self, pos):
        menu = QMenu(self)
        selected = self.get_selected_entries()
        if not selected:
            return

        menu.addAction("📋  Copy Subject", lambda: QApplication.clipboard().setText(selected[0].subject))
        menu.addAction("📋  Copy Sender", lambda: QApplication.clipboard().setText(selected[0].sender))
        menu.addAction("📋  Copy All Metadata (JSON)", lambda: self._copy_json(selected))
        menu.addSeparator()
        menu.addAction("💾  Export as EML…", lambda: self._export_eml(selected))
        menu.addAction("📄  Export as JSON…", lambda: self._export_json(selected))
        menu.addAction("📊  Export as CSV…", lambda: self._export_csv(selected))
        menu.addSeparator()
        menu.addAction("🔎  View Full Headers", lambda: self._show_headers(selected[0]))
        if selected[0].attachments:
            menu.addAction("📎  Export Attachments…", lambda: self._export_attachments(selected[0]))
        menu.exec_(self.viewport().mapToGlobal(pos))

    def _copy_json(self, entries):
        data = [e.to_dict() for e in entries]
        QApplication.clipboard().setText(json.dumps(data, indent=2, default=str))

    def _export_eml(self, entries):
        if len(entries) == 1 and entries[0].raw_path:
            dst, _ = QFileDialog.getSaveFileName(self, "Export EML", entries[0].subject + ".eml", "EML (*.eml)")
            if dst and os.path.exists(entries[0].raw_path):
                import shutil;
                shutil.copy2(entries[0].raw_path, dst)
                QMessageBox.information(self, "Exported", f"Saved to {dst}")
        else:
            folder = QFileDialog.getExistingDirectory(self, "Export EMLs to folder")
            if folder:
                for e in entries:
                    if e.raw_path and os.path.exists(e.raw_path):
                        import shutil
                        dst = os.path.join(folder, f"{e.uid}_{e.subject[:40]}.eml")
                        shutil.copy2(e.raw_path, dst)
                QMessageBox.information(self, "Exported", f"{len(entries)} emails exported.")

    def _export_json(self, entries):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "emails.json", "JSON (*.json)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump([e.to_dict() for e in entries], f, indent=2, default=str)
            QMessageBox.information(self, "Exported", f"Saved {len(entries)} entries to {path}")

    def _export_csv(self, entries):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "emails.csv", "CSV (*.csv)")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                if entries:
                    writer = csv.DictWriter(f, fieldnames=entries[0].to_dict().keys())
                    writer.writeheader()
                    for e in entries:
                        d = e.to_dict()
                        d.pop("body_text", None)
                        writer.writerow(d)
            QMessageBox.information(self, "Exported", f"Saved {len(entries)} rows to {path}")

    def _show_headers(self, entry: EmailEntry):
        dlg = QDialog(self)
        dlg.setWindowTitle("Raw Email Headers")
        dlg.resize(700, 500)
        layout = QVBoxLayout(dlg)
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont("Courier New", 11))
        txt.setStyleSheet(f"background:{COLORS['bg_dark']}; color:{COLORS['success']}; padding:12px;")
        lines = [f'<span style="color:{COLORS["accent_bright"]}">{k}</span>: {v}' for k, v in entry.headers.items()]
        txt.setHtml("<br>".join(lines) if lines else "No headers.")
        layout.addWidget(txt)
        dlg.exec_()

    def _export_attachments(self, entry: EmailEntry):
        folder = QFileDialog.getExistingDirectory(self, "Export Attachments to Folder")
        if folder:
            for att in entry.attachments:
                if att.get("data"):
                    path = os.path.join(folder, att["name"])
                    with open(path, "wb") as f:
                        f.write(att["data"])
            QMessageBox.information(self, "Done", f"Exported {len(entry.attachments)} attachments.")


# ── Folder Tree ───────────────────────────────────────────────────────────────
class FolderTree(QTreeWidget):
    folder_selected = pyqtSignal(str)  # "" = All

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setIndentation(16)
        self._folder_counts: Dict[str, int] = {}
        self.itemClicked.connect(self._on_click)

    def rebuild(self, entries: List[EmailEntry]):
        self.clear()
        self._folder_counts = {}
        for e in entries:
            folder = e.folder or "Inbox"
            self._folder_counts[folder] = self._folder_counts.get(folder, 0) + 1

        root_icon = "📦"
        all_item = QTreeWidgetItem([f"  {root_icon}  All Mail  ({len(entries)})"])
        all_item.setData(0, Qt.UserRole, "")
        all_item.setForeground(0, QColor(COLORS["accent_bright"]))
        f = all_item.font(0);
        f.setBold(True);
        all_item.setFont(0, f)
        self.addTopLevelItem(all_item)

        folder_icons = {
            "inbox": "📥", "sent": "📤", "drafts": "📝",
            "trash": "🗑️", "junk": "🚫", "spam": "🚫",
            "deleted": "🗑️", "archive": "📦",
        }
        for folder, count in sorted(self._folder_counts.items()):
            icon = "📁"
            for k, v in folder_icons.items():
                if k in folder.lower():
                    icon = v;
                    break
            parts = folder.split("/")
            display = parts[-1] if parts else folder
            item = QTreeWidgetItem([f"  {icon}  {display}  ({count})"])
            item.setData(0, Qt.UserRole, folder)
            item.setForeground(0, QColor(COLORS["text_primary"]))
            self.addTopLevelItem(item)

        self.expandAll()
        self.setCurrentItem(all_item)

    def _on_click(self, item):
        folder = item.data(0, Qt.UserRole)
        self.folder_selected.emit(folder if folder is not None else "")


# ── Main Window ───────────────────────────────────────────────────────────────
class EmailForensicsApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Forensics Tool")
        self.resize(1400, 900)
        self.setMinimumSize(1000, 650)
        self.setStyleSheet(STYLESHEET)

        self._all_entries: List[EmailEntry] = []
        self._current_folder: str = ""  # "" = All
        self._loader_thread: Optional[LoaderThread] = None

        self._build_ui()
        self._build_menu()
        self._build_toolbar()
        self._show_welcome()

    # ── UI Construction ──────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Filter bar
        self.filter_bar = FilterBar()
        self.filter_bar.setFixedHeight(60)
        self.filter_bar.filter_changed.connect(self._apply_filters)
        root_layout.addWidget(self.filter_bar)

        # Main splitter: left (folders) | right (list + content)
        self.main_splitter = QSplitter(Qt.Horizontal)
        self.main_splitter.setHandleWidth(1)
        root_layout.addWidget(self.main_splitter)

        # ── Left: Folder Panel ───────────────────────────────────────────────
        left_panel = QWidget()
        left_panel.setStyleSheet(f"background-color: {COLORS['bg_panel']};")
        left_panel.setMinimumWidth(180)
        left_panel.setMaximumWidth(280)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        folders_header = QWidget()
        folders_header.setStyleSheet(
            f"background-color: {COLORS['header_bg']}; border-bottom: 1px solid {COLORS['border']};")
        fh_layout = QHBoxLayout(folders_header)
        fh_layout.setContentsMargins(12, 8, 12, 8)
        fh_lbl = QLabel("FOLDERS")
        fh_lbl.setStyleSheet(
            f"font-size: 10px; font-weight: 700; color: {COLORS['text_muted']}; letter-spacing: 1.5px; background: transparent;")
        fh_layout.addWidget(fh_lbl)
        fh_layout.addStretch()

        self.folder_tree = FolderTree()
        self.folder_tree.folder_selected.connect(self._on_folder_selected)

        left_layout.addWidget(folders_header)
        left_layout.addWidget(self.folder_tree)
        self.main_splitter.addWidget(left_panel)

        # ── Right: list + content ────────────────────────────────────────────
        right_splitter = QSplitter(Qt.Vertical)
        right_splitter.setHandleWidth(1)

        # Email list
        list_container = QWidget()
        list_container.setStyleSheet(f"background: {COLORS['bg_mid']};")
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)

        list_header = QWidget()
        list_header.setStyleSheet(f"background: {COLORS['header_bg']}; border-bottom: 1px solid {COLORS['border']};")
        lh_layout = QHBoxLayout(list_header)
        lh_layout.setContentsMargins(12, 6, 12, 6)
        self.lbl_count = QLabel("No emails loaded")
        self.lbl_count.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']}; background: transparent;")
        lh_layout.addWidget(self.lbl_count)
        lh_layout.addStretch()
        self.lbl_selected = QLabel("")
        self.lbl_selected.setStyleSheet(f"font-size: 11px; color: {COLORS['accent_bright']}; background: transparent;")
        lh_layout.addWidget(self.lbl_selected)

        self.email_list = EmailListWidget()
        self.email_list.email_selected.connect(self._on_email_selected)
        self.email_list.itemSelectionChanged.connect(self._update_selected_count)

        list_layout.addWidget(list_header)
        list_layout.addWidget(self.email_list)
        right_splitter.addWidget(list_container)

        # Content area
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background: {COLORS['bg_panel']};")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.email_header = EmailHeaderWidget()
        content_layout.addWidget(self.email_header)

        self.content_tabs = QTabWidget()
        content_layout.addWidget(self.content_tabs)

        # Body tab
        body_widget = QWidget()
        body_layout = QVBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        self.body_view = QTextEdit()
        self.body_view.setReadOnly(True)
        self.body_view.setStyleSheet(
            f"background: {COLORS['bg_panel']}; color: {COLORS['text_primary']}; border: none; padding: 16px; font-size: 14px; line-height: 1.7;")
        body_layout.addWidget(self.body_view)
        self.content_tabs.addTab(body_widget, "📧  Body")

        # Metadata tab
        self.metadata_panel = MetadataPanel()
        self.content_tabs.addTab(self.metadata_panel, "🔍  Metadata")

        # Headers tab
        self.headers_panel = HeadersPanel()
        self.content_tabs.addTab(self.headers_panel, "📋  Raw Headers")

        # Attachments tab
        self.att_panel = AttachmentPanel()
        self.content_tabs.addTab(self.att_panel, "📎  Attachments")

        right_splitter.addWidget(content_widget)
        right_splitter.setSizes([320, 480])
        self.main_splitter.addWidget(right_splitter)
        self.main_splitter.setSizes([220, 1180])

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setMaximumHeight(14)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Ready  •  Load a PST, EML, or MSG file to begin")

    def _build_menu(self):
        mb = self.menuBar()

        file_menu = mb.addMenu("File")
        file_menu.addAction("Open PST File…", self._open_pst, "Ctrl+O")
        file_menu.addAction("Open EML File…", self._open_eml)
        file_menu.addAction("Open MSG File…", self._open_msg)
        file_menu.addAction("Open Directory…", self._open_dir, "Ctrl+Shift+O")
        file_menu.addSeparator()
        file_menu.addAction("Export All to CSV…", self._export_all_csv)
        file_menu.addAction("Export All to JSON…", self._export_all_json)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close, "Ctrl+Q")

        edit_menu = mb.addMenu("Edit")
        edit_menu.addAction("Find in Body", self._find_in_body, "Ctrl+F")
        edit_menu.addAction("Select All Emails", lambda: self.email_list.selectAll(), "Ctrl+A")
        edit_menu.addAction("Copy Selected Metadata (JSON)",
                            lambda: self.email_list._copy_json(self.email_list.get_selected_entries()), "Ctrl+C")

        view_menu = mb.addMenu("View")
        view_menu.addAction("Toggle Filter Bar", lambda: self.filter_bar.setVisible(not self.filter_bar.isVisible()))
        view_menu.addSeparator()
        view_menu.addAction("Body", lambda: self.content_tabs.setCurrentIndex(0))
        view_menu.addAction("Metadata", lambda: self.content_tabs.setCurrentIndex(1))
        view_menu.addAction("Raw Headers", lambda: self.content_tabs.setCurrentIndex(2))
        view_menu.addAction("Attachments", lambda: self.content_tabs.setCurrentIndex(3))

        help_menu = mb.addMenu("Help")
        help_menu.addAction("About", self._show_about)
        help_menu.addAction("Install PST Support", self._install_pst_help)

    def _build_toolbar(self):
        tb = self.addToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))

        def tb_btn(label, tip, callback):
            btn = QToolButton()
            btn.setText(label)
            btn.setToolTip(tip)
            btn.clicked.connect(callback)
            tb.addWidget(btn)
            return btn

        tb_btn("📂  Open PST", "Load a PST archive", self._open_pst)
        tb_btn("📄  Open EML", "Load single EML file", self._open_eml)
        tb_btn("✉️  Open MSG", "Load Outlook MSG file", self._open_msg)
        tb_btn("📁  Open Folder", "Load folder of emails", self._open_dir)
        tb.addSeparator()
        tb_btn("💾  Export CSV", "Export visible emails to CSV", self._export_visible_csv)
        tb_btn("📋  Export JSON", "Export visible emails to JSON", self._export_visible_json)
        tb.addSeparator()
        tb_btn("🔍  Find", "Search in body", self._find_in_body)
        tb.addSeparator()

        self.lbl_backend = QLabel()
        self._update_backend_label()
        tb.addWidget(self.lbl_backend)

    def _update_backend_label(self):
        parts = []
        if HAS_PST:
            parts.append(f"✅ PST ({PST_BACKEND})")
        else:
            parts.append("⚠️ PST (install libratom)")
        if HAS_MSG:
            parts.append("✅ MSG")
        else:
            parts.append("⚠️ MSG (install extract-msg)")
        parts.append("✅ EML")
        self.lbl_backend.setText("  " + "  |  ".join(parts) + "  ")
        self.lbl_backend.setStyleSheet(
            f"font-size: 11px; color: {COLORS['text_muted']}; background: transparent; padding: 0 8px;")

    # ── File Loading ─────────────────────────────────────────────────────────
    def _open_pst(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open PST File", "", "PST Files (*.pst);;All Files (*)")
        if path:
            self._load_path(path)

    def _open_eml(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open EML File", "", "EML Files (*.eml);;All Files (*)")
        if path:
            self._load_path(path)

    def _open_msg(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open MSG File", "", "MSG Files (*.msg);;All Files (*)")
        if path:
            self._load_path(path)

    def _open_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Open Directory of Emails")
        if path:
            self._load_path(path)

    def _load_path(self, path: str):
        self._all_entries = []
        self.email_list.load_entries([])
        self.folder_tree.rebuild([])
        self.email_header.clear()
        self.body_view.clear()
        self.metadata_panel.clear()
        self.headers_panel.clear_content()
        self.att_panel.clear_content()

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage(f"Loading: {path}")

        self._loader_thread = LoaderThread(path)
        self._loader_thread.progress.connect(self._on_progress)
        self._loader_thread.entry_loaded.connect(self._on_entry_loaded)
        self._loader_thread.finished_loading.connect(self._on_load_finished)
        self._loader_thread.error.connect(self._on_load_error)
        self._loader_thread.start()

    def _on_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.status_bar.showMessage(msg)

    def _on_entry_loaded(self, entry: EmailEntry):
        self._all_entries.append(entry)

    def _on_load_finished(self, total: int):
        self.progress_bar.setVisible(False)
        self.folder_tree.rebuild(self._all_entries)
        self._apply_filters()
        self.status_bar.showMessage(
            f"Loaded {total} email(s)  •  {len(set(e.folder for e in self._all_entries))} folder(s)")
        self.lbl_count.setText(f"{total} emails")

    def _on_load_error(self, msg: str):
        self.progress_bar.setVisible(False)
        QMessageBox.warning(self, "Load Error", msg)
        self.status_bar.showMessage("Error loading file.")

    # ── Folder Selection ─────────────────────────────────────────────────────
    def _on_folder_selected(self, folder: str):
        self._current_folder = folder
        self._apply_filters()

    def _get_folder_entries(self) -> List[EmailEntry]:
        if not self._current_folder:
            return self._all_entries
        return [e for e in self._all_entries if e.folder == self._current_folder]

    # ── Filtering ────────────────────────────────────────────────────────────
    def _apply_filters(self):
        filters = self.filter_bar.get_filters()
        entries = self._get_folder_entries()
        # Apply filters (the list widget will also filter, but we need the right base)
        self.email_list._entries = entries
        self.email_list.apply_filter(filters)
        n = self.email_list.rowCount()
        total = len(entries)
        self.lbl_count.setText(f"{n} / {total} email(s)")

    # ── Email Selection ──────────────────────────────────────────────────────
    def _on_email_selected(self, entry: EmailEntry):
        entry.flags["read"] = True
        self.email_header.load(entry)

        # Body
        if entry.body_html:
            self.body_view.setHtml(entry.body_html)
        elif entry.body_text:
            self.body_view.setPlainText(entry.body_text)
        else:
            self.body_view.setPlainText("(No body content)")

        self.metadata_panel.load(entry)
        self.headers_panel.load(entry)
        self.att_panel.load(entry)

        # Update attachment tab badge
        att_count = len(entry.attachments)
        self.content_tabs.setTabText(3, f"📎  Attachments ({att_count})" if att_count else "📎  Attachments")
        self.status_bar.showMessage(f"  {entry.subject}  •  {entry.sender}  •  {entry.date}")

    def _update_selected_count(self):
        n = len(self.email_list.selectionModel().selectedRows())
        self.lbl_selected.setText(f"{n} selected" if n > 1 else "")

    # ── Export ───────────────────────────────────────────────────────────────
    def _export_all_csv(self):
        self.email_list._export_csv(self._all_entries)

    def _export_all_json(self):
        self.email_list._export_json(self._all_entries)

    def _export_visible_csv(self):
        self.email_list._export_csv(self.email_list._filtered)

    def _export_visible_json(self):
        self.email_list._export_json(self.email_list._filtered)

    # ── Find ─────────────────────────────────────────────────────────────────
    def _find_in_body(self):
        text, ok = QInputDialog.getText(self, "Find in Body", "Search text:")
        if ok and text:
            cursor = self.body_view.document().find(text)
            if not cursor.isNull():
                self.body_view.setTextCursor(cursor)
                self.body_view.ensureCursorVisible()
            else:
                QMessageBox.information(self, "Not Found", f'"{text}" not found in body.')

    # ── Welcome Screen ────────────────────────────────────────────────────────
    def _show_welcome(self):
        self.body_view.setHtml(f"""
        <div style="font-family: 'Segoe UI', sans-serif; padding: 32px; color: {COLORS['text_secondary']};">
            <h1 style="color: {COLORS['accent_bright']}; font-size: 28px; margin-bottom: 8px;">📧 Email Forensics Tool</h1>
            <p style="font-size: 14px; color: {COLORS['text_muted']}; margin-bottom: 24px;">
                Professional email investigation and analysis platform
            </p>
            <hr style="border-color: {COLORS['border']}; margin-bottom: 24px;">
            <h3 style="color: {COLORS['text_primary']}; font-size: 15px;">Get Started</h3>
            <ul style="font-size: 13px; line-height: 2.2; color: {COLORS['text_secondary']};">
                <li>📂 <b>File → Open PST File</b> — Load Outlook PST archive</li>
                <li>📄 <b>File → Open EML File</b> — Load RFC-822 .eml message</li>
                <li>✉️ <b>File → Open MSG File</b> — Load Outlook .msg message</li>
                <li>📁 <b>File → Open Directory</b> — Scan folder for EML/MSG files</li>
            </ul>
            <h3 style="color: {COLORS['text_primary']}; font-size: 15px; margin-top: 20px;">Features</h3>
            <ul style="font-size: 13px; line-height: 2.2; color: {COLORS['text_secondary']};">
                <li>🔍 Full-text search across subject, sender, body</li>
                <li>📅 Date range and sender filtering</li>
                <li>📊 Export to CSV / JSON for further analysis</li>
                <li>📋 Complete raw header inspection</li>
                <li>🌐 Originating IP extraction</li>
                <li>🔐 MD5 / SHA-256 hash verification</li>
                <li>📎 Attachment extraction</li>
                <li>🖱️ Right-click entries for export options</li>
            </ul>
            <div style="margin-top: 24px; padding: 12px 16px; background: {COLORS['bg_card']}; border-radius: 8px; border-left: 3px solid {COLORS['accent']};">
                <p style="margin: 0; font-size: 12px; color: {COLORS['text_muted']};">
                    <b style="color:{COLORS['warning']}">PST Support:</b> Install <code>libratom</code> (recommended) or <code>libpff-python</code><br>
                    &nbsp;&nbsp;&nbsp;<code>pip install libratom</code><br>
                    <b style="color:{COLORS['success']}">MSG Support:</b> <code>pip install extract-msg</code><br>
                    <b style="color:{COLORS['accent_bright']}">Active backends: PST={PST_BACKEND or "None"}, MSG={"Yes" if HAS_MSG else "No"}</b>
                </p>
            </div>
        </div>
        """)

    # ── Help ─────────────────────────────────────────────────────────────────
    def _show_about(self):
        QMessageBox.about(self, "About Email Forensics Tool",
                          "Email Forensics Tool\nVersion 1.0\n\n"
                          "A professional email investigation platform supporting PST, EML, and MSG formats.\n\n"
                          "Supports: Hash verification, header analysis, attachment extraction, metadata export.")

    def _install_pst_help(self):
        QMessageBox.information(self, "PST Support",
                                "PST loading requires a backend library.\n\n"
                                "RECOMMENDED (pure Python, easiest install):\n"
                                "  pip install libratom\n\n"
                                "ALTERNATIVE (C extension, may require build tools):\n"
                                "  pip install libpff-python\n\n"
                                f"Currently detected backend: {PST_BACKEND or 'None'}\n\n"
                                "For MSG support:\n"
                                "  pip install extract-msg\n\n"
                                "EML files work with no extra dependencies.")


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Email Forensics Tool")
    app.setOrganizationName("Forensics")

    # Use Fusion style as base for consistent cross-platform look
    app.setStyle(QStyleFactory.create("Fusion"))

    window = EmailForensicsApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()