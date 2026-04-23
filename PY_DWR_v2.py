#!/usr/bin/env python3
"""
eDiscovery Pro  v4.0  —  PyQt6 Edition
=======================================
Full-featured desktop e-Discovery tool.
Converted from wxPython to PyQt6.

Features
--------
• Fully resizable window; list/viewer panes start at 50/50 and stay equal on
  first show (user can drag the splitter freely thereafter).
• Rich format-specific viewer tabs:
    Content     — TXT, PDF, DOCX, PPTX, MSG, EML, ZIP/TAR plain-text
    Spreadsheet — XLSX/CSV rendered in QTableWidget (all sheets)
    Image       — zoomable QLabel (Fit / +25% / −25%)
    Email List  — PST/MBOX message list + reading pane
    Metadata    — QTableWidget of file properties
    Notes       — free-text per document
• PST/MBOX extraction: every message becomes a child Document record
  (virtual, in-memory) fully searchable / taggable / producible.
• Inverted full-text index built in a QThread after every import;
  O(1) token lookup before falling back to linear scan.
• Thread safety: workers emit Qt signals — never touch GUI from threads.
• Dark theme via QApplication stylesheet.

Install
-------
    pip install PyQt6 pypdf python-docx python-pptx openpyxl Pillow chardet
"""

import os, sys, re, csv, json, uuid, hashlib, shutil
import email, mailbox, zipfile, tarfile, threading, datetime, time
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict, Optional, Set, Any

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QLineEdit, QTextEdit, QPlainTextEdit,
    QPushButton, QToolButton, QComboBox, QCheckBox, QRadioButton,
    QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QScrollArea, QProgressBar, QStatusBar, QToolBar,
    QMenuBar, QMenu, QDialog, QDialogButtonBox, QFileDialog,
    QMessageBox, QInputDialog, QGroupBox, QFrame,
    QAbstractItemView, QSizePolicy, QButtonGroup,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QObject, QTimer, QSize,
    QMimeData, QModelIndex,
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QPixmap, QImage, QAction,
    QStandardItemModel, QStandardItem, QIcon, QKeySequence,
    QFontDatabase, QBrush,
)

# ── Optional deps ──────────────────────────────────────────────────────────────
try:    from pypdf import PdfReader;           HAS_PDF  = True
except: HAS_PDF  = False
try:    import pypdfium2 as pdfium;            HAS_PDFIUM = True   # native PDF render
except: HAS_PDFIUM = False
try:    from docx import Document as DocxDoc;  HAS_DOCX = True
except: HAS_DOCX = False
try:    from pptx import Presentation;         HAS_PPTX = True
except: HAS_PPTX = False
try:    import openpyxl;                        HAS_XLSX = True
except: HAS_XLSX = False
try:    from PIL import Image as PILImage;      HAS_PIL  = True
except: HAS_PIL  = False
try:    import extract_msg;                     HAS_MSG  = True
except: HAS_MSG  = False
try:    import chardet;                         HAS_CHARDET = True
except: HAS_CHARDET = False
try:    import pypff ;                           HAS_PST  = True
except: HAS_PST  = False
from PyQt6.QtWidgets import QTextEdit

import re

def is_html(text):
    if not isinstance(text, str):
        return False

    text = text.strip().lower()

    # Strong indicators of real HTML email
    if "<html" in text or "<body" in text:
        return True

    # Fallback: detect real tags (not just angle brackets)
    return bool(re.search(r"</?(html|body|div|span|table|tr|td|p|br|img)[\s>]", text))

import re

def clean_html(html: str) -> str:
    if not isinstance(html, str):
        return ""

    # Fix missing semicolons between CSS properties
    html = re.sub(
        r'(#(?:[0-9a-fA-F]{3,6}))([a-zA-Z-]+)',
        r'\1; \2',
        html
    )

    # Fix color:#xxxxxx;
    html = re.sub(
        r'color\s*:\s*(#[0-9a-fA-F]{6});',
        r'color:\1',
        html
    )

    # Remove MSO-specific junk (Outlook CSS)
    html = re.sub(r'mso-[^:]+:[^;"\']+;?', '', html, flags=re.IGNORECASE)

    # Remove invalid style fragments
    html = re.sub(r'style="[^"]*?#[^";]+[a-zA-Z-]+[^"]*"', '', html)

    return html


# ── Palette ────────────────────────────────────────────────────────────────────
APP_NAME, APP_VERSION = "eDiscovery Pro", "4.1.0"

C_DARK_BG      = "#12161E"
C_PANEL_BG     = "#1A2030"   # slightly lighter for panels
C_SIDEBAR_BG   = "#161B26"
C_HEADER_BG    = "#1E283C"
C_ACCENT       = "#388BFD"
C_ACCENT_HOVER = "#58A6FF"
C_SUCCESS      = "#2EA043"
C_WARNING      = "#E6A23C"
C_DANGER       = "#F85149"
C_TEXT         = "#E6EDF3"
C_TEXT_MUTED   = "#6E7681"
C_ALT_ROW      = "#20263A"
C_BORDER       = "#30363D"
C_TAG_HOT      = "#F85149"
C_TAG_RELEVANT = "#2EA043"
C_TAG_REVIEW   = "#E6A23C"
C_TAG_PRIV     = "#8B949E"

TAG_COLORS: Dict[str, str] = {
    "Hot": C_TAG_HOT, "Relevant": C_TAG_RELEVANT,
    "Needs Review": C_TAG_REVIEW, "Privileged": C_TAG_PRIV,
    "Not Relevant": C_TEXT_MUTED, "Confidential": "#B464DC",
    "Produced": C_ACCENT, "Redacted": C_WARNING, "Hold": C_DANGER,
}

SUPPORTED_EXTS = {
    "Documents":     [".txt",".pdf",".docx",".doc",".rtf",".odt",".log"],
    "Spreadsheets":  [".xlsx",".xls",".csv",".ods"],
    "Presentations": [".pptx",".ppt",".odp"],
    "Email":         [".msg",".eml",".pst",".mbox"],
    "Images":        [".jpg",".jpeg",".png",".bmp",".tiff",".tif",".gif",".webp"],
    "Archives":      [".zip",".tar",".gz",".tar.gz"],
}
ALL_EXTS = [e for exts in SUPPORTED_EXTS.values() for e in exts]
REVIEW_TAGS = ["Hot","Relevant","Not Relevant","Needs Review",
               "Privileged","Confidential","Produced","Redacted","Hold"]

# ── Dark stylesheet ────────────────────────────────────────────────────────────
DARK_QSS = f"""
QMainWindow, QDialog, QWidget {{
    background: {C_DARK_BG};
    color: {C_TEXT};
    font-family: "Segoe UI", "SF Pro Text", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}}
QMenuBar {{
    background: {C_PANEL_BG};
    color: {C_TEXT};
    border-bottom: 1px solid {C_BORDER};
}}
QMenuBar::item:selected {{ background: {C_HEADER_BG}; }}
QMenu {{
    background: {C_PANEL_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
}}
QMenu::item:selected {{ background: {C_ACCENT}; color: white; }}
QToolBar {{
    background: {C_PANEL_BG};
    border-bottom: 1px solid {C_BORDER};
    spacing: 4px;
    padding: 2px 4px;
}}
QToolButton {{
    background: transparent;
    color: {C_TEXT};
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 12px;
}}
QToolButton:hover {{ background: {C_HEADER_BG}; border-color: {C_BORDER}; }}
QToolButton:pressed {{ background: {C_ACCENT}; }}
QPushButton {{
    background: {C_HEADER_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    border-radius: 5px;
    padding: 5px 14px;
    min-height: 22px;
}}
QPushButton:hover {{ background: {C_PANEL_BG}; border-color: {C_ACCENT}; }}
QPushButton:pressed {{ background: {C_ACCENT}; color: white; }}
QPushButton#accent {{
    background: {C_ACCENT};
    color: white;
    border-color: {C_ACCENT};
    font-weight: 600;
}}
QPushButton#accent:hover {{ background: {C_ACCENT_HOVER}; }}
QPushButton#danger {{ background: {C_DANGER}; color: white; border-color: {C_DANGER}; }}
QPushButton#success {{ background: {C_SUCCESS}; color: white; border-color: {C_SUCCESS}; }}
QLineEdit, QTextEdit, QPlainTextEdit {{
    background: {C_DARK_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    padding: 4px 8px;
    selection-background-color: {C_ACCENT};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {C_ACCENT};
}}
QComboBox {{
    background: {C_DARK_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 22px;
}}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {C_PANEL_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    selection-background-color: {C_ACCENT};
}}
QCheckBox {{ color: {C_TEXT}; spacing: 6px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {C_BORDER};
    border-radius: 3px;
    background: {C_DARK_BG};
}}
QCheckBox::indicator:checked {{
    background: {C_ACCENT};
    border-color: {C_ACCENT};
}}
QRadioButton {{ color: {C_TEXT}; spacing: 6px; }}
QGroupBox {{
    color: {C_TEXT_MUTED};
    border: 1px solid {C_BORDER};
    border-radius: 5px;
    margin-top: 8px;
    padding-top: 6px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
QTabWidget::pane {{
    border: 1px solid {C_BORDER};
    background: {C_DARK_BG};
}}
QTabBar::tab {{
    background: {C_PANEL_BG};
    color: {C_TEXT_MUTED};
    border: 1px solid {C_BORDER};
    border-bottom: none;
    padding: 5px 14px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}}
QTabBar::tab:selected {{ background: {C_DARK_BG}; color: {C_TEXT}; border-bottom: 2px solid {C_ACCENT}; }}
QTabBar::tab:hover {{ color: {C_TEXT}; }}
QSplitter::handle {{
    background: {C_BORDER};
    width: 3px;
    height: 3px;
}}
QSplitter::handle:horizontal {{ width: 3px; }}
QSplitter::handle:vertical {{ height: 3px; }}
QScrollBar:vertical {{
    background: {C_PANEL_BG}; width: 10px; margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {C_BORDER}; min-height: 20px; border-radius: 5px;
}}
QScrollBar::handle:vertical:hover {{ background: {C_TEXT_MUTED}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C_PANEL_BG}; height: 10px; margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {C_BORDER}; min-width: 20px; border-radius: 5px;
}}
QScrollBar::handle:horizontal:hover {{ background: {C_TEXT_MUTED}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QTableWidget, QTableView {{
    background: {C_DARK_BG};
    color: {C_TEXT};
    gridline-color: {C_BORDER};
    border: none;
    selection-background-color: {C_ACCENT};
    alternate-background-color: {C_ALT_ROW};
}}
QHeaderView::section {{
    background: {C_HEADER_BG};
    color: {C_ACCENT};
    border: 1px solid {C_BORDER};
    padding: 4px 8px;
    font-weight: 600;
}}
QListWidget {{
    background: {C_DARK_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    alternate-background-color: {C_ALT_ROW};
}}
QListWidget::item:selected {{ background: {C_ACCENT}; color: white; }}
QListWidget::item:hover {{ background: {C_HEADER_BG}; }}
QProgressBar {{
    background: {C_DARK_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    text-align: center;
    height: 16px;
}}
QProgressBar::chunk {{
    background: {C_ACCENT};
    border-radius: 4px;
}}
QStatusBar {{
    background: {C_PANEL_BG};
    color: {C_TEXT_MUTED};
    border-top: 1px solid {C_BORDER};
}}
QStatusBar::item {{ border: none; }}
QLabel#header {{
    color: {C_ACCENT};
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 1px;
}}
QLabel#doc_title {{
    color: {C_ACCENT};
    font-weight: 700;
    font-size: 13px;
}}
QLabel#muted {{ color: {C_TEXT_MUTED}; font-size: 11px; }}
QFrame#sidebar {{
    background: {C_SIDEBAR_BG};
    border-right: 1px solid {C_BORDER};
}}
QFrame#list_header {{
    background: {C_HEADER_BG};
    border-bottom: 1px solid {C_BORDER};
}}
"""

# ══════════════════════════════════════════════════════════════════════════════
# Search Index  (inverted index — pure Python, thread-safe, no Qt)
# ══════════════════════════════════════════════════════════════════════════════
_TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)

class SearchIndex:
    def __init__(self):
        self._idx: Dict[str, Set[str]] = defaultdict(set)
        self.doc_count = 0

    def add_document(self, doc_id: str, text: str):
        for tok in _TOKEN_RE.findall(text.lower()):
            self._idx[tok].add(doc_id)
        self.doc_count += 1

    def search(self, query: str) -> Set[str]:
        query = query.strip()
        if not query: return set()
        phrase = query[1:-1] if (query.startswith('"') and query.endswith('"')) else query
        tokens = _TOKEN_RE.findall(phrase.lower())
        if not tokens: return set()
        result = self._idx.get(tokens[0], set()).copy()
        for tok in tokens[1:]:
            result &= self._idx.get(tok, set())
        return result


# ══════════════════════════════════════════════════════════════════════════════
# PST / MBOX / MSG helpers  (pure Python, no Qt)
# ══════════════════════════════════════════════════════════════════════════════
def _email_body_from_message(msg) -> str:
    """Extract plain-text body from an email.message object, with HTML fallback."""
    plain = ""; html = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                enc = part.get_content_charset() or "utf-8"
                plain = payload.decode(enc, errors="replace")
        elif ct == "text/html" and not plain:
            payload = part.get_payload(decode=True)
            if payload:
                enc = part.get_content_charset() or "utf-8"
                raw_html = payload.decode(enc, errors="replace")
                # Strip tags for a readable fallback
                html = re.sub(r'<[^>]+>', '', raw_html)
                html = re.sub(r'\s+', ' ', html).strip()
    return plain or html


def _parse_single_eml_bytes(raw: bytes) -> dict:
    """Parse a single .eml file bytes into a message dict."""
    msg = email.message_from_bytes(raw)
    body = _email_body_from_message(msg)
    attachments = [p.get_filename("") for p in msg.walk()
                   if p.get_content_disposition() == "attachment" and p.get_filename()]
    return {
        "subject":     msg.get("Subject", "(no subject)"),
        "sender":      msg.get("From", ""),
        "recipients":  msg.get("To", ""),
        "date":        msg.get("Date", ""),
        "body":        body,
        "attachments": [a for a in attachments if a],
        "cc":          msg.get("Cc", ""),
        "message_id":  msg.get("Message-ID", ""),
    }


def _extract_pst_messages(pst_path: str) -> List[dict]:
    """
    Extract email messages from PST or MBOX files.
    Strategy order:
      1. pypff  (real PST binary format)
      2. mailbox.mbox  (Unix MBOX format — also used by Thunderbird)
      3. mailbox.Maildir / mailbox.MH  (other mail formats)
      4. Raw scan for embedded RFC-822 messages (last resort)
    Returns list of dicts: subject, sender, recipients, date, body, attachments, cc.
    """
    ext = Path(pst_path).suffix.lower()
    messages: List[dict] = []

    # ── Strategy 1: pypff for real PST/OST ───────────────────────────────────
    if HAS_PST and ext in (".pst", ".ost"):
        try:
            pst = pypff.file()
            pst.open(pst_path)
            _recurse_pst_folder(pst.get_root_folder(), messages)
            pst.close()
            if messages:
                return messages
        except Exception:
            pass

    # ── Strategy 2: mailbox.mbox (MBOX / .eml aggregate) ─────────────────────
    try:
        mbox = mailbox.mbox(pst_path)
        for i, msg in enumerate(mbox):
            if i >= 10000: break
            body = _email_body_from_message(msg)
            attachments = [p.get_filename("") for p in msg.walk()
                           if p.get_content_disposition() == "attachment" and p.get_filename()]
            messages.append({
                "subject":    msg.get("Subject", "(no subject)"),
                "sender":     msg.get("From", ""),
                "recipients": msg.get("To", ""),
                "date":       msg.get("Date", ""),
                "body":       body,
                "attachments":[a for a in attachments if a],
                "cc":         msg.get("Cc", ""),
                "message_id": msg.get("Message-ID", ""),
            })
        if messages:
            return messages
    except Exception:
        pass

    # ── Strategy 3: mailbox.Maildir ───────────────────────────────────────────
    try:
        if os.path.isdir(pst_path):
            mdir = mailbox.Maildir(pst_path)
            for key in list(mdir.keys())[:10000]:
                msg = mdir[key]
                body = _email_body_from_message(msg)
                messages.append({
                    "subject":    msg.get("Subject", "(no subject)"),
                    "sender":     msg.get("From", ""),
                    "recipients": msg.get("To", ""),
                    "date":       msg.get("Date", ""),
                    "body":       body,
                    "attachments":[],
                    "cc": msg.get("Cc", ""), "message_id": msg.get("Message-ID", ""),
                })
            if messages:
                return messages
    except Exception:
        pass

    # ── Strategy 4: raw scan for RFC-822 boundaries in binary PST ────────────
    # PST files embed RFC-822 messages; scan for "From:" at start of line
    try:
        raw = open(pst_path, "rb").read()
        # Find embedded EML blocks by scanning for common email headers
        splits = re.split(rb'(?:^|\r?\n)(?=From: )', raw, flags=re.MULTILINE)
        for chunk in splits[1:100]:
            try:
                d = _parse_single_eml_bytes(chunk)
                if d.get("subject") or d.get("sender"):
                    messages.append(d)
            except Exception:
                pass
        if messages:
            return messages
    except Exception:
        pass

    return messages


def _recurse_pst_folder(folder, out: list, depth=0):
    indent = "  " * depth

    try:
        msg_count = getattr(folder, "number_of_sub_messages", 0)
        sub_count = getattr(folder, "number_of_sub_folders", 0)

        print(f"{indent}Folder: {getattr(folder, 'name', 'N/A')}")
        print(f"{indent}Messages: {msg_count}, Subfolders: {sub_count}")

        # ── Extract messages ─────────────────────────────
        for i in range(msg_count):
            try:
                msg = folder.get_sub_message(i)

                subject = getattr(msg, "subject", None) or "(no subject)"
                sender = getattr(msg, "sender_name", None) or ""

                # Body extraction
                body = ""
                try:
                    body = msg.plain_text_body or ""
                except Exception:
                    pass
                if not body:
                    try:
                        body = msg.html_body or ""
                    except Exception:
                        pass

                # Attachments
                attachments = []
                try:
                    for j in range(msg.number_of_attachments):
                        att = msg.get_attachment(j)
                        name = att.get_name() if att else None
                        if name:
                            attachments.append(name)
                except Exception:
                    pass

                out.append({
                    "subject": subject,
                    "sender": sender,
                    "recipients": getattr(msg, "display_to", "") or "",
                    "date": str(getattr(msg, "delivery_time", "") or ""),
                    "body": body,
                    "attachments": attachments,
                    "cc": "",
                    "message_id": "",
                })

            except Exception as e:
                print(f"{indent}Error reading message {i}: {e}")

        # ── Recurse folders ─────────────────────────────
        for i in range(sub_count):
            try:
                sub = folder.get_sub_folder(i)
                _recurse_pst_folder(sub, out, depth + 1)
            except Exception as e:
                print(f"{indent}Error reading subfolder {i}: {e}")

    except Exception as e:
        print(f"{indent}Folder error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Document model  (pure Python — no Qt)
# ══════════════════════════════════════════════════════════════════════════════
class Document:
    __slots__ = (
        "doc_id","path","filename","ext","size","modified",
        "tags","custodian","bates_begin","bates_end","notes",
        "md5","sha256","text_cache","metadata",
        "is_produced","is_redacted","family_id","parent_id",
        "attachments","reviewed_by","date_reviewed",
        "email_subject","email_from","email_to","email_date",
        "sheet_data","is_virtual",
    )

    def __init__(self, path: str, virtual: bool = False):
        self.doc_id = str(uuid.uuid4())[:8].upper()
        self.path = path; self.filename = os.path.basename(path)
        self.ext = Path(path).suffix.lower(); self.is_virtual = virtual
        if not virtual and os.path.exists(path):
            try:
                st = os.stat(path); self.size = st.st_size
                self.modified = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            except OSError: self.size = 0; self.modified = ""
        else: self.size = 0; self.modified = ""
        for attr in ("tags","attachments"): object.__setattr__(self, attr, [])
        for attr in ("custodian","bates_begin","bates_end","notes","md5","sha256",
                     "family_id","parent_id","reviewed_by","date_reviewed",
                     "email_subject","email_from","email_to","email_date"):
            object.__setattr__(self, attr, "")
        self.text_cache: Optional[str] = None
        self.metadata: dict = {}; self.sheet_data: Optional[dict] = None
        self.is_produced = False; self.is_redacted = False

    @classmethod
    def from_email_dict(cls, d: dict, parent_path: str, parent_id: str) -> "Document":
        subject = d.get("subject","(no subject)")
        obj = cls(f"{parent_path}::{re.sub(r'[^\\w\\- ]','_',subject)[:60]}", virtual=True)
        obj.filename = f"[EMAIL] {subject}"; obj.ext = ".eml"
        obj.email_subject = subject; obj.email_from = d.get("sender","")
        obj.email_to = d.get("recipients",""); obj.email_date = d.get("date","")
        obj.parent_id = parent_id; obj.modified = d.get("date","")
        body = d.get("body","")
        obj.text_cache = (f"Subject: {subject}\nFrom: {obj.email_from}\n"
                          f"To: {obj.email_to}\nDate: {obj.email_date}\n"
                          f"{'─'*60}\n{body}")
        obj.size = len(obj.text_cache.encode())
        obj.attachments = [a for a in d.get("attachments",[]) if a]
        return obj

    def category(self) -> str:
        for cat, exts in SUPPORTED_EXTS.items():
            if self.ext in exts: return cat
        return "Other"

    def size_str(self) -> str:
        s = float(self.size)
        for u in ("B","KB","MB","GB"):
            if s < 1024: return f"{s:.1f} {u}"
            s /= 1024
        return f"{s:.1f} TB"

    def compute_hashes(self):
        if self.is_virtual: return
        try:
            m, sh = hashlib.md5(), hashlib.sha256()
            with open(self.path,"rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    m.update(chunk); sh.update(chunk)
            self.md5 = m.hexdigest(); self.sha256 = sh.hexdigest()
        except Exception: pass

    def extract_text(self) -> str:
        if self.text_cache is not None: return self.text_cache
        self.text_cache = _extract_text(self.path, self.ext)
        return self.text_cache

    def extract_metadata(self) -> dict:
        meta: dict = {}
        try:
            if not self.is_virtual:
                st = os.stat(self.path)
                meta["File Size"] = self.size_str()
                meta["Created"]   = datetime.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
                meta["Modified"]  = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            else:
                meta["Type"] = "Virtual (extracted from PST/MBOX)"; meta["Size"] = self.size_str()
            meta["Extension"] = self.ext; meta["Category"] = self.category()
            meta["MD5"] = self.md5 or "(not computed)"; meta["SHA-256"] = self.sha256 or "(not computed)"
            if self.custodian:   meta["Custodian"]   = self.custodian
            if self.bates_begin: meta["Bates Begin"] = self.bates_begin
            if self.bates_end:   meta["Bates End"]   = self.bates_end
            if self.email_subject:
                meta["Subject"] = self.email_subject; meta["From"] = self.email_from
                meta["To"] = self.email_to; meta["Date"] = self.email_date
            if self.ext == ".pdf" and HAS_PDF and not self.is_virtual:
                try:
                    r = PdfReader(self.path); inf = r.metadata or {}
                    meta["Pages"] = len(r.pages); meta["Author"] = inf.get("/Author","")
                    meta["Title"] = inf.get("/Title",""); meta["Creator"] = inf.get("/Creator","")
                except Exception: pass
            elif self.ext == ".docx" and HAS_DOCX and not self.is_virtual:
                try:
                    doc = DocxDoc(self.path); p = doc.core_properties
                    meta["Author"] = p.author or ""; meta["Title"] = p.title or ""
                    if p.created: meta["Doc Created"] = str(p.created)
                    if p.modified: meta["Doc Modified"] = str(p.modified)
                except Exception: pass
            elif self.ext in (".xlsx",".xls") and HAS_XLSX and not self.is_virtual:
                try:
                    wb = openpyxl.load_workbook(self.path, read_only=True)
                    p = wb.properties
                    meta["Author"] = p.creator or ""; meta["Sheets"] = ", ".join(wb.sheetnames)
                    wb.close()
                except Exception: pass
        except Exception: pass
        self.metadata = meta; return meta

    def load_sheet_data(self) -> Optional[dict]:
        """
        Load spreadsheet into {sheet_name: [[row_values]]} dict.
        Handles: merged cells (fill span with value), formula-only cells
        (show formula string), empty trailing rows/cols trimmed.
        """
        if self.sheet_data is not None: return self.sheet_data
        result: dict = {}
        try:
            if self.ext in (".xlsx", ".xls") and HAS_XLSX:
                # data_only=True returns cached formula results; keep_vba=False is default
                wb = openpyxl.load_workbook(self.path, read_only=False, data_only=True)
                for name in wb.sheetnames:
                    ws = wb[name]
                    rows: List[List[str]] = []
                    # Build merged-cell map so secondary cells inherit the primary value
                    merged_map: Dict[tuple, str] = {}
                    try:
                        for merge_range in ws.merged_cells.ranges:
                            # Get the top-left cell value
                            tl = ws.cell(merge_range.min_row, merge_range.min_col)
                            val = _cell_str(tl.value)
                            for r in range(merge_range.min_row, merge_range.max_row + 1):
                                for c in range(merge_range.min_col, merge_range.max_col + 1):
                                    if not (r == merge_range.min_row and c == merge_range.min_col):
                                        merged_map[(r, c)] = val
                    except Exception:
                        pass  # read_only workbooks don't expose merged_cells
                    for ri, row in enumerate(ws.iter_rows(), start=1):
                        row_vals = []
                        for ci, cell in enumerate(row, start=1):
                            if (ri, ci) in merged_map:
                                row_vals.append(merged_map[(ri, ci)])
                            else:
                                row_vals.append(_cell_str(cell.value))
                        rows.append(row_vals)
                    # Trim empty trailing rows
                    while rows and all(v == "" for v in rows[-1]):
                        rows.pop()
                    # Trim empty trailing columns
                    if rows:
                        max_used = max((next((len(r)-i-1 for i,v in enumerate(reversed(r)) if v), -1)
                                        for r in rows), default=0) + 1
                        rows = [r[:max(max_used, 1)] for r in rows]
                    result[name] = rows
                wb.close()

            elif self.ext == ".csv":
                import io
                raw = open(self.path, "rb").read()
                enc = chardet.detect(raw).get("encoding", "utf-8") if HAS_CHARDET else "utf-8"
                text = raw.decode(enc or "utf-8", errors="replace")
                reader = csv.reader(io.StringIO(text))
                rows = [[_cell_str(v) for v in row] for row in reader]
                # Trim empty trailing rows
                while rows and all(v == "" for v in rows[-1]):
                    rows.pop()
                result["Sheet1"] = rows

        except Exception as e:
            # Fallback: try read_only mode (handles corrupt/large files)
            try:
                wb = openpyxl.load_workbook(self.path, read_only=True, data_only=True)
                for name in wb.sheetnames:
                    rows = [[_cell_str(v) for v in row]
                            for row in wb[name].iter_rows(values_only=True)]
                    while rows and all(v == "" for v in rows[-1]): rows.pop()
                    result[name] = rows
                wb.close()
            except Exception:
                pass

        self.sheet_data = result if result else None
        return self.sheet_data

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "doc_id","path","filename","ext","size","modified","tags","custodian",
            "bates_begin","bates_end","notes","md5","sha256","is_produced","is_redacted",
            "family_id","parent_id","reviewed_by","date_reviewed",
            "email_subject","email_from","email_to","email_date","is_virtual",
        )}

    @classmethod
    def from_dict(cls, d: dict) -> "Document":
        obj = object.__new__(cls)
        for sl in cls.__slots__:
            default: Any = [] if sl in ("tags","attachments") else (False if sl.startswith("is_") else "")
            setattr(obj, sl, d.get(sl, default))
        obj.size = int(obj.size) if obj.size else 0
        obj.is_produced = bool(obj.is_produced); obj.is_redacted = bool(obj.is_redacted)
        obj.is_virtual = bool(obj.is_virtual)
        obj.text_cache = None; obj.metadata = {}; obj.sheet_data = None
        obj.attachments = d.get("attachments",[])
        return obj


# ── Text extraction ────────────────────────────────────────────────────────────
def _decode(raw: bytes) -> str:
    enc = chardet.detect(raw).get("encoding","utf-8") if HAS_CHARDET else "utf-8"
    return raw.decode(enc or "utf-8", errors="replace")

def _cell_str(value) -> str:
    """Convert an openpyxl cell value to a clean display string."""
    if value is None:       return ""
    if isinstance(value, bool): return str(value)          # True/False before int check
    if isinstance(value, int):  return str(value)
    if isinstance(value, float):
        # Avoid ugly floats like 1.0000000000000002
        if value == int(value) and abs(value) < 1e15:
            return str(int(value))
        return f"{value:g}"
    if isinstance(value, (datetime.datetime, datetime.date)):
        return str(value)
    s = str(value).strip()
    # openpyxl formula cells return '=FORMULA(...)' when data_only but no cache
    # Keep the formula text so user sees something useful
    return s

def _col_letter(col_idx: int) -> str:
    """Convert 0-based column index to Excel-style letter (A, B, … Z, AA, AB …)."""
    label = ""
    n = col_idx
    while True:
        label = chr(ord('A') + n % 26) + label
        n = n // 26 - 1
        if n < 0:
            break
    return label

def _extract_text(path: str, ext: str) -> str:
    try:
        if ext in (".txt",".rtf",".log",".md"): return _decode(open(path,"rb").read())
        if ext == ".pdf" and HAS_PDF:
            r = PdfReader(path)
            return "\n".join(f"── Page {i+1} ──\n{p.extract_text() or ''}" for i,p in enumerate(r.pages))
        if ext == ".docx" and HAS_DOCX:
            doc = DocxDoc(path); lines = [p.text for p in doc.paragraphs]
            for tbl in doc.tables:
                for row in tbl.rows: lines.append(" │ ".join(c.text for c in row.cells))
            return "\n".join(lines)
        if ext in (".xlsx",".xls") and HAS_XLSX:
            wb = openpyxl.load_workbook(path, read_only=True, data_only=True); out = []
            for name in wb.sheetnames:
                out.append(f"=== {name} ===")
                for row in wb[name].iter_rows(values_only=True):
                    out.append("\t".join("" if v is None else str(v) for v in row))
            wb.close(); return "\n".join(out)
        if ext == ".csv": return _decode(open(path,"rb").read())
        if ext == ".pptx" and HAS_PPTX:
            prs = Presentation(path); lines = []
            for i, slide in enumerate(prs.slides):
                lines.append(f"── Slide {i+1} ──")
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        for para in shape.text_frame.paragraphs: lines.append(para.text)
            return "\n".join(lines)
        if ext == ".eml":
            with open(path,"rb") as f: msg = email.message_from_bytes(f.read())
            parts = [f"From: {msg.get('From','')}", f"To: {msg.get('To','')}",
                     f"Subject: {msg.get('Subject','')}", f"Date: {msg.get('Date','')}", "─"*60]
            for part in msg.walk():
                if part.get_content_type() in ("text/plain","text/html"):
                    payload = part.get_payload(decode=True)
                    if payload: parts.append(payload.decode("utf-8", errors="replace"))
            return "\n".join(parts)
        if ext == ".msg" and HAS_MSG:
            m = extract_msg.Message(path)
            return f"From: {m.sender}\nTo: {m.to}\nSubject: {m.subject}\nDate: {m.date}\n{'─'*60}\n{m.body or ''}"
        if ext in (".pst",".mbox"):
            msgs = _extract_pst_messages(path)
            lines = [f"[{ext.upper()} — {len(msgs)} messages]\n"]
            for i, m in enumerate(msgs[:20]):
                lines += [f"{'═'*60}", f"Subject : {m.get('subject','')}", f"From    : {m.get('sender','')}",
                          f"Date    : {m.get('date','')}", m.get("body","")[:400]]
            if len(msgs) > 20: lines.append(f"\n… {len(msgs)-20} more messages (see Email List tab)")
            return "\n".join(lines)
        if ext in (".jpg",".jpeg",".png",".bmp",".tiff",".tif",".gif",".webp"):
            return f"[Image file: {os.path.basename(path)}]\n(See Image tab)"
        if ext == ".zip":
            with zipfile.ZipFile(path) as z: names = z.namelist()
            return f"[ZIP — {len(names)} entries]\n" + "\n".join(names[:500])
        if ext in (".tar",".gz"):
            try:
                with tarfile.open(path) as t: names = t.getnames()
                return f"[TAR — {len(names)} entries]\n" + "\n".join(names[:500])
            except Exception: pass
        raw = open(path,"rb").read(16384)
        if b"\x00" in raw: return f"[Binary file — {os.path.basename(path)}]"
        return _decode(raw)
    except Exception as e: return f"[Error extracting text: {e}]"


# ══════════════════════════════════════════════════════════════════════════════
# Case
# ══════════════════════════════════════════════════════════════════════════════
class Case:
    def __init__(self, name: str, folder: str):
        self.name = name; self.folder = folder
        self.created = datetime.datetime.now().isoformat()
        self.documents: List[Document] = []; self._by_id: Dict[str, Document] = {}
        self.bates_prefix = "DOC"; self.bates_counter = 1
        self.custodians: List[str] = []; self.search_history: List[str] = []
        self.audit_log: List[str] = []; self._index: Optional[SearchIndex] = None

    def add_document(self, doc: Document):
        self.documents.append(doc); self._by_id[doc.doc_id] = doc
        if doc.custodian and doc.custodian not in self.custodians:
            self.custodians.append(doc.custodian)
        self.log(f"Imported: {doc.filename} [{doc.doc_id}]")

    def remove_document(self, doc_id: str):
        doc = self._by_id.pop(doc_id, None)
        if doc: self.documents.remove(doc); self.log(f"Removed: {doc.filename}")

    def assign_bates(self, docs: List[Document], prefix="", start=0, pad=6):
        pfx = prefix or self.bates_prefix; ctr = start or self.bates_counter
        for doc in docs:
            b = f"{pfx}{ctr:0{pad}d}"; doc.bates_begin = b; doc.bates_end = b; ctr += 1
        self.bates_counter = ctr; self.log(f"Assigned Bates to {len(docs)} doc(s)")

    def set_index(self, idx: SearchIndex):
        self._index = idx; self.log(f"Search index built: {idx.doc_count} docs indexed")

    def search(self, query: str, field: str = "fulltext") -> List[Document]:
        if not query: return self.documents[:]
        q = query.lower()
        if field == "fulltext" and self._index:
            ids = self._index.search(query)
            if ids: return [d for d in self.documents if d.doc_id in ids]
        out = []
        for doc in self.documents:
            if   field == "fulltext"  and (q in doc.filename.lower() or q in doc.extract_text().lower()): out.append(doc)
            elif field == "filename"  and q in doc.filename.lower():          out.append(doc)
            elif field == "custodian" and q in doc.custodian.lower():         out.append(doc)
            elif field == "tags"      and any(q in t.lower() for t in doc.tags): out.append(doc)
            elif field == "bates"     and (q in doc.bates_begin.lower() or q in doc.bates_end.lower()): out.append(doc)
            elif field == "notes"     and q in doc.notes.lower():             out.append(doc)
            elif field == "subject"   and q in doc.email_subject.lower():     out.append(doc)
        if query not in self.search_history: self.search_history.append(query)
        return out

    def log(self, msg: str):
        self.audit_log.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

    def stats(self) -> dict:
        total = len(self.documents)
        return {"total": total,
                "by_category": dict(Counter(d.category() for d in self.documents)),
                "by_tag":      dict(Counter(t for d in self.documents for t in d.tags)),
                "produced":    sum(1 for d in self.documents if d.is_produced),
                "reviewed":    sum(1 for d in self.documents if d.reviewed_by),
                "total_size":  sum(d.size for d in self.documents),
                "indexed":     bool(self._index)}

    def save(self, path: str):
        with open(path,"w",encoding="utf-8") as f:
            json.dump({"name":self.name,"folder":self.folder,"created":self.created,
                       "bates_prefix":self.bates_prefix,"bates_counter":self.bates_counter,
                       "custodians":self.custodians,"search_history":self.search_history,
                       "audit_log":self.audit_log,
                       "documents":[d.to_dict() for d in self.documents]}, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "Case":
        with open(path,"r",encoding="utf-8") as f: data = json.load(f)
        c = cls(data["name"], data["folder"])
        c.created = data.get("created",""); c.bates_prefix = data.get("bates_prefix","DOC")
        c.bates_counter = data.get("bates_counter",1)
        c.custodians = data.get("custodians",[]); c.search_history = data.get("search_history",[])
        c.audit_log = data.get("audit_log",[])
        for dd in data.get("documents",[]):
            doc = Document.from_dict(dd); c.documents.append(doc); c._by_id[doc.doc_id] = doc
        return c


# ══════════════════════════════════════════════════════════════════════════════
# Qt Worker threads  (signals — never touch GUI directly)
# ══════════════════════════════════════════════════════════════════════════════
class ImportWorker(QThread):
    progress  = pyqtSignal(int, str)          # index, filename
    finished  = pyqtSignal(list)              # List[Document]

    def __init__(self, paths: List[str], extract_pst: bool = True):
        super().__init__()
        self.paths = paths; self.extract_pst = extract_pst
        self._cancelled = False

    def cancel(self): self._cancelled = True

    def run(self):
        INTERVAL = 1.0 / 20; last = 0.0; results: List[Document] = []
        for i, path in enumerate(self.paths):
            if self._cancelled: break
            now = time.monotonic()
            if now - last >= INTERVAL:
                self.progress.emit(i, os.path.basename(path)); last = now
            ext = Path(path).suffix.lower()
            try:
                parent = Document(path); results.append(parent)
                if self.extract_pst and ext in (".pst",".mbox"):
                    try:
                        msgs = _extract_pst_messages(path)
                        for m in msgs:
                            child = Document.from_email_dict(m, path, parent.doc_id)
                            child.custodian = parent.custodian
                            results.append(child)
                        parent.text_cache = (f"[{ext.upper()} — {len(msgs)} messages extracted]\n"
                                             "Messages appear as individual records in the list.")
                    except Exception: pass
            except Exception: pass
        self.finished.emit(results)


class IndexWorker(QThread):
    finished = pyqtSignal(object)   # SearchIndex

    def __init__(self, documents: List[Document]):
        super().__init__(); self.documents = documents

    def run(self):
        idx = SearchIndex()
        for doc in self.documents:
            try: idx.add_document(doc.doc_id, doc.extract_text() + " " + doc.filename + " " + doc.custodian)
            except Exception: pass
        self.finished.emit(idx)


class HashWorker(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal()

    def __init__(self, documents: List[Document]):
        super().__init__(); self.documents = documents; self._cancelled = False

    def cancel(self): self._cancelled = True

    def run(self):
        INTERVAL = 1.0 / 20; last = 0.0
        for i, doc in enumerate(self.documents):
            if self._cancelled: break
            now = time.monotonic()
            if now - last >= INTERVAL:
                self.progress.emit(i, doc.filename); last = now
            doc.compute_hashes()
        self.finished.emit()


# ══════════════════════════════════════════════════════════════════════════════
# Import Progress Dialog
# ══════════════════════════════════════════════════════════════════════════════
class ImportProgressDlg(QDialog):
    def __init__(self, parent, files: List[str], title: str = "Importing Documents"):
        super().__init__(parent)
        self.setWindowTitle(title); self.setModal(True)
        self.setFixedSize(520, 160)
        self.files = files; self.results: List[Document] = []
        self._worker: Optional[ImportWorker] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16); layout.setSpacing(10)

        self.lbl_file = QLabel("Preparing…"); layout.addWidget(self.lbl_file)
        self.bar = QProgressBar(); self.bar.setMaximum(max(len(files),1))
        self.bar.setValue(0); layout.addWidget(self.bar)
        self.lbl_count = QLabel(f"0 / {len(files)}")
        self.lbl_count.setObjectName("muted"); layout.addWidget(self.lbl_count)
        btn_cancel = QPushButton("Cancel"); btn_cancel.setFixedWidth(90)
        btn_cancel.clicked.connect(self._cancel)
        hb = QHBoxLayout(); hb.addStretch(); hb.addWidget(btn_cancel)
        layout.addLayout(hb)

    def run(self) -> List[Document]:
        self._worker = ImportWorker(self.files)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_done)
        self._worker.start()
        self.exec()
        return self.results

    def _on_progress(self, i: int, name: str):
        self.lbl_file.setText(name or "…")
        self.bar.setValue(min(i+1, self.bar.maximum()))
        self.lbl_count.setText(f"{i+1} / {len(self.files)}")

    def _on_done(self, docs: list):
        self.results = docs; self.accept()

    def _cancel(self):
        if self._worker: self._worker.cancel()
        self.reject()


# ══════════════════════════════════════════════════════════════════════════════
# Document List  (QTableWidget — sortable, alternating rows)
# ══════════════════════════════════════════════════════════════════════════════
COLS = ["DocID","Filename","Category","Size","Modified","Custodian","Bates","Tags","Notes"]
COL_WIDTHS = [72, 240, 90, 68, 125, 105, 115, 185, 170]

class DocTableWidget(QTableWidget):
    doc_selected  = pyqtSignal(object)   # Document
    doc_activated = pyqtSignal(object)   # Document (double-click)

    def __init__(self, parent=None):
        super().__init__(0, len(COLS), parent)
        self._docs: List[Document] = []
        self.setHorizontalHeaderLabels(COLS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setShowGrid(False)
        self.horizontalHeader().setHighlightSections(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setSortingEnabled(True)
        hdr = self.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS): hdr.resizeSection(i, w)
        hdr.setStretchLastSection(True)
        self.itemSelectionChanged.connect(self._on_selection)
        self.cellDoubleClicked.connect(self._on_double)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def populate(self, docs: List[Document]):
        self._docs = docs
        self.setSortingEnabled(False)
        self.setRowCount(0); self.setRowCount(len(docs))
        for r, doc in enumerate(docs):
            bates = doc.bates_begin
            if doc.bates_end and doc.bates_end != doc.bates_begin:
                bates += f"–{doc.bates_end}"
            vals = [doc.doc_id, doc.filename, doc.category(), doc.size_str(),
                    doc.modified, doc.custodian, bates,
                    ", ".join(doc.tags), doc.notes[:60]]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                item.setData(Qt.ItemDataRole.UserRole, doc)
                # Colour by tag
                if "Hot" in doc.tags: item.setForeground(QColor(C_TAG_HOT))
                elif "Privileged" in doc.tags: item.setForeground(QColor(C_TAG_PRIV))
                elif "Produced" in doc.tags: item.setForeground(QColor(C_ACCENT))
                self.setItem(r, c, item)
        self.setSortingEnabled(True)

    def get_focused_doc(self) -> Optional[Document]:
        row = self.currentRow()
        if 0 <= row < self.rowCount():
            item = self.item(row, 0)
            if item: return item.data(Qt.ItemDataRole.UserRole)
        return None

    def get_selected_docs(self) -> List[Document]:
        seen = set(); docs = []
        for item in self.selectedItems():
            doc = item.data(Qt.ItemDataRole.UserRole)
            if doc and id(doc) not in seen:
                seen.add(id(doc)); docs.append(doc)
        return docs

    def _on_selection(self):
        doc = self.get_focused_doc()
        if doc: self.doc_selected.emit(doc)

    def _on_double(self, row, _col):
        item = self.item(row, 0)
        if item:
            doc = item.data(Qt.ItemDataRole.UserRole)
            if doc: self.doc_activated.emit(doc)


# ══════════════════════════════════════════════════════════════════════════════
# Rich Document Viewer  — PDF native, email reading pane, spreadsheet grid
# ══════════════════════════════════════════════════════════════════════════════
class ViewerPanel(QWidget):
    """
    Tab layout:
      0  Content    — text for TXT/DOCX/PPTX/EML/MSG/ZIP
      1  PDF        — native page-image rendering (pypdfium2)
      2  Spreadsheet— QTableWidget for XLSX/CSV (merged cells, trimmed)
      3  Image      — zoomable QPixmap
      4  Email List — PST/MBOX container: message list + reading pane
      5  Metadata   — file/format properties
      6  Notes      — free-text per document
    """
    tag_edited = pyqtSignal(object)

    TAB_CONTENT = 0
    TAB_PDF     = 1
    TAB_SHEET   = 2
    TAB_IMAGE   = 3
    TAB_EMAIL   = 4
    TAB_META    = 5
    TAB_NOTES   = 6

    def __init__(self, parent=None):
        super().__init__(parent)
        self._doc: Optional[Document] = None
        self._email_msgs: List[dict] = []
        self._zoom_pct = 100
        self._orig_pixmap: Optional[QPixmap] = None
        self._pdf_doc = None           # pypdfium2 document handle
        self._pdf_page_idx = 0
        self._pdf_zoom = 1.5           # render scale (72dpi * 1.5 ≈ 108dpi)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── header bar ──────────────────────────────────────────────────────
        hdr = QFrame(); hdr.setObjectName("list_header"); hdr.setFixedHeight(38)
        hb = QHBoxLayout(hdr); hb.setContentsMargins(10, 0, 8, 0); hb.setSpacing(6)
        self.lbl_title = QLabel("No document selected")
        self.lbl_title.setObjectName("doc_title")
        hb.addWidget(self.lbl_title, 1)
        for label, slot in (("⚙ Meta", "_go_meta"), ("🔖 Tag", "_go_tag"), ("📋 Copy", "_go_copy")):
            b = QPushButton(label); b.setFixedHeight(26); b.setFixedWidth(78)
            b.clicked.connect(getattr(self, slot)); hb.addWidget(b)
        layout.addWidget(hdr)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        # ── Tab 0: Content (plain text) ──────────────────────────────────────
        self.txt_content = QPlainTextEdit()
        self.txt_content.setReadOnly(True)
        self.txt_content.setFont(QFont("Menlo, Consolas, Courier New", 10))
        self.tabs.addTab(self.txt_content, "Content")

        # ── Tab 1: PDF native viewer ─────────────────────────────────────────
        pdf_w = QWidget()
        pdf_v = QVBoxLayout(pdf_w); pdf_v.setContentsMargins(0, 0, 0, 0); pdf_v.setSpacing(0)
        # PDF toolbar
        pdf_bar = QWidget(); pdf_bar.setFixedHeight(36)
        pb = QHBoxLayout(pdf_bar); pb.setContentsMargins(8, 0, 8, 0); pb.setSpacing(4)
        self.btn_pdf_prev = QPushButton("◀ Prev"); self.btn_pdf_prev.setFixedSize(72, 26)
        self.btn_pdf_next = QPushButton("Next ▶"); self.btn_pdf_next.setFixedSize(72, 26)
        self.btn_pdf_prev.clicked.connect(self._pdf_prev)
        self.btn_pdf_next.clicked.connect(self._pdf_next)
        self.btn_pdf_zi = QPushButton("🔍+"); self.btn_pdf_zi.setFixedSize(46, 26)
        self.btn_pdf_zo = QPushButton("🔍−"); self.btn_pdf_zo.setFixedSize(46, 26)
        self.btn_pdf_zi.clicked.connect(self._pdf_zoom_in)
        self.btn_pdf_zo.clicked.connect(self._pdf_zoom_out)
        self.lbl_pdf_page = QLabel("Page 0 / 0"); self.lbl_pdf_page.setObjectName("muted")
        self.lbl_pdf_zoom = QLabel("150%");       self.lbl_pdf_zoom.setObjectName("muted")
        for w in (self.btn_pdf_prev, self.btn_pdf_next, self.btn_pdf_zi,
                  self.btn_pdf_zo, self.lbl_pdf_page, self.lbl_pdf_zoom):
            pb.addWidget(w)
        pb.addStretch()
        pdf_v.addWidget(pdf_bar)
        self.pdf_scroll = QScrollArea()
        self.pdf_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pdf_scroll.setWidgetResizable(False)
        self.lbl_pdf_img = QLabel(); self.lbl_pdf_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_pdf_img.setStyleSheet(f"background:{C_PANEL_BG};")
        self.pdf_scroll.setWidget(self.lbl_pdf_img)
        pdf_v.addWidget(self.pdf_scroll, 1)
        self.tabs.addTab(pdf_w, "PDF")

        # ── Tab 2: Spreadsheet ───────────────────────────────────────────────
        sheet_w = QWidget()
        sv = QVBoxLayout(sheet_w); sv.setContentsMargins(0, 0, 0, 0); sv.setSpacing(0)
        sh_bar = QWidget(); sh_bar.setFixedHeight(34)
        sh_hb = QHBoxLayout(sh_bar); sh_hb.setContentsMargins(8, 0, 8, 0)
        sh_lbl = QLabel("Sheet:"); sh_hb.addWidget(sh_lbl)
        self.cbo_sheet = QComboBox(); self.cbo_sheet.setMinimumWidth(200)
        self.cbo_sheet.currentTextChanged.connect(self._on_sheet_change)
        sh_hb.addWidget(self.cbo_sheet)
        self.lbl_sheet_info = QLabel(""); self.lbl_sheet_info.setObjectName("muted")
        sh_hb.addWidget(self.lbl_sheet_info); sh_hb.addStretch()
        sv.addWidget(sh_bar)
        self.sheet_tbl = QTableWidget(0, 0)
        self.sheet_tbl.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive)
        self.sheet_tbl.horizontalHeader().setDefaultSectionSize(80)
        self.sheet_tbl.setAlternatingRowColors(True)
        self.sheet_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sheet_tbl.setShowGrid(True)
        sv.addWidget(self.sheet_tbl, 1)
        self.tabs.addTab(sheet_w, "Spreadsheet")

        # ── Tab 3: Image viewer ──────────────────────────────────────────────
        img_w = QWidget()
        iv = QVBoxLayout(img_w); iv.setContentsMargins(0, 0, 0, 0); iv.setSpacing(0)
        zoom_bar = QWidget(); zoom_bar.setFixedHeight(36)
        zb = QHBoxLayout(zoom_bar); zb.setContentsMargins(8, 0, 8, 0); zb.setSpacing(4)
        for lbl, fn in (("🔍 +", "_zoom_in"), ("🔍 −", "_zoom_out"), ("⤢ Fit", "_zoom_fit")):
            b = QPushButton(lbl); b.setFixedSize(62, 26)
            b.clicked.connect(getattr(self, fn)); zb.addWidget(b)
        self.lbl_zoom = QLabel("100%"); self.lbl_zoom.setObjectName("muted")
        zb.addWidget(self.lbl_zoom); zb.addStretch()
        iv.addWidget(zoom_bar)
        self.img_scroll = QScrollArea()
        self.img_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.img_scroll.setWidgetResizable(False)
        self.lbl_img = QLabel(); self.lbl_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.img_scroll.setWidget(self.lbl_img)
        iv.addWidget(self.img_scroll, 1)
        self.tabs.addTab(img_w, "Image")

        # ── Tab 4: Email List (PST / MBOX containers + .eml / .msg reading) ──
        email_w = QWidget()
        ev = QVBoxLayout(email_w); ev.setContentsMargins(0, 0, 0, 0); ev.setSpacing(0)
        # Info bar
        self.lbl_email_info = QLabel(""); self.lbl_email_info.setObjectName("muted")
        self.lbl_email_info.setContentsMargins(8, 4, 8, 0)
        ev.addWidget(self.lbl_email_info)
        ep_split = QSplitter(Qt.Orientation.Horizontal)
        ep_split.setChildrenCollapsible(False)
        # Message list
        self.email_tbl = QTableWidget(0, 4)
        self.email_tbl.setHorizontalHeaderLabels(["Subject", "From", "Date", "Attachments"])
        self.email_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.email_tbl.setColumnWidth(1, 160); self.email_tbl.setColumnWidth(2, 130)
        self.email_tbl.setColumnWidth(3, 90)
        self.email_tbl.setAlternatingRowColors(True)
        self.email_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.email_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.email_tbl.setShowGrid(False)
        self.email_tbl.verticalHeader().setVisible(False)
        self.email_tbl.verticalHeader().setDefaultSectionSize(22)
        self.email_tbl.itemSelectionChanged.connect(self._on_email_select)
        # Reading pane
        reading_w = QWidget()
        rv = QVBoxLayout(reading_w); rv.setContentsMargins(0, 0, 0, 0); rv.setSpacing(0)
        # Header fields (From/To/Subject/Date/Attachments)
        self.email_header_box = QFrame()
        self.email_header_box.setStyleSheet(
            f"background:{C_HEADER_BG}; border-bottom:1px solid {C_BORDER};")
        ehb = QFormLayout(self.email_header_box)
        ehb.setContentsMargins(10, 6, 10, 6); ehb.setSpacing(3)
        def _hdr_lbl(t):
            l = QLabel(t); l.setStyleSheet(f"color:{C_TEXT_MUTED}; font-weight:600;"); return l
        self.lbl_eml_subject = QLabel(""); self.lbl_eml_subject.setWordWrap(True)
        self.lbl_eml_from    = QLabel(""); self.lbl_eml_to = QLabel("")
        self.lbl_eml_date    = QLabel(""); self.lbl_eml_atts = QLabel("")
        for lbl, w in (("Subject:", self.lbl_eml_subject), ("From:", self.lbl_eml_from),
                        ("To:", self.lbl_eml_to), ("Date:", self.lbl_eml_date),
                        ("Attachments:", self.lbl_eml_atts)):
            ehb.addRow(_hdr_lbl(lbl), w)
        rv.addWidget(self.email_header_box)
        self.email_body = QPlainTextEdit(); self.email_body.setReadOnly(True)
        self.email_body.setFont(QFont("Menlo, Consolas, Courier New", 10))
        rv.addWidget(self.email_body, 1)
        ep_split.addWidget(self.email_tbl)
        ep_split.addWidget(reading_w)
        ep_split.setSizes([500, 420])
        ev.addWidget(ep_split, 1)
        self.tabs.addTab(email_w, "Email")

        # ── Tab 5: Metadata ──────────────────────────────────────────────────
        self.meta_tbl = QTableWidget(0, 2)
        self.meta_tbl.setHorizontalHeaderLabels(["Property", "Value"])
        self.meta_tbl.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self.meta_tbl.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.meta_tbl.setAlternatingRowColors(True)
        self.meta_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.meta_tbl.verticalHeader().setVisible(False)
        self.tabs.addTab(self.meta_tbl, "Metadata")

        # ── Tab 6: Notes ─────────────────────────────────────────────────────
        self.txt_notes = QPlainTextEdit()
        self.txt_notes.textChanged.connect(self._notes_changed)
        self.tabs.addTab(self.txt_notes, "Notes")

    # ── Load dispatcher ───────────────────────────────────────────────────────
    def load_document(self, doc: Document):
        self._doc = doc
        self.lbl_title.setText(f"  {doc.filename}   [{doc.doc_id}]")
        ext = doc.ext

        if ext == ".pdf":
            if HAS_PDFIUM:
                self._load_pdf(doc.path)
                self.tabs.setCurrentIndex(self.TAB_PDF)
            else:
                self.txt_content.setPlainText(doc.extract_text()[:500_000])
                self.tabs.setCurrentIndex(self.TAB_CONTENT)

        elif ext in (".xlsx", ".xls", ".csv", ".ods"):
            self._load_sheet(doc)
            self.tabs.setCurrentIndex(self.TAB_SHEET)

        elif ext in (".jpg", ".jpeg", ".png", ".bmp",
                     ".tiff", ".tif", ".gif", ".webp"):
            self._load_image(doc.path)
            self.tabs.setCurrentIndex(self.TAB_IMAGE)

        elif ext in (".pst", ".mbox") and not doc.is_virtual:
            # Container: show message list tab
            self._load_email_container(doc)
            self.tabs.setCurrentIndex(self.TAB_EMAIL)

        elif ext in (".eml", ".msg") or (doc.is_virtual and doc.email_subject):
            # Single email: show in reading pane directly
            self._show_single_email(doc)
            self.tabs.setCurrentIndex(self.TAB_EMAIL)

        else:
            self.txt_content.setPlainText(doc.extract_text()[:500_000])
            self.tabs.setCurrentIndex(self.TAB_CONTENT)

        self._populate_meta(doc.extract_metadata())
        self.txt_notes.blockSignals(True)
        self.txt_notes.setPlainText(doc.notes)
        self.txt_notes.blockSignals(False)

    # ── PDF native rendering ──────────────────────────────────────────────────
    def _load_pdf(self, path: str):
        """Render PDF pages as images using pypdfium2."""
        try:
            if self._pdf_doc is not None:
                try: self._pdf_doc.close()
                except Exception: pass
            self._pdf_doc = pdfium.PdfDocument(path)
            self._pdf_page_idx = 0
            self._render_pdf_page()
        except Exception as e:
            self.lbl_pdf_img.setText(f"Cannot render PDF:\n{e}")
            self.lbl_pdf_page.setText("Error")

    def _render_pdf_page(self):
        if self._pdf_doc is None: return
        n = len(self._pdf_doc)
        if n == 0: return
        idx = max(0, min(self._pdf_page_idx, n - 1))
        self.lbl_pdf_page.setText(f"Page {idx + 1} / {n}")
        self.lbl_pdf_zoom.setText(f"{int(self._pdf_zoom * 100)}%")
        self.btn_pdf_prev.setEnabled(idx > 0)
        self.btn_pdf_next.setEnabled(idx < n - 1)
        try:
            page   = self._pdf_doc[idx]
            bitmap = page.render(scale=self._pdf_zoom, rotation=0)
            pil    = bitmap.to_pil().convert("RGB")
            data   = pil.tobytes()
            qimg   = QImage(data, pil.width, pil.height, pil.width * 3,
                            QImage.Format.Format_RGB888)
            pixmap = QPixmap.fromImage(qimg)
            self.lbl_pdf_img.setPixmap(pixmap)
            self.lbl_pdf_img.resize(pixmap.size())
        except Exception as e:
            self.lbl_pdf_img.setText(f"Render error page {idx+1}:\n{e}")

    def _pdf_prev(self):
        self._pdf_page_idx = max(0, self._pdf_page_idx - 1); self._render_pdf_page()
    def _pdf_next(self):
        if self._pdf_doc:
            self._pdf_page_idx = min(len(self._pdf_doc)-1, self._pdf_page_idx+1)
        self._render_pdf_page()
    def _pdf_zoom_in(self):
        self._pdf_zoom = min(self._pdf_zoom + 0.25, 4.0); self._render_pdf_page()
    def _pdf_zoom_out(self):
        self._pdf_zoom = max(self._pdf_zoom - 0.25, 0.5); self._render_pdf_page()

    # ── Image viewer ──────────────────────────────────────────────────────────
    def _load_image(self, path: str):
        try:
            self._orig_pixmap = QPixmap(path)
            if self._orig_pixmap.isNull(): raise ValueError("null pixmap")
            self._zoom_pct = 100; self._render_zoom()
        except Exception:
            self._orig_pixmap = None; self.lbl_img.setText("Cannot load image")

    def _render_zoom(self):
        if not self._orig_pixmap: return
        w = max(1, int(self._orig_pixmap.width()  * self._zoom_pct / 100))
        h = max(1, int(self._orig_pixmap.height() * self._zoom_pct / 100))
        scaled = self._orig_pixmap.scaled(w, h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        self.lbl_img.setPixmap(scaled); self.lbl_img.resize(scaled.size())
        self.lbl_zoom.setText(f"{self._zoom_pct}%")

    def _zoom_in(self):  self._zoom_pct = min(self._zoom_pct + 25, 400); self._render_zoom()
    def _zoom_out(self): self._zoom_pct = max(self._zoom_pct - 25, 25);  self._render_zoom()
    def _zoom_fit(self):
        if not self._orig_pixmap: return
        avail = self.img_scroll.viewport().size()
        iw, ih = self._orig_pixmap.width(), self._orig_pixmap.height()
        if iw and ih:
            self._zoom_pct = int(min(avail.width()/iw, avail.height()/ih) * 100)
            self._render_zoom()

    # ── Spreadsheet ───────────────────────────────────────────────────────────
    def _load_sheet(self, doc: Document):
        data = doc.load_sheet_data()
        if not data:
            self.txt_content.setPlainText(doc.extract_text()[:500_000])
            self.tabs.setCurrentIndex(self.TAB_CONTENT)
            return
        self._sheet_data = data
        self.cbo_sheet.blockSignals(True)
        self.cbo_sheet.clear()
        for name in data: self.cbo_sheet.addItem(name)
        self.cbo_sheet.blockSignals(False)
        first = list(data.keys())[0]
        self._render_sheet(first)

    def _render_sheet(self, sheet_name: str):
        rows = self._sheet_data.get(sheet_name, [])
        self.sheet_tbl.setUpdatesEnabled(False)
        self.sheet_tbl.setSortingEnabled(False)
        self.sheet_tbl.clearContents()
        self.sheet_tbl.setRowCount(0); self.sheet_tbl.setColumnCount(0)

        if not rows:
            self.sheet_tbl.setUpdatesEnabled(True); return

        max_cols = max((len(r) for r in rows), default=0)
        if not max_cols: self.sheet_tbl.setUpdatesEnabled(True); return

        self.sheet_tbl.setRowCount(len(rows))
        self.sheet_tbl.setColumnCount(max_cols)

        # Column headers: A, B, C … AA, AB …
        self.sheet_tbl.setHorizontalHeaderLabels(
            [_col_letter(c) for c in range(max_cols)])

        # Detect if row 0 looks like a header (non-empty strings)
        has_header = (rows and any(v and not v.lstrip('-').lstrip('+').replace('.','',1).isdigit()
                                   for v in rows[0] if v))

        for r, row in enumerate(rows):
            for c in range(max_cols):
                val = row[c] if c < len(row) else ""
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if r == 0 and has_header:
                    item.setForeground(QColor(C_ACCENT))
                    item.setBackground(QColor(C_HEADER_BG))
                    f = item.font(); f.setBold(True); item.setFont(f)
                self.sheet_tbl.setItem(r, c, item)

        self.sheet_tbl.resizeColumnsToContents()
        self.sheet_tbl.setSortingEnabled(True)
        self.sheet_tbl.setUpdatesEnabled(True)
        self.lbl_sheet_info.setText(f"{len(rows)} rows × {max_cols} cols")

    def _on_sheet_change(self, name: str):
        if name and hasattr(self, "_sheet_data"): self._render_sheet(name)

    # ── Email container (PST / MBOX) ──────────────────────────────────────────
    def _load_email_container(self, doc: Document):
        self._email_msgs = _extract_pst_messages(doc.path)
        n = len(self._email_msgs)
        self.lbl_email_info.setText(
            f"  {n:,} message{'s' if n != 1 else ''} in {doc.filename}  "
            f"{'  ⚠ Install pypff for real PST support' if doc.ext=='.pst' and not HAS_PST else ''}")
        self.email_tbl.setUpdatesEnabled(False)
        self.email_tbl.setRowCount(0)
        for i, m in enumerate(self._email_msgs):
            self.email_tbl.insertRow(i)
            atts = m.get("attachments", [])
            att_str = f"📎 {len(atts)}" if atts else ""
            for c, val in enumerate([m.get("subject","")[:100],
                                      m.get("sender","")[:50],
                                      m.get("date","")[:22],
                                      att_str]):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.email_tbl.setItem(i, c, item)
        self.email_tbl.setUpdatesEnabled(True)
        # Clear reading pane
        self._clear_email_reading_pane()
        if n == 0:
            self.email_body.setPlainText(
                "No messages found.\n\n"
                "For .pst files: install pypff (pip install pypff2)\n"
                "For .mbox files: the file may be empty or use an unsupported format.")

    def _show_single_email(self, doc: Document):
        """Show a single EML/MSG/virtual email in the reading pane directly."""
        self.lbl_email_info.setText(f"  Single message: {doc.filename}")
        self.email_tbl.setRowCount(0)
        # Populate reading pane
        if doc.is_virtual:
            d = {"subject": doc.email_subject, "sender": doc.email_from,
                 "recipients": doc.email_to, "date": doc.email_date,
                 "body": doc.text_cache or "", "attachments": doc.attachments}
        elif doc.ext == ".eml":
            try:
                with open(doc.path, "rb") as f: raw = f.read()
                d = _parse_single_eml_bytes(raw)
            except Exception as e:
                d = {"subject": doc.filename, "sender": "", "recipients": "",
                     "date": "", "body": f"Error reading EML:\n{e}", "attachments": []}
        elif doc.ext == ".msg" and HAS_MSG:
            try:
                m = extract_msg.Message(doc.path)
                d = {"subject": m.subject or "", "sender": m.sender or "",
                     "recipients": m.to or "", "date": str(m.date or ""),
                     "body": m.body or m.htmlBody or "",
                     "attachments": [a.longFilename or a.shortFilename or ""
                                     for a in (m.attachments or [])]}
            except Exception as e:
                d = {"subject": doc.filename, "sender": "", "recipients": "",
                     "date": "", "body": f"Error reading MSG:\n{e}", "attachments": []}
        else:
            d = {"subject": doc.filename, "sender": "", "recipients": "",
                 "date": doc.modified, "body": doc.extract_text(), "attachments": []}
        self._fill_email_reading_pane(d)

    def _clear_email_reading_pane(self):
        for lbl in (self.lbl_eml_subject, self.lbl_eml_from, self.lbl_eml_to,
                    self.lbl_eml_date, self.lbl_eml_atts):
            lbl.setText("")
        self.email_body.clear()

    def _fill_email_reading_pane(self, m: dict):
        self.lbl_eml_subject.setText(m.get("subject", ""))
        self.lbl_eml_from.setText(m.get("sender", ""))
        self.lbl_eml_to.setText(m.get("recipients", ""))
        self.lbl_eml_date.setText(m.get("date", ""))
        atts = m.get("attachments", [])
        self.lbl_eml_atts.setText(", ".join(a for a in atts if a) if atts else "None")
        #self.email_body.setPlainText(m.get("body", ""))

        self.email_body = QTextEdit()
        self.email_body.setReadOnly(True)
        #self.email_body = QWebEngineView()



        body = m.get("body", "")

        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")
        #self.email_body.setHtml(body)
        # Detect HTML vs plain text

        self.email_body.setPlainText(body)
        '''
        if is_html(body):
            body = clean_html(body)
            self.email_body.setHtml(body)
        else:
            self.email_body.setPlainText(body)

        '''
    def _on_email_select(self):
        row = self.email_tbl.currentRow()
        if 0 <= row < len(self._email_msgs):
            self._fill_email_reading_pane(self._email_msgs[row])

    # ── Metadata ──────────────────────────────────────────────────────────────
    def _populate_meta(self, meta: dict):
        self.meta_tbl.setUpdatesEnabled(False)
        self.meta_tbl.setRowCount(0)
        for r, (k, v) in enumerate(meta.items()):
            self.meta_tbl.insertRow(r)
            ki = QTableWidgetItem(str(k))
            ki.setForeground(QColor(C_TEXT_MUTED))
            ki.setFlags(ki.flags() & ~Qt.ItemFlag.ItemIsEditable)
            vi = QTableWidgetItem(str(v))
            vi.setFlags(vi.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.meta_tbl.setItem(r, 0, ki); self.meta_tbl.setItem(r, 1, vi)
        self.meta_tbl.setUpdatesEnabled(True)

    # ── Header buttons ────────────────────────────────────────────────────────
    def _go_meta(self):  self.tabs.setCurrentIndex(self.TAB_META)
    def _go_tag(self):
        if not self._doc: return
        dlg = TagEditorDlg(self, self._doc)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            tags, cust, notes = dlg.get_values()
            self._doc.tags = tags; self._doc.custodian = cust; self._doc.notes = notes
            self.txt_notes.blockSignals(True)
            self.txt_notes.setPlainText(notes)
            self.txt_notes.blockSignals(False)
            self.tag_edited.emit(self._doc)
    def _go_copy(self):
        if self._doc: QApplication.clipboard().setText(self._doc.extract_text())
    def _notes_changed(self):
        if self._doc: self._doc.notes = self.txt_notes.toPlainText()


# ══════════════════════════════════════════════════════════════════════════════
# Search / Filter sidebar
# ══════════════════════════════════════════════════════════════════════════════
class SearchSidebar(QFrame):
    search_requested = pyqtSignal(str, str)   # query, field
    clear_requested  = pyqtSignal()
    tag_filter       = pyqtSignal(list)        # List[str]
    cat_filter       = pyqtSignal(str)         # category or ""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(230)
        layout = QVBoxLayout(self); layout.setContentsMargins(10,10,10,10); layout.setSpacing(6)

        hdr = QLabel("🔍  SEARCH & FILTER"); hdr.setObjectName("header")
        layout.addWidget(hdr)

        self.txt_query = QLineEdit(); self.txt_query.setPlaceholderText("Search… (Enter)")
        self.txt_query.returnPressed.connect(self._on_search)
        layout.addWidget(self.txt_query)

        self.cbo_field = QComboBox()
        self.cbo_field.addItems(["Full Text (indexed)","Filename","Custodian","Tags","Bates","Notes","Email Subject"])
        layout.addWidget(self.cbo_field)

        btn_search = QPushButton("Search"); btn_search.setObjectName("accent")
        btn_search.clicked.connect(self._on_search); layout.addWidget(btn_search)
        btn_clear = QPushButton("Clear / Show All")
        btn_clear.clicked.connect(self._on_clear); layout.addWidget(btn_clear)

        self.lbl_idx = QLabel("⏳ Index: not built"); self.lbl_idx.setObjectName("muted")
        layout.addWidget(self.lbl_idx)

        layout.addWidget(self._hline())
        layout.addWidget(QLabel("Filter by Tag:"))
        self.tag_checks: Dict[str, QCheckBox] = {}
        for tag in REVIEW_TAGS:
            cb = QCheckBox(tag)
            color = TAG_COLORS.get(tag, C_TEXT_MUTED)
            cb.setStyleSheet(f"color: {color};")
            self.tag_checks[tag] = cb; layout.addWidget(cb)
        btn_tag = QPushButton("Apply Tag Filter"); btn_tag.clicked.connect(self._on_tag)
        layout.addWidget(btn_tag)

        layout.addWidget(self._hline())
        layout.addWidget(QLabel("Filter by Category:"))
        self.cbo_cat = QComboBox()
        self.cbo_cat.addItems(["All"] + list(SUPPORTED_EXTS.keys()) + ["Other"])
        layout.addWidget(self.cbo_cat)
        btn_cat = QPushButton("Apply Category"); btn_cat.clicked.connect(self._on_cat)
        layout.addWidget(btn_cat)
        layout.addStretch()

    def _hline(self) -> QFrame:
        f = QFrame(); f.setFrameShape(QFrame.Shape.HLine); f.setStyleSheet(f"color: {C_BORDER};")
        return f

    def set_index_status(self, msg: str, ready: bool):
        icon = "✅" if ready else "⏳"
        self.lbl_idx.setText(f"{icon} Index: {msg}")
        self.lbl_idx.setStyleSheet(f"color: {'#2EA043' if ready else C_TEXT_MUTED}; font-size: 11px;")

    def _on_search(self):
        fields = ["fulltext","filename","custodian","tags","bates","notes","subject"]
        self.search_requested.emit(self.txt_query.text().strip(),
                                   fields[self.cbo_field.currentIndex()])
    def _on_clear(self):
        self.txt_query.clear(); self.clear_requested.emit()
    def _on_tag(self):
        self.tag_filter.emit([t for t, cb in self.tag_checks.items() if cb.isChecked()])
    def _on_cat(self):
        cat = self.cbo_cat.currentText()
        self.cat_filter.emit("" if cat == "All" else cat)


# ══════════════════════════════════════════════════════════════════════════════
# Small dialogs
# ══════════════════════════════════════════════════════════════════════════════
class TagEditorDlg(QDialog):
    def __init__(self, parent, doc: Document):
        super().__init__(parent)
        self.setWindowTitle(f"Edit Tags — {doc.filename}")
        self.setMinimumWidth(440); self.setMinimumHeight(480)
        layout = QVBoxLayout(self); layout.setSpacing(8)

        layout.addWidget(QLabel("Review Tags:"))
        self._checks: Dict[str, QCheckBox] = {}
        for tag in REVIEW_TAGS:
            cb = QCheckBox(tag)
            cb.setChecked(tag in doc.tags)
            color = TAG_COLORS.get(tag, C_TEXT)
            cb.setStyleSheet(f"color: {color};")
            self._checks[tag] = cb; layout.addWidget(cb)

        form = QFormLayout(); form.setSpacing(6)
        self.txt_cust = QLineEdit(doc.custodian); form.addRow("Custodian:", self.txt_cust)
        self.txt_notes = QTextEdit(doc.notes); self.txt_notes.setFixedHeight(70)
        form.addRow("Notes:", self.txt_notes)
        layout.addLayout(form)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Save |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def get_values(self):
        return ([t for t, cb in self._checks.items() if cb.isChecked()],
                self.txt_cust.text(), self.txt_notes.toPlainText())


class BatesDlg(QDialog):
    def __init__(self, parent, prefix="DOC", start=1):
        super().__init__(parent); self.setWindowTitle("Assign Bates Numbers"); self.setFixedSize(360, 175)
        form = QFormLayout(self); form.setSpacing(10)
        self.t_prefix = QLineEdit(prefix); form.addRow("Prefix:", self.t_prefix)
        self.t_start  = QLineEdit(str(start)); form.addRow("Start Number:", self.t_start)
        self.t_pad    = QLineEdit("6"); form.addRow("Padding (digits):", self.t_pad)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        form.addRow(btns)

    def get_values(self):
        return (self.t_prefix.text().strip(), int(self.t_start.text() or 1), int(self.t_pad.text() or 6))


class NewCaseDlg(QDialog):
    def __init__(self, parent):
        super().__init__(parent); self.setWindowTitle("New Case"); self.setFixedSize(480, 200)
        form = QFormLayout(self); form.setSpacing(10)
        self.t_name   = QLineEdit("My Case 2025"); form.addRow("Case Name:", self.t_name)
        row = QHBoxLayout()
        self.t_folder = QLineEdit(os.path.expanduser("~/eDiscovery"))
        btn_browse = QPushButton("Browse…"); btn_browse.setFixedWidth(80)
        btn_browse.clicked.connect(self._browse)
        row.addWidget(self.t_folder); row.addWidget(btn_browse); form.addRow("Case Folder:", row)
        self.t_bates  = QLineEdit("DOC"); form.addRow("Bates Prefix:", self.t_bates)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        form.addRow(btns)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Case Folder")
        if d: self.t_folder.setText(d)

    def get_values(self): return self.t_name.text().strip(), self.t_folder.text().strip(), self.t_bates.text().strip()


class ProductionDlg(QDialog):
    def __init__(self, parent, doc_count: int):
        super().__init__(parent); self.setWindowTitle(f"Production Wizard ({doc_count} documents)")
        self.setMinimumWidth(500); layout = QVBoxLayout(self); layout.setSpacing(10)
        form = QFormLayout(); form.setSpacing(8)
        row = QHBoxLayout()
        self.t_out = QLineEdit(os.path.expanduser("~/eDiscovery/Production"))
        btn_br = QPushButton("Browse…"); btn_br.setFixedWidth(80); btn_br.clicked.connect(self._browse)
        row.addWidget(self.t_out); row.addWidget(btn_br); form.addRow("Output Folder:", row)
        layout.addLayout(form)
        grp = QGroupBox("Production Format"); grp_layout = QVBoxLayout(grp)
        self.rdo_group = QButtonGroup(self)
        for i, lbl in enumerate(["Native + Load File (CSV)","Native Only","Text Extracts (.txt)"]):
            rb = QRadioButton(lbl); self.rdo_group.addButton(rb, i)
            if i == 0: rb.setChecked(True)
            grp_layout.addWidget(rb)
        layout.addWidget(grp)
        self.chk_bates = QCheckBox("Assign Bates if not set");    self.chk_bates.setChecked(True)
        self.chk_hash  = QCheckBox("Include MD5 in load file");   self.chk_hash.setChecked(True)
        self.chk_mark  = QCheckBox("Mark documents as Produced"); self.chk_mark.setChecked(True)
        for ck in (self.chk_bates, self.chk_hash, self.chk_mark): layout.addWidget(ck)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        ok_btn = btns.button(QDialogButtonBox.StandardButton.Ok)
        ok_btn.setText("Produce"); ok_btn.setObjectName("success")
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Output Folder")
        if d: self.t_out.setText(d)

    def get_values(self) -> dict:
        return {"output_dir": self.t_out.text(), "format": self.rdo_group.checkedId(),
                "assign_bates": self.chk_bates.isChecked(), "include_hash": self.chk_hash.isChecked(),
                "mark_produced": self.chk_mark.isChecked()}


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard & Audit panels
# ══════════════════════════════════════════════════════════════════════════════
class DashboardPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        title = QLabel("Case Dashboard")
        title.setFont(QFont("", 14, QFont.Weight.Bold)); layout.addWidget(title)
        self.txt = QPlainTextEdit(); self.txt.setReadOnly(True)
        self.txt.setFont(QFont("Menlo, Consolas, Courier New", 11))
        layout.addWidget(self.txt, 1)

    def refresh(self, case: Optional[Case] = None):
        if not case: self.txt.setPlainText("No case loaded."); return
        s = case.stats(); total = s["total"] or 1; sz = s["total_size"] / 1024 / 1024
        def bar(v, t, w=26): f = int(w*v/t) if t else 0; return "█"*f + "░"*(w-f)
        lines = [f"  CASE: {case.name}", "  " + "─"*54,
                 f"  Total Documents : {s['total']:>8,}",
                 f"  Total Size      : {sz:>8.1f} MB",
                 f"  Reviewed        : {s['reviewed']:>8,}  ({100*s['reviewed']//total:>3}%)",
                 f"  Produced        : {s['produced']:>8,}  ({100*s['produced']//total:>3}%)",
                 f"  Index Built     : {'Yes' if s['indexed'] else 'No (Tools → Build Index)'}",
                 "", "  BY CATEGORY"]
        for cat, cnt in sorted(s["by_category"].items(), key=lambda x: -x[1]):
            lines.append(f"  {cat:<16} {cnt:>6,}  {bar(cnt,total)}  {100*cnt//total:>3}%")
        if s["by_tag"]:
            lines += ["", "  BY TAG"]
            for tag, cnt in sorted(s["by_tag"].items(), key=lambda x: -x[1]):
                lines.append(f"  {tag:<16} {cnt:>6,}  {bar(cnt,total)}  {100*cnt//total:>3}%")
        lines += ["", f"  CUSTODIANS: {', '.join(case.custodians) or 'None'}"]
        self.txt.setPlainText("\n".join(lines))


class AuditPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.txt = QPlainTextEdit(); self.txt.setReadOnly(True)
        self.txt.setFont(QFont("Menlo, Consolas, Courier New", 9))
        self.txt.setStyleSheet(f"color: {C_TEXT_MUTED};")
        layout.addWidget(self.txt, 1)

    def refresh(self, case: Optional[Case] = None):
        self.txt.setPlainText("\n".join(reversed(case.audit_log[-500:])) if case else "")


# ══════════════════════════════════════════════════════════════════════════════
# Main Window
# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.case: Optional[Case] = None
        self._all_docs: List[Document] = []
        self._view_docs: List[Document] = []
        self._case_file: str = ""
        self._index_worker: Optional[IndexWorker] = None
        self._first_show = True

        self.setWindowTitle(APP_NAME)
        self.resize(1400, 860)
        self.setMinimumSize(900, 600)

        self._build_menus()
        self._build_toolbar()
        self._build_ui()
        self._build_statusbar()
        self.showMaximized()

    def showEvent(self, event):
        super().showEvent(event)
        if self._first_show:
            self._first_show = False
            QTimer.singleShot(0, self._equalise_split)

    def _equalise_split(self):
        total = self.sp_right.width()
        if total > 20:
            self.sp_right.setSizes([total // 2, total - total // 2])

    # ── Menus ─────────────────────────────────────────────────────────────────
    def _build_menus(self):
        mb = self.menuBar()

        # File
        fm = mb.addMenu("&File")
        self._add_action(fm, "&New Case…",      "Ctrl+N", self._on_new_case)
        self._add_action(fm, "&Open Case…",     "Ctrl+O", self._on_open_case)
        self._add_action(fm, "&Save",           "Ctrl+S", self._on_save_case)
        self._add_action(fm, "Save &As…",       "",       self._on_saveas_case)
        fm.addSeparator()
        self._add_action(fm, "Import &Files…",  "Ctrl+I",        self._on_import_files)
        self._add_action(fm, "Import &Folder…", "Ctrl+Shift+I",  self._on_import_folder)
        self._add_action(fm, "Import PST/MBOX…","",              self._on_import_pst)
        fm.addSeparator()
        self._add_action(fm, "E&xit",           "Alt+F4",        self.close)

        # Edit
        em = mb.addMenu("&Edit")
        self._add_action(em, "Select &All",          "Ctrl+A",   self._on_select_all)
        self._add_action(em, "&Remove Selected",     "Del",       self._on_remove_sel)
        em.addSeparator()
        self._add_action(em, "&Tag Selected…",       "Ctrl+T",   self._on_tag_selected)
        self._add_action(em, "Assign &Bates…",       "Ctrl+B",   self._on_bates)
        self._add_action(em, "Set &Custodian…",      "Ctrl+U",   self._on_set_custodian)
        em.addSeparator()
        self._add_action(em, "&Deduplicate (MD5)…",  "",         self._on_deduplicate)

        # Review
        rm = mb.addMenu("&Review")
        for tag, key in (("Hot","F5"),("Relevant","F6"),("Not Relevant","F7"),("Privileged","F8"),
                         ("Needs Review",""),("Hold","")):
            self._add_action(rm, f"Mark {tag}", key, lambda _, t=tag: self._quick_tag(t))

        # Produce
        pm = mb.addMenu("&Produce")
        self._add_action(pm, "&Produce Selected…",   "Ctrl+P",  self._on_produce)
        self._add_action(pm, "Export Load File (CSV)…","",      self._on_export_csv)
        self._add_action(pm, "Export Metadata (JSON)…","",      self._on_export_json)
        pm.addSeparator()
        self._add_action(pm, "Generate &Status Report…","",     self._on_status_report)

        # Tools
        tm = mb.addMenu("&Tools")
        self._add_action(tm, "&Build / Rebuild Index", "Ctrl+R", self._on_build_index)
        self._add_action(tm, "Compute All Hashes",     "",       self._on_hash_all)
        self._add_action(tm, "Re-extract All Text",    "",       self._on_reindex)
        self._add_action(tm, "View Audit Log",         "",       self._on_view_audit)

        # Help
        hm = mb.addMenu("&Help")
        self._add_action(hm, "&About", "", self._on_about)

    def _add_action(self, menu: QMenu, label: str, shortcut: str, slot) -> QAction:
        act = QAction(label, self)
        if shortcut: act.setShortcut(QKeySequence(shortcut))
        act.triggered.connect(slot)
        menu.addAction(act); return act

    # ── Toolbar ───────────────────────────────────────────────────────────────
    def _build_toolbar(self):
        tb = self.addToolBar("Main"); tb.setMovable(False); tb.setIconSize(QSize(18,18))
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        style = self.style()
        for label, slot, icon_name in (
            ("New",     self._on_new_case,      "document-new"),
            ("Open",    self._on_open_case,     "document-open"),
            ("Save",    self._on_save_case,     "document-save"),
            (None,None,None),
            ("Import",  self._on_import_files,  "list-add"),
            ("Folder",  self._on_import_folder, "folder-open"),
            (None,None,None),
            ("Index",   self._on_build_index,   "system-search"),
            ("Produce", self._on_produce,       "document-send"),
            ("Export",  self._on_export_csv,    "document-save-as"),
        ):
            if label is None: tb.addSeparator(); continue
            act = QAction(label, self)
            icon = QIcon.fromTheme(icon_name)
            if not icon.isNull(): act.setIcon(icon)
            act.triggered.connect(slot); tb.addAction(act)

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = self.statusBar()
        self.lbl_status  = QLabel("Ready"); sb.addWidget(self.lbl_status, 1)
        self.lbl_count   = QLabel("");      sb.addPermanentWidget(self.lbl_count)
        self.lbl_case    = QLabel("");      sb.addPermanentWidget(self.lbl_case)
        self.lbl_idx_sb  = QLabel("");      sb.addPermanentWidget(self.lbl_idx_sb)

    def _set_status(self, msg: str, shown: int = None, total: int = None, idx: str = ""):
        self.lbl_status.setText(msg)
        if shown is not None: self.lbl_count.setText(f"  Showing {shown:,} of {total:,}  ")
        self.lbl_case.setText(f"  Case: {self.case.name}  " if self.case else "")
        if idx: self.lbl_idx_sb.setText(f"  {idx}  ")

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        main_h = QHBoxLayout(central); main_h.setContentsMargins(0,0,0,0); main_h.setSpacing(0)

        # Left sidebar
        self.sidebar = SearchSidebar()
        self.sidebar.search_requested.connect(self._do_search)
        self.sidebar.clear_requested.connect(self._do_clear)
        self.sidebar.tag_filter.connect(self._do_tag_filter)
        self.sidebar.cat_filter.connect(self._do_cat_filter)
        main_h.addWidget(self.sidebar)

        # Right: list + viewer
        right_w = QWidget(); right_layout = QVBoxLayout(right_w)
        right_layout.setContentsMargins(0,0,0,0); right_layout.setSpacing(0)

        # List header
        list_hdr = QFrame(); list_hdr.setObjectName("list_header"); list_hdr.setFixedHeight(36)
        hh = QHBoxLayout(list_hdr); hh.setContentsMargins(10,0,8,0); hh.setSpacing(6)
        self.lbl_doc_count = QLabel("Documents"); self.lbl_doc_count.setObjectName("header")
        hh.addWidget(self.lbl_doc_count, 1)
        for tag in ("Hot","Relevant","Not Relevant","Privileged"):
            b = QPushButton(tag); b.setFixedHeight(24); b.setFixedWidth(100)
            color = TAG_COLORS.get(tag, C_ACCENT)
            b.setStyleSheet(f"background:{color}; color:white; border-color:{color}; font-size:11px;")
            b.clicked.connect(lambda _, t=tag: self._quick_tag(t)); hh.addWidget(b)

        # Main horizontal splitter: list | viewer
        self.sp_right = QSplitter(Qt.Orientation.Horizontal)
        self.sp_right.setChildrenCollapsible(False)
        self.sp_right.setHandleWidth(4)

        # Document list
        list_container = QWidget()
        lc_layout = QVBoxLayout(list_container); lc_layout.setContentsMargins(0,0,0,0); lc_layout.setSpacing(0)
        lc_layout.addWidget(list_hdr)
        self.doc_table = DocTableWidget()
        self.doc_table.doc_selected.connect(self._on_doc_selected)
        self.doc_table.doc_activated.connect(self._on_doc_activated)
        self.doc_table.customContextMenuRequested.connect(self._on_doc_rclick)
        lc_layout.addWidget(self.doc_table, 1)
        self.sp_right.addWidget(list_container)

        # Right notebook (viewer / dashboard / audit)
        self.nb_right = QTabWidget()
        self.viewer    = ViewerPanel()
        self.viewer.tag_edited.connect(lambda _: self._refresh_list(self._view_docs))
        self.dashboard = DashboardPanel()
        self.audit_pnl = AuditPanel()
        self.nb_right.addTab(self.viewer,    "Document Viewer")
        self.nb_right.addTab(self.dashboard, "Dashboard")
        self.nb_right.addTab(self.audit_pnl, "Audit Log")
        self.sp_right.addWidget(self.nb_right)
        self.sp_right.setSizes([580, 580])

        right_layout.addWidget(self.sp_right, 1)
        main_h.addWidget(right_w, 1)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _require_case(self) -> bool:
        if not self.case:
            QMessageBox.information(self, "No Case", "Please create or open a case first.")
            return False
        return True

    def _refresh_list(self, docs: Optional[List[Document]] = None):
        if docs is None: docs = self._all_docs
        self._view_docs = docs
        self.doc_table.populate(docs)
        n, t = len(docs), len(self._all_docs)
        self.lbl_doc_count.setText(f"Documents: {n:,}" + (f"  (filtered from {t:,})" if n < t else ""))
        self._set_status(f"{n:,} documents", n, t)

    def _refresh_dashboard(self):
        self.dashboard.refresh(self.case)
        self.audit_pnl.refresh(self.case)

    def _start_index(self):
        if not self.case or not self.case.documents: return
        self._index_worker = IndexWorker(self.case.documents)
        self._index_worker.finished.connect(self._on_index_done)
        self._index_worker.start()
        self.sidebar.set_index_status("building…", False)
        self._set_status("Building search index…")

    def _on_index_done(self, idx: SearchIndex):
        if self.case:
            self.case.set_index(idx); n = idx.doc_count
            self.sidebar.set_index_status(f"{n:,} docs indexed", True)
            self._set_status(f"Index ready — {n:,} documents indexed",
                             len(self._view_docs), len(self._all_docs),
                             f"Index: {n:,}")
            self._refresh_dashboard()

    # ── Case management ───────────────────────────────────────────────────────
    def _on_new_case(self):
        dlg = NewCaseDlg(self)
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        name, folder, bates = dlg.get_values()
        if not name or not folder: return
        os.makedirs(folder, exist_ok=True)
        self.case = Case(name, folder); self.case.bates_prefix = bates or "DOC"
        self._all_docs = []; self._case_file = os.path.join(folder, f"{name}.edpro")
        self._refresh_list(); self._refresh_dashboard()
        self.setWindowTitle(f"{APP_NAME} — {name}"); self._set_status(f"New case: {name}")

    def _on_open_case(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Case", "",
                                               "eDiscovery Pro (*.edpro);;All (*)")
        if not path: return
        try:
            self.case = Case.load(path); self._all_docs = self.case.documents
            self._case_file = path; self._refresh_list(); self._refresh_dashboard()
            self.setWindowTitle(f"{APP_NAME} — {self.case.name}")
            self._set_status(f"Opened: {self.case.name}  ({len(self._all_docs):,} docs)")
            self._start_index()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Cannot open case:\n{e}")

    def _on_save_case(self):
        if not self._require_case(): return
        if not self._case_file: self._on_saveas_case(); return
        try: self.case.save(self._case_file); self._set_status(f"Saved: {self._case_file}")
        except Exception as e: QMessageBox.critical(self, "Error", f"Save failed:\n{e}")

    def _on_saveas_case(self):
        if not self._require_case(): return
        path, _ = QFileDialog.getSaveFileName(self, "Save Case As", f"{self.case.name}.edpro",
                                               "eDiscovery Pro (*.edpro)")
        if path: self._case_file = path; self._on_save_case()

    # ── Import ────────────────────────────────────────────────────────────────
    def _on_import_files(self):
        if not self._require_case(): return
        ext_filter = "All Supported (" + " ".join(f"*{e}" for e in ALL_EXTS) + ");;All (*)"
        paths, _ = QFileDialog.getOpenFileNames(self, "Import Files", "", ext_filter)
        if paths: self._do_import(paths)

    def _on_import_folder(self):
        if not self._require_case(): return
        folder = QFileDialog.getExistingDirectory(self, "Import Folder (recursive)")
        if not folder: return
        files = [os.path.join(r, fn) for r, _, fns in os.walk(folder)
                 for fn in fns if Path(fn).suffix.lower() in ALL_EXTS]
        if files: self._do_import(files)
        else: QMessageBox.information(self, "Nothing to import",
                                       f"No supported files found in:\n{folder}")

    def _on_import_pst(self):
        if not self._require_case(): return
        paths, _ = QFileDialog.getOpenFileNames(self, "Import PST/MBOX", "",
                                                "Mail Archives (*.pst *.mbox);;All (*)")
        if paths: self._do_import(paths)

    def _do_import(self, paths: List[str]):
        dlg = ImportProgressDlg(self, paths)
        docs = dlg.run()
        if not docs: return
        default_cust = self.case.custodians[0] if self.case.custodians else ""
        for doc in docs:
            if not doc.custodian and default_cust: doc.custodian = default_cust
            self.case.add_document(doc)
        self._all_docs = self.case.documents
        self._refresh_list(); self._refresh_dashboard()
        self._set_status(f"Imported {len(docs):,} documents  (total: {len(self._all_docs):,})")
        self._start_index()

    # ── List events ───────────────────────────────────────────────────────────
    def _on_doc_selected(self, doc: Document):
        self.viewer.load_document(doc); self.nb_right.setCurrentIndex(0)

    def _on_doc_activated(self, doc: Document):
        if doc.is_virtual or not os.path.exists(doc.path): return
        try:
            import subprocess
            if   sys.platform == "darwin":          subprocess.Popen(["open",  doc.path])
            elif sys.platform.startswith("win"):    os.startfile(doc.path)
            else:                                   subprocess.Popen(["xdg-open", doc.path])
        except Exception as e: QMessageBox.warning(self, "Error", f"Cannot open:\n{e}")

    def _on_doc_rclick(self, pos):
        doc = self.doc_table.get_focused_doc()
        if not doc: return
        menu = QMenu(self)
        menu.addAction("🔖 Tag / Edit…",      self._on_tag_selected)
        menu.addAction("📂 Open in OS",        lambda: self._on_doc_activated(doc))
        menu.addAction("🔑 Assign Bates…",    self._on_bates)
        menu.addAction("🗑 Remove from Case", self._on_remove_sel)
        menu.addSeparator()
        for tag in ("Hot","Relevant","Not Relevant","Privileged"):
            menu.addAction(f"✅ Mark {tag}", lambda _, t=tag: self._quick_tag(t))
        menu.addSeparator()
        menu.addAction("📦 Produce…", self._on_produce)
        menu.exec(self.doc_table.viewport().mapToGlobal(pos))

    # ── Edit ──────────────────────────────────────────────────────────────────
    def _on_select_all(self): self.doc_table.selectAll()

    def _on_remove_sel(self):
        if not self._require_case(): return
        docs = self.doc_table.get_selected_docs()
        if not docs: return
        if QMessageBox.question(self, "Confirm", f"Remove {len(docs)} document(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        for doc in docs: self.case.remove_document(doc.doc_id)
        self._all_docs = self.case.documents; self._refresh_list(); self._refresh_dashboard()

    def _on_tag_selected(self):
        if not self._require_case(): return
        docs = self.doc_table.get_selected_docs()
        if not docs:
            doc = self.doc_table.get_focused_doc()
            if doc: docs = [doc]
        if not docs: return
        dlg = TagEditorDlg(self, docs[0])
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        tags, cust, notes = dlg.get_values()
        for doc in docs:
            doc.tags = tags; doc.custodian = cust or doc.custodian
            if len(docs) == 1: doc.notes = notes
            doc.reviewed_by = "User"; doc.date_reviewed = datetime.datetime.now().strftime("%Y-%m-%d")
        self.case.log(f"Tagged {len(docs)} doc(s): {', '.join(tags)}")
        self._refresh_list(self._view_docs); self._refresh_dashboard()

    def _quick_tag(self, tag: str):
        if not self._require_case(): return
        docs = self.doc_table.get_selected_docs()
        if not docs:
            doc = self.doc_table.get_focused_doc()
            if doc: docs = [doc]
        for doc in docs:
            if tag not in doc.tags: doc.tags.append(tag)
            doc.reviewed_by = "User"; doc.date_reviewed = datetime.datetime.now().strftime("%Y-%m-%d")
        if docs:
            self.case.log(f"Quick-tagged {len(docs)} → {tag}")
            self._refresh_list(self._view_docs); self._refresh_dashboard()

    def _on_bates(self):
        if not self._require_case(): return
        docs = self.doc_table.get_selected_docs() or self._view_docs
        if not docs: return
        dlg = BatesDlg(self, self.case.bates_prefix, self.case.bates_counter)
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        prefix, start, pad = dlg.get_values()
        self.case.assign_bates(docs, prefix, start, pad); self._refresh_list(self._view_docs)

    def _on_set_custodian(self):
        if not self._require_case(): return
        docs = self.doc_table.get_selected_docs()
        if not docs: return
        cust, ok = QInputDialog.getText(self, "Set Custodian", "Custodian name:")
        if not ok or not cust: return
        for doc in docs: doc.custodian = cust.strip()
        if cust not in self.case.custodians: self.case.custodians.append(cust)
        self.case.log(f"Set custodian '{cust}' on {len(docs)} doc(s)")
        self._refresh_list(self._view_docs)

    def _on_deduplicate(self):
        if not self._require_case(): return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        for doc in self.case.documents:
            if not doc.md5 and not doc.is_virtual: doc.compute_hashes()
        QApplication.restoreOverrideCursor()
        seen: Dict[str,str] = {}; dupes = []
        for doc in self.case.documents:
            if not doc.md5: continue
            if doc.md5 in seen: dupes.append(doc)
            else: seen[doc.md5] = doc.doc_id
        if not dupes:
            QMessageBox.information(self, "Deduplicate", "No duplicates found."); return
        if QMessageBox.question(self, "Deduplicate", f"Found {len(dupes)} duplicate(s). Remove?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            for doc in dupes: self.case.remove_document(doc.doc_id)
            self._all_docs = self.case.documents; self._refresh_list(); self._refresh_dashboard()

    # ── Search / filter ───────────────────────────────────────────────────────
    def _do_search(self, query: str, field: str):
        if not self.case or not query: self._refresh_list(); return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        results = self.case.search(query, field)
        QApplication.restoreOverrideCursor()
        self._refresh_list(results)
        note = " (index)" if field == "fulltext" and self.case._index else ""
        self._set_status(f"Search '{query}' [{field}]{note}: {len(results):,} result(s)")

    def _do_clear(self): self._refresh_list()

    def _do_tag_filter(self, tags: List[str]):
        if not self.case: return
        if not tags: self._refresh_list(); return
        self._refresh_list([d for d in self.case.documents if any(t in d.tags for t in tags)])

    def _do_cat_filter(self, cat: str):
        if not self.case: return
        if not cat: self._refresh_list(); return
        self._refresh_list([d for d in self.case.documents if d.category() == cat])

    # ── Production ────────────────────────────────────────────────────────────
    def _on_produce(self):
        if not self._require_case(): return
        docs = self.doc_table.get_selected_docs() or self._view_docs
        if not docs:
            QMessageBox.information(self, "Produce", "No documents to produce."); return
        dlg = ProductionDlg(self, len(docs))
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        opts = dlg.get_values(); out = opts["output_dir"]
        nat = os.path.join(out, "NATIVE"); txt = os.path.join(out, "TEXT")
        os.makedirs(out, exist_ok=True)
        if opts["assign_bates"]:
            no_b = [d for d in docs if not d.bates_begin]
            if no_b: self.case.assign_bates(no_b)
        rows, errs = [], []
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            for doc in docs:
                try:
                    bn = (doc.bates_begin or doc.doc_id) + doc.ext; fmt = opts["format"]
                    if fmt in (0,1) and not doc.is_virtual:
                        os.makedirs(nat, exist_ok=True); shutil.copy2(doc.path, os.path.join(nat, bn))
                    if fmt in (0,2):
                        os.makedirs(txt, exist_ok=True)
                        with open(os.path.join(txt, (doc.bates_begin or doc.doc_id)+".txt"),"w",encoding="utf-8") as f:
                            f.write(doc.extract_text())
                    if opts["mark_produced"]:
                        doc.is_produced = True
                        if "Produced" not in doc.tags: doc.tags.append("Produced")
                    row = {"BatesBegin":doc.bates_begin,"BatesEnd":doc.bates_end,"Filename":doc.filename,
                           "DocID":doc.doc_id,"Custodian":doc.custodian,"Modified":doc.modified,
                           "Extension":doc.ext,"Tags":"|".join(doc.tags),"Notes":doc.notes}
                    if opts["include_hash"]:
                        if not doc.md5 and not doc.is_virtual: doc.compute_hashes()
                        row["MD5"] = doc.md5
                    rows.append(row)
                except Exception as e: errs.append(f"{doc.filename}: {e}")
            if rows:
                with open(os.path.join(out,"LOAD_FILE.csv"),"w",newline="",encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                    w.writeheader(); w.writerows(rows)
        finally: QApplication.restoreOverrideCursor()
        self.case.log(f"Produced {len(rows)} docs → {out}")
        self._refresh_list(self._view_docs); self._refresh_dashboard()
        msg = f"Production complete!\n{len(rows):,} documents → {out}"
        if errs: msg += f"\n\n{len(errs)} error(s):\n" + "\n".join(errs[:10])
        QMessageBox.information(self, "Production Complete", msg)

    # ── Export ────────────────────────────────────────────────────────────────
    def _on_export_csv(self):
        if not self._require_case(): return
        path, _ = QFileDialog.getSaveFileName(self, "Export Load File", "load_file.csv", "CSV (*.csv)")
        if not path: return
        docs = self._view_docs or self.case.documents
        fields = ["DocID","Filename","Extension","Category","Size","Modified","Custodian",
                  "BatesBegin","BatesEnd","Tags","Notes","MD5","SHA256","Produced","Reviewed",
                  "EmailSubject","EmailFrom","EmailDate"]
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
            for d in docs:
                w.writerow({"DocID":d.doc_id,"Filename":d.filename,"Extension":d.ext,
                            "Category":d.category(),"Size":d.size_str(),"Modified":d.modified,
                            "Custodian":d.custodian,"BatesBegin":d.bates_begin,"BatesEnd":d.bates_end,
                            "Tags":"|".join(d.tags),"Notes":d.notes,"MD5":d.md5,"SHA256":d.sha256,
                            "Produced":"Yes" if d.is_produced else "No","Reviewed":d.reviewed_by,
                            "EmailSubject":d.email_subject,"EmailFrom":d.email_from,"EmailDate":d.email_date})
        self.case.log(f"Exported CSV: {path}")
        QMessageBox.information(self, "Export Complete", f"Exported {len(docs):,} rows to:\n{path}")

    def _on_export_json(self):
        if not self._require_case(): return
        path, _ = QFileDialog.getSaveFileName(self, "Export Metadata JSON", "metadata.json", "JSON (*.json)")
        if not path: return
        docs = self._view_docs or self.case.documents
        with open(path,"w",encoding="utf-8") as f: json.dump([d.to_dict() for d in docs], f, indent=2)
        QMessageBox.information(self, "Export Complete", f"Exported {len(docs):,} records to:\n{path}")

    def _on_status_report(self):
        if not self._require_case(): return
        path, _ = QFileDialog.getSaveFileName(self, "Save Status Report", "status_report.txt", "Text (*.txt)")
        if not path: return
        s = self.case.stats()
        lines = ["eDiscovery Pro v4.0 — Case Status Report",
                 f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 f"Case: {self.case.name}", "="*60,
                 f"Total: {s['total']:,}  Size: {s['total_size']/1024/1024:.2f} MB",
                 f"Reviewed: {s['reviewed']:,}  Produced: {s['produced']:,}", "", "By Category:"]
        for cat, cnt in sorted(s["by_category"].items(), key=lambda x: -x[1]):
            lines.append(f"  {cat:<20} {cnt:>6,}")
        lines += ["", "By Tag:"]
        for tag, cnt in sorted(s["by_tag"].items(), key=lambda x: -x[1]):
            lines.append(f"  {tag:<20} {cnt:>6,}")
        lines += ["", "Custodians:", "  " + ", ".join(self.case.custodians),
                  "", "Audit Log (last 50):", ""] + self.case.audit_log[-50:]
        with open(path,"w",encoding="utf-8") as f: f.write("\n".join(lines))
        QMessageBox.information(self, "Report Saved", f"Saved to:\n{path}")

    # ── Tools ─────────────────────────────────────────────────────────────────
    def _on_build_index(self):
        if not self._require_case(): return
        if not self.case.documents:
            QMessageBox.information(self, "Index", "No documents to index."); return
        self._start_index()

    def _on_hash_all(self):
        if not self._require_case(): return
        docs = [d for d in self.case.documents if not d.md5 and not d.is_virtual]
        if not docs:
            QMessageBox.information(self, "Hashes", "All docs already have hashes."); return
        dlg = ImportProgressDlg(self, [d.path for d in docs], "Computing Hashes…")
        worker = HashWorker(docs)
        worker.progress.connect(dlg._on_progress)
        worker.finished.connect(lambda: (dlg.accept(), self.case.log(f"Computed hashes for {len(docs)} docs"),
                                         self._set_status("Hash computation complete")))
        dlg._worker = worker; worker.start(); dlg.exec()

    def _on_reindex(self):
        if not self._require_case(): return
        for doc in self.case.documents: doc.text_cache = None
        self.case.log("Text cache cleared"); self._set_status("Text cache cleared")
        self._start_index()

    def _on_view_audit(self):
        if not self._require_case(): return
        self.nb_right.setCurrentIndex(2); self.audit_pnl.refresh(self.case)

    def _on_about(self):
        def c(f, n): return f"{n} ✓" if f else f"{n} ✗"
        QMessageBox.about(self, f"About {APP_NAME}",
            f"<b>{APP_NAME}  v{APP_VERSION}</b><br><br>"
            "Full-featured e-Discovery desktop tool<br>"
            "Inspired by Digital WarRoom Pro (DWR)<br>"
            "<b>Now using PyQt6</b><br><br>"
            "<b>New in v4.0:</b><br>"
            "• Converted from wxPython → PyQt6<br>"
            "• Dark theme via QSS stylesheet<br>"
            "• Resizable window, 50/50 equal split<br>"
            "• Rich format-specific viewer tabs<br>"
            "• PST/MBOX message extraction → records<br>"
            "• Inverted full-text search index<br><br>"
            "<b>Formats:</b> TXT · PDF · DOCX · XLSX · PPTX<br>"
            "EML · MSG · MBOX · PST · ZIP · TAR · Images<br><br>"
            "<b>Libraries:</b> " +
            " &nbsp; ".join([c(HAS_PDF,"pypdf"), c(HAS_DOCX,"docx"), c(HAS_PPTX,"pptx"),
                              c(HAS_XLSX,"openpyxl"), c(HAS_PIL,"Pillow"),
                              c(HAS_MSG,"extract-msg"), c(HAS_CHARDET,"chardet"),
                              c(HAS_PST,"pypff")]))


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(DARK_QSS)
    # High-DPI
    if hasattr(Qt.ApplicationAttribute, 'AA_UseHighDpiPixmaps'):
        app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)
    win = MainWindow()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()