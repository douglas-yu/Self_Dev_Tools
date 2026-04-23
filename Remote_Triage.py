"""
Remote Forensic Triage GUI (PyQt6) – SMB2 Version

Features:
- Connects to a remote Windows host using SMB2/3 on TCP 445 with hostname/IP and credentials.
- Uses the smbclient (smbprotocol) library for read-only triage:
  - List directories and files.
  - View file content (HEX, TXT, IMAGE tabs, truncated for preview).
  - Export files via "Save As..." to local storage.
- UI:
  - Left: folder tree (remote filesystem for a given share, e.g., C$).
  - Top-right: list of subfolders and files for selected folder, with extended metadata.
  - Bottom-right: content viewer with HEX/TXT/IMAGE tabs.

Dependencies:
    pip install PyQt6 smbclient

Notes:
- This prototype uses the Python smbclient wrapper, which speaks SMB2/3 (via smbprotocol) to
  remote Windows hosts.
- It assumes you have access to an admin or forensic share, e.g., C$, D$, or a special triage share.
- Paths inside the share are represented internally as POSIX-style paths ("/Windows/System32"),
  but all on-the-wire paths are proper UNC (e.g., "\\\\HOST\\C$\\Windows\\System32").
"""

import sys
import os
import socket
import datetime
from dataclasses import dataclass
from typing import List

from PyQt6.QtCore import (
    Qt,
    QPoint,
)
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QLabel,
    QMessageBox,
    QFileDialog,
    QMenu,
    QTabWidget,
    QScrollArea,
)
from PyQt6.QtGui import QAction
from PyQt6.QtGui import QPixmap

import smbclient


@dataclass
class RemoteEntry:
    name: str
    path: str        # path relative to the SMB share, e.g. "/Windows/System32"
    is_dir: bool
    size: int
    mtime: float | None
    ctime: float | None


class RemoteConnection:
    """
    SMB2-based remote connection for forensic triage.

    Wraps the smbclient library to:
    - connect to a given host/share over SMB2 on port 445
    - list directories
    - read and download files
    """

    def __init__(
        self,
        server_ip: str,
        username: str,
        password: str,
        share: str,
        domain: str = "",
        port: int = 445,
    ):
        self.server_ip = server_ip
        self.username = username
        self.password = password
        self.domain = domain or ""
        self.share = share.strip("\\/")  # e.g. "C$"
        self.port = port

        # For browsing we treat "/" as the root of the share.
        self.root_path = "/"

        self.connected = False

    def connect(self):
        """
        Establish SMB2/3 session using smbclient on TCP port 445.
        """
        # smbclient uses smbprotocol under the hood (SMB2/3).
        # Domain can be provided as part of username: DOMAIN\\user.
        if self.domain:
            full_user = f"{self.domain}\\{self.username}"
        else:
            full_user = self.username

        try:
            smbclient.register_session(
                server=self.server_ip,
                username=full_user,
                password=self.password,
                port=self.port,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to establish SMB2 session with {self.server_ip}: {e}") from e

        self.connected = True

    def close(self):
        """
        Clear SMB client connection cache (no per-session handle exposed).
        """
        try:
            smbclient.reset_connection_cache()
        except Exception:
            pass
        self.connected = False

    def _ensure_conn(self):
        if not self.connected:
            raise RuntimeError("Not connected to SMB2 server")

    def _to_unc(self, path: str) -> str:
        """
        Convert a share-relative POSIX-style path (e.g. "/Windows/System32")
        into a UNC path for smbclient, e.g. "\\\\SERVER\\C$\\Windows\\System32".
        """
        rel = path or "/"
        if not rel.startswith("/"):
            rel = "/" + rel
        # "/" -> ""
        rel = rel.lstrip("/")
        if rel:
            rel_win = rel.replace("/", "\\")
            return f"\\\\{self.server_ip}\\{self.share}\\{rel_win}"
        else:
            return f"\\\\{self.server_ip}\\{self.share}"

    @staticmethod
    def join(parent: str, name: str) -> str:
        """
        Join share-relative parent and name as POSIX-style path.
        """
        if not parent or parent == "/":
            return "/" + name
        if parent.endswith("/"):
            return parent + name
        return parent + "/" + name

    def listdir(self, path: str) -> List[RemoteEntry]:
        """
        List directory contents for 'path' relative to the share.
        Example paths: "/", "/Windows", "/Users/Public".
        """
        self._ensure_conn()

        smb_rel_path = path or self.root_path
        unc_dir = self._to_unc(smb_rel_path)

        try:
            entries_iter = smbclient.scandir(unc_dir)
        except Exception as e:
            raise RuntimeError(f"Error listing {smb_rel_path} on {unc_dir}: {e}") from e

        entries: List[RemoteEntry] = []

        for info in entries_iter:
            name = info.name
            if name in (".", ".."):
                continue

            # Some system files on C$ (e.g. dumpstack.log.tmp) can be locked
            # or otherwise inaccessible, causing sharing-violation errors when
            # smbclient tries to stat them. We catch and skip those entries so
            # that listing the directory still succeeds.
            try:
                is_dir = info.is_dir()
                stat_res = info.stat()
            except Exception:
                # Skip problematic entries we cannot query metadata for.
                continue

            size = int(getattr(stat_res, "st_size", 0))

            mtime = None
            ts = getattr(stat_res, "st_mtime", None)
            if ts is not None:
                try:
                    mtime = float(ts)
                except Exception:
                    mtime = None

            ctime = None
            ct = getattr(stat_res, "st_ctime", None)
            if ct is not None:
                try:
                    ctime = float(ct)
                except Exception:
                    ctime = None

            rel_path = self.join(smb_rel_path, name)

            entries.append(
                RemoteEntry(
                    name=name,
                    path=rel_path,
                    is_dir=is_dir,
                    size=size,
                    mtime=mtime,
                    ctime=ctime,
                )
            )

        # Sort: directories first, then files, both alphabetically
        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return entries

    def read_file(self, path: str, max_bytes: int = 1024 * 1024) -> bytes:
        """
        Read up to max_bytes from the given file.
        For large files, truncates to max_bytes for safe preview.
        """
        self._ensure_conn()
        unc_path = self._to_unc(path)

        try:
            with smbclient.open_file(unc_path, mode="rb") as f:
                data = f.read(max_bytes + 1)
        except Exception as e:
            raise RuntimeError(f"Error reading {unc_path}: {e}") from e

        if len(data) > max_bytes:
            return data[:max_bytes]
        return data

    def download_file(self, remote_path: str, local_path: str):
        """
        Download remote_path from the share to local_path.
        """
        self._ensure_conn()
        unc_path = self._to_unc(remote_path)

        try:
            with smbclient.open_file(unc_path, mode="rb") as rf, open(local_path, "wb") as lf:
                while True:
                    chunk = rf.read(1024 * 1024)
                    if not chunk:
                        break
                    lf.write(chunk)
        except Exception as e:
            raise RuntimeError(f"Error downloading {unc_path} to {local_path}: {e}") from e


class ConnectDialog(QDialog):
    """
    Dialog to collect SMB2 connection parameters:
    - Host / IP
    - Domain (optional)
    - Username
    - Password
    - Share (e.g., C$)
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to Remote Host (SMB2)")

        self.host_edit = QLineEdit()
        self.domain_edit = QLineEdit()
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.share_edit = QLineEdit()
        self.share_edit.setPlaceholderText("e.g., C$")

        form = QFormLayout()
        form.addRow("Host / IP:", self.host_edit)
        form.addRow("Domain (optional):", self.domain_edit)
        form.addRow("Username:", self.user_edit)
        form.addRow("Password:", self.pass_edit)
        form.addRow("Share:", self.share_edit)

        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: red;")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(self.status_label)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def get_params(self):
        host = self.host_edit.text().strip()
        domain = self.domain_edit.text().strip()
        user = self.user_edit.text().strip()
        pwd = self.pass_edit.text()
        share = self.share_edit.text().strip()
        return host, domain, user, pwd, share


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Remote Forensic Triage (SMB2, PyQt6 Prototype)")
        self.resize(1200, 800)

        self.conn: RemoteConnection | None = None

        # Left: tree view for folders
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Remote Folders")
        self.tree.itemExpanded.connect(self.on_tree_item_expanded)
        self.tree.currentItemChanged.connect(self.on_tree_item_selected)

        # Top-right: table list for subfolders and files with extended metadata
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels(
            ["Name", "Size", "Modified", "Created", "Type", "Path"]
        )
        self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.on_file_table_context_menu)
        self.file_table.doubleClicked.connect(self.on_file_double_clicked)

        # Bottom-right: content view with HEX/TXT/IMAGE tabs
        self.tab_widget = QTabWidget()

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)

        self.txt_view = QTextEdit()
        self.txt_view.setReadOnly(True)

        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        image_container = QScrollArea()
        image_container.setWidgetResizable(True)
        image_container.setWidget(self.image_label)

        self.tab_widget.addTab(self.hex_view, "HEX")
        self.tab_widget.addTab(self.txt_view, "TXT")
        self.tab_widget.addTab(image_container, "IMAGE")

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.addWidget(self.file_table)
        right_splitter.addWidget(self.tab_widget)
        right_splitter.setSizes([400, 400])

        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.addWidget(self.tree)
        main_splitter.addWidget(right_splitter)
        main_splitter.setSizes([300, 900])

        central = QWidget()
        layout = QHBoxLayout()
        layout.addWidget(main_splitter)
        central.setLayout(layout)
        self.setCentralWidget(central)

        self._create_menu()
        # No auto-connect on startup; user connects via File -> Connect...

    def _create_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")

        connect_action = QAction("Connect...", self)
        connect_action.triggered.connect(self.connect_to_host)
        file_menu.addAction(connect_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def connect_to_host(self):
        dlg = ConnectDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        host, domain, user, pwd, share = dlg.get_params()
        if not host or not user or not share:
            QMessageBox.warning(self, "Missing data", "Host, username, and share are required.")
            return

        # Close any existing connection
        if self.conn:
            self.conn.close()
            self.conn = None

        self.statusBar().showMessage(
            f"Connecting to SMB2 {host}:445 share {share} as {user}..."
        )
        try:
            self.conn = RemoteConnection(
                server_ip=host,
                username=user,
                password=pwd,
                share=share,
                domain=domain,
                port=445,
            )
            self.conn.connect()
        except Exception as e:
            QMessageBox.critical(self, "Connection failed", str(e))
            self.statusBar().clearMessage()
            self.conn = None
            return

        self.statusBar().showMessage(f"Connected to {host} share {share}", 5000)
        self.populate_root(host, share)

    def populate_root(self, host: str, share: str):
        if not self.conn:
            return

        self.tree.clear()
        # Display something like: \\HOST\C$
        display_root = f"\\\\{host}\\{share}"
        root_path = self.conn.root_path  # "/" inside share
        root_item = QTreeWidgetItem([display_root])
        root_item.setData(0, Qt.ItemDataRole.UserRole, root_path)
        root_item.setChildIndicatorPolicy(QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)
        self.tree.addTopLevelItem(root_item)
        self.tree.expandItem(root_item)

    # ---- Tree handling -------------------------------------------------

    def on_tree_item_expanded(self, item: QTreeWidgetItem):
        if not self.conn:
            return

        # Populate children only once
        if item.childCount() > 0:
            return

        path = item.data(0, Qt.ItemDataRole.UserRole)
        try:
            entries = self.conn.listdir(path)
        except Exception as e:
            QMessageBox.warning(self, "Error listing directory", f"{path}\n\n{e}")
            return

        for entry in entries:
            if not entry.is_dir:
                continue
            child = QTreeWidgetItem([entry.name])
            child.setData(0, Qt.ItemDataRole.UserRole, entry.path)
            child.setChildIndicatorPolicy(QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)
            item.addChild(child)

    def on_tree_item_selected(self, current: QTreeWidgetItem, _previous: QTreeWidgetItem):
        if not self.conn or not current:
            return
        path = current.data(0, Qt.ItemDataRole.UserRole)
        self.load_directory_to_table(path)

    # ---- File table handling -------------------------------------------

    def load_directory_to_table(self, path: str):
        if not self.conn:
            return

        try:
            entries = self.conn.listdir(path)
        except Exception as e:
            QMessageBox.warning(self, "Error listing directory", f"{path}\n\n{e}")
            return

        self.file_table.setRowCount(0)

        for entry in entries:
            row = self.file_table.rowCount()
            self.file_table.insertRow(row)

            # Name (store share-relative path in UserRole)
            name_item = QTableWidgetItem(entry.name)
            name_item.setData(Qt.ItemDataRole.UserRole, entry.path)
            self.file_table.setItem(row, 0, name_item)

            # Size
            size_str = "-" if entry.is_dir else f"{entry.size}"
            size_item = QTableWidgetItem(size_str)
            size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.file_table.setItem(row, 1, size_item)

            # Modified
            if entry.mtime is not None:
                try:
                    dt_m = datetime.datetime.fromtimestamp(entry.mtime)
                    mtime_str = dt_m.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    mtime_str = "-"
            else:
                mtime_str = "-"
            mtime_item = QTableWidgetItem(mtime_str)
            self.file_table.setItem(row, 2, mtime_item)

            # Created
            if entry.ctime is not None:
                try:
                    dt_c = datetime.datetime.fromtimestamp(entry.ctime)
                    ctime_str = dt_c.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    ctime_str = "-"
            else:
                ctime_str = "-"
            ctime_item = QTableWidgetItem(ctime_str)
            self.file_table.setItem(row, 3, ctime_item)

            # Type
            type_str = "Directory" if entry.is_dir else "File"
            type_item = QTableWidgetItem(type_str)
            self.file_table.setItem(row, 4, type_item)

            # Path
            path_item = QTableWidgetItem(entry.path)
            self.file_table.setItem(row, 5, path_item)

        self.file_table.resizeColumnsToContents()
        self.statusBar().showMessage(f"Listing {path} ({len(entries)} entries)", 5000)

    def get_selected_file_path(self) -> str | None:
        selected = self.file_table.selectedItems()
        if not selected:
            return None
        row = selected[0].row()
        type_item = self.file_table.item(row, 4)  # Type column
        if type_item and type_item.text() == "Directory":
            return None
        name_item = self.file_table.item(row, 0)
        if not name_item:
            return None
        remote_path = name_item.data(Qt.ItemDataRole.UserRole)
        return remote_path

    def on_file_double_clicked(self, index):
        """
        Double-click behavior:
        - If row is a directory: open that directory in the list view.
        - If row is a file: view its content in the HEX/TXT/IMAGE tabs.
        """
        if not index.isValid():
            return
        row = index.row()
        type_item = self.file_table.item(row, 4)  # Type column
        if not type_item:
            return

        if type_item.text() == "Directory":
            name_item = self.file_table.item(row, 0)
            if not name_item:
                return
            path = name_item.data(Qt.ItemDataRole.UserRole)
            if path:
                self.load_directory_to_table(path)
        else:
            remote_path = self.get_selected_file_path()
            if remote_path:
                self.view_file_content(remote_path)

    def on_file_table_context_menu(self, pos: QPoint):
        remote_path = self.get_selected_file_path()
        if not remote_path:
            return

        menu = QMenu(self)
        save_action = QAction("Save As...", self)
        save_action.triggered.connect(lambda: self.save_file_as(remote_path))
        view_action = QAction("View Content", self)
        view_action.triggered.connect(lambda: self.view_file_content(remote_path))

        menu.addAction(view_action)
        menu.addSeparator()
        menu.addAction(save_action)

        global_pos = self.file_table.viewport().mapToGlobal(pos)
        menu.exec(global_pos)

    def save_file_as(self, remote_path: str):
        if not self.conn:
            return

        filename = os.path.basename(remote_path.strip("/"))
        local_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Remote File As",
            filename,
        )
        if not local_path:
            return

        try:
            self.conn.download_file(remote_path, local_path)
        except Exception as e:
            QMessageBox.critical(self, "Download failed", f"{remote_path}\n\n{e}")
            return

        self.statusBar().showMessage(f"Saved {remote_path} to {local_path}", 5000)

    def view_file_content(self, remote_path: str):
        if not self.conn:
            return
        try:
            data = self.conn.read_file(remote_path)
        except Exception as e:
            QMessageBox.critical(self, "Read failed", f"{remote_path}\n\n{e}")
            return

        # Clear previous content
        self.hex_view.clear()
        self.txt_view.clear()
        self.image_label.clear()

        # HEX view
        hex_lines = []
        width = 16
        for i in range(0, len(data), width):
            chunk = data[i : i + width]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{i:08X}  {hex_bytes:<47}  {ascii_part}")
        self.hex_view.setPlainText("\n".join(hex_lines))

        # TXT view
        default_tab = 0  # fallback to HEX
        try:
            text = data.decode("utf-8")
            self.txt_view.setPlainText(text)
            default_tab = 1  # TXT
        except UnicodeDecodeError:
            self.txt_view.setPlainText("[Not valid UTF-8 text]")

        # IMAGE view
        lower_name = remote_path.lower()
        if any(lower_name.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff"]):
            pixmap = QPixmap()
            if pixmap.loadFromData(data):
                self.image_label.setPixmap(pixmap)
            else:
                self.image_label.setText("Failed to decode image data.")
        else:
            self.image_label.setText("Not an image file.")

        # Select default tab (TXT if available, else HEX)
        self.tab_widget.setCurrentIndex(default_tab)

        self.statusBar().showMessage(f"Viewed {remote_path}", 5000)


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()


