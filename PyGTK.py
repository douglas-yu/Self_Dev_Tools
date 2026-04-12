import sys
import os
import shutil
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QSplitter, QTreeView,
    QTableView, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget, QHeaderView, QLabel, QMenu, QFileDialog, QMessageBox, QHBoxLayout
)
from PyQt6.QtGui import QFileSystemModel, QPixmap, QAction, QFont
from PyQt6.QtCore import Qt, QDir, QPoint


class ForensicsApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # 1. macOS Specific Window Flags for Custom Title Bar
        # We make it frameless to hide the standard OS title bar.
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        self.setWindowTitle("macOS Forensic Navigator")
        self.resize(1200, 850)  # Increased height slightly to account for title bar

        # Variables to handle window dragging since we are frameless
        self._old_pos = None

        # --- Base Layout (Vertical: Title Bar + Content) ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.base_layout = QVBoxLayout(central_widget)
        self.base_layout.setContentsMargins(0, 0, 0, 0)  # No padding around main container
        self.base_layout.setSpacing(0)

        # ---------------------------------------------------------
        # 2. Custom Title Bar Implementation
        # ---------------------------------------------------------
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(50)
        # Background: Light Grey
        self.title_bar.setStyleSheet("background-color: #DCDCDC; border-bottom: 1px solid #B0B0B0;")

        # Title Bar Layout (Horizontal)
        self.title_layout = QHBoxLayout(self.title_bar)
        self.title_layout.setContentsMargins(10, 0, 10, 0)

        # Right-side Window Controls (Mimicking macOS style/position slightly)
        self.close_button = QLabel("✕")
        self.close_button.setStyleSheet("color: #404040; font-weight: bold; font-size: 16px; margin-right: 10px;")
        self.close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_button.mousePressEvent = lambda e: self.close()

        # The Center Text: 'PyGTK for MacOS' (Requests PyGTK, but this is PyQt6 code)
        self.title_label = QLabel("PyGTK for MacOS")
        title_font = QFont("Helvetica Neue", 18)  # Bigger font, macOS style
        title_font.setWeight(QFont.Weight.Bold)
        self.title_label.setFont(title_font)
        self.title_label.setStyleSheet("color: #333333;")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Spacer to keep text truly centered
        dummy_spacer = QLabel("✕")
        dummy_spacer.setStyleSheet("color: transparent; font-size: 16px; margin-right: 10px;")

        # Assembly of Title Bar
        self.title_layout.addWidget(self.close_button)  # Controls on left
        self.title_layout.addStretch()  # Push title to center
        self.title_layout.addWidget(self.title_label)
        self.title_layout.addStretch()  # Push title to center
        self.title_layout.addWidget(dummy_spacer)  # Spacer on right to balance center

        # Add Title Bar to Base Layout
        self.base_layout.addWidget(self.title_bar)

        # ---------------------------------------------------------
        # 3. Rest of FTK-style GUI (Modified to fit Base Layout)
        # ---------------------------------------------------------
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.base_layout.addWidget(self.content_widget)

        # 3a. Setup Model
        self.model = QFileSystemModel()
        root_path = QDir.rootPath()
        self.model.setRootPath(root_path)

        # 3b. Main Layout (Horizontal Splitter)
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel: Tree View
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(root_path))
        for i in range(1, 4): self.tree.setColumnHidden(i, True)
        self.tree.header().hide()

        # Right Panel: Vertical Splitter
        self.right_splitter = QSplitter(Qt.Orientation.Vertical)

        # Top Right: File List
        self.file_table = QTableView()
        self.file_table.setModel(self.model)
        self.file_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        

        # Bottom Right: Tabs
        self.tabs = QTabWidget()
        self.text_view = QTextEdit(readOnly=True)
        self.hex_view = QTextEdit(readOnly=True)
        self.hex_view.setFontFamily("Courier")
        self.image_view = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)

        self.tabs.addTab(self.text_view, "Text")
        self.tabs.addTab(self.hex_view, "Hex")
        self.tabs.addTab(self.image_view, "Image")

        # Assembly of Content
        self.right_splitter.addWidget(self.file_table)
        self.right_splitter.addWidget(self.tabs)
        self.main_splitter.addWidget(self.tree)
        self.main_splitter.addWidget(self.right_splitter)
        self.main_splitter.setSizes([300, 900])
        self.content_layout.addWidget(self.main_splitter)

        # --- Signals & Slots ---
        self.tree.clicked.connect(self.on_tree_select)
        self.file_table.clicked.connect(self.on_file_select)
        self.file_table.doubleClicked.connect(self.on_table_double_click)
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)

    # --- Mouse Events for Dragging Frameless Window ---
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.title_bar.geometry().contains(event.pos()):
            self._old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self._old_pos is not None:
            delta = QPoint(event.globalPosition().toPoint() - self._old_pos)
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self._old_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self._old_pos = None

    # --- Standard Forensic Functions (Unchanged) ---
    def on_tree_select(self, index):
        path = self.model.filePath(index)
        self.file_table.setRootIndex(self.model.index(path))

    def on_table_double_click(self, index):
        path = self.model.filePath(index)
        if os.path.isdir(path):
            self.file_table.setRootIndex(self.model.index(path))
            self.tree.setCurrentIndex(self.model.index(path))

    def show_context_menu(self, position):
        index = self.file_table.indexAt(position)
        if not index.isValid(): return
        menu = QMenu()
        export_action = QAction("Export / Save As...", self)
        export_action.triggered.connect(lambda: self.export_entry(index))
        menu.addAction(export_action)
        menu.exec(self.file_table.viewport().mapToGlobal(position))

    def export_entry(self, index):
        source_path = self.model.filePath(index)
        file_name = self.model.fileName(index)
        dest_path, _ = QFileDialog.getSaveFileName(self, "Export File", file_name, "All Files (*)")
        if dest_path:
            try:
                if os.path.isdir(source_path):
                    shutil.copytree(source_path, dest_path)
                else:
                    shutil.copy2(source_path, dest_path)
                QMessageBox.information(self, "Success", f"Exported to: {dest_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {e}")

    def on_file_select(self, index):
        path = self.model.filePath(index)
        if os.path.isdir(path): return
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.text_view.setText(f.read(10000))
        except:
            pass
        try:
            with open(path, 'rb') as f:
                self.hex_view.setText(f.read(512).hex(' '))
        except:
            pass
        pixmap = QPixmap(path)
        if not pixmap.isNull():
            self.image_view.setPixmap(pixmap.scaled(
                self.image_view.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            ))
            self.tabs.setCurrentIndex(2)
            #self.image_view.setPixmap(pixmap.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio))
        else:
            self.image_view.setText("No Preview")
            self.tabs.setCurrentIndex(0)


if __name__ == "__main__":
    # Suppress Common MacOS Warnings
    os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.text.font.db.warning=false"

    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Cleaner look for custom title bars
    window = ForensicsApp()
    window.show()
    sys.exit(app.exec())