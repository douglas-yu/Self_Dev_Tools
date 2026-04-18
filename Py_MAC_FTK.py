import sys
import os
import shutil
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QSplitter, QTreeView,
    QTableView, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget, QHeaderView, QLabel, QMenu, QFileDialog, QMessageBox
)
from PyQt6.QtGui import QFileSystemModel, QPixmap, QAction
from PyQt6.QtCore import Qt, QDir


class ForensicsApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("macOS Forensic Navigator")
        self.resize(1200, 800)

        # 1. Setup Model
        self.model = QFileSystemModel()
        root_path = QDir.rootPath()
        self.model.setRootPath(root_path)

        # 2. Main Layout
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

        # Bottom Right: Tabs
        self.tabs = QTabWidget()
        self.text_view = QTextEdit(readOnly=True)
        self.hex_view = QTextEdit(readOnly=True)
        self.hex_view.setFontFamily("Courier")
        self.image_view = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)

        self.tabs.addTab(self.text_view, "Text")
        self.tabs.addTab(self.hex_view, "Hex")
        self.tabs.addTab(self.image_view, "Image")

        # Assembly
        self.right_splitter.addWidget(self.file_table)
        self.right_splitter.addWidget(self.tabs)
        self.main_splitter.addWidget(self.tree)

        self.main_splitter.addWidget(self.right_splitter)
        self.main_splitter.setSizes([300, 900])
        self.setCentralWidget(self.main_splitter)

        # --- Signals & Slots ---
        self.tree.clicked.connect(self.on_tree_select)
        self.file_table.clicked.connect(self.on_file_select)

        # NEW: Double click to enter folder
        self.file_table.doubleClicked.connect(self.on_table_double_click)

        # NEW: Right click context menu
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)

    def on_tree_select(self, index):
        path = self.model.filePath(index)
        self.file_table.setRootIndex(self.model.index(path))

    def on_table_double_click(self, index):
        path = self.model.filePath(index)
        if os.path.isdir(path):
            # Navigate deeper into the folder
            self.file_table.setRootIndex(self.model.index(path))
            # Optional: Sync the tree view to match
            self.tree.setCurrentIndex(self.model.index(path))

    def show_context_menu(self, position):
        index = self.file_table.indexAt(position)
        if not index.isValid():
            return

        menu = QMenu()
        export_action = QAction("Export / Save As...", self)
        export_action.triggered.connect(lambda: self.export_entry(index))
        menu.addAction(export_action)
        menu.exec(self.file_table.viewport().mapToGlobal(position))

    def export_entry(self, index):
        source_path = self.model.filePath(index)
        file_name = self.model.fileName(index)

        # Open Save Dialog
        dest_path, _ = QFileDialog.getSaveFileName(
            self, "Export File", file_name, "All Files (*)"
        )

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

        # Text View
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.text_view.setText(f.read(10000))
        except:
            pass

        # Hex View (Simplified)
        try:
            with open(path, 'rb') as f:
                self.hex_view.setText(f.read(512).hex(' '))
        except:
            pass

        # Image View
        pixmap = QPixmap(path)
        if not pixmap.isNull():
            self.image_view.setPixmap(pixmap.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio))
        else:
            self.image_view.setText("No Preview")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicsApp()
    window.show()
    sys.exit(app.exec())