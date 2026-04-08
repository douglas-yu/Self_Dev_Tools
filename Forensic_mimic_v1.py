import sys
import binascii
import csv
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QSplitter, QTreeView,
    QTableView, QTabWidget, QTextEdit, QLabel, QHeaderView,
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QFileDialog, QMenu
)
from PyQt6.QtGui import QFileSystemModel, QPixmap, QAction, QFont
from PyQt6.QtCore import Qt, QDir, QModelIndex, QRect


class ForensicGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PYForensic FTK")
        self.resize(1300, 900)

        # 1. Setup Models
        self.model = QFileSystemModel()
        root_path = "C:/" if sys.platform == "win32" else "/"
        self.model.setRootPath(root_path)

        # 2. UI Components
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()

        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Top Title Bar ---
        title_label = QLabel("PYForensic FTK")
        title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title_label.setStyleSheet("background-color: #2c3e50; color: white; padding: 10px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setMaximumHeight(50)
        main_layout.addWidget(title_label)


        # --- Toolbar (CSV & E01) ---
        toolbar_layout = QHBoxLayout()
        btn_import_e01 = QPushButton("Import E01 Image")
        btn_import_e01.clicked.connect(self.import_e01)

        btn_export_csv = QPushButton("Export List to CSV")
        btn_export_csv.clicked.connect(self.export_to_csv)

        toolbar_layout.addWidget(btn_import_e01)
        toolbar_layout.addWidget(btn_export_csv)
        toolbar_layout.addStretch()
        main_layout.addLayout(toolbar_layout)

        # --- Splitters ---
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.right_splitter = QSplitter(Qt.Orientation.Vertical)


        # --- Left Panel: Tree View ---
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(self.model.rootPath()))
        for i in range(1, self.model.columnCount()):
            self.tree.hideColumn(i)
        self.tree.clicked.connect(self.on_tree_select)

        # --- Right Top Panel: File List ---
        self.file_table = QTableView()
        self.file_table.setModel(self.model)
        self.file_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)
        self.file_table.clicked.connect(self.on_file_single_click)
        self.file_table.doubleClicked.connect(self.on_file_double_click)

        # --- Right Bottom Panel: Content Viewers ---
        self.tabs = QTabWidget()
        self.text_view = QTextEdit(readOnly=True)
        self.hex_view = QTextEdit(readOnly=True)
        self.hex_view.setStyleSheet("font-family: 'Courier New'; font-size: 10pt;")
        self.image_view = QLabel("Preview", alignment=Qt.AlignmentFlag.AlignCenter)

        self.tabs.addTab(self.text_view, "Text")
        self.tabs.addTab(self.hex_view, "Hex")
        self.tabs.addTab(self.image_view, "Image")

        # Assemble
        self.right_splitter.addWidget(self.file_table)
        self.right_splitter.addWidget(self.tabs)

        self.main_splitter.addWidget(self.tree)

        self.main_splitter.addWidget(self.right_splitter)
        self.right_splitter.setMinimumWidth(1000)
        main_layout.addWidget(self.main_splitter)

    # --- Forensic Functions ---

    def import_e01(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open E01 Image", "", "Forensic Images (*.e01 *.001)")
        if file_path:
            # In a real app, you would use 'pytsk3' or 'libewf' here
            self.text_view.setText(f"[SYSTEM] Attempting to mount forensic image: {file_path}\n"
                                   "Note: To browse E01 contents, you must integrate 'pytsk3'.\n"
                                   "Switching view to parent directory for simulation.")
            # For this prototype, we point the view to the image's folder
            self.tree.setRootIndex(self.model.index(os.path.dirname(file_path)))

    def export_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "file_list.csv", "CSV Files (*.csv)")
        if path:
            root = self.file_table.rootIndex()
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Name", "Size", "Type", "Modified"])
                for row in range(self.model.rowCount(root)):
                    idx = self.model.index(row, 0, root)
                    writer.writerow([
                        self.model.fileName(idx),
                        f"{self.model.size(idx)} bytes",
                        self.model.type(idx),
                        self.model.lastModified(idx).toString()
                    ])

    def show_context_menu(self, position):
        menu = QMenu()
        save_action = QAction("Save As (Export File)", self)
        save_action.triggered.connect(self.export_file)
        menu.addAction(save_action)
        menu.exec(self.file_table.viewport().mapToGlobal(position))

    def export_file(self):
        index = self.file_table.currentIndex()
        if index.isValid() and not self.model.isDir(index):
            src_path = self.model.filePath(index)
            dest_path, _ = QFileDialog.getSaveFileName(self, "Export File", self.model.fileName(index))
            if dest_path:
                import shutil
                shutil.copy2(src_path, dest_path)

    # --- Standard UI Logic ---

    def on_tree_select(self, index):
        self.file_table.setRootIndex(index)

    def on_file_single_click(self, index):
        path = self.model.filePath(index)
        if not self.model.isDir(index):
            self.load_previews(path)

    def on_file_double_click(self, index):
        if self.model.isDir(index):
            self.file_table.setRootIndex(index)
            self.tree.setCurrentIndex(index)

    def load_previews(self, path):
        try:
            # Text Preview
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.text_view.setText(f.read(5000))
            # Hex Preview
            with open(path, 'rb') as f:
                chunk = f.read(512)
                self.hex_view.setText(binascii.hexlify(chunk, ' ').decode().upper())
            # Image Preview
            pix = QPixmap(path)
            if not pix.isNull():
                self.image_view.setPixmap(pix.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio))
            else:
                self.image_view.setText("No Image Preview")
        except Exception as e:
            print(f"Error loading: {e}")


if __name__ == "__main__":
    import os

    app = QApplication(sys.argv)
    window = ForensicGUI()
    window.show()
    sys.exit(app.exec())