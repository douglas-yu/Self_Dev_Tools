import sys
import os
import librosa
import librosa.display
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QFileDialog, QLabel,
                             QTabWidget, QListWidget, QStatusBar, QTextEdit)
from PyQt6.QtGui import QFont

class AudioCanvas(FigureCanvas):
    """Forensic Visualization Engine for Waveforms and Spectrograms."""
    def __init__(self, parent=None):
        self.fig, self.ax = plt.subplots(figsize=(6, 4), dpi=100, tight_layout=True)
        super().__init__(self.fig)
        self.fig.patch.set_facecolor('#121212')
        self.ax.set_facecolor('#121212')

    def plot_wave(self, data, sr):
        self.ax.clear()
        time = np.linspace(0, len(data)/sr, len(data))
        self.ax.plot(time, data, color='#00ffcc', linewidth=0.5)
        self.ax.set_title("Time-Domain Waveform", color='white')
        self.ax.set_xlabel("Time (s)", color='gray')
        self.ax.tick_params(colors='gray')
        self.draw()

    def plot_spectrogram(self, data, sr):
        self.ax.clear()
        D = librosa.amplitude_to_db(np.abs(librosa.stft(data)), ref=np.max)
        img = librosa.display.specshow(D, sr=sr, x_axis='time', y_axis='hz',
                                       ax=self.ax, cmap='magma')
        self.ax.set_title("Frequency Fingerprint (STFT)", color='white')
        self.ax.tick_params(colors='gray')
        self.draw()

class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyForensic Audio Analyzer v1.2")
        self.resize(1300, 900)

        # Data state
        self.current_path = None
        self.current_audio = None
        self.sr = None

        self.init_ui()

    def init_ui(self):
        # Apply dark theme stylesheet
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #1e1e1e; color: #e0e0e0; }
            QPushButton { background-color: #333; border: 1px solid #555; padding: 8px; border-radius: 4px; }
            QPushButton:hover { background-color: #444; }
            QTabWidget::pane { border: 1px solid #444; }
            QListWidget { background-color: #252525; border: 1px solid #444; }
            QTextEdit { background-color: #000; color: #00ff00; font-family: 'Courier New'; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        # --- LEFT PANEL: Controls ---
        left_panel = QVBoxLayout()

        self.import_btn = QPushButton("📁 Import Evidence")
        self.import_btn.clicked.connect(self.import_audio)

        self.analysis_list = QListWidget()
        self.analysis_list.addItems([
            "📊 View Waveform",
            "🌈 View Spectrogram",
            "🔍 DeepFake Detection (Heuristic)",
            "📜 Extract Hex/Metadata",
            "🛡️ Authenticity Check"
        ])

        run_btn = QPushButton("RUN ANALYSIS")
        run_btn.setStyleSheet("background-color: #1a5f7a; font-weight: bold;")
        run_btn.clicked.connect(self.run_logic)

        left_panel.addWidget(QLabel("CASE MANAGEMENT"))
        left_panel.addWidget(self.import_btn)
        left_panel.addSpacing(20)
        left_panel.addWidget(QLabel("ANALYSIS MODULES"))
        left_panel.addWidget(self.analysis_list)
        left_panel.addWidget(run_btn)
        left_panel.addStretch()

        # --- RIGHT PANEL: Analysis Tabs ---
        self.tabs = QTabWidget()

        # Tab 1: Visuals
        self.canvas = AudioCanvas(self)
        self.tabs.addTab(self.canvas, "Visual Analysis")

        # Tab 2: Hex Viewer
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.tabs.addTab(self.hex_view, "Hexadecimal Evidence")

        # Tab 3: Report Logs
        self.report_view = QTextEdit()
        self.tabs.addTab(self.report_view, "Forensic Report")

        main_layout.addLayout(left_panel, 1)
        main_layout.addLayout(self.tabs, 4)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("System Ready")

    def import_audio(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "Audio (*.wav *.mp3 *.m4a)")
        if file_path:
            self.current_path = file_path
            self.current_audio, self.sr = librosa.load(file_path, sr=None)
            self.canvas.plot_wave(self.current_audio, self.sr)
            self.status.showMessage(f"Loaded: {os.path.basename(file_path)}")
            self.generate_hex_view()

    def generate_hex_view(self):
        """Reads the binary data of the file and formats it as a Hex Dump."""
        if not self.current_path: return

        try:
            with open(self.current_path, 'rb') as f:
                chunk = f.read(2048) # Read first 2KB for efficiency
                hex_dump = ""
                for i in range(0, len(chunk), 16):
                    sub_chunk = chunk[i:i+16]
                    # Hex part
                    hex_str = " ".join(f"{b:02x}" for b in sub_chunk)
                    # ASCII part
                    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub_chunk)
                    hex_dump += f"{i:08x}  {hex_str:<48}  |{ascii_str}|\n"

                self.hex_view.setPlainText(hex_dump)
        except Exception as e:
            self.hex_view.setPlainText(f"Error reading hex: {e}")

    def run_logic(self):
        if self.current_audio is None:
            self.status.showMessage("Import audio evidence first.")
            return

        task = self.analysis_list.currentItem().text()

        if "Waveform" in task:
            self.canvas.plot_wave(self.current_audio, self.sr)
            self.tabs.setCurrentIndex(0)

        elif "Spectrogram" in task:
            self.canvas.plot_spectrogram(self.current_audio, self.sr)
            self.tabs.setCurrentIndex(0)

        elif "Hex" in task:
            self.tabs.setCurrentIndex(1)

        elif "DeepFake" in task:
            # Heuristic calculation
            centroid = np.mean(librosa.feature.spectral_centroid(y=self.current_audio, sr=self.sr))
            verdict = "⚠️ SUSPICIOUS (High Centroid)" if centroid > 4000 else "✅ LIKELY NATURAL"

            report = f"--- DEEPFAKE ANALYSIS ---\n"
            report += f"Timestamp: {datetime.now()}\n"
            report += f"Spectral Centroid: {centroid:.2f} Hz\n"
            report += f"Result: {verdict}\n"
            report += "Note: Analysis based on spectral frequency distribution."

            self.report_view.setPlainText(report)
            self.tabs.setCurrentIndex(2)
            self.status.showMessage("Analysis complete.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Using Fusion style for cross-platform dark-mode consistency
    app.setStyle("Fusion")
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
