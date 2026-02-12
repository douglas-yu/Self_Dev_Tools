import sys
import os
import io
import hashlib
import string
import math
import colorsys

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QFileDialog,
    QTextEdit, QVBoxLayout, QHBoxLayout, QMessageBox, QScrollArea, QSizePolicy
)
   #.springframework.core.io.Resource
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtCore import Qt, QSize

from PIL import Image, ImageChops, ExifTags, ImageFilter, ImageDraw

# -----------------------
# Utility conversions
# -----------------------
def pil_to_qpixmap(pil_image):
    """Convert a PIL Image to QPixmap (RGB)."""
    if pil_image.mode in ("RGBA", "LA"):
        bg = Image.new("RGB", pil_image.size, (255, 255, 255))
        bg.paste(pil_image, mask=pil_image.split()[-1])
        pil_image = bg.convert("RGB")
    elif pil_image.mode != "RGB":
        pil_image = pil_image.convert("RGB")

    data = pil_image.tobytes("raw", "RGB")
    w, h = pil_image.size
    qimage = QImage(data, w, h, 3 * w, QImage.Format_RGB888)
    return QPixmap.fromImage(qimage)

class ForensicsApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Photo Forensics Toolkit (Extended)")
        self.resize(2000, 1200)

        self.current_image_path = None
        self.current_pil_image = None

        # Original pixmaps to rescale on window resize (keep ratio)
        self.reference_pixmap_original = None
        self.result_pixmap_original = None

        self._build_ui()

    # -----------------------
    # UI construction
    # -----------------------
    def _build_ui(self):
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        self.setCentralWidget(main_widget)

        # --- Left panel: controls ---
        controls_layout = QVBoxLayout()

        self.load_button = QPushButton("Load Image...")
        self.load_button.clicked.connect(self.load_image)
        controls_layout.addWidget(self.load_button)

        # Group: Core forensic / metadata
        self.ela_button = QPushButton("Error Level Analysis (ELA)")
        self.ela_button.clicked.connect(self.run_ela)
        controls_layout.addWidget(self.ela_button)

        self.exif_button = QPushButton("EXIF Information")
        self.exif_button.clicked.connect(self.show_exif)
        controls_layout.addWidget(self.exif_button)

        self.metadata_button = QPushButton("Full Metadata")
        self.metadata_button.clicked.connect(self.show_metadata)
        controls_layout.addWidget(self.metadata_button)

        self.thumb_button = QPushButton("Thumbnail Analysis")
        self.thumb_button.clicked.connect(self.run_thumbnail_analysis)
        controls_layout.addWidget(self.thumb_button)

        self.geo_button = QPushButton("Geo Tags")
        self.geo_button.clicked.connect(self.show_geotags)
        controls_layout.addWidget(self.geo_button)

        self.digest_button = QPushButton("File Digest (SHA-256 / MD5)")
        self.digest_button.clicked.connect(self.show_digest)
        controls_layout.addWidget(self.digest_button)

        self.jpeg_quality_button = QPushButton("JPEG Quality % (Heuristic)")
        self.jpeg_quality_button.clicked.connect(self.show_jpeg_quality)
        controls_layout.addWidget(self.jpeg_quality_button)

        # Group: Structure / artifacts
        self.block_artifacts_button = QPushButton("Block Artifacts (8×8 Grid)")
        self.block_artifacts_button.clicked.connect(self.run_block_artifact_view)
        controls_layout.addWidget(self.block_artifacts_button)

        self.noise_button = QPushButton("Noise Analysis")
        self.noise_button.clicked.connect(self.run_noise_analysis)
        controls_layout.addWidget(self.noise_button)

        self.prnu_button = QPushButton("PRNU-like Noise Residue")
        self.prnu_button.clicked.connect(self.run_prnu_residue)
        controls_layout.addWidget(self.prnu_button)

        self.copymove_button = QPushButton("Copy–Move Detection (Heuristic)")
        self.copymove_button.clicked.connect(self.run_copy_move)
        controls_layout.addWidget(self.copymove_button)

        self.lumi_grad_button = QPushButton("Luminance Gradient")
        self.lumi_grad_button.clicked.connect(self.run_luminance_gradient)
        controls_layout.addWidget(self.lumi_grad_button)

        self.level_sweep_button = QPushButton("Level Sweep")
        self.level_sweep_button.clicked.connect(self.run_level_sweep)
        controls_layout.addWidget(self.level_sweep_button)

        # Group: Histogram / color / profiles / strings
        self.hist_button = QPushButton("Histogram (RGB)")
        self.hist_button.clicked.connect(self.run_histogram)
        controls_layout.addWidget(self.hist_button)

        self.color_button = QPushButton("Color Analysis")
        self.color_button.clicked.connect(self.run_color_analysis)
        controls_layout.addWidget(self.color_button)

        self.icc_button = QPushButton("ICC Profile Info")
        self.icc_button.clicked.connect(self.show_icc_profile)
        controls_layout.addWidget(self.icc_button)

        self.strings_button = QPushButton("Strings (printable)")
        self.strings_button.clicked.connect(self.show_strings)
        controls_layout.addWidget(self.strings_button)

        controls_layout.addStretch(1)

        controls_container = QWidget()
        controls_container.setLayout(controls_layout)
        controls_container.setMaximumWidth(300)

        # --- Center panel: reference image ---
        self.reference_label = QLabel("Reference Image")
        self.reference_label.setAlignment(Qt.AlignCenter)
        self.reference_label.setStyleSheet("background-color: #333; color: #aaa;")
        self.reference_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.reference_label.setMinimumSize(QSize(200, 200))
        self.reference_label.setScaledContents(False)  # manual aspect ratio

        self.ref_scroll = QScrollArea()
        self.ref_scroll.setWidgetResizable(True)
        self.ref_scroll.setWidget(self.reference_label)

        # --- Right panel: analysis result (image + text) ---
        right_layout = QVBoxLayout()

        self.result_image_label = QLabel("Analysis Result (Image)")
        self.result_image_label.setAlignment(Qt.AlignCenter)
        self.result_image_label.setStyleSheet("background-color: #222; color: #aaa;")
        self.result_image_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.result_image_label.setMinimumSize(QSize(200, 200))
        self.result_image_label.setScaledContents(False)

        self.result_image_scroll = QScrollArea()
        self.result_image_scroll.setWidgetResizable(True)
        self.result_image_scroll.setWidget(self.result_image_label)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText("Analysis results will appear here...")

        right_layout.addWidget(self.result_image_scroll, stretch=3)
        right_layout.addWidget(self.result_text, stretch=2)

        right_container = QWidget()
        right_container.setLayout(right_layout)
        right_container.setMinimumWidth(450)

        # Add panels to main layout
        main_layout.addWidget(controls_container)
        main_layout.addWidget(self.ref_scroll, stretch=3)
        main_layout.addWidget(right_container, stretch=3)

    # -----------------------
    # Window resize: keep images aligned and aspect ratio
    # -----------------------
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_display_sizes()

    def update_display_sizes(self):
        """Rescale reference and result pixmaps to fit their viewports while keeping aspect ratio."""
        if self.reference_pixmap_original is not None:
            target_size = self.ref_scroll.viewport().size()
            if target_size.width() > 0 and target_size.height() > 0:
                scaled = self.reference_pixmap_original.scaled(
                    target_size,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
                self.reference_label.setPixmap(scaled)

        if self.result_pixmap_original is not None:
            target_size = self.result_image_scroll.viewport().size()
            if target_size.width() > 0 and target_size.height() > 0:
                scaled = self.result_pixmap_original.scaled(
                    target_size,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
                self.result_image_label.setPixmap(scaled)

    # -----------------------
    # Image loading
    # -----------------------
    def load_image(self):
        dialog = QFileDialog(self, "Select image file")
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setNameFilters([
            "Images (*.jpg *.jpeg *.png *.tif *.tiff *.bmp)",
            "All Files (*)"
        ])
        if dialog.exec_():
            path = dialog.selectedFiles()[0]
            self.open_image(path)

    def open_image(self, path):
        try:
            pil_image = Image.open(path)
            pil_image.load()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open image:\n{e}")
            return

        self.current_image_path = path
        self.current_pil_image = pil_image

        self.reference_pixmap_original = pil_to_qpixmap(pil_image)
        self.result_pixmap_original = None

        # Clear and update views
        self.result_image_label.clear()
        self.result_image_label.setText("Analysis Result (Image)")
        self.result_text.clear()
        self.result_text.append(f"Loaded: {path}")

        self.update_display_sizes()
        self.reference_label.setToolTip(os.path.basename(path))

    def _require_image(self):
        if self.current_pil_image is None or self.current_image_path is None:
            QMessageBox.warning(self, "No image", "Please load an image first.")
            return False
        return True

    # -----------------------
    # ELA
    # -----------------------
    def run_ela(self):
        if not self._require_image():
            return

        try:
            ela_image = self.compute_ela(self.current_pil_image)
            if ela_image is None:
                self.result_text.clear()
                self.result_text.append(
                    "ELA is primarily meaningful for JPEG images.\n"
                    "Please load a JPEG image."
                )
                self.result_image_label.clear()
                self.result_image_label.setText("No ELA image available")
                self.result_pixmap_original = None
                self.update_display_sizes()
                return

            self.result_pixmap_original = pil_to_qpixmap(ela_image)
            self.result_text.clear()
            self.result_text.append(
                "Error Level Analysis (ELA) completed.\n\n"
                "Brighter areas in the ELA image may indicate regions with\n"
                "different compression history or possible manipulation."
            )
            self.update_display_sizes()
        except Exception as e:
            QMessageBox.critical(self, "ELA Error", f"Failed to compute ELA:\n{e}")

    @staticmethod
    def compute_ela(pil_img, quality=90, scale=15):
        """Compute ELA for a JPEG image; returns a PIL Image."""
        img = pil_img.convert("RGB")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=quality)
        buffer.seek(0)
        resaved = Image.open(buffer)
        resaved = resaved.convert("RGB")

        diff = ImageChops.difference(img, resaved)

        def enhance(p):
            p = p * scale
            return 255 if p > 255 else p

        ela_img = diff.point(enhance)
        return ela_img

    # -----------------------
    # EXIF & Metadata
    # -----------------------
    def show_exif(self):
        if not self._require_image():
            return

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("EXIF has no image output")
        self.update_display_sizes()

        text = self.get_exif_text(self.current_pil_image)
        self.result_text.clear()
        self.result_text.append(text)

    def show_metadata(self):
        if not self._require_image():
            return

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("Metadata has no image output")
        self.update_display_sizes()

        lines = []
        img = self.current_pil_image
        path = self.current_image_path

        # Basic file info
        size_bytes = os.path.getsize(path)
        fmt = img.format or "Unknown"
        mode = img.mode
        w, h = img.size
        lines.append("Basic File / Image Info:\n")
        lines.append(f"Path: {path}")
        lines.append(f"Format: {fmt}")
        lines.append(f"Mode: {mode}")
        lines.append(f"Resolution: {w} x {h}")
        lines.append(f"File size: {size_bytes} bytes")
        lines.append("")

        # EXIF
        lines.append(self.get_exif_text(img))
        lines.append("")

        # ICC profile summary
        icc = img.info.get("icc_profile")
        if icc:
            lines.append(f"ICC profile: present ({len(icc)} bytes)")
        else:
            lines.append("ICC profile: none")

        self.result_text.clear()
        self.result_text.append("\n".join(lines))

    @staticmethod
    def get_exif_text(pil_img):
        output_lines = []
        output_lines.append("EXIF Metadata:\n")

        try:
            exif = getattr(pil_img, "_getexif", lambda: None)()
        except Exception:
            exif = None

        if not exif:
            output_lines.append("  No EXIF metadata found.")
            return "\n".join(output_lines)

        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, f"Unknown ({tag_id})")
            if isinstance(value, bytes):
                try:
                    value = value.decode(errors="replace")
                except Exception:
                    pass
            output_lines.append(f"{tag_name}: {value}")

        return "\n".join(output_lines)

    # -----------------------
    # Thumbnail Analysis
    # -----------------------
    def run_thumbnail_analysis(self):
        if not self._require_image():
            return

        img = self.current_pil_image
        path = self.current_image_path
        info = img.info

        lines = ["Thumbnail Analysis:\n", f"File: {path}\n"]
        thumb_img = None

        thumb_bytes = info.get("thumbnail")
        if thumb_bytes:
            try:
                thumb_img = Image.open(io.BytesIO(thumb_bytes))
                thumb_img.load()
                lines.append(f"Embedded thumbnail found: {thumb_img.size[0]} x {thumb_img.size[1]}")
                lines.append(f"Mode: {thumb_img.mode}, Format: {thumb_img.format or 'JPEG (embedded)'}")
            except Exception as e:
                lines.append(f"Embedded thumbnail present but failed to decode: {e}")

        if thumb_img is None:
            # No embedded thumb: generate a proxy thumbnail
            proxy = img.copy()
            proxy.thumbnail((256, 256), Image.LANCZOS)
            thumb_img = proxy
            lines.append("No embedded thumbnail found in headers.")
            lines.append("Showing a generated downscaled preview as reference.")

        self.result_pixmap_original = pil_to_qpixmap(thumb_img)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append("\n".join(lines))

    # -----------------------
    # Geo Tags
    # -----------------------
    def show_geotags(self):
        if not self._require_image():
            return

        img = self.current_pil_image

        try:
            exif = getattr(img, "_getexif", lambda: None)()
        except Exception:
            exif = None

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("Geo Tags have no image output")
        self.update_display_sizes()

        lines = ["Geo Tag Analysis:\n"]

        if not exif:
            lines.append("No EXIF metadata; Geo tags unavailable.")
            self.result_text.clear()
            self.result_text.append("\n".join(lines))
            return

        gps_info = exif.get(34853)
        if not gps_info:
            lines.append("No GPSInfo (tag 34853) in EXIF.")
            self.result_text.clear()
            self.result_text.append("\n".join(lines))
            return

        gps_tags = {}
        for key, val in gps_info.items():
            tag = ExifTags.GPSTAGS.get(key, key)
            gps_tags[tag] = val

        def _to_deg(value):
            # value is ((num,den), (num,den), (num,den))
            d = value[0][0] / value[0][1]
            m = value[1][0] / value[1][1]
            s = value[2][0] / value[2][1]
            return d + m / 60.0 + s / 3600.0

        lat = lon = None
        if "GPSLatitude" in gps_tags and "GPSLatitudeRef" in gps_tags:
            lat = _to_deg(gps_tags["GPSLatitude"])
            if gps_tags["GPSLatitudeRef"] in ["S", b"S"]:
                lat = -lat

        if "GPSLongitude" in gps_tags and "GPSLongitudeRef" in gps_tags:
            lon = _to_deg(gps_tags["GPSLongitude"])
            if gps_tags["GPSLongitudeRef"] in ["W", b"W"]:
                lon = -lon

        if lat is None or lon is None:
            lines.append("GPSInfo present but incomplete (no full lat/lon).")
        else:
            lines.append(f"Latitude:  {lat:.6f}")
            lines.append(f"Longitude: {lon:.6f}")
            lines.append("")
            lines.append(
                "Google Maps link:\n"
                f"https://www.google.com/maps/search/?api=1&query={lat:.6f},{lon:.6f}"
            )

        # Altitude, if available
        alt = gps_tags.get("GPSAltitude")
        if alt:
            altitude = alt[0] / alt[1]
            ref = gps_tags.get("GPSAltitudeRef", 0)
            if ref == 1:
                altitude = -altitude
            lines.append(f"Altitude: {altitude:.2f} m")

        self.result_text.clear()
        self.result_text.append("\n".join(lines))

    # -----------------------
    # Digest
    # -----------------------
    def show_digest(self):
        if not self._require_image():
            return

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("Digest has no image output")
        self.update_display_sizes()

        digest_text = self.compute_digest(self.current_image_path)
        self.result_text.clear()
        self.result_text.append(digest_text)

    @staticmethod
    def compute_digest(path):
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()

        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
                md5.update(chunk)

        size_bytes = os.path.getsize(path)
        return (
            "File Digest:\n\n"
            f"Path: {path}\n"
            f"Size: {size_bytes} bytes\n\n"
            f"SHA-256: {sha256.hexdigest()}\n"
            f"MD5:     {md5.hexdigest()} (for quick comparison only, not secure)"
        )

    # -----------------------
    # JPEG quality heuristic (%)
    # -----------------------
    def show_jpeg_quality(self):
        if not self._require_image():
            return

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("JPEG quality has no image output")
        self.update_display_sizes()

        text = self.estimate_jpeg_quality(self.current_pil_image, self.current_image_path)
        self.result_text.clear()
        self.result_text.append(text)

    @staticmethod
    def estimate_jpeg_quality(pil_img, path):
        """
        Heuristic JPEG 'quality %' based on bytes per pixel.
        This is NOT the real encoder-quality, but a rough indicator.
        """
        size_bytes = os.path.getsize(path)
        w, h = pil_img.size
        num_pixels = max(w * h, 1)
        bpp = size_bytes / float(num_pixels)

        if bpp <= 0.15:
            score = 10
            level = "Very high compression (likely low visual quality)"
        elif bpp <= 0.30:
            score = 25
            level = "High compression (lower quality)"
        elif bpp <= 0.50:
            score = 45
            level = "Moderate compression (medium quality)"
        elif bpp <= 0.80:
            score = 65
            level = "Relatively low compression (good quality)"
        elif bpp <= 1.5:
            score = 80
            level = "Low compression (high quality)"
        else:
            score = 95
            level = "Very low compression (near-lossless / high quality)"

        fmt = pil_img.format or "Unknown"
        info_lines = [
            "JPEG Quality Heuristic:\n",
            f"File: {path}",
            f"Format (PIL): {fmt}",
            f"Resolution: {w} x {h} = {num_pixels} pixels",
            f"File size: {size_bytes} bytes",
            f"Bytes per pixel: {bpp:.4f}",
            "",
            f"Estimated 'quality' score: {score} / 100",
            f"Interpretation: {level}",
            "",
            "Note: This is a heuristic based on size vs. resolution, not the actual\n"
            "encoder 'quality' parameter. For formal analysis, inspect JPEG\n"
            "quantization tables or recompress at different levels."
        ]

        if hasattr(pil_img, "quantization") and pil_img.quantization:
            info_lines.append("\nQuantization tables detected (truncated view):")
            for tid, table in list(pil_img.quantization.items())[:2]:
                info_lines.append(f"  Table {tid}: {table[:8]} ...")

        return "\n".join(info_lines)

    # -----------------------
    # Noise analysis
    # -----------------------
    def run_noise_analysis(self):
        if not self._require_image():
            return

        img = self.current_pil_image.convert("L")
        max_dim = 400
        scale = min(max_dim / img.width, max_dim / img.height, 1.0)
        if scale < 1.0:
            new_size = (int(img.width * scale), int(img.height * scale))
            img = img.resize(new_size, Image.BILINEAR)

        blurred = img.filter(ImageFilter.GaussianBlur(radius=1.5))
        diff = ImageChops.difference(img, blurred)

        diff_data = list(diff.getdata())
        mean_noise = sum(diff_data) / len(diff_data)
        var = sum((v - mean_noise) ** 2 for v in diff_data) / len(diff_data)
        std_noise = var ** 0.5

        amplified = diff.point(lambda p: min(255, int(p * 4)))
        amplified = amplified.convert("RGB")

        self.result_pixmap_original = pil_to_qpixmap(amplified)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(
            "Noise Analysis (blur-difference approximation):\n\n"
            f"Mean noise level: {mean_noise:.2f}\n"
            f"Std-dev of noise: {std_noise:.2f}\n\n"
            "Brighter pixels in the noise map indicate regions with higher local\n"
            "high-frequency content, which may be due to noise, texture, or editing."
        )

    # -----------------------
    # Block artifacts (8x8 grid)
    # -----------------------
    def run_block_artifact_view(self):
        if not self._require_image():
            return

        img = self.current_pil_image.convert("RGB")
        w, h = img.size
        overlay = img.copy()

        step = 8
        color = (0, 255, 0)
        alpha = 120

        grid = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        gdraw = ImageDraw.Draw(grid)

        for x in range(0, w, step):
            gdraw.line([(x, 0), (x, h)], fill=(color[0], color[1], color[2], alpha), width=1)
        for y in range(0, h, step):
            gdraw.line([(0, y), (w, y)], fill=(color[0], color[1], color[2], alpha), width=1)

        overlay = overlay.convert("RGBA")
        overlay = Image.alpha_composite(overlay, grid).convert("RGB")

        self.result_pixmap_original = pil_to_qpixmap(overlay)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(
            "Block Artifacts View:\n\n"
            "The green grid marks 8×8 blocks (typical JPEG DCT blocks). Use this\n"
            "to visually inspect for block boundary artifacts or inconsistent\n"
            "compression between regions."
        )

    # -----------------------
    # PRNU-like noise residue
    # -----------------------
    def run_prnu_residue(self):
        if not self._require_image():
            return

        img = self.current_pil_image.convert("L")
        denoised = img.filter(ImageFilter.MedianFilter(size=3))
        residue = ImageChops.subtract(img, denoised)

        def enhance(p):
            return max(0, min(255, 128 + (p - 128) * 4))

        residue_enh = residue.point(enhance).convert("RGB")

        self.result_pixmap_original = pil_to_qpixmap(residue_enh)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(
            "PRNU-like Noise Residue:\n\n"
            "This is a simplified, non-calibrated noise residue obtained by\n"
            "denoising and subtracting from the original. True PRNU camera\n"
            "fingerprinting requires more rigorous processing and multiple images.\n"
            "Here it is useful for qualitative inspection of sensor-pattern noise\n"
            "and potential local anomalies."
        )

    # -----------------------
    # Copy–move detection (very simple heuristic)
    # -----------------------
    def run_copy_move(self):
        if not self._require_image():
            return

        try:
            cm_img, summary = self.copy_move_detection(self.current_pil_image)
        except Exception as e:
            QMessageBox.critical(self, "Copy–Move Error", f"Failed to run detection:\n{e}")
            return

        if cm_img is None:
            self.result_pixmap_original = None
            self.result_image_label.clear()
            self.result_image_label.setText("No strong copy–move candidates found")
            self.update_display_sizes()
        else:
            self.result_pixmap_original = pil_to_qpixmap(cm_img)
            self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(summary)

    @staticmethod
    def copy_move_detection(pil_img):
        img = pil_img.convert("L")
        max_dim = 400
        scale = min(max_dim / img.width, max_dim / img.height, 1.0)
        if scale < 1.0:
            new_size = (int(img.width * scale), int(img.height * scale))
            img = img.resize(new_size, Image.BILINEAR)

        w, h = img.size
        block_size = 16
        step = 8

        hashes = {}
        matches = []

        for y in range(0, h - block_size + 1, step):
            for x in range(0, w - block_size + 1, step):
                block = img.crop((x, y, x + block_size, y + block_size))
                hval = hashlib.sha1(block.tobytes()).hexdigest()[:16]
                if hval in hashes:
                    matches.append(((x, y), hashes[hval]))
                else:
                    hashes[hval] = (x, y)

        if not matches:
            summary = (
                "Copy–Move Detection (heuristic):\n\n"
                "No repeated block hashes found above the simple threshold.\n"
                "This does NOT guarantee absence of copy–move manipulation."
            )
            return None, summary

        color1 = (255, 0, 0)
        color2 = (0, 255, 255)
        out = img.convert("RGB")
        draw = ImageDraw.Draw(out)

        max_pairs = 80
        for i, ((x1, y1), (x2, y2)) in enumerate(matches[:max_pairs]):
            draw.rectangle(
                [x1, y1, x1 + block_size, y1 + block_size],
                outline=color1, width=2
            )
            draw.rectangle(
                [x2, y2, x2 + block_size, y2 + block_size],
                outline=color2, width=2
            )

        summary = (
            "Copy–Move Detection (heuristic):\n\n"
            f"Downscaled image size: {w} x {h}\n"
            f"Block size: {block_size} px, step: {step} px\n"
            f"Matched block pairs (first {max_pairs} visualized): {len(matches)}\n\n"
            "Red / cyan rectangles highlight repeated block pairs with identical\n"
            "hashes. Many may be false positives (e.g., repeating textures). Use\n"
            "as a coarse indicator only."
        )
        return out, summary

    # -----------------------
    # Histogram
    # -----------------------
    def run_histogram(self):
        if not self._require_image():
            return

        hist_img = self.create_histogram_image(self.current_pil_image)
        self.result_pixmap_original = pil_to_qpixmap(hist_img)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(
            "Histogram (RGB):\n\n"
            "The histogram image shows per-channel intensity distributions:\n"
            "- Red: red channel\n"
            "- Green: green channel\n"
            "- Blue: blue channel\n"
            "Useful to inspect contrast, clipping, and global tonal balance."
        )

    @staticmethod
    def create_histogram_image(pil_img, size=(512, 200)):
        img = pil_img.convert("RGB")
        hist = img.histogram()

        r_hist = hist[0:256]
        g_hist = hist[256:512]
        b_hist = hist[512:768]

        w, h = size
        hist_img = Image.new("RGB", (w, h), (255, 255, 255))
        draw = ImageDraw.Draw(hist_img)

        max_value = max(max(r_hist), max(g_hist), max(b_hist), 1)

        def draw_channel(channel_hist, color):
            for x in range(256):
                v = channel_hist[x] / max_value
                y = int(v * (h - 20))
                x_pos = int(x * (w / 256.0))
                draw.line(
                    [(x_pos, h - 1), (x_pos, h - 1 - y)],
                    fill=color
                )

        draw_channel(r_hist, (255, 0, 0))
        draw_channel(g_hist, (0, 180, 0))
        draw_channel(b_hist, (0, 0, 255))

        return hist_img

    # -----------------------
    # Color Analysis
    # -----------------------
    def run_color_analysis(self):
        if not self._require_image():
            return

        img = self.current_pil_image.convert("RGB")
        small = img.resize((256, 256), Image.LANCZOS)
        pixels = list(small.getdata())
        n = len(pixels)

        avg_r = sum(p[0] for p in pixels) / n
        avg_g = sum(p[1] for p in pixels) / n
        avg_b = sum(p[2] for p in pixels) / n

        # Average brightness and saturation (HSV)
        total_v = 0.0
        total_s = 0.0
        for r, g, b in pixels:
            h, s, v = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
            total_s += s
            total_v += v
        mean_s = total_s / n
        mean_v = total_v / n

        # Dominant colors via palette quantization
        pal = small.convert("P", palette=Image.ADAPTIVE, colors=5)
        palette_rgb = pal.convert("RGB")
        colors_counts = palette_rgb.getcolors(256 * 256)
        colors_counts = sorted(colors_counts, key=lambda x: x[0], reverse=True)[:5]

        # Build a simple palette image (5 stripes)
        w, h = 300, 80
        pal_img = Image.new("RGB", (w, h), (255, 255, 255))
        draw = ImageDraw.Draw(pal_img)
        stripe_w = w // max(len(colors_counts), 1)
        for i, (count, col) in enumerate(colors_counts):
            x0 = i * stripe_w
            x1 = w if i == len(colors_counts) - 1 else (i + 1) * stripe_w
            draw.rectangle([x0, 0, x1, h], fill=col)

        self.result_pixmap_original = pil_to_qpixmap(pal_img)
        self.update_display_sizes()

        lines = [
            "Color Analysis:\n",
            f"Average RGB: ({avg_r:.1f}, {avg_g:.1f}, {avg_b:.1f})",
            f"Mean brightness (V in HSV): {mean_v:.3f}",
            f"Mean saturation (S in HSV): {mean_s:.3f}",
            "",
            "Top dominant colors (count, R,G,B):"
        ]
        for count, col in colors_counts:
            lines.append(f"  {count:6d}  ->  {col}")

        if mean_s < 0.2:
            tone = "low saturation (muted / near-monochrome)"
        elif mean_s < 0.5:
            tone = "moderate saturation"
        else:
            tone = "high saturation (vivid colors)"

        if mean_v < 0.3:
            bright = "overall dark"
        elif mean_v < 0.7:
            bright = "medium brightness"
        else:
            bright = "overall bright"

        lines.append("")
        lines.append(f"Overall impression: {bright}, {tone}.")

        self.result_text.clear()
        self.result_text.append("\n".join(lines))

    # -----------------------
    # Luminance Gradient
    # -----------------------
    def run_luminance_gradient(self):
        if not self._require_image():
            return

        img = self.current_pil_image.convert("L")
        max_dim = 400
        scale = min(max_dim / img.width, max_dim / img.height, 1.0)
        if scale < 1.0:
            new_size = (int(img.width * scale), int(img.height * scale))
            img = img.resize(new_size, Image.BILINEAR)

        # Sobel filters via ImageFilter.Kernel
        sobel_x = ImageFilter.Kernel(
            (3, 3),
            [-1, 0, 1,
             -2, 0, 2,
             -1, 0, 1],
            scale=1
        )
        sobel_y = ImageFilter.Kernel(
            (3, 3),
            [-1, -2, -1,
              0,  0,  0,
              1,  2,  1],
            scale=1
        )

        gx = img.filter(sobel_x)
        gy = img.filter(sobel_y)

        gx_data = list(gx.getdata())
        gy_data = list(gy.getdata())

        mags = []
        for a, b in zip(gx_data, gy_data):
            mag = int(min(255, math.hypot(a, b)))
            mags.append(mag)

        grad_img = Image.new("L", img.size)
        grad_img.putdata(mags)

        mean_grad = sum(mags) / len(mags)
        var = sum((v - mean_grad) ** 2 for v in mags) / len(mags)
        std_grad = math.sqrt(var)

        grad_vis = grad_img.point(lambda p: p).convert("RGB")

        self.result_pixmap_original = pil_to_qpixmap(grad_vis)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(
            "Luminance Gradient (Sobel magnitude):\n\n"
            f"Mean gradient magnitude: {mean_grad:.2f}\n"
            f"Std-dev of gradient:    {std_grad:.2f}\n\n"
            "Strong gradients (bright edges) highlight transitions in luminance.\n"
            "Look for inconsistencies or unusually sharp transitions around objects\n"
            "that may indicate compositing or tampering."
        )

    # -----------------------
    # Level Sweep
    # -----------------------
    def run_level_sweep(self):
        if not self._require_image():
            return

        img = self.current_pil_image.convert("L")
        max_dim = 250
        scale = min(max_dim / img.width, max_dim / img.height, 1.0)
        if scale < 1.0:
            new_size = (int(img.width * scale), int(img.height * scale))
            img = img.resize(new_size, Image.BILINEAR)

        # Different gamma values simulate level / curve sweeps
        gammas = [0.5, 0.8, 1.0, 1.2, 1.5]
        panels = []

        for g in gammas:
            panel = img.point(lambda p, g=g: int(255 * ((p / 255.0) ** g)))
            panels.append(panel)

        w, h = img.size
        sweep = Image.new("L", (w * len(panels), h))
        for i, p in enumerate(panels):
            sweep.paste(p, (i * w, 0))

        sweep_rgb = sweep.convert("RGB")
        self.result_pixmap_original = pil_to_qpixmap(sweep_rgb)
        self.update_display_sizes()

        self.result_text.clear()
        self.result_text.append(
            "Level Sweep (gamma variations):\n\n"
            "Panels from left to right show different gamma mappings:\n"
            f"  Gammas: {', '.join(str(g) for g in gammas)}\n\n"
            "Use this to visually probe shadow and highlight regions; artifacts\n"
            "may become more evident in certain tonal ranges under specific gamma\n"
            "adjustments."
        )

    # -----------------------
    # ICC profile info
    # -----------------------
    def show_icc_profile(self):
        if not self._require_image():
            return

        img = self.current_pil_image
        icc = img.info.get("icc_profile")

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("ICC profile has no image output")
        self.update_display_sizes()

        lines = []
        lines.append("ICC Profile Information:\n")
        if not icc:
            lines.append("No ICC profile embedded.")
        else:
            lines.append(f"ICC profile size: {len(icc)} bytes\n")
            try:
                from PIL import ImageCms

                profile = ImageCms.ImageCmsProfile(io.BytesIO(icc))
                info = getattr(profile, "profile", None)
                if info:
                    lines.append(f"Profile description: {info.get('desc', 'N/A')}")
                    lines.append(f"Manufacturer: {info.get('manufacturer', 'N/A')}")
                    lines.append(f"Model: {info.get('model', 'N/A')}")
                else:
                    lines.append("Parsed ICC profile, but no extra textual info available.")
            except Exception as e:
                lines.append(f"Could not parse ICC profile in detail: {e}")

        self.result_text.clear()
        self.result_text.append("\n".join(lines))

    # -----------------------
    # Strings (printable sequences)
    # -----------------------
    def show_strings(self):
        if not self._require_image():
            return

        path = self.current_image_path
        max_output = 200  # first N strings

        self.result_pixmap_original = None
        self.result_image_label.clear()
        self.result_image_label.setText("Strings has no image output")
        self.update_display_sizes()

        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Strings Error", f"Failed to read file:\n{e}")
            return

        printable = set(string.printable)
        min_len = 4
        current = []
        strings_found = []

        for b in data:
            ch = chr(b)
            if ch in printable and ch not in "\r\n":
                current.append(ch)
            else:
                if len(current) >= min_len:
                    strings_found.append("".join(current))
                current = []
        if len(current) >= min_len:
            strings_found.append("".join(current))

        header = [
            "Printable Strings (heuristic, length ≥ 4):\n",
            f"File: {path}",
            f"Total strings found: {len(strings_found)}",
            f"Showing first {max_output} entries:\n"
        ]

        out = header + strings_found[:max_output]
        self.result_text.clear()
        self.result_text.append("\n".join(out))

def main():
    app = QApplication(sys.argv)
    window = ForensicsApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
