#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyQt5 VoIP Readiness Assessment Tool

Layout:
- Dashboard:
  - Pie chart: how many metrics are within thresholds vs outside
  - History grid: all test PROBES (each of the 20 packets)
- Active Test:
  - ICMP or RTP+DSCP mode
  - Live metrics + latency graph (pyqtgraph)
  - Traffic table: one row per PROBE with IP / Mode / MOS / Progress bar
- Configuration:
  - Thresholds
- Logs

Behavior:
- Each test run sends 20 total probes (ICMP or RTP), one per second.
- Every probe is added to:
  - Active Test traffic list
  - Dashboard history list

Requirements:
    pip install pyqt5 pyqtgraph matplotlib
"""

import sys
import os
import csv
import time
import threading
import statistics
import subprocess
import socket
import struct
from dataclasses import dataclass, asdict
from datetime import datetime

from PyQt5.QtCore import (
    Qt,
    pyqtSignal,
    QObject,
    QSettings,
)
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QSpinBox,
    QComboBox,
    QDoubleSpinBox,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QTextEdit,
    QMessageBox,
    QGroupBox,
    QFormLayout,
    QCheckBox,
)

import pyqtgraph as pg
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# ----------------------------- Data Models ----------------------------- #

@dataclass
class VoipTestConfig:
    target_host: str
    test_duration_sec: int
    codec: str
    packet_rate: int  # kept for UI, not used in fixed-count mode
    jitter_buffer_ms: int
    use_icmp_ping: bool = True
    rtp_port: int = 5004
    dscp: int = 46  # DSCP (default EF)

@dataclass
class VoipMetrics:
    timestamp: datetime
    target_host: str
    codec: str
    avg_latency_ms: float
    max_latency_ms: float
    jitter_ms: float
    packet_loss_pct: float
    mos: float
    r_factor: float
    packets_sent: int
    packets_received: int

    def to_row(self):
        return [
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            self.target_host,
            self.codec,
            f"{self.avg_latency_ms:.2f}",
            f"{self.max_latency_ms:.2f}",
            f"{self.jitter_ms:.2f}",
            f"{self.packet_loss_pct:.2f}",
            f"{self.mos:.2f}",
            f"{self.r_factor:.1f}",
            str(self.packets_sent),
            str(self.packets_received),
        ]

# ----------------------------- Worker ----------------------------- #

class TestWorker(QObject):
    # sent, recv, avg_lat, max_lat, jitter, loss_pct, mos
    progress = pyqtSignal(int, int, float, float, float, float, float)
    finished = pyqtSignal(VoipMetrics)
    log = pyqtSignal(str)

    def __init__(self, config: VoipTestConfig, thresholds: dict):
        super().__init__()
        self.config = config
        self.thresholds = thresholds
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    def run(self):
        if self.config.use_icmp_ping:
            self._run_icmp_mode()
        else:
            self._run_rtp_mode()

    # ------------------------ ICMP MODE ------------------------ #

    def _run_icmp_mode(self):
        self.log.emit(
            f"Starting ICMP test to {self.config.target_host} "
            f"(20 probes, 1 per second)."
        )

        rtts = []
        packets_sent = 0
        packets_received = 0
        total_packets = 20
        interval_sec = 1.0

        while packets_sent < total_packets and not self._stop_flag.is_set():
            rtt = self._ping_once(self.config.target_host)
            packets_sent += 1
            if rtt is not None:
                rtts.append(rtt)
                packets_received += 1

            if rtts:
                avg_latency = sum(rtts) / len(rtts)
                max_latency = max(rtts)
                jitter = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
                loss_pct = 100.0 * (packets_sent - packets_received) / packets_sent
                mos, r_factor = self._estimate_mos(avg_latency, jitter, loss_pct)
            else:
                avg_latency = max_latency = jitter = loss_pct = mos = r_factor = 0.0

            self.progress.emit(
                packets_sent,
                packets_received,
                avg_latency,
                max_latency,
                jitter,
                loss_pct,
                mos,
            )
            time.sleep(interval_sec)

        if rtts:
            avg_latency = sum(rtts) / len(rtts)
            max_latency = max(rtts)
            jitter = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
            loss_pct = 100.0 * (packets_sent - packets_received) / packets_sent
            mos, r_factor = self._estimate_mos(avg_latency, jitter, loss_pct)
        else:
            avg_latency = max_latency = jitter = loss_pct = mos = r_factor = 0.0

        metrics = VoipMetrics(
            timestamp=datetime.now(),
            target_host=self.config.target_host,
            codec=self.config.codec,
            avg_latency_ms=avg_latency,
            max_latency_ms=max_latency,
            jitter_ms=jitter,
            packet_loss_pct=loss_pct,
            mos=mos,
            r_factor=r_factor,
            packets_sent=packets_sent,
            packets_received=packets_received,
        )
        self.log.emit("ICMP test finished.")
        self.finished.emit(metrics)

    def _ping_once(self, host: str):
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", "1000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", host]

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if proc.returncode != 0:
                self.log.emit(f"Ping failed: {proc.stderr.strip()}")
                return None

            out = proc.stdout
            for line in out.splitlines():
                if "time=" in line.lower():
                    part = line.lower().split("time=")[1]
                    val = ""
                    for ch in part:
                        if ch.isdigit() or ch == ".":
                            val += ch
                        else:
                            break
                    if val:
                        return float(val)
        except Exception as e:
            self.log.emit(f"Ping error: {e}")
        return None

    # ------------------------ RTP MODE ------------------------ #

    def _set_dscp(self, sock):
        try:
            dscp_val = int(self.config.dscp) & 0x3F
            tos = dscp_val << 2
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
            self.log.emit(f"Set DSCP={dscp_val} (TOS={tos}) on UDP socket.")
        except Exception as e:
            self.log.emit(f"Failed to set DSCP: {e}")

    def _run_rtp_mode(self):
        self.log.emit(
            f"Starting RTP test to {self.config.target_host}:{self.config.rtp_port} "
            f"(20 probes, 1 per second, DSCP={self.config.dscp})."
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        self._set_dscp(sock)

        rtts = []
        packets_sent = 0
        packets_received = 0
        seq = 0
        total_packets = 20
        interval_sec = 1.0

        while packets_sent < total_packets and not self._stop_flag.is_set():
            seq += 1
            ts_send = time.time()
            payload = struct.pack("!I d", seq, ts_send)

            try:
                sock.sendto(payload, (self.config.target_host, self.config.rtp_port))
                packets_sent += 1

                try:
                    data, _ = sock.recvfrom(2048)
                    if len(data) >= 12:
                        r_seq, r_ts = struct.unpack("!I d", data[:12])
                        if r_seq == seq:
                            rtt_ms = (time.time() - r_ts) * 1000.0
                            rtts.append(rtt_ms)
                            packets_received += 1
                except socket.timeout:
                    pass

            except Exception as e:
                self.log.emit(f"RTP send/recv error: {e}")

            if rtts:
                avg_latency = sum(rtts) / len(rtts)
                max_latency = max(rtts)
                jitter = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
                loss_pct = 100.0 * (packets_sent - packets_received) / packets_sent
                mos, r_factor = self._estimate_mos(avg_latency, jitter, loss_pct)
            else:
                avg_latency = max_latency = jitter = loss_pct = mos = r_factor = 0.0

            self.progress.emit(
                packets_sent,
                packets_received,
                avg_latency,
                max_latency,
                jitter,
                loss_pct,
                mos,
            )
            time.sleep(interval_sec)

        if rtts:
            avg_latency = sum(rtts) / len(rtts)
            max_latency = max(rtts)
            jitter = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
            loss_pct = 100.0 * (packets_sent - packets_received) / packets_sent
            mos, r_factor = self._estimate_mos(avg_latency, jitter, loss_pct)
        else:
            avg_latency = max_latency = jitter = loss_pct = mos = r_factor = 0.0

        metrics = VoipMetrics(
            timestamp=datetime.now(),
            target_host=self.config.target_host,
            codec=self.config.codec,
            avg_latency_ms=avg_latency,
            max_latency_ms=max_latency,
            jitter_ms=jitter,
            packet_loss_pct=loss_pct,
            mos=mos,
            r_factor=r_factor,
            packets_sent=packets_sent,
            packets_received=packets_received,
        )
        self.log.emit("RTP test finished.")
        self.finished.emit(metrics)

    # ------------------------ MOS Estimation ------------------------ #

    def _estimate_mos(self, latency_ms, jitter_ms, loss_pct):
        delay = latency_ms + 2 * jitter_ms
        if delay < 0:
            delay = 0
        I_delay = 0.024 * delay + 0.11 * max(delay - 177.3, 0)

        I_eff = 30 * (loss_pct / 100.0)

        R0 = 94.2
        R = R0 - I_delay - I_eff
        R = max(0, min(100, R))

        if R < 0:
            mos = 1.0
        elif R > 100:
            mos = 4.5
        else:
            mos = 1 + (0.035 * R) + (R * (R - 60) * (100 - R) * 7e-6)

        mos = max(1.0, min(4.5, mos))
        return mos, R

# ----------------------------- Dashboard ----------------------------- #

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # ---------- Top panel: Summary table + Pie chart ---------- #
        top_layout = QHBoxLayout()

        # Summary table
        summary_group = QGroupBox("Last Test Summary")
        summary_layout = QVBoxLayout()
        self.summary_table = QTableWidget(5, 2)
        self.summary_table.setHorizontalHeaderLabels(["Metric", "Value"])
        metrics_labels = [
            "Readiness",
            "Avg Latency (ms)",
            "Jitter (ms)",
            "Loss (%)",
            "MOS",
        ]
        for i, label in enumerate(metrics_labels):
            self.summary_table.setItem(i, 0, QTableWidgetItem(label))
            self.summary_table.setItem(i, 1, QTableWidgetItem("-"))

        self.summary_table.horizontalHeader().setStretchLastSection(True)
        self.summary_table.verticalHeader().setVisible(False)
        self.summary_table.setEditTriggers(QTableWidget.NoEditTriggers)
        summary_layout.addWidget(self.summary_table)
        summary_layout.setContentsMargins(20, 30, 20, 20)
        summary_group.setLayout(summary_layout)

        # Pie chart
        pie_group = QGroupBox("Readiness Breakdown")
        pie_layout = QVBoxLayout()
        self.fig = Figure(figsize=(3, 3))
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_facecolor('#2b3038')
        self.ax.set_facecolor('#2b3038')
        self._init_pie()
        pie_layout.addWidget(self.canvas)
        pie_layout.setContentsMargins(20, 30, 20, 20)

        pie_group.setLayout(pie_layout)

        # Put summary and pie side by side
        top_layout.addWidget(summary_group, 1)
        top_layout.addWidget(pie_group, 1)

        # ---------- Bottom panel: History records grid (all probes) ---------- #
        history_group = QGroupBox("History (All Probes)")
        history_layout = QVBoxLayout()
        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels([
            "Time",
            "Target",
            "Codec",
            "Avg Lat (ms)",
            "Max Lat (ms)",
            "Jitter (ms)",
            "Loss (%)",
            "MOS",
            "R-Factor",
            "Sent",
            "Recv",
        ])
        self.table.horizontalHeader().setStretchLastSection(True)

        self.btn_export = QPushButton("Export to CSV")
        self.btn_export.clicked.connect(self._export_csv)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)
        btn_layout.addWidget(self.btn_export)

        history_layout.addWidget(self.table)
        history_layout.setContentsMargins(20, 30, 20, 20)
        history_layout.addLayout(btn_layout)
        history_group.setLayout(history_layout)

        # ---------- Assemble main layout ---------- #
        main_layout.addLayout(top_layout)
        main_layout.addWidget(history_group)
        self.setLayout(main_layout)

    def _init_pie(self):
        self.ax.clear()
        self.ax.set_facecolor('#2b3038')
        self.ax.text(
            0.5, 0.5, "No data",
            ha='center', va='center',
            color='#e0e0e0',
            fontsize=10,
        )
        self.ax.axis('off')
        self.canvas.draw_idle()

    def add_result(self, metrics: VoipMetrics):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, val in enumerate(metrics.to_row()):
            self.table.setItem(row, col, QTableWidgetItem(val))

    def update_pie(self, metrics: VoipMetrics, thresholds: dict):
        # Calculate pass/fail and readiness
        ok_latency = metrics.avg_latency_ms <= thresholds["latency_ms"]
        ok_jitter = metrics.jitter_ms <= thresholds["jitter_ms"]
        ok_loss = metrics.packet_loss_pct <= thresholds["loss_pct"]
        ok_mos = metrics.mos >= thresholds["mos_min"]

        pass_count = sum([ok_latency, ok_jitter, ok_loss, ok_mos])
        fail_count = 4 - pass_count
        readiness = "READY" if all([ok_latency, ok_jitter, ok_loss, ok_mos]) else "NOT READY"

        # ---- Update summary table ----
        if self.summary_table is not None:
            self.summary_table.setItem(0, 1, QTableWidgetItem(readiness))
            self.summary_table.setItem(
                1, 1, QTableWidgetItem(f"{metrics.avg_latency_ms:.2f}")
            )
            self.summary_table.setItem(
                2, 1, QTableWidgetItem(f"{metrics.jitter_ms:.2f}")
            )
            self.summary_table.setItem(
                3, 1, QTableWidgetItem(f"{metrics.packet_loss_pct:.2f}")
            )
            self.summary_table.setItem(
                4, 1, QTableWidgetItem(f"{metrics.mos:.2f}")
            )

        # ---- Update pie chart ----
        self.ax.clear()
        self.ax.set_facecolor('#2b3038')

        if pass_count + fail_count == 0:
            self._init_pie()
            return

        sizes = [pass_count, fail_count]
        labels = ["Within Thresh", "Outside Thresh"]
        colors = ["#44a86a", "#d9534f"]

        wedges, texts, autotexts = self.ax.pie(
            sizes,
            labels=labels,
            colors=colors,
            autopct="%1.0f%%",
            textprops={"color": "#e0e0e0"},
        )

        for text in texts:
            text.set_color("#e0e0e0")
        for autotext in autotexts:
            autotext.set_color("#e0e0e0")

        self.ax.set_title("Readiness Breakdown", color="#e0e0e0")
        self.canvas.draw_idle()

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export History", "", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            headers = [self.table.horizontalHeaderItem(i).text()
                       for i in range(self.table.columnCount())]
            writer.writerow(headers)
            for row in range(self.table.rowCount()):
                values = []
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    values.append(item.text() if item else "")
                writer.writerow(values)
# ----------------------------- Active Test ----------------------------- #

class ActiveTestTab(QWidget):
    start_test = pyqtSignal(VoipTestConfig)
    stop_test = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.latency_data = []
        self.total_packets = 20
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # --- Test Configuration ---
        cfg_group = QGroupBox("Test Configuration")
        cfg_layout = QFormLayout()
        cfg_layout.setContentsMargins(20, 30, 20, 20)

        self.txt_target = QLineEdit("127.0.0.1")
        self.spin_duration = QSpinBox()
        self.spin_duration.setRange(5, 3600)
        self.spin_duration.setValue(30)

        self.combo_codec = QComboBox()
        self.combo_codec.addItems(["G.711", "G.729", "Opus", "G.722"])

        self.spin_pkt_rate = QSpinBox()
        self.spin_pkt_rate.setRange(1, 1000)
        self.spin_pkt_rate.setValue(10)

        self.spin_jitter_buf = QSpinBox()
        self.spin_jitter_buf.setRange(0, 300)
        self.spin_jitter_buf.setValue(50)

        self.spin_rtp_port = QSpinBox()
        self.spin_rtp_port.setRange(1024, 65535)
        self.spin_rtp_port.setValue(5004)

        self.combo_dscp = QComboBox()
        self.combo_dscp.addItem("Best Effort (0)", 0)
        self.combo_dscp.addItem("EF (46) - Voice", 46)
        self.combo_dscp.addItem("AF31 (26)", 26)
        self.combo_dscp.addItem("CS3 (24)", 24)

        self.chk_icmp = QCheckBox("Use ICMP ping instead of RTP (demo mode)")
        self.chk_icmp.setChecked(False)

        cfg_layout.addRow("Target Host/IP:", self.txt_target)
        cfg_layout.addRow("Duration (sec):", self.spin_duration)
        cfg_layout.addRow("Codec:", self.combo_codec)
        cfg_layout.addRow("Packet Rate (pps):", self.spin_pkt_rate)
        cfg_layout.addRow("Jitter Buffer (ms):", self.spin_jitter_buf)
        cfg_layout.addRow("RTP Port:", self.spin_rtp_port)
        cfg_layout.addRow("DSCP:", self.combo_dscp)
        cfg_layout.addRow("", self.chk_icmp)

        cfg_group.setLayout(cfg_layout)

        # --- Live Metrics + Graph ---
        live_group = QGroupBox("Live Metrics")
        live_layout = QGridLayout()
        live_layout.setContentsMargins(20, 30, 20, 20)

        self.lbl_latency = QLabel("Avg Latency: - ms")
        self.lbl_jitter = QLabel("Jitter: - ms")
        self.lbl_loss = QLabel("Loss: - %")
        self.lbl_mos = QLabel("MOS: -")

        self.mos_bar = QProgressBar()
        self.mos_bar.setRange(0, 450)
        self.mos_bar.setFormat("MOS (scaled): %v")

        self.latency_plot = pg.PlotWidget()
        self.latency_plot.setBackground('#2b3038')
        self.latency_plot.showGrid(x=True, y=True, alpha=0.2)
        self.latency_plot.setLabel('left', 'Latency', units='ms')
        self.latency_plot.setLabel('bottom', 'Sample')
        self.latency_curve = self.latency_plot.plot(
            pen=pg.mkPen('#44a86a', width=2)
        )

        live_layout.addWidget(self.lbl_latency, 0, 0)
        live_layout.addWidget(self.lbl_jitter, 0, 1)
        live_layout.addWidget(self.lbl_loss, 1, 0)
        live_layout.addWidget(self.lbl_mos, 1, 1)
        live_layout.addWidget(self.mos_bar, 2, 0, 1, 2)
        live_layout.addWidget(self.latency_plot, 3, 0, 1, 2)

        live_group.setLayout(live_layout)

        # --- Traffic Table (IP / Mode / MOS / Progress) ---
        self.traffic_table = QTableWidget(0, 4)
        self.traffic_table.setHorizontalHeaderLabels(
            ["Target", "Mode", "MOS", "Status"]
        )
        self.traffic_table.horizontalHeader().setStretchLastSection(True)

        # --- Controls ---
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("Start Test")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)

        self.btn_start.clicked.connect(self._on_start)
        self.btn_stop.clicked.connect(lambda: self.stop_test.emit())

        btn_layout.addStretch(1)
        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)

        main_layout.addWidget(cfg_group)
        main_layout.addWidget(live_group)
        main_layout.addWidget(self.traffic_table)
        main_layout.addLayout(btn_layout)
        self.setLayout(main_layout)

    def _on_start(self):
        cfg = VoipTestConfig(
            target_host=self.txt_target.text().strip(),
            test_duration_sec=self.spin_duration.value(),
            codec=self.combo_codec.currentText(),
            packet_rate=self.spin_pkt_rate.value(),
            jitter_buffer_ms=self.spin_jitter_buf.value(),
            use_icmp_ping=self.chk_icmp.isChecked(),
            rtp_port=self.spin_rtp_port.value(),
            dscp=self.combo_dscp.currentData(),
        )
        if not cfg.target_host:
            QMessageBox.warning(self, "Validation", "Please enter a target host/IP.")
            return

        self.latency_data = []
        self.latency_curve.clear()
        self.traffic_table.setRowCount(0)

        self.start_test.emit(cfg)

    def set_running(self, running: bool):
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)

    def update_live(self, latency, jitter, loss, mos):
        self.lbl_latency.setText(f"Avg Latency: {latency:.2f} ms")
        self.lbl_jitter.setText(f"Jitter: {jitter:.2f} ms")
        self.lbl_loss.setText(f"Loss: {loss:.2f} %")
        self.lbl_mos.setText(f"MOS: {mos:.2f}")
        self.mos_bar.setValue(int(mos * 100))

        self.latency_data.append(latency)
        if len(self.latency_data) > 300:
            self.latency_data = self.latency_data[-300:]
        self.latency_curve.setData(self.latency_data)

    def add_probe_row(self, target: str, mode: str, seq: int, mos: float):
        row = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)
        self.traffic_table.setItem(row, 0, QTableWidgetItem(target))
        self.traffic_table.setItem(row, 1, QTableWidgetItem(mode))
        self.traffic_table.setItem(row, 2, QTableWidgetItem(f"{mos:.2f}"))

        bar = QProgressBar()
        bar.setRange(0, 100)
        if self.total_packets > 0:
            val = int(seq / self.total_packets * 100)
        else:
            val = 0
        bar.setValue(val)
        bar.setFormat(f"{seq}/{self.total_packets}")
        self.traffic_table.setCellWidget(row, 3, bar)

# ----------------------------- Config & Logs ----------------------------- #

class ConfigTab(QWidget):
    thresholds_changed = pyqtSignal(dict)

    def __init__(self, settings: QSettings):
        super().__init__()
        self.settings = settings
        self._build_ui()
        self._load()

    def _build_ui(self):
        layout = QFormLayout(self)

        self.spin_latency_warn = QDoubleSpinBox()
        self.spin_latency_warn.setRange(0, 1000)
        self.spin_latency_warn.setValue(150.0)

        self.spin_jitter_warn = QDoubleSpinBox()
        self.spin_jitter_warn.setRange(0, 1000)
        self.spin_jitter_warn.setValue(30.0)

        self.spin_loss_warn = QDoubleSpinBox()
        self.spin_loss_warn.setRange(0, 100)
        self.spin_loss_warn.setDecimals(2)
        self.spin_loss_warn.setValue(1.0)

        self.spin_mos_min = QDoubleSpinBox()
        self.spin_mos_min.setRange(1.0, 4.5)
        self.spin_mos_min.setSingleStep(0.1)
        self.spin_mos_min.setValue(3.5)

        self.btn_save = QPushButton("Save Thresholds")
        self.btn_save.clicked.connect(self._save)

        layout.addRow("Max Avg Latency (ms):", self.spin_latency_warn)
        layout.addRow("Max Jitter (ms):", self.spin_jitter_warn)
        layout.addRow("Max Loss (%):", self.spin_loss_warn)
        layout.addRow("Min MOS:", self.spin_mos_min)
        layout.addRow("", self.btn_save)

        self.setLayout(layout)

    def _load(self):
        self.spin_latency_warn.setValue(float(self.settings.value("th_latency", 150.0)))
        self.spin_jitter_warn.setValue(float(self.settings.value("th_jitter", 30.0)))
        self.spin_loss_warn.setValue(float(self.settings.value("th_loss", 1.0)))
        self.spin_mos_min.setValue(float(self.settings.value("th_mos", 3.5)))

    def _save(self):
        self.settings.setValue("th_latency", self.spin_latency_warn.value())
        self.settings.setValue("th_jitter", self.spin_jitter_warn.value())
        self.settings.setValue("th_loss", self.spin_loss_warn.value())
        self.settings.setValue("th_mos", self.spin_mos_min.value())
        self.settings.sync()
        thresholds = self.get_thresholds()
        self.thresholds_changed.emit(thresholds)
        QMessageBox.information(self, "Config", "Thresholds saved.")

    def get_thresholds(self):
        return {
            "latency_ms": self.spin_latency_warn.value(),
            "jitter_ms": self.spin_jitter_warn.value(),
            "loss_pct": self.spin_loss_warn.value(),
            "mos_min": self.spin_mos_min.value(),
        }

class LogTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text)
        self.setLayout(layout)

    def append(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.text.append(f"[{ts}] {msg}")

# ----------------------------- Main Window ----------------------------- #

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("ExampleCorp", "VoipReadiness")
        self.worker_thread = None
        self.worker = None
        self.current_config: VoipTestConfig | None = None
        self.thresholds = {
            "latency_ms": 150.0,
            "jitter_ms": 30.0,
            "loss_pct": 1.0,
            "mos_min": 3.5,
        }

        self._build_ui()
        self._apply_style()
        self._load_thresholds()

    def _build_ui(self):
        self.setWindowTitle("VoIP Readiness Assessment")
        self.resize(2000, 1300)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tab_dashboard = DashboardTab()
        self.tab_active = ActiveTestTab()
        self.tab_config = ConfigTab(self.settings)
        self.tab_log = LogTab()

        self.tabs.addTab(self.tab_dashboard, "Dashboard")
        self.tabs.addTab(self.tab_active, "Active Test")
        self.tabs.addTab(self.tab_config, "Configuration")
        self.tabs.addTab(self.tab_log, "Logs")

        self.tab_active.start_test.connect(self.start_test)
        self.tab_active.stop_test.connect(self.stop_test)
        self.tab_config.thresholds_changed.connect(self._on_thresholds_changed)

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #20252b;
            }
            QWidget {
                color: #e0e0e0;
                background-color: #2b3038;
                font-family: Segoe UI, Arial;
                font-size: 10pt;
            }
            QGroupBox {
                border: 1px solid #3b414b;
                margin-top: 6px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
            }
            QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit {
                background-color: #1e2228;
                border: 1px solid #3b414b;
                padding: 2px;
            }
            QPushButton {
                background-color: #3a945b;
                border: 1px solid #2d7346;
                padding: 4px 10px;
                color: white;
            }
            QPushButton:hover {
                background-color: #44a86a;
            }
            QPushButton:disabled {
                background-color: #555a61;
                border-color: #444a51;
            }
            QTabBar::tab {
                background: #2b3038;
                padding: 6px 14px;
            }
            QTabBar::tab:selected {
                background: #3b414b;
            }
            QTableWidget {
                gridline-color: #3b414b;
            }
            QHeaderView::section {
                background-color: #3b414b;
                padding: 4px;
                border: 1px solid #20252b;
            }
        """)

    def _load_thresholds(self):
        self.thresholds = self.tab_config.get_thresholds()

    def _on_thresholds_changed(self, th: dict):
        self.thresholds = th
        self.tab_log.append("Thresholds updated.")

    def log(self, msg: str):
        self.tab_log.append(msg)

    # ------------------- Test orchestration ------------------- #

    def start_test(self, config: VoipTestConfig):
        if self.worker_thread is not None:
            QMessageBox.warning(self, "Test Running",
                                "A test is already running. Stop it first.")
            return

        self.current_config = config
        self.worker = TestWorker(config, self.thresholds)
        self.worker_thread = threading.Thread(target=self.worker.run, daemon=True)

        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.log.connect(self.log)

        self.tab_active.set_running(True)
        self.log(f"Launching test: {asdict(config)}")

        self.worker_thread.start()

    def stop_test(self):
        if self.worker is not None:
            self.log("Stopping test...")
            self.worker.stop()

    def _on_progress(
        self,
        packets_sent: int,
        packets_received: int,
        avg_latency: float,
        max_latency: float,
        jitter: float,
        loss: float,
        mos: float,
    ):
        # Update Active Test live metrics and traffic list
        self.tab_active.update_live(avg_latency, jitter, loss, mos)
        if self.current_config is not None:
            mode = "ICMP" if self.current_config.use_icmp_ping else "RTP"
            self.tab_active.add_probe_row(
                self.current_config.target_host,
                mode,
                packets_sent,
                mos,
            )

            # Add this probe to history as a row
            metrics = VoipMetrics(
                timestamp=datetime.now(),
                target_host=self.current_config.target_host,
                codec=self.current_config.codec,
                avg_latency_ms=avg_latency,
                max_latency_ms=max_latency,
                jitter_ms=jitter,
                packet_loss_pct=loss,
                mos=mos,
                r_factor=0.0,  # per-probe R-factor not strictly needed; can be 0 or recomputed
                packets_sent=packets_sent,
                packets_received=packets_received,
            )
            self.tab_dashboard.add_result(metrics)

    def _on_finished(self, metrics: VoipMetrics):
        self.tab_active.set_running(False)

        # Update pie chart with final summary metrics
        self.tab_dashboard.update_pie(metrics, self.thresholds)

        self.worker = None
        self.worker_thread = None
        self.current_config = None

        ok_latency = metrics.avg_latency_ms <= self.thresholds["latency_ms"]
        ok_jitter = metrics.jitter_ms <= self.thresholds["jitter_ms"]
        ok_loss = metrics.packet_loss_pct <= self.thresholds["loss_pct"]
        ok_mos = metrics.mos >= self.thresholds["mos_min"]

        readiness = "READY" if all([ok_latency, ok_jitter, ok_loss, ok_mos]) else "NOT READY"
        msg = (
            f"VoIP Readiness: {readiness}\n\n"
            f"Avg Latency: {metrics.avg_latency_ms:.2f} ms "
            f"(threshold {self.thresholds['latency_ms']:.2f})\n"
            f"Jitter: {metrics.jitter_ms:.2f} ms "
            f"(threshold {self.thresholds['jitter_ms']:.2f})\n"
            f"Loss: {metrics.packet_loss_pct:.2f} % "
            f"(threshold {self.thresholds['loss_pct']:.2f})\n"
            f"MOS: {metrics.mos:.2f} "
            f"(threshold {self.thresholds['mos_min']:.2f})\n"
        )
        self.log(msg.replace("\n", " | "))
        QMessageBox.information(self, "Test Result", msg)

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.stop()
        super().closeEvent(event)

# ----------------------------- Entry Point ----------------------------- #

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()