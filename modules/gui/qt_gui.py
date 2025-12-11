# modules/core/qt_gui.py
from __future__ import annotations

import os
import sys
import re
import json
import time
import ipaddress
import logging
import warnings
from typing import Optional, List, Callable, Any

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtPrintSupport import QPrinter

SCAPY_OK = False
AsyncSniffer = None
conf = None
PcapNgWriter = None
RawPcapNgWriter = None
try:
    from scapy.all import AsyncSniffer, conf
    try:
        from scapy.utils import PcapNgWriter as _PNW
        PcapNgWriter = _PNW
    except Exception:
        PcapNgWriter = None
    try:
        from scapy.utils import RawPcapNgWriter as _RPNW
        RawPcapNgWriter = _RPNW
    except Exception:
        RawPcapNgWriter = None
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

for name in ("scapy.runtime", "scapy.utils", "scapy"):
    logging.getLogger(name).setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=r".*PcapNgWriter: unknown LL type.*")

#  경로 
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(os.path.dirname(HERE))
RESULT_DIR = os.path.join(PROJECT, "result")
os.makedirs(RESULT_DIR, exist_ok=True)
CACHE_PCAP = os.path.join(RESULT_DIR, "cache_temp_scan.pcapng")
LAYOUT_INI = os.path.join(HERE, "qt_layout.ini")

# 코어 연결
CORE_OK = True
try:
    from modules.core.models import AppConfig, ScanJob, ScanOptions
    from modules.core.scheduler import SimpleScheduler
except Exception:
    CORE_OK = False

    class AppConfig:  # type: ignore
        def to_dict(self): return {}

    class ScanOptions:  # type: ignore
        def __init__(self, **kw): self.__dict__.update(kw)

    class ScanJob:  # type: ignore
        def __init__(self, **kw): self.__dict__.update(kw)

    class SimpleScheduler:  # type: ignore
        def __init__(self, **kw): pass
        def add_job(self, *a, **k): pass
        def run(self): time.sleep(1.0)

# utill 
def parse_ports_spec(text: str) -> List[int]:
    text = (text or "").strip()
    if not text:
        return []
    toks = re.split(r"[\s,]+", text)
    out = set()
    for t in toks:
        if not t:
            continue
        try:
            if "-" in t:
                a, b = t.split("-", 1)
                a, b = int(a), int(b)
                if a > b: a, b = b, a
                out.update(range(a, b + 1))
            else:
                out.add(int(t))
        except Exception:
            # 숫자 변환 실패는 무시
            continue
    return [p for p in sorted(out) if 1 <= p <= 65535]

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def is_loopback(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).is_loopback
    except Exception:
        return False

def safe_open(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

# 패킷 캡처 
class PacketCapture(QtCore.QObject):
    packet = QtCore.Signal(dict)     # {"time","src","dst","proto","info"}
    info   = QtCore.Signal(str)
    error  = QtCore.Signal(str)
    started = QtCore.Signal()
    first_packet = QtCore.Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._sniffer = None
        self._writer = None
        self._writer_ready = False
        self._seen = 0

    def _create_writer(self) -> bool:
      
        if self._writer is not None and self._writer_ready:
            return True

        self._writer = None
        self._writer_ready = False

        try:
           
            if PcapNgWriter is not None:
                try:
                    self._writer = PcapNgWriter(CACHE_PCAP, sync=True)
                except TypeError:
                    # 구버전 호환 생각
                    self._writer = PcapNgWriter(CACHE_PCAP)
            elif RawPcapNgWriter is not None:
                self._writer = RawPcapNgWriter(CACHE_PCAP, linktype=1)
        except Exception as e:
            self._writer = None
            self.error.emit(f"pcap writer 생성 실패: {e}")

        self._writer_ready = self._writer is not None
        return self._writer_ready

    def start(self, iface: Optional[str], bpf: Optional[str], reuse_file: bool = False):
        # 파일 정리
        try:
            if os.path.exists(CACHE_PCAP) and not reuse_file:
                os.remove(CACHE_PCAP)
        except Exception:
            pass

        # 카운터/상태 리셋
        self._seen = 0
        self._writer = None
        self._writer_ready = False

        if not SCAPY_OK:
            self.info.emit("Scapy 미설치: 캡처 비활성")
            return

        # pcap writer를 미리 한 번 생성 시도 (실패해도 on_pkt에서 재시도)
        self._create_writer()

        use_iface = iface or (conf.iface if SCAPY_OK else None)

        def on_pkt(pkt):
            # writer가 아직 준비 안됐으면 재시도
            if not self._writer_ready:
                self._create_writer()
            # 파일 기록
            try:
                if self._writer:
                    self._writer.write(pkt)
            except Exception as e:
                # 한 번 오류가 나면 다음 패킷에서 다시 생성 시도
                self._writer = None
                self._writer_ready = False
                self.error.emit(f"pcap write 실패, 재시도 예정: {e}")

            # 화면 표시
            try:
                ts   = time.strftime("%H:%M:%S")
                src  = getattr(pkt, "src", getattr(pkt[0][1], "src", "-"))
                dst  = getattr(pkt, "dst", getattr(pkt[0][1], "dst", "-"))
                name = getattr(pkt, "name", "pkt")
                info = pkt.summary() if hasattr(pkt, "summary") else "packet"
                self.packet.emit({"time": ts, "src": src, "dst": dst, "proto": name, "info": info})
                if self._seen == 0:
                    self.first_packet.emit()
                self._seen += 1
            except Exception:
                pass

        try:
            kwargs = {}
            if use_iface:
                kwargs["iface"] = use_iface
            self._sniffer = AsyncSniffer(filter=bpf or None, prn=on_pkt, store=False, **kwargs)
            self._sniffer.start()
            self.started.emit()
            self.info.emit(f"pcap 캡처 시작 (iface={use_iface}, bpf={bpf})")
        except Exception as e:
            self._sniffer = None
            self.error.emit(f"pcap sniffer 시작 실패: {e}")

    def stop(self):
        # 캡처 중단
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        # 파일 flush/close
        if self._writer:
            try:
                if hasattr(self._writer, "flush"):
                    self._writer.flush()
                if hasattr(self._writer, "close"):
                    self._writer.close()
            except Exception:
                pass
        self._writer = None
        self._writer_ready = False

        self.info.emit("pcap 캡처 중지")

    def packets_seen(self) -> int:
        return int(self._seen)

        # 파일 처리
        try:
            if os.path.exists(CACHE_PCAP) and not reuse_file:
                os.remove(CACHE_PCAP)
        except Exception:
            pass

        # 카운터 리셋 (reuse여도 처음으로 reset 저장은 파일크기로 판단)
        self._seen = 0
        self._writer = None
        self._writer_ready = False

        if not SCAPY_OK:
            self.info.emit("Scapy 미설치: 캡처 비활성")
            return

        use_iface = iface or (conf.iface if SCAPY_OK else None)

        def on_pkt(pkt):
            if not self._writer_ready:
                self._create_writer()
            try:
                if self._writer:
                    self._writer.write(pkt)
            except Exception:
                pass
            try:
                ts   = time.strftime("%H:%M:%S")
                src  = getattr(pkt, "src", getattr(pkt[0][1], "src", "-"))
                dst  = getattr(pkt, "dst", getattr(pkt[0][1], "dst", "-"))
                name = getattr(pkt, "name", "pkt")
                info = pkt.summary() if hasattr(pkt, "summary") else "packet"
                self.packet.emit({"time": ts, "src": src, "dst": dst, "proto": name, "info": info})
                if self._seen == 0:
                    self.first_packet.emit()
                self._seen += 1
            except Exception:
                pass

        try:
            kwargs = {}
            if use_iface:
                kwargs["iface"] = use_iface
            self._sniffer = AsyncSniffer(filter=bpf or None, prn=on_pkt, store=False, **kwargs)
            self._sniffer.start()
            self.started.emit()
            self.info.emit(f"pcap 캡처 시작 (iface={use_iface}, bpf={bpf})")
        except Exception as e:
            self._sniffer = None
            self.error.emit(f"pcap sniffer 시작 실패: {e}")

    def stop(self):
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._writer:
            try:
                if hasattr(self._writer, "flush"):
                    self._writer.flush()
                if hasattr(self._writer, "close"):
                    self._writer.close()
            except Exception:
                pass
            self._writer = None
            self._writer_ready = False
        self.info.emit("pcap 캡처 중지")

    def packets_seen(self) -> int:
        return int(self._seen)

#도킹
class SafeDockWidget(QtWidgets.QDockWidget):
    def __init__(self, title: str, parent=None):
        super().__init__(title, parent)
        self.setFeatures(
            QtWidgets.QDockWidget.DockWidgetMovable
            | QtWidgets.QDockWidget.DockWidgetFloatable
            | QtWidgets.QDockWidget.DockWidgetClosable
        )

    def closeEvent(self, e: QtGui.QCloseEvent):
        e.ignore()
        self.hide()

# 컨트롤 패널
class ControlsPanel(QtWidgets.QWidget):
    rebuild_bpf   = QtCore.Signal(str)
    start_clicked = QtCore.Signal()
    stop_clicked  = QtCore.Signal()
    reset_clicked = QtCore.Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        form = QtWidgets.QFormLayout(self)
        form.setLabelAlignment(QtCore.Qt.AlignLeft)

        # 인터페이스
        self.combo_iface = QtWidgets.QComboBox()
        self._populate_interfaces()
        form.addRow("네트워크 인터페이스", self.combo_iface)

        # 호스트/포트
        self.edit_host  = QtWidgets.QLineEdit("127.0.0.1")
        self.edit_ports = QtWidgets.QLineEdit("22,80,443,8000-8100")
        form.addRow("호스트(단일 IP)", self.edit_host)
        form.addRow("포트(예: 22,80,443 또는 1-1024)", self.edit_ports)

        # 모드 (라디오)
        mrow = QtWidgets.QHBoxLayout()
        self.rad_net  = QtWidgets.QRadioButton("Network Scan")
        self.rad_mass = QtWidgets.QRadioButton("Masscan")
        self.rad_net.setChecked(True)
        mrow.addWidget(self.rad_net); mrow.addWidget(self.rad_mass)
        form.addRow("스캔", mrow)

        # Masscan 그룹
        self.mass_group = QtWidgets.QGroupBox("Masscan 옵션")
        mg = QtWidgets.QFormLayout(self.mass_group)
        self.edit_mass_rate = QtWidgets.QSpinBox(); self.edit_mass_rate.setRange(1, 10_000_000); self.edit_mass_rate.setValue(1000)
        self.edit_mass_wait = QtWidgets.QDoubleSpinBox(); self.edit_mass_wait.setRange(0.1, 600.0); self.edit_mass_wait.setSingleStep(0.1); self.edit_mass_wait.setValue(10.0)
        self.edit_mass_targets = QtWidgets.QLineEdit("")
        mg.addRow("Rate(packets/sec)", self.edit_mass_rate)
        mg.addRow("대기시간(초)", self.edit_mass_wait)
        mg.addRow("Targets(IP/CIDR/RANGE 다중)", self.edit_mass_targets)
        form.addRow(self.mass_group)

        # Network 그룹
        self.net_group = QtWidgets.QGroupBox("Network Scan 옵션")
        ng_v = QtWidgets.QVBoxLayout(self.net_group)

        proto = QtWidgets.QHBoxLayout()
        self.chk_tcp  = QtWidgets.QCheckBox("TCP"); self.chk_tcp.setChecked(True)
        self.chk_udp  = QtWidgets.QCheckBox("UDP")
        self.chk_icmp = QtWidgets.QCheckBox("ICMP")
        self.chk_dns  = QtWidgets.QCheckBox("DNS")
        for w in (self.chk_tcp, self.chk_udp, self.chk_icmp, self.chk_dns):
            proto.addWidget(w)
        ng_v.addLayout(proto)

        # TCP 옵션
        self.tcp_opts_group = QtWidgets.QGroupBox("TCP 옵션")
        tovl = QtWidgets.QVBoxLayout(self.tcp_opts_group)

        self.chk_http_probe = QtWidgets.QCheckBox("HTTP Probe 시 UA 사용")
        self.edit_ua = QtWidgets.QLineEdit("scanner-x/0.1")
        tovl.addWidget(self.chk_http_probe); tovl.addWidget(self.edit_ua)

        self.tcp_mode_box = QtWidgets.QGroupBox("TCP 모드")
        tmb = QtWidgets.QHBoxLayout(self.tcp_mode_box)
        self.rb_full = QtWidgets.QRadioButton("FULL")
        self.rb_syn  = QtWidgets.QRadioButton("SYN"); self.rb_syn.setChecked(True)
        self.rb_fin  = QtWidgets.QRadioButton("FIN")
        self.rb_null = QtWidgets.QRadioButton("NULL")
        self.rb_xmas = QtWidgets.QRadioButton("XMAS")
        for w in (self.rb_full, self.rb_syn, self.rb_fin, self.rb_null, self.rb_xmas):
            tmb.addWidget(w)
        tovl.addWidget(self.tcp_mode_box)

        self.chk_graceful = QtWidgets.QCheckBox("FULL 스캔 시 4-way 종료 사용")
        tovl.addWidget(self.chk_graceful)

        grid = QtWidgets.QGridLayout()
        grid.addWidget(QtWidgets.QLabel("SYN Retries"), 0, 0)
        self.spin_syn_retry = QtWidgets.QSpinBox(); self.spin_syn_retry.setRange(0, 10); self.spin_syn_retry.setValue(2)
        grid.addWidget(self.spin_syn_retry, 0, 1)

        self.chk_fallback = QtWidgets.QCheckBox("모호한 경우 TCP connect() 대체")
        self.chk_fallback.setChecked(True)
        grid.addWidget(self.chk_fallback, 1, 0, 1, 2)

        grid.addWidget(QtWidgets.QLabel("connect() 타임아웃(초)"), 2, 0)
        self.spin_conn_to = QtWidgets.QDoubleSpinBox(); self.spin_conn_to.setRange(0.1, 30.0); self.spin_conn_to.setSingleStep(0.05); self.spin_conn_to.setValue(1.5)
        grid.addWidget(self.spin_conn_to, 2, 1)

        tovl.addLayout(grid)
        ng_v.addWidget(self.tcp_opts_group)

        # DNS 옵션
        self.dns_box = QtWidgets.QGroupBox("DNS 옵션")
        df = QtWidgets.QFormLayout(self.dns_box)
        self.edit_qname    = QtWidgets.QLineEdit("example.com")
        self.edit_qtype    = QtWidgets.QLineEdit("A")
        self.edit_resolver = QtWidgets.QLineEdit("8.8.8.8")
        df.addRow("name", self.edit_qname)
        df.addRow("type", self.edit_qtype)
        df.addRow("resolver", self.edit_resolver)
        ng_v.addWidget(self.dns_box)

        form.addRow(self.net_group)

        # BPF (읽기전용)
        self.edit_bpf = QtWidgets.QLineEdit(""); self.edit_bpf.setReadOnly(True)
        form.addRow("BPF(읽기전용)", self.edit_bpf)

        # 아랫버튼
        hb = QtWidgets.QHBoxLayout()
        self.btn_start = QtWidgets.QPushButton("시작")
        self.btn_stop  = QtWidgets.QPushButton("정지"); self.btn_stop.setEnabled(False)
        self.btn_reset = QtWidgets.QPushButton("초기화")
        hb.addWidget(self.btn_start); hb.addWidget(self.btn_stop); hb.addWidget(self.btn_reset)
        form.addRow(hb)

        # 시그널
        self.btn_start.clicked.connect(self.start_clicked.emit)
        self.btn_stop.clicked.connect(self.stop_clicked.emit)    
        self.btn_reset.clicked.connect(self.reset_clicked.emit)

        self.rad_net.toggled.connect(self._toggle_mode)
        self.rad_mass.toggled.connect(self._toggle_mode)

        self.chk_tcp.toggled.connect(self._update_tcp_visibility)
        self.chk_dns.toggled.connect(self._update_dns_visibility)
        for rb in (self.rb_full, self.rb_syn, self.rb_fin, self.rb_null, self.rb_xmas):
            rb.toggled.connect(self._update_graceful_visibility)

        self._hook_rebuild_signals()
        self._toggle_mode(); self._update_tcp_visibility(); self._update_dns_visibility(); self._update_graceful_visibility()
        self._emit_rebuild()

    def _populate_interfaces(self):
        self.combo_iface.clear()
        items = []
        if SCAPY_OK:
            try:
                for _, info in getattr(conf, "ifaces", {}).items():
                    items.append(getattr(info, "name", None) or str(info))
            except Exception:
                pass
        if not items:
            items = ["(default)"]
        self.combo_iface.addItems(items)

    def _hook_rebuild_signals(self):
        widgets = [
            self.rad_net, self.rad_mass,
            self.edit_host, self.edit_ports, self.edit_mass_targets,
            self.chk_tcp, self.chk_udp, self.chk_icmp, self.chk_dns,
            self.rb_full, self.rb_syn, self.rb_fin, self.rb_null, self.rb_xmas,
            self.edit_qname, self.edit_qtype, self.edit_resolver, self.combo_iface
        ]
        for w in widgets:
            if isinstance(w, QtWidgets.QAbstractButton):
                w.toggled.connect(self._emit_rebuild)
            elif isinstance(w, QtWidgets.QLineEdit):
                w.textChanged.connect(self._emit_rebuild)
            elif isinstance(w, QtWidgets.QComboBox):
                w.currentIndexChanged.connect(lambda *_: self._emit_rebuild())
            else:
                try:
                    w.valueChanged.connect(self._emit_rebuild)
                except Exception:
                    pass

    def _toggle_mode(self):
        is_net = self.rad_net.isChecked()
        self.net_group.setVisible(is_net)
        self.mass_group.setVisible(not is_net)

    def _update_tcp_visibility(self):
        self.tcp_opts_group.setVisible(self.chk_tcp.isChecked())

    def _update_dns_visibility(self):
        self.dns_box.setVisible(self.chk_dns.isChecked())

    def _update_graceful_visibility(self):
        self.chk_graceful.setVisible(self.rb_full.isChecked())

    def _emit_rebuild(self):
        bpf = ""
        if self.rad_net.isChecked():
            host = self.edit_host.text().strip()
            if host and is_ip(host):
                parts = []
                if self.chk_icmp.isChecked():
                    parts.append(f"(icmp and host {host})")
                if self.chk_tcp.isChecked() or self.chk_udp.isChecked():
                    ports = parse_ports_spec(self.edit_ports.text())
                    p_expr = ""
                    if ports:
                        if len(ports) <= 10:
                            p_expr = " or ".join([f"port {p}" for p in ports])
                        else:
                            p_expr = f"portrange {min(ports)}-{max(ports)}"
                    if self.chk_tcp.isChecked():
                        parts.append(f"(tcp and host {host}{(' and ('+p_expr+')') if p_expr else ''})")
                    if self.chk_udp.isChecked():
                        parts.append(f"(udp and host {host}{(' and ('+p_expr+')') if p_expr else ''})")
                if self.chk_dns.isChecked():
                    resolver = self.edit_resolver.text().strip() or "8.8.8.8"
                    parts.append(f"(udp port 53 and (host {resolver} or host {host}))")
                parts.append("arp")
                bpf = " or ".join(parts)
        self.edit_bpf.setText(bpf)
        self.rebuild_bpf.emit(bpf)

    def build_job(self) -> Optional[Any]:
        try:
            iface_txt = self.combo_iface.currentText().strip()
            iface = None if "(default)" in iface_txt else iface_txt.split(" | ")[0]
        except Exception:
            iface = None

        if self.rad_net.isChecked():
            host = self.edit_host.text().strip()
            if not host or not is_ip(host):
                QtWidgets.QMessageBox.warning(self, "입력 오류", "Network Scan은 단일 IP만 가능합니다.")
                return None
            if is_loopback(host):
                QtWidgets.QMessageBox.warning(self, "입력 오류", "loopback 주소는 허용되지 않습니다.")
                return None

            ports_spec = self.edit_ports.text().strip()
            ports = parse_ports_spec(ports_spec)
            if not ports:
                QtWidgets.QMessageBox.warning(self, "입력 오류", "유효한 포트를 입력하세요.")
                return None

            protos = []
            if self.chk_tcp.isChecked():  protos.append("tcp")
            if self.chk_udp.isChecked():  protos.append("udp")
            if self.chk_icmp.isChecked(): protos.append("icmp")
            if self.chk_dns.isChecked():  protos.append("dns")
            if not protos:
                QtWidgets.QMessageBox.warning(self, "입력 오류", "최소 하나의 프로토콜을 선택하세요.")
                return None

            tcp_mode = "syn"
            if self.rb_full.isChecked(): tcp_mode = "full"
            elif self.rb_fin.isChecked(): tcp_mode = "fin"
            elif self.rb_null.isChecked(): tcp_mode = "null"
            elif self.rb_xmas.isChecked(): tcp_mode = "xmas"

            graceful = self.rb_full.isChecked() and self.chk_graceful.isChecked()

            options = ScanOptions(
                interface=iface,
                ua_enabled=self.chk_http_probe.isChecked(),
                ua_string=self.edit_ua.text().strip() or "scanner-x/0.1",
                syn_retries=int(self.spin_syn_retry.value()),
                tcp_connect_fallback=bool(self.chk_fallback.isChecked()),
                connect_timeout=float(self.spin_conn_to.value()),
                scan_protocols=protos,
                tcp_scan_mode=tcp_mode,
                graceful_close=bool(graceful),
                dns_qname=self.edit_qname.text().strip() or None,
                dns_qtype=(self.edit_qtype.text().strip() or "A").upper(),
                dns_resolver=self.edit_resolver.text().strip() or "8.8.8.8",
                use_masscan_for_tcp=False,
            )

            job = ScanJob(
                name="network-scan",
                target=host,
                ports=ports,
                org_ports=ports_spec,
                capture_file=CACHE_PCAP,
                timeout=2.0,
                rate_interval=0.0,
                options=options,
            )
            return job

        # Masscan
        targets_raw = self.edit_mass_targets.text().strip()
        if not targets_raw:
            QtWidgets.QMessageBox.warning(self, "입력 오류", "Masscan Targets를 입력하세요.")
            return None

        options = ScanOptions(
            interface=iface,
            use_masscan_for_tcp=True,
            scan_protocols=["tcp"],
            masscan_rate=int(self.edit_mass_rate.value()),
            masscan_wait=float(self.edit_mass_wait.value()),
            masscan_targets=[t for t in re.split(r"[,\s]+", targets_raw) if t],
        )
        job = ScanJob(
            name="masscan-only",
            target=targets_raw,
            ports=[],
            org_ports=self.edit_ports.text().strip(),
            capture_file=CACHE_PCAP,
            timeout=2.0,
            rate_interval=0.0,
            options=options,
        )
        return job

# 결과/로그
class ResultsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        v = QtWidgets.QVBoxLayout(self)
        ph = QtWidgets.QHBoxLayout()
        self.progress = QtWidgets.QProgressBar(); self.progress.setRange(0, 100); self.progress.setValue(0)
        self.lbl = QtWidgets.QLabel("0%")
        ph.addWidget(self.progress); ph.addWidget(self.lbl)
        v.addLayout(ph)

        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Port", "Open?", "Latency(ms)", "Service"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        v.addWidget(self.table)

        self.log = QtWidgets.QTextEdit(); self.log.setReadOnly(True)
        self.log.setPlaceholderText("스캔 완료 시 TXT 요약 보고서가 표시됩니다.")
        v.addWidget(self.log)

    def clear_all(self):
        self.table.setRowCount(0)
        self.log.clear()
        self.progress.setValue(0); self.lbl.setText("0%")

    def set_value(self, val: int):
        if self.progress.maximum() == 0:
            self.progress.setRange(0, 100)
        val = max(0, min(100, int(val)))
        self.progress.setValue(val)
        self.lbl.setText(f"{val}%")

    def add_result(self, r: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(r.get("port",""))))
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem("OPEN" if r.get("open") else "closed"))
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(f'{r.get("latency_ms", 0):.1f}'))
        self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(r.get("service","")))

    def show_report(self, text: str):
        self.log.setPlainText(text or "")

# 상세/스트림
class PacketDetailDialog(QtWidgets.QDialog):
    def __init__(self, pkt:dict, session_log_provider:Optional[Callable[[],str]]=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("패킷 상세")
        self.resize(720, 520)
        v = QtWidgets.QVBoxLayout(self)
        tabs = QtWidgets.QTabWidget()
        detail = QtWidgets.QTextEdit(); detail.setReadOnly(True)
        lines = [f"Time : {pkt.get('time','')}",
                 f"Src  : {pkt.get('src','')}",
                 f"Dst  : {pkt.get('dst','')}",
                 f"Proto: {pkt.get('proto','')}",
                 "", "Info:", pkt.get('info','')]
        detail.setPlainText("\n".join(lines))
        tabs.addTab(detail, "패킷")
        log = QtWidgets.QTextEdit(); log.setReadOnly(True)
        if session_log_provider:
            log.setPlainText(session_log_provider())
        tabs.addTab(log, "세션 로그")
        v.addWidget(tabs)

class StreamDialog(QtWidgets.QDialog):
    def __init__(self, title:str, rows:List[dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 560)
        v = QtWidgets.QVBoxLayout(self)
        table = QtWidgets.QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Time","Src","Dst","Proto","Info"])
        header = table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for r in rows:
            row = table.rowCount()
            table.insertRow(row)
            for c, k in enumerate(["time","src","dst","proto","info"]):
                table.setItem(row, c, QtWidgets.QTableWidgetItem(str(r.get(k,""))))
        v.addWidget(table)

# 패킷 패널
class PacketsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        v = QtWidgets.QVBoxLayout(self)
        v.addWidget(QtWidgets.QLabel("패킷 패널 — Npcap + scapy가 설치되면 실제 패킷이 표시됩니다.")) #지워도 됨

        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Src", "Dst", "Proto", "Info"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx)
        self.table.itemDoubleClicked.connect(self._detail)
        v.addWidget(self.table)

        self.session_log_provider: Optional[Callable[[],str]] = None
        self.stream_matcher: Callable[[dict,dict],bool] = self._default_stream_matcher

        self._settings = QtCore.QSettings(LAYOUT_INI, QtCore.QSettings.IniFormat)
        self._restore_column_widths()
        header.sectionResized.connect(self._save_column_widths)

    def _save_column_widths(self):
        header = self.table.horizontalHeader()
        widths = [header.sectionSize(i) for i in range(self.table.columnCount())]
        self._settings.setValue("packets/colwidths", widths)

    def _restore_column_widths(self):
        widths = self._settings.value("packets/colwidths", None)
        if widths:
            try:
                for i, w in enumerate(widths):
                    self.table.setColumnWidth(i, int(w))
            except Exception:
                pass

    def clear_packets(self):
        self.table.setRowCount(0)

    def add_packet_row(self, d: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key in enumerate(["time", "src", "dst", "proto", "info"]):
            self.table.setItem(row, col, QtWidgets.QTableWidgetItem(str(d.get(key, ""))))
        self.table.setRowHeight(row, 20)

    def _get_row_dict(self, r:int) -> dict:
        vals = {}
        for c, k in enumerate(["time","src","dst","proto","info"]):
            it = self.table.item(r, c)
            vals[k] = it.text() if it else ""
        return vals

    def _detail(self, item: QtWidgets.QTableWidgetItem):
        r = item.row()
        pkt = self._get_row_dict(r)
        PacketDetailDialog(pkt, self.session_log_provider, self).exec()

    def _ctx(self, pos):
        m = QtWidgets.QMenu(self)
        a1 = m.addAction("패킷 상세보기")
        a2 = m.addAction("스트림 따라가기")
        act = m.exec(self.table.mapToGlobal(pos))
        if act == a1:
            cur = self.table.item(self.table.currentRow(), 0)
            if cur: self._detail(cur)
        elif act == a2:
            r = self.table.currentRow()
            if r < 0: return
            base = self._get_row_dict(r)
            rows = []
            for i in range(self.table.rowCount()):
                d = self._get_row_dict(i)
                if self.stream_matcher(base, d):
                    rows.append(d)
            title = f"스트림: {base.get('src','?')} ⇄ {base.get('dst','?')} ({base.get('proto','?')})"
            StreamDialog(title, rows, self).exec()

    @staticmethod
    def _default_stream_matcher(a:dict, b:dict) -> bool:
        if a.get("proto") != b.get("proto"):
            return False
        s1, d1 = a.get("src"), a.get("dst")
        s2, d2 = b.get("src"), b.get("dst")
        return (s1 == s2 and d1 == d2) or (s1 == d2 and d1 == s2)

# 스케줄러 스레드 
class SchedulerThread(QtCore.QThread):
    info = QtCore.Signal(str)
    finished_signal = QtCore.Signal()
    progress_signal = QtCore.Signal(int, int)   # done, total
    percent_signal = QtCore.Signal(int)         # 0~100
    result_signal = QtCore.Signal(dict)

    def __init__(self, job: Any, parent=None):
        super().__init__(parent)
        self.job = job
        self._sched_ref = None

    def request_cancel(self):
        s = self._sched_ref
        for name in ("stop", "cancel", "request_stop", "request_cancel", "shutdown"):
            try:
                if s and hasattr(s, name):
                    getattr(s, name)()
                    self.info.emit(f"[scan] scheduler.{name}() 호출")
                    break
            except Exception as e:
                self.info.emit(f"[scan] cancel 호출 실패: {e}")

    def request_pause(self):
        s = self._sched_ref
        if s and hasattr(s, "pause"):
            try:
                s.pause()
                self.info.emit("[scan] scheduler.pause() 호출")
            except Exception as e:
                self.info.emit(f"[scan] pause 실패: {e}")
        else:
            self.info.emit("[scan] 코어가 pause 미지원 → cancel로 대체")
            self.request_cancel()

    def request_resume(self):
        s = self._sched_ref
        if s and hasattr(s, "resume"):
            try:
                s.resume()
                self.info.emit("[scan] scheduler.resume() 호출")
            except Exception as e:
                self.info.emit(f"[scan] resume 실패: {e}")
        else:
            self.info.emit("[scan] 코어가 resume 미지원 (재시작 필요)")

    def _wire_callbacks(self, sched):
        def _prog_adapter(*args):
            try:
                if len(args) == 2:
                    done, total = int(args[0]), max(1, int(args[1]))
                    self.progress_signal.emit(done, total)
                elif len(args) == 1:
                    self.percent_signal.emit(int(args[0]))
            except Exception:
                pass

        def _result_adapter(*args, **kw):
            rec = {}
            if args:
                if isinstance(args[0], dict):
                    rec = args[0]
                elif len(args) >= 4:
                    rec = {"port": args[0], "open": args[1], "latency_ms": args[2], "service": args[3]}
            if kw:
                rec.update(kw)
            if rec:
                self.result_signal.emit(rec)

        # 진행 콜백: 정확히 하나만 연결
        attached = False
        for name in ("set_progress_callback", "set_progress_cb"):
            if hasattr(sched, name):
                try:
                    getattr(sched, name)(_prog_adapter)
                    attached = True
                    break
                except Exception:
                    pass
        if not attached:
            for attr in ("on_progress", "progress_cb", "progress_callback"):
                if hasattr(sched, attr):
                    try:
                        setattr(sched, attr, _prog_adapter)
                        attached = True
                        break
                    except Exception:
                        pass

        # 결과 콜백: 정확히 하나만 연결
        attached_res = False
        for name in ("set_result_callback",):
            if hasattr(sched, name):
                try:
                    getattr(sched, name)(_result_adapter)
                    attached_res = True
                    break
                except Exception:
                    pass
        if not attached_res:
            for attr in ("on_result", "result_cb", "result_callback"):
                if hasattr(sched, attr):
                    try:
                        setattr(sched, attr, _result_adapter)
                        attached_res = True
                        break
                    except Exception:
                        pass

        self.info.emit(f"[scan] 콜백 연결: progress={attached}, result={attached_res}")

    def run(self):
        try:
            sched = SimpleScheduler(result_dir=RESULT_DIR, config=AppConfig() if CORE_OK else None)
            self._sched_ref = sched
            try:
                sched.add_job(self.job, ports_spec=self.job.org_ports)
            except Exception:
                if not getattr(self.job, "ports", None):
                    self.job.ports = []
                sched.jobs = [self.job]

            self._wire_callbacks(sched)
            self.info.emit("[scan] scheduler.run() 시작")
            sched.run()
            self.info.emit("[scan] scheduler.run() 종료")
        except Exception as e:
            self.info.emit(f"[scan error] {e}")
        finally:
            self.finished_signal.emit()
            self._sched_ref = None

#메인
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Scanner — Qt (PySide6)")
        self.resize(1280, 800)
        self.setCentralWidget(QtWidgets.QWidget())

        self.ctrls = ControlsPanel(self)
        self.res   = ResultsPanel(self)
        self.pkts  = PacketsPanel(self)

        self.dB = SafeDockWidget("스캔 설정", self); self.dB.setWidget(self.ctrls)
        self.dC = SafeDockWidget("실행/결과 & 로그", self); self.dC.setWidget(self.res)
        self.dD = SafeDockWidget("패킷 뷰", self); self.dD.setWidget(self.pkts)

        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea,  self.dB)
        self.addDockWidget(QtCore.Qt.RightDockWidgetArea, self.dD)
        self.splitDockWidget(self.dB, self.dD, QtCore.Qt.Horizontal)
        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea,  self.dC)
        self.splitDockWidget(self.dB, self.dC, QtCore.Qt.Vertical)

        self._build_menu()
        self._status = QtWidgets.QStatusBar(self); self.setStatusBar(self._status)

        # 캡처
        self.capture = PacketCapture(self)
        self.capture.packet.connect(self.pkts.add_packet_row)
        self.capture.info.connect(self._log)
        self.capture.error.connect(self._log)
        self.capture.started.connect(lambda: self._status.showMessage("Capture starting...", 1200))
        self.capture.first_packet.connect(lambda: self._status.showMessage("Capture running.", 1200))

        # 컨트롤 
        self.ctrls.rebuild_bpf.connect(lambda b: setattr(self, "_last_bpf", b))
        self.ctrls.start_clicked.connect(self._on_start)
        self.ctrls.stop_clicked.connect(self._on_stop_toggle)   
        self.ctrls.reset_clicked.connect(self._on_reset)

        # 상태
        self._state = "idle"
        self._worker: Optional[SchedulerThread] = None
        self._last_bpf: Optional[str] = None
        self._session_logs: List[str] = []
        self.pkts.session_log_provider = lambda: "\n".join(self._session_logs)

        # 레이아웃/테마
        self._settings = QtCore.QSettings(LAYOUT_INI, QtCore.QSettings.IniFormat)
        dark_on = self._settings.value("theme/dark", True, bool)
        self._apply_dark() if dark_on else self._apply_light()

        # 초기 체크 상태
        self.act_theme_dark.setChecked(dark_on)
        self.aB.setChecked(True); self.aC.setChecked(True); self.aD.setChecked(True)

        # 레이아웃 복원
        geo = self._settings.value("layout/geometry"); state = self._settings.value("layout/state")
        if geo: self.restoreGeometry(geo)
        if state: self.restoreState(state)

    def _build_menu(self):
        # 툴바
        tb = self.addToolBar("작업")
        self.act_start = QtGui.QAction("전체 시작", self, triggered=self._on_start)
        self.act_stop  = QtGui.QAction("전체 정지", self, triggered=self._on_stop_toggle); self.act_stop.setEnabled(False)
        self.act_reset = QtGui.QAction("전체 초기화", self, triggered=self._on_reset)
        for a in (self.act_start, self.act_stop, self.act_reset): tb.addAction(a)

        m = self.menuBar()

        # 패널
        mp = m.addMenu("보기")
        self.aB = QtGui.QAction("스캔 설정", self, checkable=True, checked=True, toggled=lambda v: self.dB.setVisible(v))
        self.aC = QtGui.QAction("실행/결과 & 로그", self, checkable=True, checked=True, toggled=lambda v: self.dC.setVisible(v))
        self.aD = QtGui.QAction("패킷 뷰", self, checkable=True, checked=True, toggled=lambda v: self.dD.setVisible(v))
        for a in (self.aB, self.aC, self.aD): mp.addAction(a)

        # 저장
        me = m.addMenu("저장")
        me.addAction(QtGui.QAction("JSON 저장", self, triggered=self._export_json))
        me.addAction(QtGui.QAction("CSV 저장",  self, triggered=self._export_csv))
        me.addAction(QtGui.QAction("PDF 리포트", self, triggered=self._export_pdf))
        me.addAction(QtGui.QAction("로그 저장",  self, triggered=self._export_log))
        me.addAction(QtGui.QAction("PCAPNG 저장", self, triggered=self._export_pcap))

        # 레이아웃
        ml = m.addMenu("레이아웃")
        self.act_theme_dark = QtGui.QAction("다크 모드 (ON/OFF)", self, checkable=True, toggled=self._on_theme_toggle)
        ml.addAction(self.act_theme_dark)
        ml.addSeparator()
        ml.addAction(QtGui.QAction("현재 레이아웃 저장", self, triggered=self._save_layout))
        ml.addAction(QtGui.QAction("레이아웃 불러오기", self, triggered=self._load_layout))
        ml.addAction(QtGui.QAction("기본 배치로 초기화", self, triggered=self._reset_layout))

    # 모드(배경)
    def _apply_light(self):
        app = QtWidgets.QApplication.instance(); app.setStyle("Fusion")
        pal = QtGui.QPalette()
        pal.setColor(QtGui.QPalette.Window, QtGui.QColor(240,240,240))
        pal.setColor(QtGui.QPalette.WindowText, QtCore.Qt.black)
        pal.setColor(QtGui.QPalette.Base, QtCore.Qt.white)
        pal.setColor(QtGui.QPalette.Text, QtCore.Qt.black)
        pal.setColor(QtGui.QPalette.Button, QtGui.QColor(240,240,240))
        pal.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.black)
        app.setPalette(pal)

    def _apply_dark(self):
        app = QtWidgets.QApplication.instance(); app.setStyle("Fusion")
        pal = QtGui.QPalette()
        pal.setColor(QtGui.QPalette.Window, QtGui.QColor(53,53,53))
        pal.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
        pal.setColor(QtGui.QPalette.Base, QtGui.QColor(35,35,35))
        pal.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
        pal.setColor(QtGui.QPalette.Button, QtGui.QColor(53,53,53))
        pal.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
        pal.setColor(QtGui.QPalette.Highlight, QtGui.QColor(76,163,224))
        pal.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
        app.setPalette(pal)

    def _on_theme_toggle(self, on: bool):
        self._apply_dark() if on else self._apply_light()
        self._settings.setValue("theme/dark", on)

    # 레이아웃
    def _save_layout(self):
        self._settings.setValue("layout/geometry", self.saveGeometry())
        self._settings.setValue("layout/state", self.saveState())
        self._status.showMessage("[layout] 저장됨", 1500)

    def _load_layout(self):
        geo = self._settings.value("layout/geometry"); st = self._settings.value("layout/state")
        if geo: self.restoreGeometry(geo)
        if st: self.restoreState(st)
        self._status.showMessage("[layout] 복원됨", 1500)

    def _reset_layout(self):
        for d in (self.dB, self.dC, self.dD):
            try: self.removeDockWidget(d)
            except Exception: pass
            d.setFloating(False); d.show()
        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea, self.dB)
        self.addDockWidget(QtCore.Qt.RightDockWidgetArea, self.dD)
        self.splitDockWidget(self.dB, self.dD, QtCore.Qt.Horizontal)
        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea, self.dC)
        self.splitDockWidget(self.dB, self.dC, QtCore.Qt.Vertical)
        self._status.showMessage("[layout] 기본 배치 재적용", 1500)

    # 상태 전환
    def _set_state(self, s: str):
        self._state = s
        if s == "running":
            self.ctrls.btn_start.setEnabled(False); self.act_start.setEnabled(False)
            self.ctrls.btn_stop.setEnabled(True);  self.act_stop.setEnabled(True)
            self.ctrls.btn_stop.setText("정지")
        elif s == "paused":
            self.ctrls.btn_start.setEnabled(True);  self.act_start.setEnabled(True)
            self.ctrls.btn_stop.setEnabled(True);  self.act_stop.setEnabled(True)
            self.ctrls.btn_stop.setText("계속하기")
        else:
            self.ctrls.btn_start.setEnabled(True);  self.act_start.setEnabled(True)
            self.ctrls.btn_stop.setEnabled(False); self.act_stop.setEnabled(False)
            self.ctrls.btn_stop.setText("정지")

    @QtCore.Slot(str)
    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self._session_logs.append(f"[{ts}] {msg}")
        self.statusBar().showMessage(msg, 2500)

    def _current_iface_text(self) -> Optional[str]:
        try:
            t = self.ctrls.combo_iface.currentText().strip()
            return None if "(default)" in t else t.split(" | ")[0]
        except Exception:
            return None

    # 실행 제어
    def _on_start(self):
        if self._state == "running":
            return
        if self._state == "paused":
            
            self._on_stop_toggle()
            return

        self.res.clear_all()
        self.pkts.clear_packets()
        self._session_logs.clear()

        job = self.ctrls.build_job()
        if not job:
            return

        # BPF 자동 완화 (빈/과도한 필터일 경우 기본 필터)
        bpf = self.ctrls.edit_bpf.text().strip()
        if not bpf:
            bpf = "arp or tcp or udp"
        self._last_bpf = bpf

        iface = self._current_iface_text()

        # 캡처 먼저 안정적으로 시작
        self.capture.stop()
        self.capture.start(iface, bpf, reuse_file=False)
        QtCore.QCoreApplication.processEvents()

        # 스케줄러 시작
        self._worker = SchedulerThread(job, self)
        self._worker.info.connect(self._log)
        self._worker.finished_signal.connect(self._on_done)
        self._worker.progress_signal.connect(lambda d, t: self.res.set_value(int(d / max(1, t) * 100)))
        self._worker.percent_signal.connect(self.res.set_value)  # 중복 호출 제거
        self._worker.result_signal.connect(self.res.add_result)
        self._worker.start()

        self._set_state("running")

    def _on_stop_toggle(self):
        if self._state == "running":
            if self._worker:
                self._worker.request_pause()
            self.capture.stop()
            self._set_state("paused")
        elif self._state == "paused":
            if self._worker:
                self._worker.request_resume()
            iface = self._current_iface_text()
            bpf = self._last_bpf or (self.ctrls.edit_bpf.text().strip() or None)
            self.capture.start(iface, bpf, reuse_file=True)
            self._set_state("running")

    def _on_reset(self):
        if self._worker:
            self._worker.request_cancel()
        self.capture.stop()
        self.res.clear_all()
        self.pkts.clear_packets()
        try:
            if os.path.exists(CACHE_PCAP):
                os.remove(CACHE_PCAP)
        except Exception:
            pass
        self._set_state("idle")

    def _on_done(self):
        self.capture.stop()
        self.res.set_value(100)
        self._set_state("idle")
        latest = self._find_latest_report()
        if latest:
            self.res.show_report(safe_open(latest))

    def _find_latest_report(self) -> Optional[str]:
        try:
            cand = [os.path.join(RESULT_DIR, f) for f in os.listdir(RESULT_DIR) if f.lower().endswith(".txt")]
            if not cand:
                return None
            cand.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return cand[0]
        except Exception:
            return None

    # 저장 안내 문구
    def _export_json(self):
        t = self.res.table
        if t.rowCount() <= 0:
            QtWidgets.QMessageBox.information(self, "안내", "저장할 결과가 없습니다."); return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "JSON 저장", os.path.join(RESULT_DIR, "scan_results.json"), "JSON (*.json)")
        if not path: return
        data = []
        for r in range(t.rowCount()):
            row = {}
            for c, key in enumerate(("port","open","latency_ms","service")):
                it = t.item(r, c); row[key] = it.text() if it else ""
            data.append(row)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self.statusBar().showMessage(f"Saved: {path}", 2000)

    def _export_csv(self):
        t = self.res.table
        if t.rowCount() <= 0:
            QtWidgets.QMessageBox.information(self, "안내", "저장할 결과가 없습니다."); return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "CSV 저장", os.path.join(RESULT_DIR, "scan_results.csv"), "CSV (*.csv)")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write("port,open,latency_ms,service\n")
            for r in range(t.rowCount()):
                vals = [(t.item(r,c).text() if t.item(r,c) else "") for c in range(4)]
                f.write(",".join(vals) + "\n")
        self.statusBar().showMessage(f"Saved: {path}", 2000)

    def _export_log(self):
        text = self.res.log.toPlainText().strip()
        if not text:
            QtWidgets.QMessageBox.information(self, "안내", "저장할 로그가 없습니다."); return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "로그 저장", os.path.join(RESULT_DIR, "scan.log"), "Log (*.log);;Text (*.txt)")
        if not path: return
        with open(path, "w", encoding="utf-8") as f: f.write(text)
        self.statusBar().showMessage(f"Saved: {path}", 2000)

    def _export_pdf(self):
        text = self.res.log.toPlainText().strip(); t = self.res.table
        if not text and t.rowCount() <= 0:
            QtWidgets.QMessageBox.information(self, "안내", "저장할 내용이 없습니다."); return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "PDF 리포트", os.path.join(RESULT_DIR, "scan_report.pdf"), "PDF (*.pdf)")
        if not path: return
        html = ["<h2>Port Scanner Report</h2>"]
        if t.rowCount() > 0:
            html.append("<h3>Results</h3><table border='1' cellspacing='0' cellpadding='3'>")
            html.append("<tr><th>Port</th><th>Open</th><th>Latency(ms)</th><th>Service</th></tr>")
            for r in range(t.rowCount()):
                vals = [(t.item(r,c).text() if t.item(r,c) else "") for c in range(4)]
                html.append(f"<tr><td>{vals[0]}</td><td>{vals[1]}</td><td>{vals[2]}</td><td>{vals[3]}</td></tr>")
            html.append("</table>")
        if text:
            html.append("<h3>Log</h3><pre>")
            html.append(QtGui.QTextDocument(text).toPlainText())
            html.append("</pre>")
        doc = QtGui.QTextDocument(); doc.setHtml("".join(html))
        printer = QPrinter(QPrinter.HighResolution); printer.setOutputFormat(QPrinter.PdfFormat); printer.setOutputFileName(path)
        doc.print_(printer); self.statusBar().showMessage(f"Saved: {path}", 2000)

    def _export_pcap(self):
        
        if self.capture.packets_seen() == 0 and (not os.path.exists(CACHE_PCAP) or os.path.getsize(CACHE_PCAP) == 0):
            QtWidgets.QMessageBox.information(self, "안내", "저장할 패킷이 없습니다.")
            return

        was_running = (self._state == "running")
        if was_running:
            try: self.capture.stop()
            except Exception: pass

        deadline = time.time() + 1.0
        size = 0
        while time.time() < deadline:
            try:
                if os.path.exists(CACHE_PCAP):
                    size = os.path.getsize(CACHE_PCAP)
                    if size > 0:
                        break
            except Exception:
                pass
            time.sleep(0.05)

        if size <= 0:
            QtWidgets.QMessageBox.information(self, "안내", "저장할 패킷이 없습니다.")
            if was_running:
                iface = self._current_iface_text()
                bpf = self._last_bpf or (self.ctrls.edit_bpf.text().strip() or None)
                self.capture.start(iface, bpf, reuse_file=True)
            return

        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "PCAPNG 저장", os.path.join(RESULT_DIR, "capture.pcapng"), "pcapng (*.pcapng)")
        if not path:
            if was_running:
                iface = self._current_iface_text()
                bpf = self._last_bpf or (self.ctrls.edit_bpf.text().strip() or None)
                self.capture.start(iface, bpf, reuse_file=True)
            return

        try:
            with open(CACHE_PCAP, "rb") as rf, open(path, "wb") as wf:
                wf.write(rf.read())
            self.statusBar().showMessage(f"Saved: {path}", 2000)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "오류", f"PCAP 저장 실패: {e}")

        if was_running:
            iface = self._current_iface_text()
            bpf = self._last_bpf or (self.ctrls.edit_bpf.text().strip() or None)
            self.capture.start(iface, bpf, reuse_file=True)

def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow(); w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
