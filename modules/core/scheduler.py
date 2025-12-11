# modules/core/scheduler.py
from __future__ import annotations

import os
import time
import datetime
import json
import csv
import ipaddress
import socket
from collections import Counter, defaultdict
from typing import Optional, List, Dict, Iterable, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import conf  # noqa: F401

from modules.capture import PacketCapture, CaptureConfig
from modules.capture.filters import (
    create_scan_filter,
    BPFFilterBuilder,  # noqa: F401
)

from modules.core.models import AppConfig, ScanJob
from modules.utils.ip import parse_ports
from modules.utils.log import get_logger

# 스캐너(기본)
from modules.scanner.tcp import TCPScanner
from modules.scanner.udp import UDPScanner
from modules.scanner.icmp import ICMPScanner
from modules.scanner.dns import DNSScanner

# OS 추정 (p0f/nmap + 휴리스틱)
from modules.service.os_fp_paths import resolve_fp_paths
from modules.service.os_fp import OSDetectorCascade

# 확장 분석(자동 활성화)
from modules.tls.analyzer import TLSAnalyzer
from modules.analysis.asset_identifier import AssetIdentifier

log = get_logger("scheduler")

# --------------------------- PDF 저장 훅 ---------------------------
# - pdf_writer 모듈이 없으면 기존 동작에 영향 없음
# - 옵션 기본 False: export_pdf_for_enhanced / export_pdf_for_masscan
_pdf_writer = None
try:
    from modules.export.pdf_writer import pdf_writer as _pdf_writer
except Exception as _e:
    try:
        # 배포 구조에 따라 패키지 상대 임포트 시도
        from .. import pdf_writer as _pdf_writer  # type: ignore
    except Exception:
        _pdf_writer = None
        log.info("pdf_writer not available: %s", _e)


class SimpleScheduler:
    """
    - 기본 스캐너 모드: BPF 생성 → PacketCapture 시작(파일 저장) → 스캐너 실행 → 캡처 중지/리포트
    - Masscan-only 모드(use_masscan_for_tcp=True): 캡처를 전혀 시작하지 않음(파일도 생성하지 않음).
      대신 Masscan으로 전체 포트(1-65535) 스캔 → ICMP/TCP 기반 liveness 통과한 호스트만 이벤트화/리포트.
    - TLS 분석 및 자산 식별: 자동 활성화 (HTTPS 포트 발견 시 TLS 분석, 모든 결과에 대해 자산 식별)
    """

    def __init__(self, result_dir: str = "result", config: Optional[AppConfig] = None):
        self.jobs: List[ScanJob] = []
        self.result_dir = result_dir
        os.makedirs(self.result_dir, exist_ok=True)
        self.config = config or AppConfig()

        # 확장 분석기 (자동 활성화)
        self.tls_analyzer = TLSAnalyzer(max_workers=5)
        self.asset_identifier = AssetIdentifier()
        self.scan_results: List[Dict] = []

    # --------------------------------------------------------------------------
    # Job 관리
    # --------------------------------------------------------------------------
    def add_job(self, job: ScanJob, *, ports_spec: Optional[str] = None) -> None:
        if ports_spec:
            job.ports = parse_ports(ports_spec)
        self.jobs.append(job)

    # --------------------------------------------------------------------------
    # 리포트 유틸
    # --------------------------------------------------------------------------
    def _safe_basename(self, path: Optional[str]) -> str:
        if not path:
            return "scan"
        base = os.path.basename(path)
        name, _ = os.path.splitext(base)
        return name or "scan"

    def _write_masscan_reports(
        self, job: ScanJob, masscan_raw: dict, alive_events: list[dict]
    ) -> None:
        """
        Masscan 전용 리포트 생성: 원본 JSON + 필터링된 'alive' 이벤트 JSON + CSV
        """
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        base = job.name or "masscan"

        # 원본 JSON
        raw_path = os.path.join(self.result_dir, f"{base}_masscan_raw_{ts}.json")
        try:
            with open(raw_path, "w", encoding="utf-8") as f:
                json.dump(masscan_raw or {}, f, ensure_ascii=False, indent=2)
            log.info("Masscan raw saved: %s", raw_path)
        except Exception as e:
            log.exception("Failed to write masscan raw json: %s", e)

        # 필터링된 이벤트 JSON
        alive_json = os.path.join(self.result_dir, f"{base}_masscan_alive_{ts}.json")
        try:
            with open(alive_json, "w", encoding="utf-8") as f:
                json.dump({"events": alive_events}, f, ensure_ascii=False, indent=2)
            log.info("Masscan alive events saved: %s", alive_json)
        except Exception as e:
            log.exception("Failed to write masscan alive json: %s", e)

        # 간단 CSV (IP, port, protocol, state, source)
        alive_csv = os.path.join(self.result_dir, f"{base}_masscan_alive_{ts}.csv")
        try:
            with open(alive_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "port", "protocol", "state", "source"])
                for ev in alive_events:
                    writer.writerow(
                        [
                            ev.get("host") or ev.get("target") or "",
                            ev.get("port", ""),
                            ev.get("protocol", ""),
                            ev.get("state", ""),
                            ev.get("source", ""),
                        ]
                    )
            log.info("Masscan alive CSV saved: %s", alive_csv)
        except Exception as e:
            log.exception("Failed to write masscan alive csv: %s", e)

        # ------------------------ (추가) CSV -> PDF ------------------------
        # 옵션이 True이고 pdf_writer가 있으면 Masscan CSV를 PDF로 생성
        try:
            if _pdf_writer and getattr(job.options, "export_pdf_for_masscan", False):
                out_pdf = os.path.splitext(alive_csv)[0] + "_report.pdf"
                _pdf_writer.build_pdf_from_csv(
                    input_csv=alive_csv,
                    output_pdf=out_pdf,
                    landscape_mode=False,
                    title=f"Xcanner Masscan Report - {base}",
                    logo_path=getattr(job.options, "report_logo", None),
                )
                log.info("Masscan PDF generated: %s", out_pdf)
        except Exception as e:
            log.warning("Masscan PDF generation failed: %s", e)
        # ------------------------------------------------------------------

    def _write_network_scan_text_report(self, job: ScanJob, events: list[dict]) -> str:
        """
        (구 _write_text_report) 콜백(events) 기반의 간단 요약 텍스트 리포트 생성
        """
        os.makedirs(self.result_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        base = self._safe_basename(job.capture_file) if job.capture_file else job.name
        report_path = os.path.join(self.result_dir, f"{base}_{ts}.txt")

        by_proto = defaultdict(list)
        for ev in events:
            by_proto[ev.get("protocol", "other")].append(ev)

        # TCP/UDP 요약
        tcp_states = Counter(ev.get("state", "?") for ev in by_proto.get("tcp", []))
        tcp_open = sorted(
            ev["port"] for ev in by_proto.get("tcp", []) if ev.get("state") == "open"
        )
        tcp_closed = sorted(
            ev["port"] for ev in by_proto.get("tcp", []) if ev.get("state") == "closed"
        )

        udp_states = Counter(ev.get("state", "?") for ev in by_proto.get("udp", []))
        udp_open = sorted(
            ev["port"] for ev in by_proto.get("udp", []) if ev.get("state") == "open"
        )
        udp_closed = sorted(
            ev["port"] for ev in by_proto.get("udp", []) if ev.get("state") == "closed"
        )

        # ICMP/DNS 요약
        icmp_ev = by_proto.get("icmp", [])
        icmp_status = icmp_ev[-1].get("state") if icmp_ev else "n/a"

        dns_ev = by_proto.get("dns", [])
        dns_lines = [
            f'  - resolver={d.get("resolver")} qname={d.get("qname")} qtype={d.get("qtype")} ok={d.get("ok")}'
            for d in dns_ev
        ]

        # OS 힌트 원문
        os_hints = []
        for ev in by_proto.get("tcp", []):
            if any(
                k in ev
                for k in ("ttl", "tcp_window", "tcp_ops", "mss", "wscale", "sack_perm")
            ):
                os_hints.append(
                    f'  - port {ev.get("port")}: ttl={ev.get("ttl")} '
                    f'win={ev.get("tcp_window")} ops={ev.get("tcp_ops")} '
                    f'mss={ev.get("mss")} wscale={ev.get("wscale")} '
                    f'sack={ev.get("sack_perm")}'
                )

        # OS 추정(가능 시)
        os_guess = None
        try:
            os_guess = self._os_guess_from_events(events)
        except Exception:
            log.exception("OS guess failed")

        # 작성
        lines = []
        if len(by_proto.get("udp", [])) > 0:
            of = sum(1 for ev in by_proto["udp"] if ev.get("state") == "open|filtered")
            tot = len(by_proto["udp"])
            if tot and of / tot > 0.8:
                lines.append(
                    "(!) UDP: open|filtered 비율이 높아 결과 신뢰도가 낮습니다."
                )

        lines.append("== Scanner-X Result Summary ==")
        lines.append(f"Target         : {job.target or '(multi/masscan)'}")
        lines.append(f"Ports Spec     : {job.ports or job.org_ports}")
        lines.append(
            f"Protocols      : {', '.join(job.options.scan_protocols or ['tcp'])}"
        )
        lines.append(f"TCP mode       : {getattr(job.options, 'tcp_scan_mode', 'syn')}")
        lines.append(
            f"Interface      : {getattr(job.options,'interface',None) or 'default'}"
        )
        lines.append(f"Capture (pcap) : {job.capture_file or '- (disabled)'}")
        lines.append("")
        lines.append("-- TCP --")
        lines.append(f"States         : {dict(tcp_states)}")
        lines.append(f"Open ports     : {tcp_open or '-'}")
        lines.append(f"Closed ports   : {tcp_closed or '-'}")
        lines.append("")
        lines.append("-- UDP --")
        lines.append(f"States         : {dict(udp_states)}")
        lines.append(f"Open ports     : {udp_open or '-'}")
        lines.append(f"Closed ports   : {udp_closed or '-'}")
        lines.append("")
        lines.append("-- ICMP --")
        lines.append(f"Host status    : {icmp_status}")
        lines.append("")
        lines.append("-- DNS --")
        lines.extend(dns_lines or ["  - (no queries)"])
        lines.append("")
        lines.append("-- OS best guess --")
        if os_guess:
            src = os_guess.get("source", "-")
            label = os_guess.get("label", "unknown")
            score = os_guess.get("score", 0.0)
            reason = os_guess.get("reason")
            lines.append(f"  source={src} label={label} score={score}")
            if reason:
                lines.append(f"  reason={reason}")
        else:
            lines.append("  (no guess)")
        lines.append("")
        lines.append("-- OS feature hints (raw) --")
        lines.extend(os_hints or ["  - (no hints)"])
        lines.append("")
        lines.append(f"Generated at   : {ts}")

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        except Exception as e:
            log.exception("write report failed: %s", e)
            return ""
        log.info("Report saved: %s", report_path)
        return report_path

    @staticmethod
    def _targets_str(t) -> str:
        if isinstance(t, (list, tuple, set)):
            return ", ".join(str(x) for x in t)
        return str(t)

    def _write_masscan_text_report(
        self, job: ScanJob, events: list[dict], masscan_raw: dict | None = None
    ) -> str:
        """
        Masscan 전용 텍스트 요약 리포트 생성.
        - events: masscan에서 필터링(예: alive hosts)된 이벤트 리스트
        - masscan_raw: masscan이 반환한 원본 dict (선택)
        """
        os.makedirs(self.result_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        base = job.name or "masscan"
        report_path = os.path.join(self.result_dir, f"{base}_masscan_summary_{ts}.txt")

        # 집계
        total_raw_records = 0
        try:
            if isinstance(masscan_raw, dict):
                total_raw_records = len(masscan_raw.get("records", []))
        except Exception:
            total_raw_records = 0

        by_host = defaultdict(list)
        for ev in events:
            host = ev.get("host") or ev.get("target") or ev.get("ip")
            if not host:
                continue
            by_host[host].append(ev.get("port"))

        lines = []
        lines.append("== Masscan Summary Report ==")
        lines.append(
            f"Target(s)           : {self._targets_str(job.target or getattr(job.options,'masscan_targets', None) or '(multi)')}"
        )
        lines.append(f"Total raw records    : {total_raw_records}")
        lines.append(f"Alive hosts (count)  : {len(by_host)}")
        lines.append("")
        lines.append("-- Alive hosts (sample / all) --")
        if not by_host:
            lines.append("  - (no alive hosts detected)")
        else:
            # 모든 호스트 나열하되, 포트가 많은 경우 상위 10개만 표시
            for host, ports in sorted(by_host.items()):
                ports_sorted = sorted(set(p for p in ports if p is not None))
                top_ports = ports_sorted[:10]
                ports_str = ", ".join(str(p) for p in top_ports)
                more = (
                    f" (+{len(ports_sorted)-len(top_ports)} more)"
                    if len(ports_sorted) > len(top_ports)
                    else ""
                )
                suffix = (
                    f": ports={ports_str}{more}" if ports_str else ": (no port details)"
                )
                lines.append(f"  - {host}{suffix}")

        lines.append("")
        lines.append(
            f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            log.info("Masscan text report saved: %s", report_path)
            return report_path
        except Exception as e:
            log.exception("Failed to write masscan text report: %s", e)
            return ""

    def _write_enhanced_report(self, job: ScanJob, events: list[dict]) -> str:
        """
        확장 리포트: 기본 리포트 + TLS/자산 식별 결과 요약 (자동 생성)
        """
        basic_report_path = self._write_network_scan_text_report(job, events)

        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        base = self._safe_basename(job.capture_file) if job.capture_file else job.name
        enhanced_path = os.path.join(self.result_dir, f"{base}_{ts}_enhanced.txt")

        lines: List[str] = []
        try:
            with open(basic_report_path, "r", encoding="utf-8") as f:
                lines.extend(f.readlines())
        except Exception:
            pass

        lines.append("\n" + "=" * 60)
        lines.append("\n== ENHANCED ANALYSIS RESULTS ==\n")

        # TLS 요약 (결과가 있으면 표시)
        if self.tls_analyzer.results:
            lines.append("\n-- TLS Certificate Analysis --")
            tls_report = self.tls_analyzer.generate_tls_report()
            summ = tls_report["summary"]
            lines.append(f"Total certificates analyzed: {summ['total_certificates']}")
            lines.append(
                f"Certificates expiring in 30 days: {summ['expiring_in_30_days']}"
            )
            lines.append(
                f"Certificates expiring in 7 days: {summ['expiring_in_7_days']}"
            )
            lines.append(f"Expired certificates: {summ['expired']}")

            # 만료 임박 인증서 상세
            if tls_report.get("expiring_soon"):
                lines.append("\nCertificates expiring soon:")
                for cert in tls_report["expiring_soon"][:5]:
                    subject_cn = "Unknown"
                    if cert.get("subject"):
                        for item in cert["subject"]:
                            if item[0][0] == "commonName":
                                subject_cn = item[0][1]
                                break
                    lines.append(
                        f"  - {cert['host']}:{cert.get('port', 443)} ({subject_cn}) expires in {cert['days_left']} days"
                    )
        else:
            lines.append("\n-- TLS Certificate Analysis --")
            lines.append("No TLS certificates analyzed (no HTTPS ports found)")

        # 자산 식별 요약 (결과가 있으면 표시)
        if self.asset_identifier.assets:
            lines.append("\n-- Asset Inventory --")
            asset_report = self.asset_identifier.create_inventory_report()
            summ = asset_report["summary"]
            lines.append(f"Total assets identified: {summ['total_assets']}")

            lines.append("\nAsset types:")
            for asset_type, count in summ.get("asset_types", {}).items():
                lines.append(f"  - {asset_type}: {count}")

            lines.append("\nCriticality distribution:")
            for criticality, count in summ.get("criticality_distribution", {}).items():
                lines.append(f"  - {criticality}: {count}")

            if asset_report.get("high_risk_assets"):
                lines.append(
                    f"\nHigh-risk assets: {len(asset_report['high_risk_assets'])}"
                )
                for asset in asset_report["high_risk_assets"][:5]:
                    services = ", ".join(list(asset.get("services", {}).values())[:3])
                    lines.append(
                        f"  - {asset['ip']} ({asset['asset_type']}) - Risk: {asset['criticality']} - Services: {services}"
                    )

            # 통계 정보
            stats = asset_report.get("statistics", {})
            if stats:
                lines.append(f"\nStatistics:")
                lines.append(
                    f"  - Average open ports per asset: {stats.get('avg_open_ports', 0):.1f}"
                )
                lines.append(
                    f"  - Most common OS: {stats.get('most_common_os', 'Unknown')}"
                )
                lines.append(
                    f"  - Unique services found: {stats.get('unique_services', 0)}"
                )
        else:
            lines.append("\n-- Asset Inventory --")
            lines.append("No assets identified from scan results")

        # 권고사항 (자동 생성)
        recs = self._generate_security_recommendations()
        if recs:
            lines.append("\n-- Security Recommendations --")
            for i, r in enumerate(recs, 1):
                lines.append(f"{i}. {r}")

        lines.append(
            f"\nEnhanced report generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        try:
            with open(enhanced_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            log.info("Enhanced report saved: %s", enhanced_path)
        except Exception as e:
            log.error("Failed to save enhanced report: %s", e)
            return basic_report_path

        # --------------------- ENHANCED TXT -> PDF ---------------------
        # 옵션이 True이고 pdf_writer가 있으면 ENHANCED TXT를 PDF로 생성
        try:
            if _pdf_writer and getattr(job.options, "export_pdf_for_enhanced", False):
                out_pdf = os.path.splitext(enhanced_path)[0] + ".pdf"
                _pdf_writer.build_pdf_from_txt(
                    input_txt=enhanced_path,
                    output_pdf=out_pdf,
                    landscape_mode=True,
                    title=f"Xcanner Report - {base}",
                    logo_path=getattr(job.options, "report_logo", None),
                )
                log.info("Enhanced PDF generated: %s", out_pdf)
        except Exception as e:
            log.warning("Enhanced PDF generation failed: %s", e)
        return enhanced_path

    # --------------------------------------------------------------------------
    # 확장 분석/권고 및 유틸
    # --------------------------------------------------------------------------
    @staticmethod
    def _expand_cidr_to_hosts(target: str) -> List[str]:
        """
        CIDR 또는 단일 IP를 받아서 호스트(네트워크/브로드캐스트 제외) 리스트 반환.
        예: "172.30.254.0/24" -> ["172.30.254.1", ..., "172.30.254.254"]
        """
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return [target]

    @staticmethod
    def _chunk_iterable(it: Iterable, chunk_size: int):
        """
        이터러블을 청크(리스트)로 나눔
        """
        current = []
        for item in it:
            current.append(item)
            if len(current) >= chunk_size:
                yield current
                current = []
        if current:
            yield current

    @staticmethod
    def _tcp_connect_check(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
        """
        TCP connect()를 이용한 단순 liveness/port 체크 (fallback 용도)
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, int(port)))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def _tcp_try_ports(ip: str, ports: List[int], timeout: float) -> bool:
        for p in ports:
            if SimpleScheduler._tcp_connect_check(ip, p, timeout):
                return True
        return False

    @staticmethod
    def _parallel_icmp_or_tcp_fallback(
        ips: List[str],
        icmp_check_func: Callable[[str], bool],
        tcp_ports_to_try: List[int] = [80, 443],
        workers: int = 32,
        tcp_timeout: float = 0.8,
    ) -> List[str]:
        """
        1) 병렬로 ICMP 검사 수행
        2) ICMP가 ambiguous/False인 경우, TCP connect fallback으로 보완(지정 포트들에 대해)
        반환: alive_ip_list
        """
        alive = set()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            # 1) ICMP 병렬 검사
            fut_to_ip = {ex.submit(icmp_check_func, ip): ip for ip in ips}
            pending_tcp_fallback = []
            for fut in as_completed(fut_to_ip):
                ip = fut_to_ip[fut]
                try:
                    ok = bool(fut.result())
                except Exception:
                    ok = False
                if ok:
                    alive.add(ip)
                else:
                    pending_tcp_fallback.append(ip)

            # 2) TCP fallback for ambiguous ones (병렬)
            fut2 = {}
            for ip in pending_tcp_fallback:
                fut2[
                    ex.submit(
                        SimpleScheduler._tcp_try_ports,
                        ip,
                        tcp_ports_to_try,
                        tcp_timeout,
                    )
                ] = ip

            for fut in as_completed(fut2):
                ip = fut2[fut]
                try:
                    ok = bool(fut.result())
                except Exception:
                    ok = False
                if ok:
                    alive.add(ip)

        return sorted(alive)

    @staticmethod
    def _tcp_probe_liveness(ip: str, port: int, timeout: float = 0.6) -> str:
        """
        TCP connect 기반 liveness 판단:
        - 'open'     : connect 성공
        - 'closed'   : ConnectionRefusedError (RST) -> 호스트는 살아있음
        - 'no_reply' : 타임아웃/필터/기타 오류(드롭)
        """
        import socket, errno

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, int(port)))
            s.close()
            return "open"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            # 일부 플랫폼에서 WSAECONNREFUSED 등으로 들어올 수 있음
            if getattr(e, "errno", None) in (errno.ECONNREFUSED, 10061):
                return "closed"
            return "no_reply"
        except Exception:
            return "no_reply"

    @staticmethod
    def _pick_rep_dst_from_targets(targets_list: List[str]) -> Optional[str]:
        """
        대상 목록에서 대표 목적지 하나를 고른다.
        CIDR이면 usable host 하나(첫 번째), 단일 IP면 그대로.
        """
        if not targets_list:
            return None
        import ipaddress

        for t in targets_list:
            if not t:
                continue
            s = str(t).strip()
            if not s:
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
                for h in net.hosts():
                    return str(h)
            except Exception:
                # 단일 IP 등
                return s
        return None

    def _auto_router_ip(self, targets_list: List[str]) -> Optional[str]:
        """
        OS 라우팅 테이블 기반으로 라우터(게이트웨이) IP 자동 탐지.
        1) scapy 라우팅 테이블(conf.route.route(dst))에서 게이트웨이 조회
        2) netifaces의 default gateway 사용 (보조)
        동일 L2인 경우 게이트웨이가 0.0.0.0이면 None 반환(= router 불필요).
        """
        try:
            rep_dst = self._pick_rep_dst_from_targets(targets_list)
            if rep_dst:
                try:
                    gw = conf.route.route(rep_dst)[2]
                    if gw and gw != "0.0.0.0":
                        return gw
                except Exception:
                    pass
        except Exception:
            pass

        # 보조: netifaces로 기본 게이트웨이 확보 (여러 NIC 중 기본 경로)
        try:
            import netifaces

            gws = netifaces.gateways()
            default_gw = gws.get("default", {}).get(netifaces.AF_INET)
            if default_gw:
                # default_gw = (gateway_ip, iface_name, ...)
                return str(default_gw[0])
        except Exception:
            pass

        # 마지막: 못 찾으면 None (동일 L2로 간주하거나 수동 지정 필요)
        return None

    def _generate_security_recommendations(self) -> List[str]:
        """보안 권고사항 자동 생성"""
        recs: List[str] = []

        if self.tls_analyzer.results:
            tls_report = self.tls_analyzer.generate_tls_report()
            summ = tls_report["summary"]
            if summ["expired"] > 0:
                recs.append(f"만료된 TLS 인증서 {summ['expired']}개를 즉시 갱신하세요.")
            if summ["expiring_in_7_days"] > 0:
                recs.append(
                    f"7일 내 만료 예정인 TLS 인증서 {summ['expiring_in_7_days']}개를 갱신하세요."
                )
            if summ["expiring_in_30_days"] > 0:
                recs.append(
                    f"30일 내 만료 예정인 TLS 인증서 {summ['expiring_in_30_days']}개의 갱신 계획을 수립하세요."
                )

        if self.asset_identifier.assets:
            asset_report = self.asset_identifier.create_inventory_report()
            high_risk_count = len(asset_report["high_risk_assets"])
            if high_risk_count > 0:
                recs.append(
                    f"고위험 자산 {high_risk_count}개에 대한 보안 강화 조치가 필요합니다."
                )

            services = asset_report["summary"]["top_services"]
            if "Telnet" in services:
                recs.append(
                    "Telnet 서비스는 보안상 위험하므로 SSH로 대체를 권장합니다."
                )
            if "FTP" in services:
                recs.append("FTP 서비스는 SFTP 또는 FTPS로 대체를 권장합니다.")
            if "HTTP" in services and services["HTTP"] > 0:
                recs.append("HTTP 서비스는 HTTPS로 전환하여 통신을 암호화하세요.")
            for s in ("RDP", "SSH", "VNC"):
                if s in services:
                    recs.append(
                        f"{s} 등 원격 접근 서비스에는 강력한 인증과 접근제어(소스 IP 제한, MFA)를 적용하세요."
                    )
                    break

        return recs

    def _extract_https_hosts(self, events: List[Dict]) -> List[str]:
        """HTTPS 포트가 열린 호스트 추출"""
        https_hosts: List[str] = []
        for event in events:
            if (
                event.get("state") == "open"
                and event.get("protocol") == "tcp"
                and event.get("port") in (443, 8443)
            ):
                host = event.get("host") or event.get("target")
                if host:
                    https_hosts.append(host)
        return sorted(set(https_hosts))

    def _run_post_scan_analysis(self, job: ScanJob, events: List[Dict]) -> None:
        """
        스캔 종료 후 이벤트 기반의 후처리 분석 (자동 활성화)
        - 자산 식별: 항상 실행
        - TLS 분석: HTTPS 포트 발견 시 자동 실행
        """
        log.info("Starting post-scan analysis...")
        self.scan_results.extend(events)

        # 1. 자산 식별 (항상 실행)
        log.info("Running asset identification...")
        try:
            asset_events = []
            for ev in events:
                host = ev.get("host") or ev.get("target")
                if not host:
                    continue
                asset_events.append(
                    {
                        "host": host,
                        "port": ev.get("port"),
                        "state": ev.get("state"),
                        "protocol": ev.get("protocol", "tcp"),
                    }
                )
            self.asset_identifier.identify_from_scan_results(asset_events)
            log.info(
                "Asset identification completed. Found %d assets.",
                len(self.asset_identifier.assets),
            )
        except Exception as e:
            log.error("Asset identification failed: %s", e)

        # 2. TLS 분석 (HTTPS 포트 발견 시 자동 실행)
        https_hosts = self._extract_https_hosts(events)
        if https_hosts:
            log.info(f"Running TLS analysis on {len(https_hosts)} hosts...")
            try:
                ports = [443, 8443]
                timeout = 3.0
                self.tls_analyzer.analyze_multiple_hosts(https_hosts, ports, timeout)
                log.info(
                    "TLS analysis completed. Analyzed %d certificates.",
                    len(self.tls_analyzer.results),
                )
            except Exception as e:
                log.error("TLS analysis failed: %s", e)
        else:
            log.info("No HTTPS hosts found for TLS analysis")

    def _os_guess_from_events(self, events: list[dict]) -> dict | None:
        """
        TCP 이벤트의 특징치(ttl/window/옵션 등)를 기반으로 p0f/nmap/휴리스틱을 통해 최적 후보 반환
        """
        feats_list: list[dict] = []
        for ev in events:
            if ev.get("protocol") != "tcp":
                continue
            feats = {
                k: ev.get(k)
                for k in (
                    "ttl",
                    "tcp_window",
                    "ip_df",
                    "mss",
                    "wscale",
                    "sack_perm",
                    "ts_val",
                    "ts_ecr",
                    "tcp_ops",
                )
            }
            if any(v is not None for v in feats.values()):
                feats_list.append(feats)
        if not feats_list:
            return None

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        p0f_path, nmap_path = resolve_fp_paths(
            project_root, getattr(self.config, "fingerprints", None)
        )
        detector = OSDetectorCascade(p0f_path, nmap_path)
        return detector.best_guess(feats_list)

    def _is_host_alive_by_icmp(self, ip: str, timeout: float = 1.0) -> bool:
        """
        ICMPScanner를 이용하여 호스트 생존 여부를 판단.
        반환값이 True이면 'alive'로 간주.
        """
        try:
            icmp = ICMPScanner(iface=None, timeout=timeout, result_callback=None)
            ev = icmp.ping(ip)
            state = ev.get("state")
            if state and str(state).lower() in (
                "alive",
                "up",
                "responded",
                "reachable",
            ):
                return True
            if ev.get("rtt") is not None:
                return True
            if ev.get("ok") is True:
                return True
        except Exception as e:
            log.debug("ICMP liveness check failed for %s: %s", ip, e)
        return False

    # --------------------------------------------------------------------------
    # 실행 메인
    # --------------------------------------------------------------------------
    def run(self) -> None:
        if not self.jobs:
            log.info("No jobs to run")
            return

        for job in list(self.jobs):
            log.info(
                "Running job name=%s target=%s ports=%s",
                job.name,
                job.target,
                job.ports,
            )
            events: List[Dict] = []
            chosen = [p.lower() for p in (job.options.scan_protocols or ["tcp"])]
            use_masscan_only = bool(getattr(job.options, "use_masscan_for_tcp", False))

            # ------------------------------------------------------------------
            # 1) Masscan-only 모드: 캡처/pcap 저장 완전 비활성
            # ------------------------------------------------------------------
            if use_masscan_only:
                log.info("Masscan-only mode: packet capture is DISABLED for this job.")

                # targets 정규화(리스트)
                targets_raw = getattr(job.options, "masscan_targets", None) or (
                    job.target or ""
                )
                targets_list: List[str] = []
                if isinstance(targets_raw, (list, tuple, set)):
                    for t in targets_raw:
                        if not t:
                            continue
                        for token in str(t).replace(",", " ").split():
                            if token:
                                targets_list.append(token)
                else:
                    s = str(targets_raw).strip()
                    if s:
                        for token in s.replace(",", " ").split():
                            if token:
                                targets_list.append(token)

                # 라우터 자동 탐지
                auto_router = self._auto_router_ip(targets_list)
                router_ip = getattr(job.options, "router_ip", None) or auto_router
                if router_ip:
                    log.info(
                        "Router IP selected: %s (auto=%s, option=%s)",
                        router_ip,
                        bool(auto_router),
                        bool(getattr(job.options, "router_ip", None)),
                    )

                # Masscan 실행
                try:
                    from modules.scanner.masscan import MasscanScanner
                except Exception as e:
                    log.error("FastSyn module not available: %s", e)
                    continue

                masscan_cb_records: List[Dict] = []

                def _cb(ev: Dict):
                    log.info("[FASTSYN EVENT] %s", ev)
                    ip = ev.get("ip") or ev.get("host") or ev.get("target")
                    port = ev.get("port")
                    if ip and port is not None and ev.get("state") == "open":
                        try:
                            masscan_cb_records.append(
                                {"ip": str(ip), "port": int(port)}
                            )
                        except Exception:
                            pass

                forced_ports = "1-65535"

                try:
                    masscan = MasscanScanner(
                        targets=targets_list,
                        ports=forced_ports,
                        iface=getattr(job.options, "interface", None),
                        rate=int(getattr(job.options, "masscan_rate", 10000) or 10000),
                        wait=float(getattr(job.options, "masscan_wait", 5.0) or 5.0),
                        router_ip=router_ip,
                        ping=bool(getattr(job.options, "masscan_ping", False)),
                        allow_broadcast=bool(
                            getattr(job.options, "allow_broadcast", True)
                        ),
                        result_callback=_cb,
                    )
                    res = masscan.run()
                except Exception as e:
                    log.error("FastSync run failed: %s", e)
                    continue

                # 결과 처리
                records: List[Dict] = []
                if isinstance(res, dict):
                    records.extend(res.get("records", []) or [])
                for r in masscan_cb_records:
                    records.append({"ip": r["ip"], "port": r["port"]})

                ip_ports = defaultdict(set)
                for rec in records:
                    ip = rec.get("ip") or rec.get("target") or rec.get("host")
                    port = rec.get("port")
                    if not ip or port is None:
                        continue
                    ip_ports[str(ip)].add(int(port))

                masscan_events: List[Dict] = []

                if not ip_ports:
                    # Fallback: 순수 TCP connect() 기반 liveness (RST=alive 인정)
                    log.warning(
                        "Masscan produced 0 open-port records. Using TCP-based liveness probe (no broadcast/ICMP)."
                    )

                    # CIDR 확장
                    cidr_hosts = []
                    for tgt in targets_list:
                        try:
                            net = ipaddress.ip_network(tgt, strict=False)
                            cidr_hosts.extend(str(h) for h in net.hosts())
                        except Exception:
                            cidr_hosts.append(tgt)

                    preferred_ports = getattr(
                        job.options,
                        "liveness_tcp_ports",
                        [
                            80,
                            443,
                            22,
                            3389,
                            445,
                            139,
                            135,
                            53,
                            8080,
                            8443,
                            49152,
                            49153,
                        ],
                    )
                    probe_timeout = float(
                        getattr(job.options, "liveness_tcp_probe_timeout", 0.4)
                    )
                    probe_workers = int(
                        getattr(job.options, "liveness_tcp_probe_workers", 256)
                    )

                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    def _tcp_probe(ip: str) -> tuple[bool, List[int]]:
                        opened: List[int] = []
                        any_alive = False
                        for p in preferred_ports:
                            st = SimpleScheduler._tcp_probe_liveness(
                                ip, p, probe_timeout
                            )
                            if st == "open":
                                any_alive = True
                                opened.append(p)
                            elif st == "closed":
                                any_alive = True
                        return any_alive, opened

                    alive_ips = []
                    if cidr_hosts:
                        with ThreadPoolExecutor(
                            max_workers=min(len(cidr_hosts) * 2, probe_workers)
                        ) as ex:
                            fut_map = {
                                ex.submit(_tcp_probe, ip): ip for ip in cidr_hosts
                            }
                            for fut in as_completed(fut_map):
                                ip = fut_map[fut]
                                try:
                                    is_alive, opened = fut.result()
                                except Exception:
                                    is_alive, opened = False, []
                                if not is_alive:
                                    continue
                                alive_ips.append(ip)
                                if opened:
                                    for p in sorted(set(opened)):
                                        ev = {
                                            "protocol": "tcp",
                                            "target": ip,
                                            "host": ip,
                                            "port": int(p),
                                            "state": "open",
                                            "source": "tcp_probe",
                                        }
                                        masscan_events.append(ev)
                                        events.append(ev)
                                else:
                                    ev = {
                                        "protocol": "tcp",
                                        "target": ip,
                                        "host": ip,
                                        "port": None,
                                        "state": "alive",
                                        "source": "tcp_probe",
                                    }
                                    masscan_events.append(ev)
                                    events.append(ev)

                    alive_ips = sorted(set(alive_ips))
                    log.info(
                        "TCP liveness probe found %d alive hosts (RST accepted)",
                        len(alive_ips),
                    )
                else:
                    # FastSyn 결과 재확인 및 이벤트화
                    tcp_timeout = float(
                        getattr(job.options, "liveness_tcp_probe_timeout", 0.4)
                    )
                    preferred_ports = getattr(
                        job.options,
                        "liveness_tcp_ports",
                        [80, 443, 22, 3389, 445, 139, 135, 53, 8080, 8443],
                    )
                    for ip in sorted(ip_ports.keys()):
                        confirmed_any = False
                        for p in sorted(ip_ports[ip]):
                            if SimpleScheduler._tcp_connect_check(ip, p, tcp_timeout):
                                confirmed_any = True
                                ev = {
                                    "protocol": "tcp",
                                    "target": ip,
                                    "host": ip,
                                    "port": int(p),
                                    "state": "open",
                                    "source": "fastsyn",
                                }
                                masscan_events.append(ev)
                                events.append(ev)
                        if not confirmed_any:
                            for p in preferred_ports:
                                st = SimpleScheduler._tcp_probe_liveness(
                                    ip, p, tcp_timeout
                                )
                                if st == "open":
                                    ev = {
                                        "protocol": "tcp",
                                        "target": ip,
                                        "host": ip,
                                        "port": int(p),
                                        "state": "open",
                                        "source": "tcp_probe",
                                    }
                                    masscan_events.append(ev)
                                    events.append(ev)
                                    confirmed_any = True
                                    break
                        if not confirmed_any:
                            ev = {
                                "protocol": "tcp",
                                "target": ip,
                                "host": ip,
                                "port": None,
                                "state": "alive",
                                "source": "tcp_probe",
                            }
                            masscan_events.append(ev)
                            events.append(ev)

                # 리포트 생성
                try:
                    self._write_masscan_reports(
                        job, res if isinstance(res, dict) else {}, masscan_events
                    )
                except Exception as e:
                    log.exception("Failed to write masscan reports: %s", e)

                try:
                    self._write_masscan_text_report(
                        job, masscan_events, res if isinstance(res, dict) else {}
                    )
                except Exception as e:
                    log.exception("Failed to write masscan text report: %s", e)

                # 후처리 분석 (자동)
                try:
                    self._run_post_scan_analysis(job, masscan_events)
                except Exception as e:
                    log.exception("Post-scan analysis failed: %s", e)

                # 확장 보고서 (자동)
                try:
                    self._write_enhanced_report(job, masscan_events)
                except Exception as e:
                    log.exception("Enhanced report generation failed: %s", e)

                log.info(
                    "Job '%s' finished (masscan-only) with %d event(s)",
                    job.name,
                    len(masscan_events),
                )
                result = defaultdict(list)
                for i in masscan_events:
                    result[i["target"]].append(i["port"])
                result = dict(result)
                return result

            # ------------------------------------------------------------------
            # 2) 기본 스캐너 모드: 캡처 시작 → 스캐너 실행 → 캡처 중지
            # ------------------------------------------------------------------
            proto_set = set(chosen)
            port_set = set(job.ports or [])
            bpf = create_scan_filter(job.target or "0.0.0.0/0", proto_set, port_set)

            cap_cfg = CaptureConfig(
                interface=getattr(job.options, "interface", None),
                target=job.target or "0.0.0.0",
                ports=port_set,
                protocols=proto_set,
                capture_file=job.capture_file,
                bpf_filter=bpf,
                promisc=True,
                snaplen=65535,
                timeout=1000,
                buffer_size=100,
            )
            capture = PacketCapture(cap_cfg)

            def cb(ev: Dict):
                events.append(ev)
                log.info("[EVENT] %s", ev)

            try:
                if not capture.start():
                    log.warning(
                        "Packet capture failed to start; continuing without capture."
                    )
                else:
                    time.sleep(0.15)

                # TCP
                if "tcp" in chosen:
                    tcp = TCPScanner(
                        iface=getattr(job.options, "interface", None),
                        timeout=job.timeout,
                        rate_interval=job.rate_interval,
                        result_callback=cb,
                        options=job.options,
                    )
                    res = tcp.scan_target(job.target, job.ports, workers=50)
                    log.info("TCP scan done")

                # UDP
                if "udp" in chosen:
                    udp = UDPScanner(
                        iface=getattr(job.options, "interface", None),
                        timeout=job.timeout,
                        rate_interval=job.rate_interval,
                        result_callback=cb,
                    )
                    udp.scan_target(job.target, job.ports, workers=50)
                    log.info("UDP scan done")

                # ICMP
                if "icmp" in chosen:
                    icmp = ICMPScanner(
                        iface=getattr(job.options, "interface", None),
                        timeout=job.timeout,
                        result_callback=cb,
                    )
                    cb(icmp.ping(job.target))
                    log.info("ICMP ping done")

                # DNS
                if "dns" in chosen:
                    dns = DNSScanner(
                        iface=getattr(job.options, "interface", None),
                        timeout=2.0,
                        result_callback=cb,
                    )
                    qname = job.options.dns_qname or "example.com"
                    qtype = (job.options.dns_qtype or "A").upper()
                    resolver = job.options.dns_resolver or "8.8.8.8"
                    cb(dns.query(resolver, qname, qtype=qtype))
                    log.info("DNS query done")

            finally:
                stats = capture.stop()
                log.info("Capture stats: %s", stats)

                # 후처리 분석 (자동)
                try:
                    self._run_post_scan_analysis(job, events)
                except Exception as e:
                    log.exception("Post-scan analysis failed: %s", e)

                # 확장 보고서 생성 (자동)
                try:
                    self._write_enhanced_report(job, events)
                except Exception:
                    log.exception("report generation failed")

                log.info("Job '%s' finished with %d event(s)", job.name, len(events))
                return res

    # --------------------------------------------------------------------------
    # 외부 요약/초기화
    # --------------------------------------------------------------------------
    def get_analysis_summary(self) -> Dict:
        summary = {
            "total_scan_results": len(self.scan_results),
            "total_assets": len(self.asset_identifier.assets),
            "total_certificates": len(self.tls_analyzer.results),
            "timestamp": datetime.datetime.now().isoformat(),
        }
        if self.asset_identifier.assets:
            asset_report = self.asset_identifier.create_inventory_report()
            summary["asset_summary"] = asset_report["summary"]
        if self.tls_analyzer.results:
            tls_report = self.tls_analyzer.generate_tls_report()
            summary["tls_summary"] = tls_report["summary"]
        return summary

    def clear_analysis_data(self) -> None:
        self.scan_results.clear()
        self.asset_identifier.clear_assets()
        self.tls_analyzer.clear_results()
        log.info("Analysis data cleared")

# ==========================
# Non-invasive CSV Injector
# (Appended without modifying existing code)
# Usage example:
#   python scheduler_patched.py --wrap-run \
#       --runpy ./run.py \
#       --result-dir ./result \
#       --pattern "*_masscan_alive_*.csv" \
#       -- --targets 192.168.0.0/24 --mode masscan-only --rate 12000
# ==========================
import argparse as _argparse
import subprocess as _subprocess
import sys as _sys
import time as _time
import json as _json
import os as _os
import glob as _glob
import shutil as _shutil
import csv as _csv
from datetime import datetime as _dt, timezone as _tz

def _iso_now():
    return _dt.now(_tz.utc).astimezone().isoformat(timespec="seconds")

def _newest_csvs(result_dir, pattern, since_epoch):
    paths = sorted(
        _glob.glob(_os.path.join(result_dir, pattern)),
        key=lambda p: _os.path.getmtime(p),
        reverse=True,
    )
    return [p for p in paths if _os.path.getmtime(p) >= since_epoch]

def _augment_csv(csv_path, extra_cols):
    # skip if already injected
    with open(csv_path, "r", encoding="utf-8", newline="") as rf:
        reader = _csv.reader(rf)
        try:
            header = next(reader)
        except StopIteration:
            return
        already = any(h in ("run_command", "run_args_json", "started_at", "finished_at") for h in header)
    if already:
        return

    tmp_path = csv_path + ".tmp"
    with open(csv_path, "r", encoding="utf-8", newline="") as rf, \
         open(tmp_path, "w", encoding="utf-8", newline="") as wf:
        reader = _csv.reader(rf)
        writer = _csv.writer(wf)

        header = next(reader, None)
        if not header:
            return
        new_header = header + ["run_command", "run_args_json", "started_at", "finished_at"]
        writer.writerow(new_header)

        for row in reader:
            writer.writerow(row + [
                extra_cols["run_command"],
                extra_cols["run_args_json"],
                extra_cols["started_at"],
                extra_cols["finished_at"],
            ])

    _shutil.move(tmp_path, csv_path)

def _main_wrap():
    ap = _argparse.ArgumentParser(description="Wrap run.py and inject CLI options into masscan CSV results (no code changes).")
    ap.add_argument("--wrap-run", action="store_true", help="Run wrapper mode (required to avoid changing existing behavior).")
    ap.add_argument("--python", default=_sys.executable, help="Python interpreter to use for run.py")
    ap.add_argument("--runpy", help="Path to run.py")
    ap.add_argument("--result-dir", default="result", help="Directory where CSVs are written")
    ap.add_argument("--pattern", default="*_masscan_alive_*.csv", help="Glob pattern for target CSVs")
    ap.add_argument("--timeout", type=int, default=0, help="Optional timeout (seconds) for run.py")
    ap.add_argument("run_args", nargs=_argparse.REMAINDER, help="Arguments to pass to run.py (prefix with -- )")
    args = ap.parse_args()

    if not args.wrap_run:
        print("[scheduler.py] This module was executed directly without --wrap-run. "
              "Existing behavior remains unchanged. To use the CSV injector wrapper, "
              "run with --wrap-run and provide --runpy and arguments after -- .")
        return 0

    if not args.runpy:
        ap.error("--runpy is required when using --wrap-run")

    run_argv = args.run_args
    if run_argv and run_argv[0] == "--":
        run_argv = run_argv[1:]

    started_at = _iso_now()
    started_epoch = _time.time()

    cmd = [args.python, args.runpy] + run_argv
    run_command_str = " ".join(cmd)

    try:
        res = _subprocess.run(cmd, timeout=args.timeout if args.timeout > 0 else None)
        ret = res.returncode
    except _subprocess.TimeoutExpired:
        ret = 124
    finished_at = _iso_now()

    csvs = _newest_csvs(args.result_dir, args.pattern, since_epoch=started_epoch)
    extra = {
        "run_command": run_command_str,
        "run_args_json": _json.dumps(run_argv, ensure_ascii=False),
        "started_at": started_at,
        "finished_at": finished_at,
    }
    for p in csvs:
        try:
            _augment_csv(p, extra)
            print(f"[OK] Injected run options into: {p}")
        except Exception as e:
            print(f"[WARN] Failed to inject into {p}: {e}")

    return ret

if __name__ == "__main__":
    # Only activate wrapper if --wrap-run is explicitly provided.
    # This guarantees ZERO behavior change for any existing imports/usages.
    exit_code = _main_wrap()
    if isinstance(exit_code, int):
        _sys.exit(exit_code)
