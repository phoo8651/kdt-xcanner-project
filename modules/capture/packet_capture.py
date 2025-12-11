# modules/capture/packet_capture.py

"""
메인 패킷 캡처 로직
- AsyncSniffer 기반 실시간 패킷 캡처
- 멀티스레드 안전한 패킷 처리
- 통계 및 모니터링 기능
"""

import logging
import threading
import time
from typing import Optional, Callable, List, Set, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from scapy.all import AsyncSniffer, conf, get_if_list, get_if_addr
from scapy.packet import Packet

from .pcap_writer import ThreadSafePcapWriter
from .filters import BPFFilterBuilder, create_scan_filter
from ..utils.log import get_logger

log = get_logger("packet_capture")


@dataclass
class CaptureConfig:
    """패킷 캡처 설정"""

    interface: Optional[str] = None
    target: str = "127.0.0.1"
    ports: Set[int] = None
    protocols: Set[str] = None
    capture_file: Optional[str] = None
    bpf_filter: Optional[str] = None
    promisc: bool = True
    snaplen: int = 65535
    timeout: int = 1000
    buffer_size: int = 100

    def __post_init__(self):
        if self.ports is None:
            self.ports = set()
        if self.protocols is None:
            self.protocols = {"tcp"}


class PacketCapture:
    """
    패킷 캡처 메인 클래스
    - AsyncSniffer를 사용한 비동기 패킷 캡처
    - ThreadSafePcapWriter로 안전한 파일 저장
    - 실시간 통계 및 모니터링
    """

    def __init__(
        self,
        config: CaptureConfig,
        packet_callback: Optional[Callable[[Packet], None]] = None,
    ):
        """
        Args:
            config: 캡처 설정
            packet_callback: 패킷 수신 시 호출할 콜백 함수
        """
        self.config = config
        self.packet_callback = packet_callback

        # 상태 관리
        self.sniffer: Optional[AsyncSniffer] = None
        self.writer: Optional[ThreadSafePcapWriter] = None
        self.is_running = False
        self._stats_lock = threading.Lock()
        self._stats = {
            "packets_captured": 0,
            "packets_written": 0,
            "start_time": 0,
            "bytes_captured": 0,
            "errors": 0,
        }

        # 통계 모니터링 스레드
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor = threading.Event()

        # 인터페이스 설정
        self.interface = self._resolve_interface()

        # BPF 필터 생성
        if config.bpf_filter:
            self.bpf_filter = config.bpf_filter
        else:
            self.bpf_filter = self._generate_filter()

        log.info(
            "PacketCapture initialized - interface=%s, filter=%s",
            self.interface,
            self.bpf_filter,
        )

    def _resolve_interface(self) -> Optional[str]:
        """네트워크 인터페이스 결정"""
        if self.config.interface:
            # 명시적으로 지정된 인터페이스
            available_ifs = get_if_list()
            if self.config.interface in available_ifs:
                return self.config.interface
            else:
                log.warning(
                    "Interface %s not found, available: %s",
                    self.config.interface,
                    available_ifs,
                )
                return None

        # 기본 인터페이스 사용
        default_iface = conf.iface
        if default_iface:
            log.info("Using default interface: %s", default_iface)
            return default_iface

        log.error("No network interface available")
        return None

    def _generate_filter(self) -> str:
        """BPF 필터 자동 생성"""
        try:
            filter_str = create_scan_filter(
                target=self.config.target,
                protocols=self.config.protocols,
                ports=self.config.ports,
            )
            log.debug("Generated BPF filter: %s", filter_str)
            return filter_str
        except Exception as e:
            log.error("Failed to generate BPF filter: %s", e)
            # 기본 필터로 폴백
            return f"host {self.config.target}"

    def _packet_handler(self, packet: Packet) -> None:
        """
        패킷 처리 핸들러
        - 통계 업데이트
        - 파일 저장
        - 콜백 호출
        """
        try:
            # 통계 업데이트
            with self._stats_lock:
                self._stats["packets_captured"] += 1
                self._stats["bytes_captured"] += len(packet)

            # 파일 저장
            if self.writer:
                try:
                    self.writer.write(packet)
                    self.writer.flush()
                    with self._stats_lock:
                        self._stats["packets_written"] += 1
                except Exception as e:
                    log.error("writer.write failed: %s", e)
                    with self._stats_lock:
                        self._stats["errors"] += 1

            # 사용자 콜백 호출
            if self.packet_callback:
                try:
                    self.packet_callback(packet)
                except Exception as e:
                    log.error("Packet callback error: %s", e)
                    with self._stats_lock:
                        self._stats["errors"] += 1

        except Exception as e:
            log.error("Packet handler error: %s", e)
            with self._stats_lock:
                self._stats["errors"] += 1

    def _start_monitor(self) -> None:
        """통계 모니터링 스레드 시작"""

        def monitor_loop():
            last_count = 0
            while not self._stop_monitor.is_set():
                try:
                    current_stats = self.get_stats()
                    current_count = current_stats["packets_captured"]
                    rate = current_count - last_count

                    if rate > 0:  # 패킷이 수신되고 있을 때만 로그
                        log.info(
                            "Capture: %d packets (+%d/10s), %d bytes, %.1f pkt/s",
                            current_count,
                            rate,
                            current_stats["bytes_captured"],
                            current_stats.get("capture_rate", 0),
                        )

                    last_count = current_count

                except Exception as e:
                    log.error("Monitor thread error: %s", e)

                self._stop_monitor.wait(10)  # 10초마다 체크

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
        log.debug("Statistics monitor started")

    def start(self) -> bool:
        """패킷 캡처 시작"""
        if self.is_running:
            log.warning("Packet capture already running")
            return True

        if not self.interface:
            log.error("No valid network interface")
            return False

        try:
            # PCAP writer 초기화
            if self.config.capture_file:
                self.writer = ThreadSafePcapWriter(
                    self.config.capture_file,
                    sync=True,
                )
                log.info("PCAP writer initialized: %s", self.config.capture_file)

            # AsyncSniffer 설정
            sniffer_kwargs = {
                "iface": self.interface,
                "prn": self._packet_handler,
                "store": False,  # 메모리 절약
                "count": 0,  # 무제한
            }

            # BPF 필터 적용
            if self.bpf_filter:
                sniffer_kwargs["filter"] = self.bpf_filter

            # Promiscuous 모드
            if hasattr(AsyncSniffer, "promisc"):
                sniffer_kwargs["promisc"] = self.config.promisc

            # 스니퍼 생성 및 시작
            self.sniffer = AsyncSniffer(**sniffer_kwargs)
            self.sniffer.start()

            # 시작 확인
            time.sleep(0.1)
            if not getattr(self.sniffer, "running", False):
                log.error("Failed to start packet sniffer")
                return False

            # 상태 업데이트
            self.is_running = True
            with self._stats_lock:
                self._stats["start_time"] = time.time()

            # 모니터링 시작
            self._start_monitor()

            log.info("Packet capture started on interface %s", self.interface)
            return True

        except PermissionError:
            log.error(
                "Permission denied - packet capture requires administrator/root privileges"
            )
            return False
        except Exception as e:
            log.error("Failed to start packet capture: %s", e)
            self.stop()
            return False

    def stop(self) -> Dict[str, Any]:
        """
        패킷 캡처 중지

        Returns:
          최종 통계 정보
        """
        # 이미 멈춘 경우에도 일관된 상태 반환
        if not self.is_running:
            stats = self.get_stats()
            stats["is_running"] = False
            return stats

        log.info("Stopping packet capture...")

        # 모니터링 스레드 중지
        self._stop_monitor.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=2.0)
            except Exception as e:
                log.warning("Monitor join error: %s", e)
        self._monitor_thread = None

        # sniffer 정지 시도
        sniffer_exc = None
        if self.sniffer:
            try:
                if getattr(self.sniffer, "running", False):
                    self.sniffer.stop()
                # 스레드가 있다면 합류 시도
                try:
                    self.sniffer.join(timeout=1.0)
                except Exception:
                    pass
            except Exception as e:
                sniffer_exc = e
                log.warning("Error stopping sniffer: %s", e)

        # 기본 통계 스냅샷
        final_stats = self.get_stats()

        # writer 종료는 sniffer 성공/실패와 무관하게 반드시 수행
        writer_exc = None
        if self.writer:
            try:
                # 최신 상태 한번 더 조회 (파일 경로/크기 등)
                try:
                    ws = self.writer.get_stats()
                    final_stats.update(ws)
                except Exception:
                    pass

                # flush + close 보장
                try:
                    self.writer.flush()
                except Exception:
                    pass

                self.writer.close()

                # 닫은 후 다시 통계 반영 시도
                try:
                    ws2 = self.writer.get_stats()
                    final_stats.update(ws2)
                except Exception:
                    pass

                log.info(
                    "PCAP writer closed: %s (packets=%s)",
                    final_stats.get("file_path", self.config.capture_file),
                    final_stats.get("packet_count", "unknown"),
                )
            except Exception as e:
                writer_exc = e
                log.warning("Error closing PCAP writer: %s", e)

        # 상태 플래그 정리
        self.is_running = False
        final_stats["is_running"] = False
        # writer/파일 관련 플래그 보정
        final_stats.setdefault("file_path", self.config.capture_file or "")
        final_stats.setdefault("packet_count", 0)
        final_stats["is_closed"] = True

        # 내부 참조 정리(메모리/재사용 안전)
        self.sniffer = None
        self.writer = None

        # 마지막 로그
        if sniffer_exc:
            log.debug("Sniffer stop had error but capture finalized.")
        if writer_exc:
            log.debug("Writer close had error but stop() returned final stats.")

        log.info("Packet capture stopped. Final stats: %s", final_stats)
        return final_stats


    def get_stats(self) -> Dict[str, Any]:
        """현재 캡처 통계 반환"""
        with self._stats_lock:
            stats = self._stats.copy()

        # 계산된 통계 추가
        if stats["start_time"] > 0:
            elapsed = time.time() - stats["start_time"]
            stats["elapsed_seconds"] = elapsed
            if elapsed > 0:
                stats["capture_rate"] = stats["packets_captured"] / elapsed
            else:
                stats["capture_rate"] = 0
        else:
            stats["elapsed_seconds"] = 0
            stats["capture_rate"] = 0

        stats["is_running"] = self.is_running
        stats["interface"] = self.interface
        stats["bpf_filter"] = self.bpf_filter

        # Writer 통계 추가
        if self.writer:
            try:
                writer_stats = self.writer.get_stats()
                stats.update(
                    {
                        "file_size_bytes": writer_stats.get("file_size_bytes", 0),
                        "file_path": writer_stats.get("file_path", ""),
                    }
                )
            except Exception:
                pass

        return stats

    def is_alive(self) -> bool:
        """캡처가 활성 상태인지 확인"""
        if not self.is_running or not self.sniffer:
            return False
        return getattr(self.sniffer, "running", False)

    def __enter__(self):
        """컨텍스트 매니저 진입"""
        success = self.start()
        if not success:
            raise RuntimeError("Failed to start packet capture")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """컨텍스트 매니저 종료"""
        self.stop()

    def __del__(self):
        """소멸자에서 안전하게 정리"""
        try:
            if self.is_running:
                self.stop()
        except Exception:
            pass  # 소멸자에서는 예외 무시


# 편의 함수들
def create_packet_capture(
    target: str,
    ports: Optional[List[int]] = None,
    protocols: Optional[List[str]] = None,
    capture_file: Optional[str] = None,
    interface: Optional[str] = None,
    packet_callback: Optional[Callable] = None,
) -> PacketCapture:
    """
    패킷 캡처 인스턴스 생성 편의 함수

    Args:
        target: 캡처 대상 호스트
        ports: 포트 리스트
        protocols: 프로토콜 리스트
        capture_file: PCAP 파일 경로
        interface: 네트워크 인터페이스
        packet_callback: 패킷 처리 콜백

    Returns:
        PacketCapture 인스턴스
    """
    config = CaptureConfig(
        target=target,
        ports=set(ports) if ports else set(),
        protocols=set(protocols) if protocols else {"tcp"},
        capture_file=capture_file,
        interface=interface,
    )

    return PacketCapture(config, packet_callback)


def quick_capture(
    target: str, duration: int = 10, capture_file: str = "quick_capture.pcap"
) -> Dict[str, Any]:
    """
    간단한 패킷 캡처 실행

    Args:
        target: 캡처 대상
        duration: 캡처 시간(초)
        capture_file: 저장할 파일명

    Returns:
        캡처 통계
    """
    capture = create_packet_capture(target, capture_file=capture_file)

    try:
        if not capture.start():
            return {"error": "Failed to start capture"}

        log.info("Quick capture started for %d seconds", duration)
        time.sleep(duration)

        return capture.stop()

    except KeyboardInterrupt:
        log.info("Capture interrupted by user")
        return capture.stop()
    except Exception as e:
        log.error("Quick capture error: %s", e)
        return {"error": str(e)}
