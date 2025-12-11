# modules/capture/__init__.py
"""
패킷 캡처 모듈
- 실시간 네트워크 패킷 캡처
- PCAP/PCAPNG 파일 저장
- BPF 필터링 및 최적화
- 스레드 안전한 파일 쓰기
"""

from .pcap_writer import ThreadSafePcapWriter, PacketBuffer, create_pcap_writer
from .packet_capture import (
    PacketCapture,
    CaptureConfig,
    create_packet_capture,
    quick_capture,
)
from .filters import (
    BPFFilterBuilder,
    create_scan_filter,
    validate_filter,
    FilterPresets,
)

__all__ = [
    "ThreadSafePcapWriter",
    "PacketBuffer",
    "create_pcap_writer",
    "PacketCapture",
    "CaptureConfig",
    "create_packet_capture",
    "quick_capture",
    "BPFFilterBuilder",
    "FilterPresets",
    "create_scan_filter",
    "validate_filter",
]

__version__ = "1.0.0"
