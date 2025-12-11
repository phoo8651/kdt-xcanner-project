from __future__ import annotations
import yaml
from dataclasses import dataclass, field, asdict
from typing import List, Optional
import os

@dataclass
class AppConfig:
    gui_profile: str = "default"
    scan_template: str = "default"
    output_dir: str = "result"
    capture_dir: str = "result"

    @staticmethod
    def load(path: str):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            return AppConfig(
                gui_profile = raw.get("gui_profile", "default"),
                scan_template = raw.get("scan_template", "default"),
                output_dir = raw.get("output_dir", "result"),
                capture_dir = raw.get("capture_dir", "result"),
            )
        return AppConfig()

    def to_dict(self):
        return asdict(self)

@dataclass
class ScanOptions:
    # probe options
    ua_enabled: bool = False
    ua_string: str = "scanner-x/0.1"
    http_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8000, 8443])

    # tcp scanning options
    syn_retries: int = 2
    tcp_connect_fallback: bool = True
    connect_timeout: float = 1.0

    # NEW: which protocols to run (e.g. ["tcp","udp","icmp","os","dns"])
    scan_protocols: List[str] = field(default_factory=lambda: ["tcp"])

    # NEW: tcp scan mode: one of "full","syn","fin","null","xmas"
    tcp_scan_mode: str = "syn"

    # full-connect graceful close?
    graceful_close: bool = False

    # NEW: network
    interface: str | None = None

    # dns
    dns_qname: str = "example.com"
    dns_qtype: str = "A"
    dns_resolver: str | None = None

    use_masscan_for_tcp: bool = False
    masscan_rate: str = 1000
    masscan_wait: str = 10
    masscan_targets: List[str] = field(default_factory=lambda: ["127.0.0.1"])

    # ========== TLS 분석 옵션 ==========
    # TLS 인증서 분석 활성화 여부
    enable_tls_analysis: bool = False
    
    # TLS 분석 대상 포트 목록 (기본: HTTPS 포트들)
    tls_analysis_ports: List[int] = field(default_factory=lambda: [443, 8443])
    
    # TLS 연결 타임아웃 (초)
    tls_analysis_timeout: float = 3.0
    
    # TLS 분석 병렬 작업자 수
    tls_max_workers: int = 5
    
    # ========== 자산 식별 옵션 ==========
    # 자산 식별 기능 활성화 여부 (기본: 활성화)
    enable_asset_identification: bool = True
    
    # 고위험 자산 판단 임계값 (0-100 점수)
    asset_risk_threshold: int = 70
    
    # ========== 보고서 및 내보내기 옵션 ==========
    # 확장 보고서 생성 여부 (TLS + 자산 분석 포함)
    generate_enhanced_report: bool = True
    
    # 보안 권고사항 포함 여부
    include_security_recommendations: bool = True
    
    # 자산 인벤토리 CSV 내보내기
    export_asset_csv: bool = False
    
    # TLS 인증서 데이터 CSV 내보내기
    export_tls_csv: bool = False
    
    # ========== TCP 4-way handshake 옵션 ==========
    # TCP full scan 시 4-way handshake 사용 여부 (김예지님 1번 작업)
    use_4way_handshake: bool = False


@dataclass
class ScanJob:
    name: str
    target: str
    org_ports: str
    ports: List[int] = field(default_factory=list)

    # 실행할 프로토콜
    protocols_to_scan: List[str] = field(default_factory=list)

    capture_file: Optional[str] = None
    timeout: float = 1.5
    rate_interval: float = 0.0
    options: ScanOptions = field(default_factory=ScanOptions)

    def to_dict(self):
        return asdict(self)


# ========== 분석 결과 데이터 모델 ==========

@dataclass
class TLSCertificateInfo:
    """TLS 인증서 정보"""
    host: str
    port: int
    subject: Optional[dict] = None
    issuer: Optional[dict] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_left: Optional[int] = None
    warning_level: str = "ok"  # "ok", "D-30", "D-7", "expired"
    
    def to_dict(self):
        return asdict(self)


@dataclass
class AssetInfo:
    """자산 정보"""
    ip: str
    hostname: Optional[str] = None
    asset_type: str = "Unknown Device"
    open_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)  # {port: service_name}
    os_hints: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    criticality: str = "Low"  # "Low", "Medium", "High", "Critical"
    last_updated: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)


@dataclass
class AnalysisReport:
    """분석 보고서 종합 정보"""
    timestamp: str
    scan_summary: dict = field(default_factory=dict)
    tls_analysis: dict = field(default_factory=dict)
    asset_inventory: dict = field(default_factory=dict)
    security_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)


# ========== 설정 관련 유틸리티 함수 ==========

def create_default_scan_options(
    enable_tls: bool = False,
    enable_assets: bool = True,
    protocols: List[str] = None
) -> ScanOptions:
    """기본 스캔 옵션 생성 헬퍼 함수"""
    if protocols is None:
        protocols = ["tcp"]
    
    return ScanOptions(
        scan_protocols=protocols,
        enable_tls_analysis=enable_tls,
        enable_asset_identification=enable_assets,
        generate_enhanced_report=True,
        include_security_recommendations=True
    )


def create_tls_focused_options() -> ScanOptions:
    """TLS 분석 중심 스캔 옵션"""
    return ScanOptions(
        scan_protocols=["tcp"],
        tcp_scan_mode="syn",
        enable_tls_analysis=True,
        tls_analysis_ports=[443, 8443, 993, 995, 465, 587, 636],  # 확장된 TLS 포트
        tls_analysis_timeout=5.0,
        tls_max_workers=10,
        enable_asset_identification=True,
        generate_enhanced_report=True,
        export_tls_csv=True,
        include_security_recommendations=True
    )


def create_comprehensive_options() -> ScanOptions:
    """종합 분석 옵션 (모든 기능 활성화)"""
    return ScanOptions(
        scan_protocols=["tcp", "udp", "icmp", "dns"],
        tcp_scan_mode="syn",
        enable_tls_analysis=True,
        tls_analysis_ports=[443, 8443, 993, 995, 465, 587, 636],
        tls_analysis_timeout=3.0,
        enable_asset_identification=True,
        generate_enhanced_report=True,
        include_security_recommendations=True,
        export_asset_csv=True,
        export_tls_csv=True,
        asset_risk_threshold=60  # 좀 더 민감한 위험도 설정
    )


def create_quick_scan_options() -> ScanOptions:
    """빠른 스캔 옵션 (기본 기능만)"""
    return ScanOptions(
        scan_protocols=["tcp"],
        tcp_scan_mode="syn",
        enable_tls_analysis=False,  # TLS 분석 비활성화로 속도 향상
        enable_asset_identification=True,
        generate_enhanced_report=False,  # 기본 보고서만
        include_security_recommendations=False
    )