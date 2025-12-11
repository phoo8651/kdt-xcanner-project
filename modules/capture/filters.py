# modules/capture/filters.py

"""
BPF 필터 생성 및 관리
- 프로토콜별 최적화된 필터 생성
- 포트 범위 및 네트워크 대상 지원
- 성능을 위한 필터 길이 제한
"""

import logging
import ipaddress
from typing import Set, List, Optional, Union

log = logging.getLogger("bpf_filters")


class BPFFilterBuilder:
    """
    BPF 필터 동적 생성기
    - 다양한 네트워크 조건을 BPF 문법으로 변환
    - 필터 복잡도 및 길이 제한
    - 프로토콜별 최적화
    """

    # 성능을 위한 제한값들
    MAX_FILTER_LENGTH = 1024
    MAX_PORTS_PER_PROTOCOL = 15
    MAX_HOSTS = 10

    def __init__(self):
        """필터 빌더 초기화"""
        self.reset()

    def reset(self) -> "BPFFilterBuilder":
        """필터 조건 초기화"""
        self.host_conditions = []
        self.protocol_conditions = []
        self.extra_conditions = []
        return self

    def add_host(self, host: str) -> "BPFFilterBuilder":
        """단일 호스트 추가"""
        try:
            # IP 주소 검증
            ip = ipaddress.ip_address(host)
            self.host_conditions.append(f"host {ip}")
            log.debug("Added host filter: %s", host)
        except ValueError:
            # 도메인명 또는 기타 형식
            self.host_conditions.append(f"host {host}")
            log.debug("Added hostname filter: %s", host)
        return self

    def add_hosts(self, hosts: List[str]) -> "BPFFilterBuilder":
        """여러 호스트 추가"""
        limited_hosts = hosts[: self.MAX_HOSTS]
        if len(hosts) > self.MAX_HOSTS:
            log.warning("Limited hosts to %d (was %d)", self.MAX_HOSTS, len(hosts))

        for host in limited_hosts:
            self.add_host(host)
        return self

    def add_network(self, network: str) -> "BPFFilterBuilder":
        """네트워크 CIDR 추가"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            self.host_conditions.append(f"net {net}")
            log.debug("Added network filter: %s", network)
        except ValueError as e:
            log.error("Invalid network %s: %s", network, e)
        return self

    def add_tcp(self, ports: Optional[Set[int]] = None) -> "BPFFilterBuilder":
        """TCP 프로토콜 및 포트 추가"""
        if not ports:
            self.protocol_conditions.append("tcp")
            log.debug("Added TCP filter (all ports)")
            return self

        # 포트 수 제한
        limited_ports = sorted(ports)[: self.MAX_PORTS_PER_PROTOCOL]
        if len(ports) > self.MAX_PORTS_PER_PROTOCOL:
            log.info("Limited TCP ports to %d", self.MAX_PORTS_PER_PROTOCOL)

        if len(limited_ports) == 1:
            self.protocol_conditions.append(f"(tcp and port {limited_ports[0]})")
        else:
            port_expr = " or ".join(f"port {p}" for p in limited_ports)
            self.protocol_conditions.append(f"(tcp and ({port_expr}))")

        log.debug("Added TCP filter with %d ports", len(limited_ports))
        return self

    def add_udp(self, ports: Optional[Set[int]] = None) -> "BPFFilterBuilder":
        """UDP 프로토콜 및 포트 추가"""
        if not ports:
            self.protocol_conditions.append("udp")
            log.debug("Added UDP filter (all ports)")
            return self

        limited_ports = sorted(ports)[: self.MAX_PORTS_PER_PROTOCOL]
        if len(ports) > self.MAX_PORTS_PER_PROTOCOL:
            log.info("Limited UDP ports to %d", self.MAX_PORTS_PER_PROTOCOL)

        if len(limited_ports) == 1:
            self.protocol_conditions.append(f"(udp and port {limited_ports[0]})")
        else:
            port_expr = " or ".join(f"port {p}" for p in limited_ports)
            self.protocol_conditions.append(f"(udp and ({port_expr}))")

        log.debug("Added UDP filter with %d ports", len(limited_ports))
        return self

    def add_icmp(self) -> "BPFFilterBuilder":
        """ICMP 프로토콜 추가 (IPv4/IPv6 모두)"""
        self.protocol_conditions.append("(icmp or icmp6)")
        log.debug("Added ICMP filter")
        return self

    def add_dns(self, servers: Optional[List[str]] = None) -> "BPFFilterBuilder":
        """DNS 쿼리 필터 추가"""
        if not servers:
            # 모든 DNS 트래픽
            self.protocol_conditions.append("((tcp or udp) and port 53)")
            log.debug("Added DNS filter (all servers)")
        else:
            # 특정 DNS 서버들과의 통신만
            limited_servers = servers[:5]  # DNS 서버 수 제한
            server_expr = " or ".join(f"host {srv}" for srv in limited_servers)
            self.protocol_conditions.append(
                f"(((tcp or udp) and port 53) and ({server_expr}))"
            )
            log.debug("Added DNS filter for %d servers", len(limited_servers))
        return self

    def add_arp(self) -> "BPFFilterBuilder":
        """ARP 프로토콜 추가"""
        self.extra_conditions.append("arp")
        log.debug("Added ARP filter")
        return self

    def add_port_range(
        self, start: int, end: int, protocol: str = "tcp"
    ) -> "BPFFilterBuilder":
        """포트 범위 추가"""
        if start > end:
            start, end = end, start

        if end - start > self.MAX_PORTS_PER_PROTOCOL:
            log.warning(
                "Port range too large (%d-%d), may impact performance", start, end
            )

        self.protocol_conditions.append(f"({protocol} and portrange {start}-{end})")
        log.debug("Added %s port range: %d-%d", protocol, start, end)
        return self

    def add_custom(self, filter_expr: str) -> "BPFFilterBuilder":
        """커스텀 BPF 표현식 추가"""
        if filter_expr.strip():
            self.extra_conditions.append(f"({filter_expr})")
            log.debug("Added custom filter: %s", filter_expr)
        return self

    def build(self, optimize: bool = True) -> str:
        """
        최종 BPF 필터 문자열 생성
        """
        components = []

        # 1. 호스트 조건
        if self.host_conditions:
            if len(self.host_conditions) == 1:
                host_expr = self.host_conditions[0]
            else:
                host_expr = "(" + " or ".join(self.host_conditions) + ")"
            components.append(host_expr)

        # 2. 프로토콜 조건
        if self.protocol_conditions:
            if len(self.protocol_conditions) == 1:
                proto_expr = self.protocol_conditions[0]
            else:
                proto_expr = "(" + " or ".join(self.protocol_conditions) + ")"

            if components:
                components = [f"({components[0]} and {proto_expr})"]
            else:
                components.append(proto_expr)

        # 3. 추가 조건 (ARP, 커스텀 등)
        if self.extra_conditions:
            extra_expr = " or ".join(self.extra_conditions)
            if components:
                # 전체를 다시 괄호로 묶어 균형 유지
                combined = components[0]
                final_expr = f"({combined} or {extra_expr})"
                components = [final_expr]
            else:
                components.append(extra_expr)

        # 최종 조합
        if not components:
            return ""

        final_filter = components[0]

        # 항상 최상위 괄호로 감싸기 (안전한 and/or 결합 보장)
        if not (final_filter.startswith("(") and final_filter.endswith(")")):
            final_filter = f"({final_filter})"

        # 길이 제한 확인
        if len(final_filter) > self.MAX_FILTER_LENGTH:
            log.warning("BPF filter too long (%d chars), truncating", len(final_filter))
            final_filter = final_filter[: self.MAX_FILTER_LENGTH - 20] + "..."

        # 괄호 균형 자동 보정
        left, right = final_filter.count("("), final_filter.count(")")
        if left > right:
            final_filter += ")" * (left - right)
        elif right > left:
            final_filter = "(" * (right - left) + final_filter

        # 최적화 적용
        if optimize:
            final_filter = self._optimize_filter(final_filter)

        log.info("Generated BPF filter (%d chars): %s", len(final_filter), final_filter)
        return final_filter

    def _optimize_filter(self, filter_str: str) -> str:
        """
        BPF 필터 최적화
        - 과격한 괄호 치환 제거
        - 기본적인 중복 공백만 처리
        """
        optimized = filter_str

        # 중복 공백 제거
        while "  " in optimized:
            optimized = optimized.replace("  ", " ")

        # 연속 괄호 단순 정리 (안전하게)
        while "((" in optimized and "))" in optimized:
            tmp = optimized.replace("((", "(").replace("))", ")")
            if tmp == optimized:
                break
            optimized = tmp

        return optimized


# 미리 정의된 필터 패턴들
class FilterPresets:
    """자주 사용되는 BPF 필터 프리셋"""

    @staticmethod
    def web_services(target: str, ports: Optional[Set[int]] = None) -> str:
        """웹 서비스 스캔용 필터"""
        web_ports = ports or {80, 443, 8000, 8080, 8443, 3000, 9000}
        return BPFFilterBuilder().add_host(target).add_tcp(web_ports).add_arp().build()

    @staticmethod
    def common_services(target: str) -> str:
        """일반적인 서비스 포트 스캔용"""
        common_ports = {
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            993,
            995,
            1433,
            3306,
            3389,
            5432,
        }
        return (
            BPFFilterBuilder()
            .add_host(target)
            .add_tcp(common_ports)
            .add_udp({53, 161, 162})  # DNS, SNMP
            .add_arp()
            .build()
        )

    @staticmethod
    def full_scan(target: str, ports: Set[int]) -> str:
        """전체 포트 스캔용"""
        return (
            BPFFilterBuilder()
            .add_host(target)
            .add_tcp(ports)
            .add_udp(ports)
            .add_icmp()
            .add_arp()
            .build()
        )

    @staticmethod
    def network_discovery(target: str) -> str:
        """네트워크 발견용 (핑, ARP, DNS)"""
        return (
            BPFFilterBuilder().add_host(target).add_icmp().add_arp().add_dns().build()
        )

    @staticmethod
    def stealth_scan(target: str, ports: Set[int]) -> str:
        """스텔스 스캔용 (최소 트래픽)"""
        # 포트 수를 크게 제한
        limited_ports = set(sorted(ports)[:5])
        return BPFFilterBuilder().add_host(target).add_tcp(limited_ports).build()

    @staticmethod
    def dns_enumeration(target: str, resolvers: List[str]) -> str:
        """DNS 열거용"""
        return BPFFilterBuilder().add_host(target).add_dns(resolvers).build()

    @staticmethod
    def vulnerability_scan(target: str) -> str:
        """취약점 스캔용 (일반적인 취약 서비스)"""
        vuln_ports = {
            21,
            23,
            25,
            53,
            79,
            80,
            110,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            1521,
            3306,
            3389,
        }
        return (
            BPFFilterBuilder()
            .add_host(target)
            .add_tcp(vuln_ports)
            .add_udp({53, 135, 137, 138, 161})
            .add_icmp()
            .build()
        )


# 편의 함수들
def create_scan_filter(
    target: str,
    protocols: Set[str],
    ports: Optional[Set[int]] = None,
    scan_mode: str = "syn",
) -> str:
    """
    스캔 설정에 맞는 BPF 필터 생성

    Args:
        target: 스캔 대상 호스트/네트워크
        protocols: 프로토콜 집합 {"tcp", "udp", "icmp", "dns"}
        ports: 포트 집합 (None이면 프로토콜별 기본값)
        scan_mode: TCP 스캔 모드 (현재는 사용하지 않음)

    Returns:
        BPF 필터 문자열
    """
    if target is None:
        target_str = ""
    else:
        target_str = str(target).strip()
    target = target_str

    builder = BPFFilterBuilder()

    # 타겟 추가 (IP/도메인/네트워크 자동 판별)
    if "/" in target:
        # CIDR 형식
        builder.add_network(target)
    else:
        # 단일 호스트
        builder.add_host(target)

    # 프로토콜별 필터 추가
    protocols = {p.lower() for p in protocols} if protocols else {"tcp"}

    if "tcp" in protocols:
        builder.add_tcp(ports)

    if "udp" in protocols:
        builder.add_udp(ports)

    if "icmp" in protocols:
        builder.add_icmp()

    if "dns" in protocols:
        builder.add_dns()

    # ARP는 네트워크 상태 파악용으로 항상 포함
    builder.add_arp()

    return builder.build()


def create_host_filter(hosts: Union[str, List[str]], include_arp: bool = True) -> str:
    """
    호스트 기반 필터 생성

    Args:
        hosts: 단일 호스트 또는 호스트 리스트
        include_arp: ARP 트래픽 포함 여부

    Returns:
        BPF 필터 문자열
    """
    builder = BPFFilterBuilder()

    if isinstance(hosts, str):
        builder.add_host(hosts)
    else:
        builder.add_hosts(hosts)

    if include_arp:
        builder.add_arp()

    return builder.build()


def create_port_filter(
    ports: Union[int, List[int], Set[int]],
    protocol: str = "tcp",
    target: Optional[str] = None,
) -> str:
    """
    포트 기반 필터 생성

    Args:
        ports: 포트 번호(들)
        protocol: 프로토콜 ("tcp" 또는 "udp")
        target: 대상 호스트 (선택)

    Returns:
        BPF 필터 문자열
    """
    builder = BPFFilterBuilder()

    if target:
        builder.add_host(target)

    # 포트 집합으로 변환
    if isinstance(ports, int):
        port_set = {ports}
    elif isinstance(ports, list):
        port_set = set(ports)
    else:
        port_set = ports

    if protocol.lower() == "tcp":
        builder.add_tcp(port_set)
    elif protocol.lower() == "udp":
        builder.add_udp(port_set)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    return builder.build()


def validate_filter(filter_str: str) -> bool:
    """
    BPF 필터 기본 검증

    Args:
        filter_str: 검증할 필터 문자열

    Returns:
        유효성 여부
    """
    if not filter_str:
        return True  # 빈 필터는 유효

    try:
        # 기본적인 문법 검사

        # 1. 괄호 균형 확인
        if filter_str.count("(") != filter_str.count(")"):
            log.error("Unbalanced parentheses in BPF filter")
            return False

        # 2. 금지된 문자 확인
        forbidden_chars = ["<", ">", "|", "&", ";", ",", "`", "\\"]
        for char in forbidden_chars:
            if char in filter_str:
                log.error("Forbidden character '%s' in BPF filter", char)
                return False

        # 3. 길이 제한
        if len(filter_str) > BPFFilterBuilder.MAX_FILTER_LENGTH:
            log.error("BPF filter too long: %d chars", len(filter_str))
            return False

        # 4. 기본 키워드 확인 (매우 기본적)
        valid_keywords = {
            "host",
            "net",
            "port",
            "portrange",
            "tcp",
            "udp",
            "icmp",
            "icmp6",
            "arp",
            "and",
            "or",
            "not",
            "src",
            "dst",
            "greater",
            "less",
        }

        # 공백으로 분리하여 각 토큰 확인 (완전하지 않지만 기본 검사)
        tokens = filter_str.replace("(", " ").replace(")", " ").split()
        for token in tokens:
            # 숫자나 IP 주소는 건너뛰기
            if token.replace(".", "").replace(":", "").replace("-", "").isdigit():
                continue
            # 알려진 키워드가 아닌 경우 (도메인명 등은 허용)
            if token.lower() in valid_keywords:
                continue
            # 기타 허용되는 패턴들 (IP 주소, 도메인명 등)
            if "." in token or token.replace("-", "").replace("_", "").isalnum():
                continue

            log.debug("Unknown token in BPF filter: %s", token)

        log.debug("BPF filter validation passed: %s", filter_str)
        return True

    except Exception as e:
        log.error("BPF filter validation error: %s", e)
        return False


def optimize_filter_for_performance(filter_str: str) -> str:
    """
    성능을 위한 BPF 필터 최적화

    Args:
        filter_str: 원본 필터

    Returns:
        최적화된 필터
    """
    if not filter_str:
        return filter_str

    optimized = filter_str

    # 1. 중복 공백 제거
    while "  " in optimized:
        optimized = optimized.replace("  ", " ")

    # 2. 불필요한 괄호 제거 (기본적인 수준)
    # 전체가 하나의 괄호로 감싸진 경우
    if optimized.startswith("(") and optimized.endswith(")"):
        inner = optimized[1:-1]
        if inner.count("(") == inner.count(")"):
            # 내부에 균형잡힌 괄호가 있으면 외부 괄호 제거 고려
            paren_count = 0
            can_remove = True
            for char in inner:
                if char == "(":
                    paren_count += 1
                elif char == ")":
                    paren_count -= 1
                    if paren_count < 0:
                        can_remove = False
                        break

            if can_remove and paren_count == 0:
                optimized = inner

    # 3. 기타 최적화는 복잡하므로 생략

    if optimized != filter_str:
        log.debug("Filter optimized: '%s' -> '%s'", filter_str, optimized)

    return optimized


# 테스트 및 디버깅용 함수들
def test_filter_builder():
    """BPF 필터 빌더 기능 테스트"""
    print("=== BPF Filter Builder Test ===")

    # 1. 기본 호스트 필터
    filter1 = BPFFilterBuilder().add_host("192.168.1.1").build()
    print(f"Host filter: {filter1}")

    # 2. TCP 포트 필터
    filter2 = (
        BPFFilterBuilder().add_host("example.com").add_tcp({80, 443, 8080}).build()
    )
    print(f"TCP ports filter: {filter2}")

    # 3. 복합 필터
    filter3 = (
        BPFFilterBuilder()
        .add_host("10.0.0.1")
        .add_tcp({22, 80, 443})
        .add_udp({53, 161})
        .add_icmp()
        .add_arp()
        .build()
    )
    print(f"Complex filter: {filter3}")

    # 4. 프리셋 테스트
    filter4 = FilterPresets.web_services("google.com")
    print(f"Web services preset: {filter4}")

    # 5. 스캔 필터 테스트
    filter5 = create_scan_filter("192.168.1.0/24", {"tcp", "udp"}, {22, 80, 443})
    print(f"Scan filter: {filter5}")

    # 6. 검증 테스트
    valid = validate_filter(filter3)
    print(f"Filter validation: {valid}")


if __name__ == "__main__":
    test_filter_builder()
