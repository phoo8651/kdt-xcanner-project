# modules/utils/ip.py
"""
IP/포트 파싱 및 정규화 유틸
- 포트: "22,80,443", "8000-8100", 혼용/중복 제거
- 타깃: "192.168.0.1,10.0.0.0/24,10.0.0.10-10.0.0.20,host.name"
- CIDR 확장(iter) 및 유효성 검사
"""
from __future__ import annotations
import ipaddress
from typing import Iterable, Iterator, List, Set, Tuple

# -----------------------
# 포트 유틸
# -----------------------
def validate_port(p: int) -> bool:
    return isinstance(p, int) and 0 < p <= 65535

def parse_ports(spec: str) -> List[int]:
    """
    "22,80,443,8000-8100" → [22,80,443,8000..8100]
    잘못된 값은 무시. 중복 제거/정렬.
    """
    if not spec:
        return []
    out: Set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            try:
                a, b = int(a), int(b)
                if a <= b:
                    for p in range(a, b + 1):
                        if validate_port(p):
                            out.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(token)
                if validate_port(p):
                    out.add(p)
            except ValueError:
                continue
    return sorted(out)

# -----------------------
# IP/대역/범위 유틸
# -----------------------
def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

def is_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False

def expand_cidr(cidr: str, *, max_hosts: int = 1_048_576) -> List[str]:
    """
    CIDR을 호스트 리스트로 확장 (max_hosts 초과 시 예외)
    /31,/32(또는 /127,/128)는 그대로 반환.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if (isinstance(net, ipaddress.IPv4Network) and net.prefixlen >= 31) or (
        isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 127
    ):
        return [str(net.network_address)]
    hosts = list(net.hosts())
    if len(hosts) > max_hosts:
        raise ValueError(f"CIDR {cidr} has too many hosts ({len(hosts)} > {max_hosts})")
    return [str(h) for h in hosts] or [str(net.network_address)]

def _expand_ip_range(start: str, end: str) -> List[str]:
    a = ipaddress.ip_address(start)
    b = ipaddress.ip_address(end)
    if a.version != b.version:
        raise ValueError("IP range must be same family (both v4 or both v6)")
    if int(a) > int(b):
        a, b = b, a
    return [str(ipaddress.ip_address(i)) for i in range(int(a), int(b) + 1)]

def normalize_targets(spec: str) -> List[str]:
    """
    타깃 문자열을 콤마로 구분하여 정규화.
    - IPv4/IPv6 단일, CIDR, IP-범위("a-b"), 호스트명(형식만 통과) 허용
    - 여기서는 호스트명 해석은 하지 않음(런타임에서 resolve)
    """
    if not spec:
        return []
    result: List[str] = []
    for token in (t.strip() for t in spec.split(",") if t.strip()):
        try:
            if "/" in token:  # CIDR
                # 확장하지 않고 CIDR 원본을 보관 (iter_targets에서 확장)
                ipaddress.ip_network(token, strict=False)
                result.append(token)
            elif "-" in token:  # IP 범위
                a, b = token.split("-", 1)
                # 유효성 검사용
                ipaddress.ip_address(a.strip())
                ipaddress.ip_address(b.strip())
                result.append(f"{a.strip()}-{b.strip()}")
            else:
                # 단일 IP 또는 호스트명 형식(문자열 그대로)
                # IP 유효성만 빠르게 통과해 보고, 실패 시 호스트명으로 간주
                try:
                    ipaddress.ip_address(token)
                except Exception:
                    # 호스트명일 수 있음. 여기서는 포맷만 체크(공백/콤마 제외)
                    if any(c.isspace() for c in token):
                        continue
                result.append(token)
        except Exception:
            continue
    # 중복 제거(순서 유지)
    seen: Set[str] = set()
    out: List[str] = []
    for t in result:
        if t not in seen:
            out.append(t)
            seen.add(t)
    return out

def iter_targets(targets: Iterable[str]) -> Iterator[str]:
    """
    normalize_targets() 출력(혼합된 CIDR/범위/단일)을 순회 가능한 단일 호스트 IP들로 전개.
    호스트명은 그대로 yield (상위 계층에서 resolve).
    """
    for t in targets:
        if "/" in t:
            # CIDR
            for h in expand_cidr(t):
                yield h
        elif "-" in t:
            a, b = t.split("-", 1)
            for h in _expand_ip_range(a.strip(), b.strip()):
                yield h
        else:
            yield t
