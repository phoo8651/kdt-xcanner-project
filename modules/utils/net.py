# modules/utils/net.py
"""
네트워크/권한/소켓 옵션 유틸
- 관리자/루트 권한 확인
- 인터페이스 나열(가능하면 Scapy 보조), IP 조회
- 호스트 해석(IPv4 우선)
- 소켓 옵션(TCP_NODELAY, SO_REUSEADDR) 및 TOS/TTL 설정
"""
from __future__ import annotations
import os
import socket
import sys
from typing import Dict, List, Optional, Tuple

# Scapy가 설치되어 있으면 보조 정보 활용 (없어도 동작)
try:
    from scapy.all import get_if_list, get_if_addr  # type: ignore
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:
        get_windows_if_list = None
except Exception:
    get_if_list = None
    get_if_addr = None
    get_windows_if_list = None

# -----------------------
# 권한 유틸
# -----------------------
def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False

# -----------------------
# 인터페이스/주소
# -----------------------
def list_interfaces() -> List[Tuple[str, str]]:
    """
    인터페이스 목록을 (표시명, sniff용 이름) 튜플 리스트로 반환.
    - Windows: get_windows_if_list()가 있으면 (name, win_name)
    - 공통: get_if_list() fallback
    """
    out: List[Tuple[str, str]] = []
    if get_windows_if_list:
        try:
            for item in get_windows_if_list():
                disp = item.get("name") or item.get("description") or "unknown"
                sniff = item.get("win_name") or item.get("name") or disp
                out.append((disp, sniff))
        except Exception:
            pass
    if not out and get_if_list:
        try:
            for name in get_if_list():
                out.append((name, name))
        except Exception:
            pass
    # 중복 제거, 표시명 기준 정렬
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for d, s in out:
        if (d, s) not in seen:
            uniq.append((d, s))
            seen.add((d, s))
    uniq.sort(key=lambda x: x[0])
    return uniq

def get_iface_ips(sniff_name: str) -> Dict[str, Optional[str]]:
    """
    인터페이스 IPv4/IPv6 대표 주소 조회(가능한 경우).
    """
    ipv4 = None
    ipv6 = None
    # Scapy의 get_if_addr는 IPv4만 제공 가능
    if get_if_addr:
        try:
            a = get_if_addr(sniff_name)
            if a and ":" not in a:
                ipv4 = a
        except Exception:
            pass
    # IPv6는 표준 라이브러리로 시도(보장되지 않음)
    try:
        host = socket.gethostname()
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, addr in infos:
            if fam == socket.AF_INET6:
                ipv6 = addr[0]
                break
    except Exception:
        pass
    return {"ipv4": ipv4, "ipv6": ipv6}

# -----------------------
# 해석/소켓 옵션
# -----------------------
def resolve_host(target: str) -> str:
    """
    호스트 이름을 IPv4로 우선 해석. 실패 시 원문 반환.
    """
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target

def set_socket_opts(sock: socket.socket, *, nodelay: bool = True, reuseaddr: bool = True) -> None:
    try:
        if reuseaddr:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    try:
        if nodelay and sock.family in (socket.AF_INET, socket.AF_INET6) and sock.type == socket.SOCK_STREAM:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

def set_tos_ttl(sock: socket.socket, *, tos: Optional[int] = None, ttl: Optional[int] = None) -> None:
    # IPv4 TOS/TTL
    if sock.family == socket.AF_INET:
        if tos is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, int(tos))
            except Exception:
                pass
        if ttl is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, int(ttl))
            except Exception:
                pass
    # IPv6 Traffic Class/Hop Limit
    elif sock.family == socket.AF_INET6:
        if tos is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, int(tos))
            except Exception:
                pass
        if ttl is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, int(ttl))
            except Exception:
                pass

def pick_interface(preferred: Optional[str] = None) -> Tuple[str, str]:
    """
    선호 이름(preferred)이 있으면 매칭, 없으면 첫 번째 인터페이스 반환.
    반환: (display_name, sniff_name)
    """
    items = list_interfaces()
    if not items:
        raise RuntimeError("No network interfaces found")
    if preferred:
        for d, s in items:
            if preferred.lower() in (d.lower(), s.lower()):
                return d, s
    return items[0]
