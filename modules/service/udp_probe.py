# modules/service/udp_probe.py
from __future__ import annotations
import socket, struct, random, time
from typing import Dict, Optional

# ===== 공통 UDP 송수신 유틸 =====


def _udp_send_recv(
    host: str, port: int, payload: bytes, timeout: float = 1.5, recv_len: int = 2048
) -> bytes | None:
    """
    단순 UDP 송수신. recvfrom()이므로 응답 포트가 바뀌는 프로토콜(TFTP 등)도 수신 가능.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            data, _ = s.recvfrom(recv_len)
            return data
    except Exception:
        return None


# ===== 개별 서비스 프로브 =====


def probe_dns(
    host: str,
    port: int = 53,
    qname: str = "example.com",
    qtype: int = 1,
    timeout: float = 1.5,
) -> Dict:
    """
    DNS 질의: rd=1, qd=1 / RFC 1035
    qtype: 1=A, 28=AAAA, 15=MX 등
    """
    tid = random.randrange(0, 0xFFFF)
    flags = 0x0100  # rd=1
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    qname_wire = (
        b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    )
    q = header + qname_wire + struct.pack("!HH", qtype, 1)
    ans = _udp_send_recv(host, port, q, timeout=timeout)
    ok = False
    rcode = None
    ancount = 0
    if ans and len(ans) >= 12:
        r_tid, r_flags, _, r_ancount, _, _ = struct.unpack("!HHHHHH", ans[:12])
        rcode = r_flags & 0x000F
        ancount = r_ancount
        ok = (r_tid == tid) and (rcode == 0) and (r_ancount >= 1)
    return {
        "ok": ok,
        "service": "dns",
        "product": "DNS",
        "version": None,
        "extra": {"rcode": rcode, "answers": ancount},
    }


def probe_ntp(host: str, port: int = 123, timeout: float = 1.5) -> Dict:
    # RFC 5905: LI=0, VN=4, Mode=3(Client)
    pkt = bytes([0x1B]) + b"\x00" * 47
    ans = _udp_send_recv(host, port, pkt, timeout=timeout, recv_len=68)
    ok = bool(ans and len(ans) >= 48 and (ans[0] & 0x7) in (4, 5))  # server/broadcast
    ver = (ans[0] >> 3) & 0x7 if ans else None
    return {
        "ok": ok,
        "service": "ntp",
        "product": "NTP",
        "version": f"v{ver}" if ver else None,
    }


def probe_snmp(
    host: str, port: int = 161, community: str = "public", timeout: float = 1.8
) -> Dict:
    """
    매우 단순 SNMPv2c GetRequest(sysDescr.0)을 기대하는 최소 PDU.
    community 길이에 따라 BER 길이 갱신이 필요하지만, 기본 'public'에 맞춰 둠.
    환경에 맞는 community 목록을 순회하도록 상위에서 옵션화 권장.
    """
    # sysDescr.0: 1.3.6.1.2.1.1.1.0
    # 간단/고정 길이 PDU (community='public' 가정)
    pdu = bytes.fromhex(
        "30 2c"  # SEQUENCE (len 0x2c)
        "02 01 01"  # Version=1 (v2c)
        "04 06 70 75 62 6c 69 63"  # OCTET STRING 'public'
        "A0 1F"  # GetRequest-PDU (len 0x1F)
        "02 04 00 00 00 01"  # request-id
        "02 01 00"  # error-status
        "02 01 00"  # error-index
        "30 13"  # VarBindList (len 0x13)
        "30 11"  # VarBind (len 0x11)
        "06 08 2b 06 01 02 01 01 01 00"  # OID 1.3.6.1.2.1.1.1.0
        "05 00"  # NULL
    )
    ans = _udp_send_recv(host, port, pdu, timeout=timeout, recv_len=1500)
    ok = bool(ans and ans[:1] == b"\x30")  # SEQ 시작 확인
    return {"ok": ok, "service": "snmp", "product": "SNMPv2c", "version": None}


def probe_ssdp(host: str, port: int = 1900, timeout: float = 1.5) -> Dict:
    # 유니캐스트 M-SEARCH (일부 장비는 응답)
    req = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    ans = _udp_send_recv(host, port, req, timeout=timeout)
    ok = bool(ans and ans.startswith(b"HTTP/1.1 200 OK"))
    return {"ok": ok, "service": "ssdp", "product": "UPnP/SSDP", "version": None}


def probe_mdns(
    host: str,
    port: int = 5353,
    qname: str = "_services._dns-sd._udp.local",
    timeout: float = 1.5,
) -> Dict:
    # mDNS는 멀티캐스트가 표준이나, 타깃 에이전트에 유니캐스트로 응답하는 경우 존재
    return probe_dns(host, port=port, qname=qname, qtype=12, timeout=timeout) | {
        "service": "mdns",
        "product": "mDNS",
    }


def probe_stun(host: str, port: int = 3478, timeout: float = 1.8) -> Dict:
    # RFC 5389 Binding Request (magic cookie 0x2112A442)
    try:
        tid = random.randbytes(12)  # py3.11+
    except AttributeError:
        tid = bytes([random.randrange(256) for _ in range(12)])
    hdr = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tid
    ans = _udp_send_recv(host, port, hdr, timeout=timeout)
    ok = bool(
        ans and len(ans) >= 20 and ans[:2] in (b"\x01\x01", b"\x01\x11")
    )  # 성공/대체 서버
    return {"ok": ok, "service": "stun", "product": "STUN", "version": None}


def probe_tftp(host: str, port: int = 69, timeout: float = 1.8) -> Dict:
    # RRQ "test" octet / 응답 DATA(0x0003) or ERROR(0x0005)면 존재
    rrq = b"\x00\x01" + b"test\x00octet\x00"
    ans = _udp_send_recv(host, port, rrq, timeout=timeout)
    ok = bool(ans and ans[:2] in (b"\x00\x03", b"\x00\x05"))
    return {"ok": ok, "service": "tftp", "product": "TFTP", "version": None}


def probe_quic(host: str, port: int = 443, timeout: float = 1.2) -> Dict:
    # 복잡한 초기 ClientHello 대신, 간단 페이로드 응답 존재만 감지
    payload = b"\x00" * 16
    ans = _udp_send_recv(host, port, payload, timeout=timeout)
    ok = bool(ans)
    return {"ok": ok, "service": "quic", "product": "QUIC", "version": None}


def probe_syslog(host: str, port: int = 514, timeout: float = 1.2) -> Dict:
    # 보통 응답이 없음. 응답 시 서버 특성 추정 가능.
    msg = f"<13> {time.strftime('%b %d %H:%M:%S')} scanner-x test\n".encode()
    ans = _udp_send_recv(host, port, msg, timeout=timeout)
    ok = bool(ans)
    return {
        "ok": ok,
        "service": "syslog",
        "product": "RFC3164",
        "version": None if not ok else "unknown",
    }


# ===== 디스패처 =====

WELL_KNOWN_UDP = {
    # (Wikipedia/IANA 관례 기반: 대표적인 것만 포함)
    53: probe_dns,
    67: None,  # DHCP server(특수), 능동 프로브 비권장
    68: None,  # DHCP client
    69: probe_tftp,
    123: probe_ntp,
    137: None,  # NetBIOS-NS (비권장)
    161: probe_snmp,
    1900: probe_ssdp,
    3478: probe_stun,
    3702: None,  # WS-Discovery (멀티캐스트 특성)
    443: probe_quic,
    500: None,  # ISAKMP (벤더/정책상 응답 제한 가능)
    514: probe_syslog,
    5353: probe_mdns,
}


def udp_service_probe(
    host: str,
    port: int,
    timeout: float = 1.5,
    qname: Optional[str] = None,
    snmp_communities: Optional[list[str]] = None,
) -> Dict:
    """
    포트별 능동 프로브 실행.
    - DNS/mDNS: qname이 주어지면 이를 사용
    - SNMP: community 리스트가 주어지면 순차 시도
    """
    fn = WELL_KNOWN_UDP.get(port)
    if fn is None:
        return {"ok": False, "service": None, "product": None, "version": None}

    try:
        # 개별 포트 커스터마이즈
        if fn is probe_dns and qname:
            return probe_dns(host, port=port, qname=qname, timeout=timeout)
        if fn is probe_mdns and qname:
            return probe_mdns(host, port=port, qname=qname, timeout=timeout)
        if fn is probe_snmp and snmp_communities:
            for comm in snmp_communities:
                r = probe_snmp(host, port=port, community=comm, timeout=timeout)
                if r.get("ok"):
                    return r
            return {"ok": False, "service": None, "product": None, "version": None}

        # 기본 호출
        return fn(host, port=port, timeout=timeout)
    except Exception:
        return {"ok": False, "service": None, "product": None, "version": None}
