# modules/scanner/udp.py
from __future__ import annotations
from typing import List, Tuple, Optional, Callable, Dict
import socket, threading, time, os, random

from scapy.all import IP, UDP, ICMP, Raw, sr1, sniff, conf

from modules.service.udp_probe import udp_service_probe

# Wikipedia/IANA 기반의 대표 UDP 포트 힌트(표시용/추정부)
PORT_HINTS_UDP: dict[int, str] = {
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmp-trap",
    1900: "ssdp",
    2049: "nfs",
    3478: "stun",
    3702: "ws-discovery",
    443: "quic",
    500: "isakmp",
    514: "syslog",
    51820: "wireguard",
    5353: "mdns",
    5683: "coap",
}

GENERIC_PAYLOADS = [
    b"",  # 빈 페이로드
    b"probe",  # 일반 텍스트
    os.urandom(8),  # 랜덤
]

# ★ 응답 포트 특성: 대부분은 서버 srcport == 대상 포트
#    예외적으로 TFTP(69)는 서버가 ephemeral srcport 를 사용
RESPONSE_SAME_PORT = {
    53,
    123,
    137,
    138,
    161,
    162,
    1900,
    2049,
    3478,
    3702,
    443,
    500,
    514,
    51820,
    5353,
    5683,
}
RESPONSE_DIFFERENT_PORT = {69}  # TFTP


def _get_local_addr_for_dst(dst_ip: str) -> str | None:
    """Scapy 라우팅 테이블을 이용해 dst로 나갈 때의 로컬 IP 추정(스니프 검증에 사용)."""
    try:
        _, src, _ = conf.route.route(dst_ip)
        return src
    except Exception:
        return None


def _sniff_any_udp_from_target(target_ip: str, timeout: float, iface: str | None):
    """
    target_ip에서 수신되는 '임의 UDP' 응답을 1개 포착.
    (TFTP처럼 응답 포트가 바뀌는 서비스 보완)
    """
    bpf = f"udp and host {target_ip}"
    try:
        pkts = sniff(
            iface=iface or conf.iface,
            filter=bpf,
            timeout=timeout,
            count=1,
            store=True,
        )
        return pkts[0] if pkts else None
    except Exception:
        return None


class UDPScanner:
    def __init__(
        self,
        iface: str | None = None,
        timeout: float = 1.5,
        rate_interval: float = 0.0,
        result_callback: Optional[Callable[[Dict], None]] = None,
        options: Optional[object] = None,
    ):
        self.iface = iface
        self.timeout = timeout
        self.rate_interval = rate_interval
        self.result_callback = result_callback
        self.options = options
        if iface:
            try:
                conf.iface = iface
            except Exception:
                pass

    def _emit(self, ev: Dict) -> None:
        if self.result_callback:
            try:
                self.result_callback(ev)
            except Exception:
                pass

    def _probe_port(self, ip: str, port: int) -> Tuple[int, str]:
        """
        1) 서비스별 능동 프로브 (udp_service_probe)
        2) 일반 UDP 프로브 + 재시도 + 스니프 폴백(엄격 검증)
        """
        # ---- (1) 서비스별 능동 프로브 ----
        dns_qname = getattr(self.options, "dns_qname", None) if self.options else None
        snmp_communities = (
            getattr(self.options, "snmp_communities", None) if self.options else None
        )
        svc_timeout = max(
            self.timeout,
            float(
                getattr(self.options, "udp_probe_timeout", self.timeout) or self.timeout
            ),
        )

        svc = udp_service_probe(
            ip,
            port,
            timeout=svc_timeout,
            qname=dns_qname,
            snmp_communities=snmp_communities,
        )
        if svc.get("ok"):
            ev = {"protocol": "udp", "target": ip, "port": port, "state": "open"}
            hint = PORT_HINTS_UDP.get(port)
            if hint and not svc.get("service"):
                ev["hint"] = hint
            if svc.get("service"):
                ev["service"] = svc["service"]
            if svc.get("product"):
                ev["product"] = svc["product"]
            if svc.get("version"):
                ev["version"] = svc["version"]
            if svc.get("extra"):
                ev["extra"] = svc["extra"]
            self._emit(ev)
            return port, "open"

        # ---- (2) 일반 프로브 + 재시도 + 스니프 폴백 ----
        retries = int(getattr(self.options, "udp_retries", 2) or 2)
        timeout_per_try = float(
            getattr(self.options, "udp_timeout", self.timeout) or self.timeout
        )
        payloads = GENERIC_PAYLOADS
        local_ip = _get_local_addr_for_dst(ip)  # ★ 스니프 검증 보조

        for _ in range(max(1, retries)):
            for pl in payloads:
                sport = random.randint(1024, 65535)
                pkt = IP(dst=ip) / UDP(dport=port, sport=sport) / Raw(pl)
                ans = sr1(pkt, timeout=timeout_per_try, iface=self.iface, verbose=0)

                if ans is None:
                    # dport-매칭 응답 없음 → 타깃에서 오는 "임의 UDP"를 잠깐 스니프
                    sniff_ans = _sniff_any_udp_from_target(
                        ip, timeout=min(timeout_per_try, 1.0), iface=self.iface
                    )
                    if not sniff_ans:
                        continue

                    # ★ 스니프 응답을 엄격 검증
                    if not sniff_ans.haslayer(UDP):
                        continue
                    ip_l = sniff_ans.getlayer(IP)
                    udp_l = sniff_ans.getlayer(UDP)

                    # 1) 반드시 타깃 ↔ 우리 간 통신이어야 함
                    if ip_l.src != ip:
                        continue
                    if local_ip and ip_l.dst != local_ip:
                        # 로컬 IP를 알아냈다면 목적지도 일치해야 신뢰
                        continue

                    # 2) 포트 검증: 대부분은 서버 srcport == 대상 포트
                    if port in RESPONSE_SAME_PORT:
                        if udp_l.sport != port:
                            continue
                        # dport는 우리가 보낸 sport 이어야 함
                        if udp_l.dport != sport:
                            continue
                        # 여기까지 충족하면 open
                        ev = {
                            "protocol": "udp",
                            "target": ip,
                            "port": port,
                            "state": "open",
                        }
                        hint = PORT_HINTS_UDP.get(port)
                        if hint:
                            ev["hint"] = hint
                        self._emit(ev)
                        return port, "open"

                    # 3) 예외: TFTP(69) — 서버는 임의 srcport 사용, opcode 확인
                    if port in RESPONSE_DIFFERENT_PORT:
                        # dport는 여전히 우리가 보낸 sport 이어야 함
                        if udp_l.dport != sport:
                            continue
                        # 간단한 TFTP opcode(0x0003 DATA 또는 0x0005 ERROR) 확인
                        raw = bytes(sniff_ans[Raw]) if sniff_ans.haslayer(Raw) else b""
                        if len(raw) >= 2 and raw[:2] in (b"\x00\x03", b"\x00\x05"):
                            ev = {
                                "protocol": "udp",
                                "target": ip,
                                "port": port,
                                "state": "open",
                                "hint": "tftp",
                            }
                            self._emit(ev)
                            return port, "open"
                        continue

                    # 그 외 포트는 스니프 폴백으로 open 판정하지 않음
                    continue

                # ---- sr1()로 응답이 온 케이스 검증 ----
                # ICMP → closed/filtered 판단 우선
                if ans.haslayer(ICMP):
                    icmp = ans.getlayer(ICMP)
                    if icmp.type == 3 and icmp.code in (1, 2, 3, 9, 10, 13):
                        ev = {
                            "protocol": "udp",
                            "target": ip,
                            "port": port,
                            "state": "closed",
                        }
                        hint = PORT_HINTS_UDP.get(port)
                        if hint:
                            ev["hint"] = hint
                        self._emit(ev)
                        return port, "closed"
                    # 그 외 ICMP는 다음 시도로 계속
                    continue

                # ★ 반드시 UDP 응답이어야 하고, 회신 포트(dport)가 우리가 보낸 sport와 일치해야 함
                if not ans.haslayer(UDP):
                    continue
                ip_a = ans.getlayer(IP)
                udp_a = ans.getlayer(UDP)

                # 응답은 타깃에서 와야 함
                if ip_a.src != ip:
                    continue

                # dport == sport(우리가 보낸 소스포트)
                if udp_a.dport != sport:
                    continue

                # 대부분은 서버 srcport == 대상 포트
                if port in RESPONSE_SAME_PORT and udp_a.sport != port:
                    continue

                # 예외(TFTP) 처리: sr1로 잡힌 경우에도 opcode 체크
                if port in RESPONSE_DIFFERENT_PORT and ans.haslayer(Raw):
                    raw = bytes(ans[Raw])
                    if not (len(raw) >= 2 and raw[:2] in (b"\x00\x03", b"\x00\x05")):
                        continue

                # 위 조건을 모두 통과하면 open
                ev = {"protocol": "udp", "target": ip, "port": port, "state": "open"}
                hint = PORT_HINTS_UDP.get(port)
                if hint:
                    ev["hint"] = hint
                self._emit(ev)
                return port, "open"

        # 모든 시도 실패 → open|filtered
        ev = {"protocol": "udp", "target": ip, "port": port, "state": "open|filtered"}
        hint = PORT_HINTS_UDP.get(port)
        if hint:
            ev["hint"] = hint
        self._emit(ev)
        return port, "open|filtered"

    def scan_target(
        self, target: str, ports: List[int], workers: int = 50
    ) -> List[Tuple[int, str]]:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

        results: List[Tuple[int, str]] = []
        q = ports[:]
        lock = threading.Lock()

        def worker():
            while True:
                with lock:
                    if not q:
                        return
                    p = q.pop()
                results.append(self._probe_port(ip, p))
                if self.rate_interval:
                    time.sleep(self.rate_interval)

        threads = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(min(workers, max(1, len(ports))))
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        results.sort(key=lambda x: x[0])
        return results
