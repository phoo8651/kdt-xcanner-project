# modules/scanner/masscan.py
from __future__ import annotations
import time, random, threading, ipaddress
from typing import List, Dict, Optional, Callable, Sequence, Union, Set, Tuple

import logging
from scapy.all import (
    conf as scapy_conf,
    AsyncSniffer,
    Ether,
    ARP,
    sendp,
    srp1,
    IP,
    TCP,
    ICMP,
    get_if_hwaddr,
    get_if_addr,
)

log = logging.getLogger("masscan_scanner")


def _cidr_expand(targets: Union[str, Sequence[str]]) -> List[str]:
    out: List[str] = []
    if targets is None:
        return out
    if isinstance(targets, str):
        raw = [s for s in targets.replace(",", " ").split() if s]
    else:
        raw = []
        for t in targets:
            if not t:
                continue
            raw.extend(str(t).replace(",", " ").split())
    for tok in raw:
        try:
            net = ipaddress.ip_network(tok, strict=False)
            out.extend(str(h) for h in net.hosts())
        except Exception:
            out.append(tok)

    # 중복 제거/정렬
    def _ipkey(ip: str):
        return tuple(int(x) for x in ip.split(".") if x.isdigit())

    return sorted(set(out), key=_ipkey)


def _ports_expand(ports: str) -> List[int]:
    out: Set[int] = set()
    for tok in str(ports).split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            for p in range(max(1, a), min(65535, b) + 1):
                out.add(p)
        else:
            out.add(int(tok))
    return sorted(out)


def _auto_gateway(dst_ip: str) -> Optional[str]:
    try:
        gw = scapy_conf.route.route(dst_ip)[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    try:
        import netifaces

        gws = netifaces.gateways()
        default_gw = gws.get("default", {}).get(netifaces.AF_INET)
        if default_gw:
            return str(default_gw[0])
    except Exception:
        pass
    return None


def _arp_resolve_mac(iface: str, ip: str, timeout: float = 1.0) -> Optional[str]:
    try:
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface,
            timeout=timeout,
            verbose=0,
        )
        if ans and ans.haslayer(Ether):
            return ans[Ether].src
    except Exception as e:
        log.debug("ARP resolve failed for %s on %s: %s", ip, iface, e)
    return None


class MasscanScanner:
    """
    Masscan 유사 스캐너 (직접 구현, TCP SYN)
    - 고정 소스포트 범위 + BPF (dst host <local> & dst portrange <range>)
    - (옵션) ICMP ping pre-scan (--ping 유사)
    - (옵션) router_ip, allow_broadcast 제어
    - 응답 검증: ACK == SEQ+1 & (src,dst,ports) 매칭
    """

    def __init__(
        self,
        targets: Union[str, Sequence[str]],
        ports: str,
        iface: str,
        rate: int = 10000,
        wait: float = 5.0,
        router_ip: Optional[str] = None,
        ping: bool = False,
        allow_broadcast: bool = True,
        result_callback: Optional[Callable[[Dict], None]] = None,
        # 고정 소스 포트 범위
        sport_base: int = 40000,
        sport_span: int = 1024,
    ):
        self.iface = iface
        self.local_ip = get_if_addr(iface)  # 수신 필터에 사용
        self.hosts = _cidr_expand(targets)
        self.ports = _ports_expand(ports)
        self.rate = max(100, int(rate))
        self.wait = float(wait)
        self.router_ip = router_ip
        self.ping = bool(ping)
        self.allow_broadcast = bool(allow_broadcast)
        self.result_callback = result_callback
        self.sport_base = int(sport_base)
        self.sport_span = max(64, int(sport_span))  # 너무 좁으면 충돌↑

        # 내부 상태
        self._stop = threading.Event()
        self._seen_open: Set[Tuple[str, int]] = set()
        self._seen_closed: Set[Tuple[str, int]] = set()
        # 기대 매핑: dport(=target port)로 보내는 우리의 sport 별 송신 시퀀스
        # key: sport -> (dst_ip, dport, seq)
        self._expect: Dict[int, Tuple[str, int, int]] = {}
        # 빠른 타겟 검증용
        self._targets_set: Set[str] = set(self.hosts)

    # ------------------------------- Emit ------------------------------- #
    def _emit(self, ev: Dict):
        if self.result_callback:
            try:
                self.result_callback(ev)
            except Exception as e:
                log.error("callback error: %s", e)

    # ------------------------------- L2 Helper ------------------------------- #
    def _resolve_next_hop_mac(self, dst_ip: str) -> Optional[str]:
        gw = self.router_ip or _auto_gateway(dst_ip)
        try:
            if gw and gw != dst_ip:
                if not self.allow_broadcast:
                    return None
                return _arp_resolve_mac(self.iface, gw)
            if not self.allow_broadcast:
                return None
            return _arp_resolve_mac(self.iface, dst_ip)
        except Exception:
            return None

    # ------------------------------- Capture ------------------------------- #
    def _start_sniffer(self) -> AsyncSniffer:
        # dst host = our local IP, and dst port in our sport range
        lo = self.sport_base
        hi = self.sport_base + self.sport_span - 1
        bpf = f"tcp and dst host {self.local_ip} and dst portrange {lo}-{hi}"
        sniffer = AsyncSniffer(
            iface=self.iface, filter=bpf, store=False, prn=self._on_packet
        )
        sniffer.start()
        return sniffer

    def _on_packet(self, pkt):
        try:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return
            ip = pkt[IP]
            tcp = pkt[TCP]

            # 1) 우리에게 온 패킷인지(BPF가 이미 보장) + 기대한 sport인지
            sport = int(tcp.dport)  # dst port = our source port
            exp = self._expect.get(sport)
            if not exp:
                return
            dst_ip, dport, seq = exp

            # 2) 응답이 우리가 보낸 대상에서 왔는지, 원격 포트 일치?
            if ip.src != dst_ip or int(tcp.sport) != int(dport):
                return

            # 3) ACK 검증 (SYN/ACK 또는 RST의 ack==seq+1 인게 일반적)
            ack_ok = False
            if tcp.flags & 0x12 == 0x12:  # SYN+ACK
                ack_ok = (int(tcp.ack) == (seq + 1) & 0xFFFFFFFF) or (
                    int(tcp.ack) == seq + 1
                )
            elif tcp.flags & 0x04:  # RST
                # 일부 스택은 RST에도 ack=seq+1을 준수
                ack_ok = int(tcp.ack) in (seq, seq + 1)

            if not ack_ok:
                return

            key = (ip.src, int(tcp.sport))
            if tcp.flags & 0x12 == 0x12:  # open
                if key not in self._seen_open:
                    self._seen_open.add(key)
                    self._emit(
                        {
                            "protocol": "tcp",
                            "target": ip.src,
                            "host": ip.src,
                            "port": int(tcp.sport),
                            "state": "open",
                            "source": "masscan",
                        }
                    )
            elif tcp.flags & 0x04:  # closed
                if key not in self._seen_closed:
                    self._seen_closed.add(key)
                    self._emit(
                        {
                            "protocol": "tcp",
                            "target": ip.src,
                            "host": ip.src,
                            "port": int(tcp.sport),
                            "state": "closed",
                            "source": "masscan",
                        }
                    )
        except Exception:
            return

    # ------------------------------- Sender ------------------------------- #
    def _send_syns(self):
        random.shuffle(self.hosts)

        try:
            hwsrc = get_if_hwaddr(self.iface)
        except Exception:
            hwsrc = None

        # rate limiter: 1ms 단위 배치
        batch = max(1, int(self.rate / 1000))
        delay = 0.001
        sent = 0
        last = time.perf_counter()

        def throttle():
            nonlocal sent, last
            sent += 1
            if sent >= batch:
                now = time.perf_counter()
                if now - last < delay:
                    time.sleep(delay - (now - last))
                last = time.perf_counter()
                sent = 0

        mac_cache: Dict[str, Optional[str]] = {}
        sport_cursor = 0

        for dst in self.hosts:
            if self._stop.is_set():
                break

            # (옵션) ICMP ping
            if self.ping:
                try:
                    sendp(Ether() / IP(dst=dst) / ICMP(), iface=self.iface, verbose=0)
                except Exception:
                    pass

            nh_mac = mac_cache.get(dst)
            if nh_mac is None:
                nh_mac = self._resolve_next_hop_mac(dst)
                mac_cache[dst] = nh_mac

            for dport in self.ports:
                if self._stop.is_set():
                    break
                try:
                    # --- 고정 소스 포트 + 기대 매핑 저장 ---
                    sport = self.sport_base + (sport_cursor % self.sport_span)
                    sport_cursor += 1
                    seq = random.randrange(0, 2**32)

                    self._expect[sport] = (dst, int(dport), seq)

                    if nh_mac:
                        ether = Ether(src=hwsrc, dst=nh_mac)
                        pkt = (
                            ether
                            / IP(dst=dst)
                            / TCP(dport=int(dport), flags="S", sport=sport, seq=seq)
                        )
                        sendp(pkt, iface=self.iface, verbose=0)
                    else:
                        pkt = IP(dst=dst) / TCP(
                            dport=int(dport), flags="S", sport=sport, seq=seq
                        )
                        sendp(pkt, iface=self.iface, verbose=0)
                except Exception:
                    pass
                throttle()

    # ------------------------------- Public API ------------------------------- #
    def run(self) -> Dict:
        if not self.hosts:
            log.warning("MasscanScanner: no targets resolved")
            return {"records": []}
        if not self.ports:
            log.warning("MasscanScanner: no ports spec provided")
            return {"records": []}

        sniffer = self._start_sniffer()
        try:
            sender = threading.Thread(target=self._send_syns, daemon=True)
            sender.start()
            # 송신 종료까지 기다리고 수신 여유 대기
            sender.join(timeout=max(0.1, self.wait))
            time.sleep(self.wait)
        finally:
            self._stop.set()
            try:
                sniffer.stop()
            except Exception:
                pass

        # open만 요약으로 반환 (closed는 alive 판정용으로 콜백에서만 사용)
        recs: List[Dict] = []
        for ip, port in sorted(self._seen_open):
            # 타겟 범위를 마지막으로 한 번 더 보장
            if ip in self._targets_set:
                recs.append({"ip": ip, "port": int(port), "proto": "tcp"})
        return {"records": recs}
