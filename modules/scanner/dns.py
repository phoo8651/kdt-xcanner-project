# modules/scanner/dns.py
from __future__ import annotations
from typing import Optional, Callable, Dict
from scapy.all import IP, UDP, DNS, DNSQR, sr1, conf


class DNSScanner:
    """
    Scapy 기반 DNS 질의/응답. 캡처는 Scheduler의 AsyncSniffer가 담당.
    """

    def __init__(
        self,
        iface: str | None = None,
        timeout: float = 2.0,
        result_callback: Optional[Callable[[Dict], None]] = None,
    ):
        self.iface = iface
        self.timeout = timeout
        self.result_callback = result_callback
        if iface:
            try:
                conf.iface = iface
            except Exception:
                pass

    def query(self, resolver: str, qname: str, qtype: str = "A") -> Dict:
        """
        지정한 resolver로 qname을 qtype 타입으로 질의.
        """
        pkt = (
            IP(dst=resolver)
            / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
        )
        ans = sr1(pkt, timeout=self.timeout, iface=self.iface, verbose=0)

        ok = bool(ans and ans.haslayer(DNS))
        ev = {
            "protocol": "dns",
            "resolver": resolver,
            "qname": qname,
            "qtype": qtype,
            "ok": ok,
        }
        if self.result_callback:
            try:
                self.result_callback(ev)
            except Exception:
                pass
        return ev
