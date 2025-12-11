# modules/scanner/icmp.py
from __future__ import annotations
from typing import Optional, Callable, Dict
from scapy.all import IP, ICMP, sr1, conf


class ICMPScanner:
    """
    ICMP Echo 기반 가용성 확인. 캡처는 Scheduler의 AsyncSniffer가 담당.
    """

    def __init__(
        self,
        iface: str | None = None,
        timeout: float = 1.0,
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

    def ping(self, target: str) -> Dict:
        pkt = IP(dst=target) / ICMP()
        ans = sr1(pkt, timeout=self.timeout, iface=self.iface, verbose=0)

        state = "up" if ans is not None else "down/filtered"
        ev = {"protocol": "icmp", "target": target, "state": state}
        if self.result_callback:
            try:
                self.result_callback(ev)
            except Exception:
                pass
        return ev
