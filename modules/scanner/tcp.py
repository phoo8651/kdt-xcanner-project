# modules/scanner/tcp.py
from __future__ import annotations
from typing import List, Tuple, Optional, Callable, Dict
import socket, threading, time
from scapy.all import IP, TCP, sr1, send, conf, ICMP

from modules.core.models import ScanOptions
from modules.service.http_probe import http_probe
from modules.service.detector import detect_from_banner

try:
    from modules.tls.collector import collect_cert
except Exception:
    collect_cert = None

# Wikipedia List of TCP/UDP port numbers의 관례(Well-known/Registered) 반영한 힌트(대표 포트)
# - 정확한 서비스 식별은 배너/프로브로 수행, 힌트는 표시/추정 보조용
PORT_HINTS_TCP: dict[int, str] = {
    7: "echo",
    9: "discard",
    13: "daytime",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    38: "rap",
    53: "dns-tcp",
    79: "finger",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    110: "pop3",
    111: "sunrpc",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    514: "shell",
    515: "printer",
    520: "rip",
    543: "klogin",
    544: "kshell",
    548: "afp",
    587: "submission",
    631: "ipp",
    873: "rsync",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1025: "ephemeral-start",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "app-dev",
    3306: "mysql",
    3389: "rdp",
    3632: "distcc",
    4333: "msql",
    4444: "metasploit",
    4848: "glassfish-admin",
    5000: "http-alt",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-https",
    6379: "redis",
    7001: "weblogic",
    7002: "weblogic-ssl",
    8000: "http-alt",
    8008: "http",
    8080: "http-proxy",
    8081: "http-alt",
    8088: "http-alt",
    8161: "activemq",
    8443: "https-alt",
    8888: "http-alt",
    9000: "sonarqube",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch-node",
    11211: "memcached",
    27017: "mongodb",
}

_FLAG_MAP: dict[str, Optional[str]] = {
    "syn": "S",
    "fin": "F",
    "null": "",  # no flags
    "xmas": "FPU",  # FIN+PSH+URG
    # "full" 은 소켓 connect() 사용
}


class TCPScanner:
    def __init__(
        self,
        iface: Optional[str] = None,
        timeout: float = 1.0,
        rate_interval: float = 0.0,
        result_callback: Optional[Callable[[Dict], None]] = None,
        options: Optional[ScanOptions] = None,
    ):
        self.iface = iface
        self.timeout = timeout
        self.rate_interval = rate_interval
        self.result_callback = result_callback
        self.options = options or ScanOptions()
        if iface:
            try:
                conf.iface = iface
            except Exception:
                pass

    # ---------- 내부 유틸 ----------
    def _emit(self, data: Dict) -> None:
        if self.result_callback:
            try:
                self.result_callback(data)
            except Exception:
                pass

    def _write_rst(self, dst_ip: str, dport: int) -> None:
        try:
            rpkt = IP(dst=dst_ip) / TCP(dport=dport, flags="R")
            send(
                rpkt,
                iface=self.iface or getattr(self.options, "interface", None),
                verbose=0,
            )
        except Exception:
            pass

    def _extract_features(self, ans) -> dict:
        feats = {
            "ttl": None,
            "tcp_window": None,
            "ip_df": None,
            "mss": None,
            "wscale": None,
            "sack_perm": None,
            "ts_val": None,
            "ts_ecr": None,
            "tcp_ops": None,
        }
        try:
            if ans.haslayer(IP):
                feats["ttl"] = int(ans[IP].ttl)
                try:
                    feats["ip_df"] = bool(int(ans[IP].flags) & 0x2)
                except Exception:
                    pass
            if ans.haslayer(TCP):
                feats["tcp_window"] = int(ans[TCP].window)
                names = []
                for k, v in ans[TCP].options or []:
                    key = (k if isinstance(k, str) else str(k)).lower()
                    if key.startswith("mss"):
                        feats["mss"] = int(v)
                        names.append("mss")
                    elif key.startswith("wscale"):
                        try:
                            feats["wscale"] = int(v)
                        except Exception:
                            pass
                        names.append("wscale")
                    elif key.startswith("sack"):
                        feats["sack_perm"] = True
                        names.append("sack")
                    elif key.startswith("timestamp"):
                        try:
                            feats["ts_val"] = int(v[0])
                            feats["ts_ecr"] = int(v[1])
                        except Exception:
                            pass
                        names.append("ts")
                    elif key.startswith("nop"):
                        names.append("nop")
                    elif key.startswith("eol"):
                        names.append("eol")
                    else:
                        names.append(key)
                if names:
                    feats["tcp_ops"] = ",".join(names)
        except Exception:
            pass
        return feats

    # ---------- 연결 기반(full-connect) ----------
    def _tcp_connect_check(
        self, ip: str, port: int, timeout: float, graceful_close: bool = False
    ) -> Optional[str]:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.settimeout(timeout)
            try:
                _ = s.recv(512)
            except Exception:
                pass
            if graceful_close:
                try:
                    s.shutdown(socket.SHUT_WR)
                    try:
                        _ = s.recv(1024)
                    except Exception:
                        pass
                finally:
                    s.close()
            else:
                s.close()
            return "open"
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return None

    # ---------- SYN/FIN/NULL/XMAS ----------
    def _raw_flag_probe(self, ip: str, port: int, flags: str):
        pkt = IP(dst=ip) / TCP(dport=port, flags=flags)
        ans = sr1(
            pkt,
            timeout=self.timeout,
            iface=self.iface or getattr(self.options, "interface", None),
            verbose=0,
        )
        if ans is None:
            return "open|filtered", None, None, {}
        if ans.haslayer(ICMP):
            icmp = ans.getlayer(ICMP)
            if icmp.type == 3 and icmp.code in (1, 2, 3, 9, 10, 13):
                return "filtered", None, None, {}
        feats = self._extract_features(ans)
        ttl, win = feats.get("ttl"), feats.get("tcp_window")
        if ans.haslayer(TCP):
            flags_rcv = ans[TCP].flags
            if flags_rcv & 0x12 == 0x12:  # SYN/ACK(희귀)
                self._write_rst(ip, port)
                return "open", ttl, win, feats
            if (flags_rcv & 0x14 == 0x14) or (flags_rcv & 0x04 == 0x04):
                return "closed", ttl, win, feats
        return "filtered/unknown", ttl, win, feats

    def _syn_probe(self, ip: str, port: int):
        attempts = 1 + max(0, getattr(self.options, "syn_retries", 0))
        feats: dict = {}
        for _ in range(attempts):
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            ans = sr1(
                pkt,
                timeout=self.timeout,
                iface=self.iface or getattr(self.options, "interface", None),
                verbose=0,
            )
            if ans is None:
                continue
            feats = self._extract_features(ans)
            ttl, win = feats.get("ttl"), feats.get("tcp_window")
            if ans.haslayer(TCP):
                flags = ans[TCP].flags
                if flags & 0x12 == 0x12:
                    self._write_rst(ip, port)
                    return "open", ttl, win, feats
                if flags & 0x14 == 0x14:
                    return "closed", ttl, win, feats
        return None, None, None, feats

    # ---------- 서비스/배너 프로브 ----------
    def _generic_banner(
        self, ip: str, port: int, hello: bytes | None = None, read_bytes: int = 1024
    ) -> str:
        try:
            with socket.create_connection(
                (ip, port), timeout=min(self.timeout, 3.0)
            ) as s:
                s.settimeout(min(self.timeout, 3.0))
                if hello:
                    s.sendall(hello)
                try:
                    data = s.recv(read_bytes)
                except socket.timeout:
                    data = b""
                return data.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _service_probe(self, ip: str, port: int) -> Dict:
        info: Dict = {}
        # 힌트(표시용)
        hint = PORT_HINTS_TCP.get(port)
        if hint:
            info["hint"] = hint

        # HTTP/HTTPS
        if port in (80, 81, 8000, 8008, 8080, 8081, 8088, 8888) or port in (443, 8443):
            use_tls = port in (443, 8443)
            hp = http_probe(
                host=ip,
                port=port,
                timeout=min(self.timeout, 3.0),
                use_tls=use_tls,
                sni=ip,
                user_agent=(
                    self.options.ua_string
                    if getattr(self.options, "ua_enabled", False)
                    else None
                ),
                method="HEAD",
                path="/",
            )
            info["http"] = hp
            banner = (
                (hp.get("status") or "")
                + "\n"
                + "\n".join(f"{k}: {v}" for k, v in (hp.get("headers") or {}).items())
            )
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            if use_tls and collect_cert:
                info["tls"] = collect_cert(ip, port, timeout=min(self.timeout, 3.0))
            return info

        # SSH
        if port == 22:
            banner = self._generic_banner(ip, port, hello=None, read_bytes=256)
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # SMTP
        if port in (25, 587, 465):
            hello = b"EHLO scanner-x\r\n"
            banner = self._generic_banner(ip, port, hello=hello)
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            if port == 465 and collect_cert:
                info["tls"] = collect_cert(ip, port, timeout=min(self.timeout, 3.0))
            return info

        # FTP
        if port == 21:
            banner = self._generic_banner(ip, port, hello=b"FEAT\r\n", read_bytes=1024)
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # POP3
        if port == 110:
            banner = self._generic_banner(ip, port, hello=b"CAPA\r\n", read_bytes=512)
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # IMAP
        if port == 143:
            banner = self._generic_banner(
                ip, port, hello=b"a1 CAPABILITY\r\n", read_bytes=512
            )
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # MySQL
        if port == 3306:
            banner = self._generic_banner(ip, port, hello=None, read_bytes=128)
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # Redis
        if port == 6379:
            banner = self._generic_banner(
                ip, port, hello=b"*1\r\n$4\r\nPING\r\n", read_bytes=128
            )
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # RDP
        if port == 3389:
            x224 = bytes.fromhex("030000130ee00000000000010008000a000100")
            banner = self._generic_banner(ip, port, hello=x224, read_bytes=64)
            det = detect_from_banner(port, banner)
            info.update(det)
            info["banner"] = banner
            return info

        # fallback
        banner = self._generic_banner(ip, port, hello=b"\r\n", read_bytes=256)
        det = detect_from_banner(port, banner)
        info.update(det)
        info["banner"] = banner
        return info

    # ---------- 포트 스캔 ----------
    def _scan_port(self, ip: str, port: int) -> Tuple[int, str]:
        mode = (getattr(self.options, "tcp_scan_mode", "syn") or "syn").lower()
        ttl = None
        win = None
        feats: dict = {}
        state = None

        if mode == "full":
            state = self._tcp_connect_check(
                ip,
                port,
                getattr(self.options, "connect_timeout", 1.0),
                getattr(self.options, "graceful_close", False),
            )
            if state is None:
                state = "filtered/unknown"

        elif mode == "syn":
            state, ttl, win, feats = self._syn_probe(ip, port)
            if state is None and getattr(self.options, "tcp_connect_fallback", True):
                cstate = self._tcp_connect_check(
                    ip,
                    port,
                    getattr(self.options, "connect_timeout", 1.0),
                    getattr(self.options, "graceful_close", False),
                )
                if cstate is not None:
                    state = cstate
            if state is None:
                state = "filtered/unknown"

        else:
            # FIN/NULL/XMAS
            flags = _FLAG_MAP.get(mode, "")
            state, ttl, win, feats = self._raw_flag_probe(ip, port, flags)
            if state in (None, "open|filtered") and getattr(
                self.options, "tcp_connect_fallback", False
            ):
                cstate = self._tcp_connect_check(
                    ip,
                    port,
                    getattr(self.options, "connect_timeout", 1.0),
                    getattr(self.options, "graceful_close", False),
                )
                if cstate is not None:
                    state = cstate
            if state is None:
                state = "filtered/unknown"

        svc: Dict = {}
        if state == "open":
            try:
                svc = self._service_probe(ip, port)
            except Exception:
                svc = {}

        result = {
            "protocol": "tcp",
            "target": ip,
            "port": port,
            "state": state,
            "ttl": ttl if ttl is not None else feats.get("ttl"),
            "tcp_window": win if win is not None else feats.get("tcp_window"),
        }
        # OS 힌트 보강
        if feats:
            result.update(
                {
                    k: v
                    for k, v in feats.items()
                    if k not in ("ttl", "tcp_window") and v is not None
                }
            )
        # 서비스 결과 병합
        hint = PORT_HINTS_TCP.get(port)
        if hint and not result.get("service"):
            result["hint"] = hint
        if svc:
            if svc.get("service"):
                result["service"] = svc["service"]
            if svc.get("product"):
                result["product"] = svc["product"]
            if svc.get("version"):
                result["version"] = svc["version"]
            if "banner" in svc and svc["banner"]:
                result["banner"] = svc["banner"][:512]
            if "http" in svc and svc["http"]:
                http = svc["http"]
                result["http"] = {
                    "status": http.get("status"),
                    "server": (http.get("headers") or {}).get("server"),
                    "ua_used": bool(getattr(self.options, "ua_enabled", False)),
                }
            if "tls" in svc and svc["tls"]:
                result["tls"] = svc["tls"]

        self._emit(result)
        return port, state

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
                    port = q.pop()
                p, s = self._scan_port(ip, port)
                results.append((p, s))
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
        res = [ip]
        return res
