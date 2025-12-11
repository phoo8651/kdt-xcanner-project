# modules/service/http_probe.py
import socket, ssl
from typing import Dict, Optional


def _build_request(
    host_header: str, path: str, ua: Optional[str], method: str = "HEAD"
) -> bytes:
    ua_line = f"User-Agent: {ua}\r\n" if ua else ""
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Connection: close\r\n"
        f"{ua_line}\r\n"
    )
    return req.encode("ascii", errors="ignore")


def http_probe(
    host: str,
    port: int = 80,
    timeout: float = 2.0,
    use_tls: bool = False,
    sni: Optional[str] = None,
    user_agent: Optional[str] = None,
    path: str = "/",
    method: str = "HEAD",
) -> Dict:
    ret: Dict = {"status": None, "headers": {}, "raw_head": None}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            sni_name = sni or host
            sock = ctx.wrap_socket(sock, server_hostname=sni_name)

        req = _build_request(host, path, user_agent, method)
        sock.sendall(req)

        data = b""
        sock.settimeout(timeout)
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()

        raw = data.decode(errors="ignore")
        head = raw.split("\r\n\r\n", 1)[0]
        ret["raw_head"] = head

        lines = head.split("\r\n")
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2 and parts[1].isdigit():
                ret["status"] = int(parts[1])
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        ret["headers"] = headers
        return ret
    except Exception as e:
        ret["error"] = str(e)
        return ret
