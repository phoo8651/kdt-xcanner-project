# modules/tls/collector.py
import ssl, socket
from typing import Optional, Dict

def fetch_cert(host: str, port: int = 443, timeout: float = 3.0) -> Optional[Dict]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.getpeercert()
    except Exception:
        return None
