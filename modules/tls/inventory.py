# modules/tls/inventory.py
from datetime import datetime
from typing import Optional, Dict

def _parse_asn1_time(s: str) -> Optional[datetime]:
    # 'Jun  1 12:00:00 2025 GMT' 형식
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None

def build_cert_record(host: str, cert: Dict) -> Dict:
    not_before = _parse_asn1_time(cert.get("notBefore",""))
    not_after  = _parse_asn1_time(cert.get("notAfter",""))
    now = datetime.utcnow()
    days_left = (not_after - now).days if not_after else None
    warn = "ok"
    if days_left is not None:
        if days_left <= 7: warn = "D-7"
        elif days_left <= 30: warn = "D-30"
    return {
        "host": host,
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "days_left": days_left,
        "warn": warn
    }
