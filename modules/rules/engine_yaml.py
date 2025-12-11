# modules/rules/engine_yaml.py
"""
YAML 규칙 엔진(간단 가중치 합산)
rules 예:
- id: open_http
  when:
    protocol: tcp
    port_in: [80,8080,8000,443,8443]
    state: open
  weight: 5
- id: old_tls
  when:
    protocol: tls
    days_left_le: 30
  weight: 3
"""
import yaml
from typing import List, Dict, Any

class YamlRuleEngine:
    def __init__(self, path: str):
        self.rules: List[Dict[str,Any]] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or []
                if isinstance(raw, list):
                    self.rules = raw
        except Exception:
            self.rules = []

    def score(self, event: Dict[str, Any]) -> int:
        total = 0
        for r in self.rules:
            w = int(r.get("weight", 0))
            cond = r.get("when", {})
            if self._match(cond, event):
                total += w
        return total

    def _match(self, cond: Dict[str,Any], ev: Dict[str,Any]) -> bool:
        for k, v in cond.items():
            if k == "port_in":
                port = ev.get("port")
                if port not in set(v or []):
                    return False
            elif k.endswith("_le"):  # <= 비교
                key = k[:-3]
                try:
                    if ev.get(key) is None or not (ev.get(key) <= v):
                        return False
                except Exception:
                    return False
            else:
                if ev.get(k) != v:
                    return False
        return True
