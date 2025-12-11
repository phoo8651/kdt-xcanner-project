# modules/service/detector.py
from __future__ import annotations
import re, yaml, os
from typing import List, Dict, Optional


class ServiceDetector:
    """
    probes.yaml 기반 단순 배너 식별기
    YAML 예)
    http:
      - pattern: "(?i)nginx"
      - pattern: "(?i)apache"
    ssh:
      - pattern: "(?i)^SSH-"
    """

    def __init__(self, probes_path: str):
        self.rules: Dict[str, List[re.Pattern]] = {}
        self.probes_path = probes_path
        try:
            with open(probes_path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            for svc, arr in raw.items() if isinstance(raw, dict) else []:
                pats: List[re.Pattern] = []
                for r in arr or []:
                    pat = (r or {}).get("pattern")
                    if not pat:
                        continue
                    try:
                        pats.append(re.compile(pat))
                    except re.error:
                        # 잘못된 정규식은 건너뜀
                        continue
                if pats:
                    self.rules[svc] = pats
        except Exception:
            self.rules = {}

    def detect_from_banner(self, banner: str) -> List[str]:
        if not banner:
            return []
        out: List[str] = []
        for svc, pats in self.rules.items():
            try:
                if any(p.search(banner) for p in pats):
                    out.append(svc)
            except Exception:
                continue
        return out


# -------------------------
# 함수형 어댑터 (호환용)
# -------------------------

_DETECTOR: Optional[ServiceDetector] = None
_DEFAULT_LOCATIONS = [
    # 우선순위: 프로젝트 표준 경로들
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data",
        "probes.yaml",
    ),
    os.path.join(os.getcwd(), "data", "probes.yaml"),
]


def _resolve_probes_path(explicit: Optional[str] = None) -> Optional[str]:
    # 1) 인자 우선
    if explicit and os.path.isfile(explicit):
        return explicit
    # 2) 환경변수
    envp = os.getenv("SCANNERX_PROBES_PATH")
    if envp and os.path.isfile(envp):
        return envp
    # 3) 기본 후보 경로
    for p in _DEFAULT_LOCATIONS:
        if os.path.isfile(p):
            return p
    return None


def set_detector_probes(path: str) -> None:
    """
    외부에서 프로브 파일 경로를 명시적으로 지정할 때 사용.
    """
    global _DETECTOR
    path_resolved = _resolve_probes_path(path)
    if not path_resolved:
        # 지정 경로가 없으면 초기화 해제
        _DETECTOR = None
        return
    _DETECTOR = ServiceDetector(path_resolved)


def detect_from_banner(
    port: int, banner: str, probes_path: Optional[str] = None
) -> Dict:
    """
    tcp.py 등에서 호출하는 함수형 인터페이스.
    반환 형태(예):
      {"service": "http"} 또는 {"service": "http", "candidates": ["http","haproxy"], "source":"probes"}
    """
    global _DETECTOR
    if _DETECTOR is None:
        resolved = _resolve_probes_path(probes_path)
        if resolved:
            _DETECTOR = ServiceDetector(resolved)
        else:
            # probes.yaml을 찾지 못해도 안전하게 빈 결과 반환
            return {}

    if not banner:
        return {}

    try:
        candidates = _DETECTOR.detect_from_banner(banner)  # List[str]
    except Exception:
        return {}

    if not candidates:
        return {}

    # 첫 번째 매칭을 대표 서비스로, 나머지는 후보로 제공
    result: Dict = {"service": candidates[0], "source": "probes"}
    if len(candidates) > 1:
        result["candidates"] = candidates
    return result
