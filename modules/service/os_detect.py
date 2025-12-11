# modules/service/os_detect.py
"""
간단한 휴리스틱 기반 OS 추정기
입력: ttl (int|None), tcp_window (int|None)
출력: dict { guess: str, confidence: float (0..1), reason: str }

주의:
- 매우 단순한 휴리스틱입니다. '추측입니다'로 간주하세요.
- 정확도를 보증하지 않습니다. 실제 요구 시 p0f이나 nmap OS fingerprint DB 연동 권장.
"""
from typing import Optional, Dict

def guess_from_ttl_window(ttl: Optional[int], window: Optional[int]) -> Dict:
    if ttl is None and window is None:
        return {"guess": "unknown", "confidence": 0.0, "reason": "no ttl/window"}

    reason_parts = []
    guess = "unknown"
    score = 0.0

    # TTL 기반 범주 (일반적 관찰)
    if ttl is not None:
        reason_parts.append(f"ttl={ttl}")
        if ttl <= 64:
            # Unix/Linux 계열 흔함 (Linux, BSD 등)
            guess = "Linux/Unix-like"
            score += 0.6
        elif 65 <= ttl <= 128:
            # Windows 계열 흔함 (Windows 기본 TTL 128)
            guess = "Windows"
            score += 0.6
        elif ttl > 128:
            # 매우 큰 TTL은 네트워크 장비/임베디드일 가능성
            guess = "Network appliance / Embedded"
            score += 0.5

    # TCP window 보정 (추측 보조)
    if window is not None:
        reason_parts.append(f"win={window}")
        # 대표적 패턴(일부 관찰치 기반)
        if window in (5840, 5720, 64240, 29200):  # Linux-ish common windows (varies)
            if guess == "Linux/Unix-like":
                score += 0.25
            else:
                # if TTL suggested Windows but window matches Linux, soften confidence
                score -= 0.1
        if window in (65535, 8192, 16384):  # Windows-ish windows (examples)
            if guess == "Windows":
                score += 0.25
            else:
                score -= 0.05

    # normalize score
    if score < 0:
        score = 0.0
    if score > 1:
        score = 1.0

    reason = ";".join(reason_parts) if reason_parts else "no data"
    return {"guess": guess, "confidence": round(score, 2), "reason": reason}
