# modules/service/os_fp.py
from __future__ import annotations
import os, re
from typing import List, Dict, Optional
from .os_detect import guess_from_ttl_window

# ---------- 공통 스코어링 ----------
def _score_eq(a, b, w): 
    return w if (a is not None and b is not None and a == b) else 0.0

def _score_bool(a, b, w):
    return w if (a is not None and b is not None and bool(a) == bool(b)) else 0.0

# ---------- p0f ----------
class P0fDB:
    """
    p0f v3 스타일 일부 키만 파싱:
      label= OS/desc
      sig= ...:ops="MSS,NOP,WS,TS":mss=1460:df=Y:win=...
    ※ 전체 문법을 다 파싱하지 않습니다. (추측 기반 부분 매칭)
    """
    RX_LABEL = re.compile(r'^\s*label\s*=\s*(.+)$', re.I)
    RX_SIG   = re.compile(r'^\s*sig\s*=\s*(.+)$', re.I)
    RX_OPS   = re.compile(r'ops="([^"]+)"')
    RX_MSS   = re.compile(r'(?:(?:^|:)mss=)(\d+)')
    RX_DF    = re.compile(r'(?:(?:^|:)df=)([YN])')
    RX_WIN   = re.compile(r'(?:(?:^|:)win=)(\d+)')

    def __init__(self, path: str | None):
        self.path = path
        self.fps: List[Dict] = []
        if path and os.path.isfile(path):
            self._load(path)

    def _load(self, path: str) -> None:
        cur_label: str | None = None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if m := self.RX_LABEL.match(line):
                    cur_label = m.group(1).strip()
                    continue
                if m := self.RX_SIG.match(line):
                    sigs = m.group(1)
                    ops = self.RX_OPS.search(sigs)
                    mss = self.RX_MSS.search(sigs)
                    df  = self.RX_DF.search(sigs)
                    win = self.RX_WIN.search(sigs)
                    fp = {
                        "label": cur_label or "unknown",
                        "ops": (ops.group(1).lower() if ops else None),
                        "mss": (int(mss.group(1)) if mss else None),
                        "df":  (True if (df and df.group(1) == "Y") else (False if df else None)),
                        "win": (int(win.group(1)) if win else None),
                    }
                    self.fps.append(fp)

    def match(self, feats: Dict) -> Optional[Dict]:
        if not self.fps:
            return None
        best = None; best_score = 0.0
        for fp in self.fps:
            s = 0.0
            s += _score_eq(feats.get("tcp_ops"), fp.get("ops"), 0.5)
            s += _score_eq(feats.get("mss"), fp.get("mss"), 0.3)
            s += _score_bool(feats.get("ip_df"), fp.get("df"), 0.12)
            s += _score_eq(feats.get("tcp_window"), fp.get("win"), 0.08)
            if s > best_score:
                best_score, best = s, fp
        if best:
            return {"source": "p0f", "label": best["label"], "score": round(best_score, 2)}
        return None

# ---------- Nmap ----------
class NmapOSDB:
    """
    nmap-os-db 제한적 파서:
      - 'Fingerprint ' 라인으로 라벨
      - T1(...) 블록에서 Ops, W, DF 만 추출하여 점수화
    """
    RX_FP  = re.compile(r'^\s*Fingerprint\s+(.+)$', re.I)
    RX_T1  = re.compile(r'\bT1\(([^)]*)\)')
    RX_OPS = re.compile(r'\bOps=([A-Z]+)')
    RX_W   = re.compile(r'\bW=([0-9A-Fa-f]+)')
    RX_DF  = re.compile(r'\bDF=([YN])')

    def __init__(self, path: str | None):
        self.path = path
        self.fps: List[Dict] = []
        if path and os.path.isfile(path):
            self._load(path)

    def _load(self, path: str) -> None:
        cur_label: str | None = None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if m := self.RX_FP.match(line):
                    cur_label = m.group(1).strip()
                    continue
                if m := self.RX_T1.search(line):
                    if not cur_label:
                        continue
                    t1 = m.group(1)
                    ops = self.RX_OPS.search(t1)
                    win = self.RX_W.search(t1)
                    df  = self.RX_DF.search(t1)
                    fp = {
                        "label": cur_label,
                        "ops": (ops.group(1).lower() if ops else None),   # nmap 축약코드 그대로
                        "win_hex": (win.group(1) if win else None),
                        "df":  (True if (df and df.group(1) == "Y") else (False if df else None)),
                    }
                    self.fps.append(fp)

    def match(self, feats: Dict) -> Optional[Dict]:
        if not self.fps:
            return None
        ops_norm = (feats.get("tcp_ops") or "").replace(",", "")
        best = None; best_score = 0.0
        for fp in self.fps:
            s = 0.0
            if fp_ops := fp.get("ops"):
                # 문자 교집합 비율로 대략 점수화(추측)
                inter = sum(1 for ch in fp_ops if ch in ops_norm)
                s += min(inter / max(1, len(fp_ops)), 1.0) * 0.42
            try:
                if (win_hex := fp.get("win_hex")) and (feats.get("tcp_window") is not None):
                    if int(win_hex, 16) == int(feats["tcp_window"]):
                        s += 0.38
            except Exception:
                pass
            s += _score_bool(feats.get("ip_df"), fp.get("df"), 0.12)
            if s > best_score:
                best_score, best = s, fp
        if best:
            return {"source": "nmap", "label": best["label"], "score": round(best_score, 2)}
        return None

# ---------- 상위 감지기 ----------
class OSDetectorCascade:
    def __init__(self, p0f_path: str | None, nmap_path: str | None):
        self.p0f = P0fDB(p0f_path) if p0f_path else None
        self.nmap = NmapOSDB(nmap_path) if nmap_path else None

    def best_guess(self, feats_list: List[Dict]) -> Dict:
        """
        feats_list: TCP SYN/ACK에서 수집한 특징들(dict)의 리스트
        반환: {label, source, score, reason?}
        """
        best: Dict | None = None
        for feats in feats_list:
            cand = None
            if self.p0f:
                cand = self.p0f.match(feats)
            if (not cand) and self.nmap:
                cand = self.nmap.match(feats)
            if not cand:
                h = guess_from_ttl_window(feats.get("ttl"), feats.get("tcp_window"))
                cand = {"source":"heuristic", "label": h["guess"], "score": h["confidence"], "reason": h["reason"]}
            if (best is None) or (cand.get("score", 0) > best.get("score", 0)):
                best = cand
        return best or {"source":"none","label":"unknown","score":0.0,"reason":"no features"}
