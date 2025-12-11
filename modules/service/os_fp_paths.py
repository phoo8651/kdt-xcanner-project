# modules/service/os_fp_paths.py
from __future__ import annotations
import os
from typing import Tuple, Optional

def resolve_fp_paths(project_root: str, config_fps: dict | None = None) -> Tuple[Optional[str], Optional[str]]:
    """
    p0f / nmap OS DB 파일 경로를 결정:
    우선순위: (1) defaults.yaml의 fingerprints.*  (2) data/fingerprint/*  (3) data/fingerprints/*
    반환: (p0f_path, nmap_path) — 없으면 None
    """
    def _norm(p: str | None) -> str | None:
        if not p:
            return None
        return p if os.path.isabs(p) else os.path.join(project_root, p)

    # 1) config 우선
    p0f_cfg  = _norm((config_fps or {}).get("p0f") if config_fps else None)
    nmap_cfg = _norm((config_fps or {}).get("nmap") if config_fps else None)

    if p0f_cfg and os.path.exists(p0f_cfg) and os.path.isfile(p0f_cfg):
        p0f_path = p0f_cfg
    else:
        # 2) 단수형 우선
        p0f_candidates = [
            os.path.join(project_root, "data", "fingerprint", "p0f.fp"),
            os.path.join(project_root, "data", "fingerprints", "p0f.fp"),
        ]
        p0f_path = next((p for p in p0f_candidates if os.path.isfile(p)), None)

    if nmap_cfg and os.path.exists(nmap_cfg) and os.path.isfile(nmap_cfg):
        nmap_path = nmap_cfg
    else:
        nmap_candidates = [
            os.path.join(project_root, "data", "fingerprint", "nmap-os-db"),
            os.path.join(project_root, "data", "fingerprints", "nmap-os-db"),
        ]
        nmap_path = next((p for p in nmap_candidates if os.path.isfile(p)), None)

    return p0f_path, nmap_path
