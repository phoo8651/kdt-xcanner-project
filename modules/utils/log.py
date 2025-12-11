# modules/utils/log.py
"""
구조화 로깅 기본 설정
- 파일 + 콘솔 동시 출력
- get_logger(name) 헬퍼
"""
import logging
import os
from typing import Optional

_DEFAULT_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

def setup_logging(log_dir: str, level: int = logging.INFO, fmt: str = _DEFAULT_FMT) -> None:
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "scanner.log")

    root = logging.getLogger()
    root.setLevel(level)

    # 중복 핸들러 방지
    for h in list(root.handlers):
        root.removeHandler(h)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt))
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(fmt))

    root.addHandler(fh)
    root.addHandler(ch)

def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    lg = logging.getLogger(name)
    if level is not None:
        lg.setLevel(level)
    return lg