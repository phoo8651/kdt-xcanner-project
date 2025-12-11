# modules/core/timing.py
import time
from typing import Callable, Type, Tuple

def backoff_retry(func: Callable, retries: int = 3, base: float = 0.5, exc: Tuple[Type[BaseException], ...] = (Exception,)):
    for i in range(retries):
        try:
            return func()
        except exc:
            time.sleep(base * (2 ** i))
    return func()
