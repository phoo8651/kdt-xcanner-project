# modules/export/json_writer.py
import json, os
from typing import Dict, List

class JSONWriter:
    def __init__(self, path: str):
        self.path = path
        self.buf: List[Dict] = []

    def add(self, obj: Dict):
        self.buf.append(obj)

    def flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.buf, f, ensure_ascii=False, indent=2)
