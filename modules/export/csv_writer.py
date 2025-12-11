# modules/export/csv_writer.py
import csv, os
from typing import Dict, List

class CSVWriter:
    def __init__(self, path: str, fieldnames: List[str]):
        self.path = path
        self.fieldnames = fieldnames
        self.rows: List[Dict] = []

    def add(self, row: Dict):
        self.rows.append(row)

    def flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self.fieldnames)
            w.writeheader()
            for r in self.rows:
                w.writerow(r)
