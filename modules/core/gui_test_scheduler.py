# modules/core/scheduler.py
# 취소 + 일시정지/재개(Pause/Resume) 지원 스케줄러
from __future__ import annotations
import socket, time, threading
from typing import Callable, List, Optional, Any, Dict

class SimpleScheduler:
    def __init__(self, result_dir: str = ".", config: Optional[Any] = None):
        self.result_dir = result_dir
        self.config = config
        self.jobs: List[Any] = []
        self._cancel = threading.Event()
        self._paused = threading.Event()   # set()이면 "일시정지"

        # 콜백
        self._progress_cb: Optional[Callable[..., None]] = None
        self._result_cb:   Optional[Callable[..., None]] = None

        # 너무 빨라서 UI가 한 번에 100% 되는 것 방지
        self.min_step_sleep = 0.003

    # ---- 콜백 세터/속성 ----
    def set_progress_callback(self, cb: Callable[..., None]): self._progress_cb = cb
    def set_progress_cb(self, cb: Callable[..., None]): self._progress_cb = cb
    def set_result_callback(self, cb: Callable[..., None]):   self._result_cb = cb

    @property
    def on_progress(self): return self._progress_cb
    @on_progress.setter
    def on_progress(self, cb): self._progress_cb = cb

    @property
    def progress_cb(self): return self._progress_cb
    @progress_cb.setter
    def progress_cb(self, cb): self._progress_cb = cb

    @property
    def progress_callback(self): return self._progress_cb
    @progress_callback.setter
    def progress_callback(self, cb): self._progress_cb = cb

    @property
    def on_result(self): return self._result_cb
    @on_result.setter
    def on_result(self, cb): self._result_cb = cb

    @property
    def result_cb(self): return self._result_cb
    @result_cb.setter
    def result_cb(self, cb): self._result_cb = cb

    @property
    def result_callback(self): return self._result_cb
    @result_callback.setter
    def result_callback(self, cb): self._result_cb = cb

    # ---- 취소/일시정지 API ----
    def stop(self): self._cancel.set()
    def cancel(self): self._cancel.set()
    def request_stop(self): self._cancel.set()
    def request_cancel(self): self._cancel.set()
    def shutdown(self): self._cancel.set()

    def pause(self): self._paused.set()
    def resume(self): self._paused.clear()
    def is_paused(self) -> bool: return self._paused.is_set()

    # ---- 잡 추가 ----
    def add_job(self, job: Any, ports_spec: Optional[str] = None):
        self.jobs.append(job)

    # ---- 실행 ----
    def run(self):
        # total 계산: 포트 수 + (udp/icmp/dns는 0.2 가중)
        total_steps = 0
        plans: List[Dict[str, Any]] = []
        for job in self.jobs:
            ports = list(getattr(job, "ports", []) or [])
            target = getattr(job, "target", None)
            opts   = getattr(job, "options", None)
            protos = (getattr(opts, "scan_protocols", None) or ["tcp"])
            steps = max(1, len(ports))
            extra = 0
            for p in ("udp","icmp","dns"):
                if p in protos: extra += max(1, int(len(ports)*0.2))
            total_steps += steps + extra
            plans.append({"job": job, "ports": ports, "target": target, "protos": protos})

        done = 0
        self._emit_progress(done, total_steps)

        for plan in plans:
            if self._cancel.is_set(): break
            target = plan["target"]
            ports  = plan["ports"]
            protos = plan["protos"]

            # TCP
            if "tcp" in protos:
                for p in ports:
                    if self._cancel.is_set(): break
                    while self._paused.is_set() and not self._cancel.is_set():
                        time.sleep(0.05)

                    rec = self._tcp_probe(target, p, getattr(plan["job"].options, "connect_timeout", 1.5))
                    self._emit_result(rec); done += 1
                    self._emit_progress(done, total_steps)
                    time.sleep(self.min_step_sleep)

            # UDP/ICMP/DNS(데모)
            for proto in ("udp","icmp","dns"):
                if proto in protos:
                    step_count = max(1, int(len(ports)*0.2))
                    for _ in range(step_count):
                        if self._cancel.is_set(): break
                        while self._paused.is_set() and not self._cancel.is_set():
                            time.sleep(0.05)
                        dummy = {"port": "-", "open": False, "latency_ms": 0.0, "service": proto}
                        self._emit_result(dummy); done += 1
                        self._emit_progress(done, total_steps)
                        time.sleep(self.min_step_sleep)

        self._emit_progress(total_steps, total_steps)

    # ---- 내부 유틸 ----
    def _emit_progress(self, done: int, total: int):
        cb = self._progress_cb
        if cb:
            try: cb(int(done), max(1, int(total)))
            except Exception: pass

    def _emit_result(self, rec: dict):
        cb = self._result_cb
        if cb:
            try: cb(rec)
            except Exception: pass

    def _tcp_probe(self, host: str, port: int, timeout: float) -> dict:
        t0 = time.perf_counter()
        ok = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, int(port)))
                ok = True
        except Exception:
            ok = False
        dt = (time.perf_counter() - t0) * 1000.0
        return {"port": port, "open": ok, "latency_ms": dt, "service": self._common_service_name(port)}

    @staticmethod
    def _common_service_name(port: int) -> str:
        mapping = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",
                   110:"pop3",143:"imap",443:"https",3306:"mysql",3389:"rdp",6379:"redis",8080:"http-alt"}
        return mapping.get(int(port), "")
