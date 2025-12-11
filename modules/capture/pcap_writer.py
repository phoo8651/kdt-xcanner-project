# modules/capture/pcap_writer.py

import os
import logging
import threading
import time
from typing import Optional
from pathlib import Path
from scapy.all import PcapWriter, PcapNgWriter, RawPcapWriter
from scapy.packet import Packet

log = logging.getLogger("pcap_writer")


class ThreadSafePcapWriter:
    def __init__(
        self, filepath: str, linktype: int = 1, sync: bool = False, flush_every: int = 0
    ):
        """
        filepath : 저장 경로
        linktype : DLT (pcap일 때만 의미, pcapng에선 무시됨)
        sync     : 매 write 후 가능한 한 디스크에 즉시 flush 시도
        flush_every : N개의 패킷마다 flush (0이면 비활성)
        """
        self.filepath = filepath
        self.sync = bool(sync)
        self.flush_every = int(flush_every) if flush_every is not None else 0
        self._lock = threading.Lock()
        self._pkt_count = 0
        self._bytes = 0
        self._closed = False
        self._fp = None  # file-like object (가능하면 잡아둠)
        self._fd = None  # os-level fd (fsync용)

        # Writer 결정: pcapng 우선
        try:
            # PcapNgWriter는 linktype 인자를 받지 않으므로 제외
            self._writer = PcapNgWriter(self.filepath)
            try:
                # 내부 파일 핸들 추출 (버전에 따라 다름)
                self._fp = (
                    getattr(self._writer, "f", None)
                    or getattr(self._writer, "_f", None)
                    or getattr(self._writer, "_fp", None)
                )
                if self._fp and hasattr(self._fp, "fileno"):
                    self._fd = self._fp.fileno()
            except Exception:
                pass
            log.info("PCAP writer initialized (pcapng): %s", self.filepath)
        except Exception as e:
            log.warning(
                "PcapNgWriter unavailable (%s); falling back to RawPcapWriter", e
            )
            # RawPcapWriter는 linktype 사용
            self._writer = RawPcapWriter(
                self.filepath, linktype=linktype, append=False, sync=False
            )
            try:
                self._fp = getattr(self._writer, "f", None) or getattr(
                    self._writer, "_f", None
                )
                if self._fp and hasattr(self._fp, "fileno"):
                    self._fd = self._fp.fileno()
            except Exception:
                pass
            log.info("PCAP writer initialized (pcap): %s", self.filepath)

    def write(self, pkt) -> bool:
        if self._closed:
            log.error("write on closed writer")
            return False
        try:
            with self._lock:
                self._writer.write(pkt)
                self._pkt_count += 1
                try:
                    self._bytes += len(bytes(pkt))
                except Exception:
                    pass

                # 즉시/주기적 flush
                if self.sync or (
                    self.flush_every and (self._pkt_count % self.flush_every == 0)
                ):
                    self._flush_nolock()
            return True
        except Exception as e:
            log.error("writer.write failed: %s", e)
            return False

    # ✅ 새로 추가: 공용 flush API
    def flush(self) -> None:
        with self._lock:
            self._flush_nolock()

    # 내부용: 락 없이 호출 금지
    def _flush_nolock(self) -> None:
        try:
            # 1) writer 객체가 flush를 제공하는 경우
            if hasattr(self._writer, "flush") and callable(
                getattr(self._writer, "flush")
            ):
                self._writer.flush()  # 일부 Scapy 버전은 구현돼 있음
            # 2) 내부 파일 핸들 flush
            if self._fp and hasattr(self._fp, "flush"):
                self._fp.flush()
            # 3) 가능한 경우 fsync로 디스크 반영
            if self._fd is not None:
                try:
                    os.fsync(self._fd)
                except Exception:
                    # Windows에선 버퍼링 상황에 따라 fsync가 필요 없을 수 있음
                    pass
        except Exception as e:
            log.debug("flush skipped/failed: %s", e)

    def close(self) -> None:
        if self._closed:
            return
        with self._lock:
            try:
                # 마지막 flush
                self._flush_nolock()
            except Exception:
                pass
            try:
                # Scapy writer 닫기
                if hasattr(self._writer, "close"):
                    self._writer.close()
                # 파일 핸들 닫기 (Scapy가 닫아주지 않는 경우 대비)
                if self._fp and hasattr(self._fp, "close"):
                    try:
                        self._fp.close()
                    except Exception:
                        pass
            finally:
                self._closed = True
                log.info(
                    "PCAP writer closed: %s (packets=%d)",
                    self.filepath,
                    self._pkt_count,
                )

    def get_stats(self) -> dict:
        try:
            size = 0
            if self.filepath and os.path.exists(self.filepath):
                size = os.path.getsize(self.filepath)
        except Exception:
            size = 0
        return {
            "file_path": self.filepath,
            "packet_count": self._pkt_count,
            "file_size_bytes": size,
            "bytes_written": self._bytes,
            "is_closed": self._closed,
        }


class PacketBuffer:
    """메모리 버퍼링을 통한 배치 저장"""

    def __init__(self, writer: ThreadSafePcapWriter, buffer_size: int = 100):
        self.writer = writer
        self.buffer_size = buffer_size
        self._buffer = []
        self._lock = threading.Lock()

    def add(self, pkt: Packet) -> bool:
        """패킷을 버퍼에 추가"""
        with self._lock:
            self._buffer.append(pkt)

            if len(self._buffer) >= self.buffer_size:
                return self._flush_buffer()
            return True

    def _flush_buffer(self) -> bool:
        """버퍼 플러시"""
        if not self._buffer:
            return True

        success_count = 0
        for pkt in self._buffer:
            if self.writer.write(pkt):
                success_count += 1

        buffer_len = len(self._buffer)
        self._buffer.clear()
        return success_count == buffer_len

    def flush(self) -> bool:
        with self._lock:
            return self._flush_buffer()

    def close(self):
        self.flush()
        self.writer.close()


def create_pcap_writer(
    path: str,
    linktype: Optional[int] = None,
    buffered: bool = False,
    buffer_size: int = 100,
):
    """PCAP writer 팩토리 함수"""
    writer = ThreadSafePcapWriter(path, linktype=linktype)

    if buffered:
        return PacketBuffer(writer, buffer_size=buffer_size)

    return writer
