# mix_server_rules.py
import socket
import threading
import time
from typing import Literal

BIND_ADDR = "0.0.0.0"

# TCP "FW" 근사 모드
TCP_FW_MODE: Literal["silent", "immediate_close"] = "silent"
TCP_SILENT_SECONDS = 5.0

HTTP_BANNER = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK\r\n"
)

# 규칙: (port, proto, fw_sim)
#  - proto: "tcp" 또는 "udp"
#  - fw_sim: True면 방화벽처럼 동작
PORT_RULES: list[tuple[int, Literal["tcp", "udp"], bool]] = [
    # --- 사용자가 실제로 보셨던 포트들 ---
    (22, "tcp", False),
    (80, "tcp", False),
    (443, "tcp", False),
    (3306, "tcp", False),
    (3389, "tcp", False),  # RDP
    (123, "udp", False),
    (1194, "udp", False),
    # --- 방화벽처럼 보일 포트들 ---
    (3000, "tcp", True),
    (5000, "tcp", True),
    (5050, "tcp", True),
    (5500, "tcp", True),
    (5550, "tcp", True),
    (8000, "tcp", True),
    (8080, "tcp", True),
    (8443, "tcp", True),
    # 필요시 UDP도 추가 가능 예: (8080, "udp", True)
]


def has_user_agent_http(data: bytes) -> bool:
    try:
        header = data.decode("iso-8859-1", errors="ignore")
    except Exception:
        return False
    return "user-agent:" in header.lower()


def has_user_agent_any(data: bytes) -> bool:
    return b"user-agent:" in data.lower()


def tcp_handler(
    conn: socket.socket, addr: tuple[str, int], port: int, fw_sim: bool
) -> None:
    conn.settimeout(2.0)
    try:
        try:
            peek = conn.recv(2048)
        except socket.timeout:
            peek = b""

        if fw_sim:
            if TCP_FW_MODE == "immediate_close":
                # 즉시 종료 → 스캐너에 closed로 보일 가능성 큼
                return
            elif TCP_FW_MODE == "silent":
                # 무응답 유지 → 타임아웃 유도
                time.sleep(TCP_SILENT_SECONDS)
                return

        # 정상 포트: User-Agent 있을 때만 응답
        if has_user_agent_http(peek):
            conn.sendall(HTTP_BANNER)
        else:
            # UA 없으면 응답하지 않음(요구사항)
            time.sleep(0.5)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()


def run_tcp_server(port: int, fw_sim: bool) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((BIND_ADDR, port))
            s.listen(128)
            tag = " (FW-sim)" if fw_sim else ""
            print(f"[TCP] Listening on {BIND_ADDR}:{port}{tag}")
            while True:
                conn, addr = s.accept()
                t = threading.Thread(
                    target=tcp_handler, args=(conn, addr, port, fw_sim), daemon=True
                )
                t.start()
    except PermissionError:
        print(
            f"[ERR] TCP {port}: Permission denied (root/Administrator 필요할 수 있음)"
        )
    except OSError as e:
        print(f"[ERR] TCP {port}: {e}")


def run_udp_server(port: int, fw_sim: bool) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((BIND_ADDR, port))
            tag = " (FW-sim=drop)" if fw_sim else ""
            print(f"[UDP] Listening on {BIND_ADDR}:{port}{tag}")
            while True:
                data, addr = s.recvfrom(4096)
                if fw_sim:
                    # 완전 드롭(무응답)
                    continue
                if has_user_agent_any(data):
                    s.sendto(b"OK: User-Agent seen\n", addr)
                # UA 없으면 무응답
    except PermissionError:
        print(
            f"[ERR] UDP {port}: Permission denied (root/Administrator 필요할 수 있음)"
        )
    except OSError as e:
        print(f"[ERR] UDP {port}: {e}")


def spawn_servers(rules: list[tuple[int, Literal["tcp", "udp"], bool]]) -> None:
    for port, proto, fw in rules:
        if proto == "tcp":
            t = threading.Thread(target=run_tcp_server, args=(port, fw), daemon=True)
        else:
            t = threading.Thread(target=run_udp_server, args=(port, fw), daemon=True)
        t.start()


if __name__ == "__main__":
    print("[*] Starting mixed servers...")
    spawn_servers(PORT_RULES)
    print("[*] Servers are running. Press Enter to quit.")
    try:
        input()
    except KeyboardInterrupt:
        pass
