from __future__ import annotations
import os
import sys
import argparse
from scapy.all import conf, IFACES
import asyncio
from modules.scanner.vuln import VulnerabilityMapper
from modules.core.models import AppConfig, ScanJob, ScanOptions
from modules.core.scheduler import SimpleScheduler
from modules.utils.log import setup_logging

# --- 추가된 imports ---
import time as _time
import glob as _glob
import shutil as _shutil
import csv as _csv
import json as _json
from datetime import datetime as _dt, timezone as _tz

PROJECT_ROOT = os.path.dirname(__file__)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RESULT_DIR = os.path.join(PROJECT_ROOT, "result")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def _prompt_nonempty(msg: str, default: str | None = None) -> str:
    while True:
        v = input(f"{msg}{f' [{default}]' if default else ''}: ").strip()
        if v:
            return v
        if default is not None:
            return default
        print("값을 입력해주세요.")


def _prompt_bool(msg: str, default: bool = False) -> bool:
    d = "Y" if default else "N"
    v = _prompt_nonempty(f"{msg} (Y/n)", d).strip().lower()
    return v in ("y", "yes")


def _prompt_float(msg: str, default: float) -> float:
    v = _prompt_nonempty(f"{msg}", str(default))
    try:
        return float(v)
    except ValueError:
        return default


def _prompt_iface() -> str:
    print("\n=== Available Interfaces ===")
    indexed = []
    for idx, (key, iface) in enumerate(IFACES.data.items()):
        name = getattr(iface, "name", str(key)) or str(key)
        ip = None
        try:
            ip = getattr(iface, "ip", None) or getattr(iface, "ip6", None)
        except Exception:
            ip = None
        desc = getattr(iface, "description", "") or ""
        shown_ip = ip if ip else "0.0.0.0"
        print(f"[{idx}] {name} | {shown_ip} ({desc})")
        indexed.append((idx, key, name))
    print("============================")
    choice = _prompt_nonempty("Select interface index", "0")
    try:
        idx = int(choice)
        key = indexed[idx][1]
        return key
    except Exception:
        return conf.iface  # fallback


def _prompt_protocols() -> list[str]:
    v = _prompt_nonempty(
        "Scan protocols (comma separated) [tcp,udp,dns,icmp]", "tcp,udp,dns,icmp"
    )
    return [x.strip().lower() for x in v.split(",") if x.strip()]


def _prompt_tcp_mode() -> str:
    v = _prompt_nonempty("TCP scan mode ['full','syn','fin','null','xmas']", "syn")
    return v.strip().lower()


async def run_shodan_scan(ips_to_scan: list[str]):
    try:
        mapper = VulnerabilityMapper(ip_list=ips_to_scan)
        await mapper.run_mapping()
    except ValueError as e:
        print(f"오류: {e}")
    except Exception as e:
        print(f"예상치 못한 오류가 발생했습니다: {e}")


# ---------------------------
# CSV injection helpers (MODIFIED)
# ---------------------------
def _iso_now():
    return _dt.now(_tz.utc).astimezone().isoformat(timespec="seconds")

def _newest_csvs(result_dir, pattern, since_epoch):
    paths = sorted(
        _glob.glob(os.path.join(result_dir, pattern)),
        key=lambda p: os.path.getmtime(p),
        reverse=True,
    )
    return [p for p in paths if os.path.getmtime(p) >= since_epoch]

def _augment_csv_with_meta(csv_path, meta_dict):
    """
    Inject meta_dict into CSV by adding one column per key in meta_dict.
    If any of the keys already exist in the CSV header, they will be skipped.
    """
    try:
        with open(csv_path, "r", encoding="utf-8", newline="") as rf:
            reader = _csv.reader(rf)
            header = next(reader)
    except Exception:
        return

    keys_to_add = [k for k in meta_dict.keys() if k not in header]
    if not keys_to_add:
        return

    tmp_path = csv_path + ".tmp"
    try:
        with open(csv_path, "r", encoding="utf-8", newline="") as rf, \
             open(tmp_path, "w", encoding="utf-8", newline="") as wf:
            reader = _csv.reader(rf)
            writer = _csv.writer(wf)

            header = next(reader, None)
            if header is None:
                return
            new_header = header + keys_to_add
            writer.writerow(new_header)

            for row in reader:
                extra_vals = [str(meta_dict.get(k, "")) for k in keys_to_add]
                writer.writerow(row + extra_vals)
        _shutil.move(tmp_path, csv_path)
    except Exception:
        # never allow meta writing errors to break scan flow
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
# ---------------------------
# End CSV injection helpers
# ---------------------------


def run_cli(config_path: str) -> None:
    setup_logging(LOG_DIR)
    config = AppConfig.load(config_path)
    print(f"[*] Config loaded: {config.to_dict()}")

    iface = _prompt_iface()
    conf.iface = iface

    mass_only = _prompt_bool("Use Masscan ONLY (disable built-in scanners)?", default=False)

    if mass_only:
        targets_raw = _prompt_nonempty("Targets (space/comma separated, CIDR ok)", "127.0.0.1")
        targets = [t.strip() for t in targets_raw.replace(",", " ").split() if t.strip()]
        ports_spec = _prompt_nonempty("Ports (예: 22,80,443 또는 1-65535)", "22,80,443")
        mass_rate = _prompt_nonempty("Masscan rate (packets/sec)", "1000")
        mass_wait = _prompt_nonempty("Masscan wait (sec)", "10")

        options = ScanOptions(
            interface=iface,
            use_masscan_for_tcp=True,
            masscan_targets=targets,
            masscan_rate=int(mass_rate),
            masscan_wait=float(mass_wait),
            enable_asset_identification=True,
            enable_tls_analysis=False,
            generate_enhanced_report=True,
        )

        job = ScanJob(
            name="masscan-only",
            target=None,
            ports=[],
            org_ports=ports_spec,
            protocols_to_scan=["tcp"],
            capture_file=None,
            timeout=1.0,
            rate_interval=0.0,
            options=options,
        )

        sched = SimpleScheduler(result_dir=RESULT_DIR, config=config)
        sched.add_job(job, ports_spec=None)

        _started_epoch = _time.time()
        _started_at = _iso_now()

        res = sched.run()

        _finished_at = _iso_now()

        print(f"main:\n{res}========================================================================")

        try:
            extra_meta = {
                "mode": "cli",
                "config": config_path,
                "mass_only": str(mass_only),
                "masscan_targets": ",".join(targets),
                "masscan_ports": ports_spec,
                "masscan_rate": str(mass_rate),
                "masscan_wait": str(mass_wait),
                "iface": str(iface),
            }
            csvs = _newest_csvs(RESULT_DIR, "*_masscan_alive_*.csv", since_epoch=_started_epoch)
            for p in csvs:
                try:
                    _augment_csv_with_meta(p, extra_meta)
                    print(f"[meta] Injected run options into: {p}")
                except Exception as e:
                    print(f"[meta] Failed injecting into {p}: {e}")
        except Exception as e:
            print(f"[meta] CSV injection error: {e}")

        if res:
            detailed_scan = _prompt_bool("정밀스캔?", default=False)
            if detailed_scan:
                # masscan 결과(res)에 있는 각 IP와 포트 목록을 순회합니다.
                for target_ip, open_ports in res.items():
                    if not open_ports:
                        print(f"[*] 호스트 {target_ip}는 열린 포트가 발견되지 않아 건너뜁니다.")
                        continue
                    
                    print(f"\n[*] 대상: {target_ip}, 포트: {open_ports} 정밀 스캔 시작...")

                    detailed_options = ScanOptions(
                        interface=iface,
                        enable_asset_identification=True,
                        enable_tls_analysis=True,
                        generate_enhanced_report=True,
                        tcp_scan_mode='full',
                        tcp_connect_fallback=True,
                        connect_timeout=2.0,
                        graceful_close=True,
                    )
                    detailed_job = ScanJob(
                        name=f"detailed-scan-{target_ip.replace('.', '_')}",
                        target=target_ip,
                        ports=open_ports,
                        org_ports=",".join(map(str, open_ports)),
                        protocols_to_scan=["tcp"],
                        capture_file=os.path.join(RESULT_DIR, f"detailed_scan_{target_ip.replace('.', '_')}.pcapng"),
                        options=detailed_options,
                    )
                    detailed_sched = SimpleScheduler(result_dir=RESULT_DIR, config=config)
                    detailed_sched.add_job(detailed_job)
                    detailed_sched.run()

                    print(f"[+] 대상 {target_ip} 정밀 스캔 완료.")
                
                print("\n--- 모든 정밀 스캔이 완료되었습니다. ---")
        vuln_scan = _prompt_bool("취약점 스캔?", default=False)
        if vuln_scan:
            vuln_ip = list(res.keys())
            if not vuln_ip:
                print("[!] 취약점을 스캔할 대상 IP가 없습니다.")
            else:
                print(f"\n--- Shodan 취약점 스캔을 시작합니다 (대상: {', '.join(vuln_ip)}) ---")
                # asyncio.run()을 사용하여 위에서 정의한 비동기 함수를 실행합니다.
                asyncio.run(run_shodan_scan(vuln_ip))
                print("\n--- Shodan 취약점 스캔이 완료되었습니다. ---")
        return


    # --- 기본 스캐너 흐름 ---
    target = _prompt_nonempty("Target host/IP", "127.0.0.1")
    ports_spec = _prompt_nonempty("Ports (예: 22,80,443 또는 8000-8100)", "22,80,443")
    outfile_default = os.path.join(RESULT_DIR, "scan.pcapng")
    outfile = _prompt_nonempty("Output pcap file path", outfile_default)

    protocols = _prompt_protocols()
    ua_toggle = _prompt_bool("Use User-Agent for HTTP probe?", default=False)
    ua_string = "scanner-x/0.1"
    if ua_toggle:
        ua_string = _prompt_nonempty("User-Agent string", ua_string)

    tcp_mode = "syn"
    if "tcp" in protocols:
        tcp_mode = _prompt_tcp_mode()

    syn_retries = int(_prompt_nonempty("SYN retries (정수)", "2"))
    connect_fb = _prompt_bool("Fallback to TCP connect() when ambiguous?", default=True)
    connect_timeout = _prompt_float("connect() timeout (sec)", 1.5)
    graceful_close = _prompt_bool("Use graceful close (4-way) on full-connect?", default=False)

    dns_qname = dns_qtype = dns_resolver = None
    if "dns" in protocols:
        dns_qname = _prompt_nonempty("DNS query name (qname)", "example.com")
        dns_qtype = _prompt_nonempty("DNS query type (A/AAAA/MX/TXT...)", "A").upper()
        dns_resolver = _prompt_nonempty("DNS resolver", "8.8.8.8")

    options = ScanOptions(
        ua_enabled=ua_toggle,
        ua_string=ua_string,
        syn_retries=syn_retries,
        tcp_connect_fallback=connect_fb,
        connect_timeout=connect_timeout,
        scan_protocols=protocols,
        tcp_scan_mode=tcp_mode,
        graceful_close=graceful_close,
        interface=iface,
        dns_qname=dns_qname,
        dns_qtype=dns_qtype,
        dns_resolver=dns_resolver,
        enable_asset_identification=True,
        enable_tls_analysis=False,
        generate_enhanced_report=True,
        use_masscan_for_tcp=False,
    )

    job = ScanJob(
        name="interactive",
        target=target,
        ports=[],
        org_ports=ports_spec,
        protocols_to_scan=protocols,
        capture_file=outfile,
        timeout=1.0,
        rate_interval=0.0,
        options=options,
    )

    sched = SimpleScheduler(result_dir=RESULT_DIR, config=config)
    sched.add_job(job, ports_spec=ports_spec)

    _started_epoch = _time.time()
    _started_at = _iso_now()

    res = sched.run()

    _finished_at = _iso_now()

    try:
        extra_meta = {
            "mode": "cli",
            "config": config_path,
            "target": target,
            "ports": ports_spec,
            "protocols": ",".join(protocols),
            "tcp_mode": tcp_mode,
            "iface": str(iface),
        }
        csvs = _newest_csvs(RESULT_DIR, "*_masscan_alive_*.csv", since_epoch=_started_epoch)
        for p in csvs:
            try:
                _augment_csv_with_meta(p, extra_meta)
                print(f"[meta] Injected run options into: {p}")
            except Exception as e:
                print(f"[meta] Failed injecting into {p}: {e}")
    except Exception as e:
        print(f"[meta] CSV injection error: {e}")

    sched = SimpleScheduler(result_dir=RESULT_DIR, config=config)
    sched.add_job(job, ports_spec=ports_spec)
    res = sched.run()
    vuln_scan = _prompt_bool("취약점 스캔?", default=False)
    if vuln_scan:
        vuln_ip = res
        if not vuln_ip:
            print("[!] 취약점을 스캔할 대상 IP가 없습니다.")
        else:
            print(f"\n--- Shodan 취약점 스캔을 시작합니다 (대상: {', '.join(vuln_ip)}) ---")
            asyncio.run(run_shodan_scan(vuln_ip))
            print("\n--- Shodan 취약점 스캔이 완료되었습니다. ---")


def run_gui(config_path: str) -> None:
    try:
        from PySide6 import QtWidgets  # noqa
        # ... (unchanged)
    except Exception:
        print("[!] PySide6가 설치되어야 GUI 모드를 사용할 수 있습니다: pip install PySide6")
        raise

    try:
        from modules.gui.qt_gui import MainWindow
    except Exception:
        print("[!] GUI 모듈을 찾을 수 없습니다. 경로를 확인하세요: modules/core/qt_gui.py")
        raise

    from PySide6 import QtWidgets
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["cli", "gui"], required=True)
    parser.add_argument("--config", default=os.path.join(DATA_DIR, "defaults.yaml"))
    args = parser.parse_args()

    if args.mode == "cli":
        run_cli(args.config)
    else:
        run_gui(args.config)


if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
