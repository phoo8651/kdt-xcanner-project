import asyncio
import aiohttp
import json
import socket
import ipaddress
from typing import List, Dict, Any
import logging
from datetime import datetime

log = logging.getLogger("shodan_mapper")

class VulnerabilityMapper:
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
    CVEDB_URL = "https://cvedb.shodan.io/cve/{cve}"

    def __init__(self, ip_list: List[str]):
        if not ip_list:
            raise ValueError("IP 리스트는 비어있을 수 없습니다.")
        self.original_list = ip_list
        self.has_domains = self.contains_domain(self.original_list)

        if self.has_domains:
            print("도메인이 포함되어 있어 IP 주소 변환을 시작합니다.")
            resolved_ips, domain_map = self.resolve_hostnames(self.original_list)
            self.ip_list = resolved_ips
            self.domain_ip_map = domain_map
        else:
            self.ip_list = self.original_list
            self.domain_ip_map = {}
        self._session = None
        if self.ip_list:
            print(f"\n총 {len(self.ip_list)}개의 유효 IP로 스캔을 시작합니다: {self.ip_list}")
        else:
            print("\n스캔을 진행할 유효한 IP 주소가 없습니다.")

    @staticmethod
    def contains_domain(host_list: list[str]) -> bool:
        for host in host_list:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                return True
        return False

    @staticmethod
    def resolve_hostnames(host_list: list[str]) -> tuple[list[str], dict]:
        final_ips = []
        resolved_domains = {}
        print("--- 호스트 주소 변환 시작 ---")
        for host in host_list:
            try:
                ipaddress.ip_address(host)
                final_ips.append(host)
            except ValueError:
                try:
                    ip = socket.gethostbyname(host)
                    print(f"  -> 변환 성공: '{host}' -> {ip}")
                    final_ips.append(ip)
                    resolved_domains[host] = ip
                except socket.gaierror:
                    print(f"  -> 변환 실패: 도메인 '{host}'의 IP 주소를 찾을 수 없습니다. 스캔에서 제외됩니다.")
        
        unique_final_ips = list(dict.fromkeys(final_ips))
        return unique_final_ips, resolved_domains

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    # 특정 IP에 대해 InternetDB를 스캔하는 비동기 메서드
    async def _scan_internetdb(self, ip: str) -> Dict[str, Any]:
        session = await self._get_session()
        url = self.INTERNETDB_URL.format(ip=ip)
        print(f"[InternetDB] IP 스캔 시작: {ip}")
        
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"[InternetDB] IP 스캔 성공: {ip}")
                    return data
                else:
                    print(f"[InternetDB] IP 스캔 실패: {ip} (HTTP {response.status})")
                    return {"ip": ip, "error": f"HTTP Error {response.status}"}
        # aiohttp 관련 클라이언트 오류가 발생했을 경우
        except aiohttp.ClientError as e:
            print(f"[InternetDB] IP 스캔 중 클라이언트 오류 발생: {ip} - {e}")
            return {"ip": ip, "error": f"Client Error: {e}"}

    # 특정 CVE ID에 대한 상세 정보를 조회하는 비동기 메서드
    async def _fetch_cve_details(self, cve_id: str) -> Dict[str, Any]:
        session = await self._get_session()
        url = self.CVEDB_URL.format(cve=cve_id)
        
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    return {"cve": cve_id, "error": "Not Found in Shodan DB"}
                else:
                    return {"cve": cve_id, "error": f"HTTP Error {response.status}"}
        except aiohttp.ClientError as e:
            return {"cve": cve_id, "error": f"Client Error: {e}"}

    # 데이터를 JSON 파일로 저장하는 메서드
    def _save_to_json(self, data: Any, filename: str):
        try:
            with open(filename, 'w', encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"\n결과가 '{filename}' 파일로 성공적으로 저장되었습니다.")
        except IOError as e:
            print(f"\n파일을 저장하는 중 오류가 발생했습니다: {filename} - {e}")

    # 전체 취약점 매핑 프로세스를 실행하는 메인 비동기 메서드
    async def run_mapping(self):
        if not self.ip_list:
            return
        print("--- 1. InternetDB 스캔 시작 ---")
        scan_tasks = [self._scan_internetdb(ip) for ip in self.ip_list]
        internetdb_results = await asyncio.gather(*scan_tasks)
        
        # 발견된 모든 CVE를 중복 없이 저장하기 위해 set 자료형 사용
        all_cves = set()
        for res in internetdb_results:
            # 결과에 'vulns' 키가 있고, 그 값이 리스트 형태인지 확인
            if "vulns" in res and isinstance(res.get("vulns"), list):
                for cve in res["vulns"]:
                    all_cves.add(cve)
        
        if not all_cves:
            print("InternetDB 스캔 결과에서 발견된 CVE가 없습니다. 프로세스를 종료합니다.")
            await self.close_session()
            return

        print(f"--- 2. 고유 CVE {len(all_cves)}개 상세 정보 조회 시작 ---")
        cve_detail_tasks = [] # CVE 상세 정보 조회 작업을 담을 리스트
        # 중복 제거된 CVE 목록을 정렬하여 순회
        print("[CVEDB] 조회 작업 생성 중...", end="", flush=True)
        for cve_id in sorted(list(all_cves)):
            # Shodan API에 과도한 요청을 보내지 않기 위해 0.5초 대기 (Rate Limiting)
            await asyncio.sleep(0.3)
            print(".", end="", flush=True)
            # 각 CVE에 대한 상세 정보 조회 작업을 리스트에 추가
            cve_detail_tasks.append(self._fetch_cve_details(cve_id))
            
        # asyncio.gather를 사용해 모든 CVE 상세 정보 조회 작업을 동시에 실행
        cve_details_list = await asyncio.gather(*cve_detail_tasks)
        # 빠른 조회를 위해 CVE 상세 정보 리스트를 딕셔너리(맵) 형태로 변환
        cve_details_map = {item.get('cve_id'): item for item in cve_details_list}


        final_results = [] # 최종 결과를 담을 리스트
        for res in internetdb_results:
            # 결과에 'vulns' 키가 있고 리스트 형태라면
            if "vulns" in res and isinstance(res.get("vulns"), list):
                # 각 CVE에 대해 cve_details_map에서 상세 정보를 찾아 새로운 리스트를 만듦
                # 만약 맵에 정보가 없으면 "Details not fetched" 오류 메시지를 포함한 딕셔너리를 사용
                enriched_vulns = [cve_details_map.get(cve, {"cve_id": cve, "error": "Details not fetched"}) for cve in res["vulns"]]
                # 기존 결과에 'vulns_details'라는 새로운 키로 상세 정보가 추가된 리스트를 저장
                res["vulns_details"] = enriched_vulns
            final_results.append(res)
        ip_to_domain_map = {ip: domain for domain, ip in self.domain_ip_map.items()}
        for result in final_results:
            ip = result.get('ip')
            original_domain = ip_to_domain_map.get(ip)
            
            if original_domain:
                result['target'] = f"{original_domain} ({ip})"
            else:
                result['target'] = ip

        now = datetime.now().strftime("%Y%m%d%H%M%S")
        self._save_to_json(final_results, f"vulnerability_mapping_{now}.json")
        await self.close_session()

    async def close_session(self):
        if self._session and not self._session.closed:
            await self._session.close()
            print("\n클라이언트 세션이 안전하게 종료되었습니다.")