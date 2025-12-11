from .collector import fetch_cert
from .inventory import build_cert_record
from typing import List, Dict, Optional
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("tls_analyzer")

class TLSAnalyzer:
    """TLS 인증서 분석 및 수집"""
    
    def __init__(self, max_workers: int = 10):
        self.results = []
        self.max_workers = max_workers
        self._lock = threading.Lock()
    
    def analyze_host(self, host: str, port: int = 443, timeout: float = 3.0) -> Optional[Dict]:
        """단일 호스트의 TLS 인증서 분석"""
        try:
            cert = fetch_cert(host, port, timeout)
            if cert:
                record = build_cert_record(host, cert)
                record['port'] = port
                with self._lock:
                    self.results.append(record)
                log.info(f"TLS analysis completed for {host}:{port}")
                return record
            else:
                log.warning(f"No TLS certificate found for {host}:{port}")
        except Exception as e:
            log.error(f"TLS analysis failed for {host}:{port}: {e}")
        return None
    
    def analyze_multiple_hosts(self, hosts: List[str], ports: List[int] = None, timeout: float = 3.0) -> List[Dict]:
        """여러 호스트의 TLS 인증서 병렬 분석"""
        if ports is None:
            ports = [443]
        
        tasks = []
        for host in hosts:
            for port in ports:
                tasks.append((host, port, timeout))
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {
                executor.submit(self.analyze_host, host, port, timeout): (host, port)
                for host, port, timeout in tasks
            }
            
            for future in as_completed(future_to_task):
                host, port = future_to_task[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    log.error(f"TLS analysis exception for {host}:{port}: {e}")
        
        return results
    
    def get_expiring_certs(self, days_threshold: int = 30) -> List[Dict]:
        """만료 임박 인증서 반환"""
        expiring = []
        for record in self.results:
            days_left = record.get('days_left')
            if days_left is not None and days_left <= days_threshold:
                expiring.append(record)
        return expiring
    
    def get_expired_certs(self) -> List[Dict]:
        """이미 만료된 인증서 반환"""
        expired = []
        for record in self.results:
            days_left = record.get('days_left')
            if days_left is not None and days_left < 0:
                expired.append(record)
        return expired
    
    def get_weak_ciphers(self) -> List[Dict]:
        """약한 암호화 알고리즘 사용 인증서 (확장 가능)"""
        # 추후 확장: 인증서의 암호화 알고리즘 분석
        weak = []
        for record in self.results:
            # 예시: RSA 키 길이가 2048 미만인 경우 (실제 구현 시 cert 파싱 필요)
            if 'subject' in record:
                # 실제로는 공개키 길이, 서명 알고리즘 등을 분석해야 함
                pass
        return weak
    
    def get_certificate_chains(self) -> Dict[str, List[Dict]]:
        """호스트별 인증서 체인 정보"""
        chains = {}
        for record in self.results:
            host = record.get('host')
            if host:
                if host not in chains:
                    chains[host] = []
                chains[host].append(record)
        return chains
    
    def generate_tls_report(self) -> Dict:
        """TLS 분석 보고서 생성"""
        total_certs = len(self.results)
        expiring_30 = len(self.get_expiring_certs(30))
        expiring_7 = len(self.get_expiring_certs(7))
        expired = len(self.get_expired_certs())
        
        report = {
            'summary': {
                'total_certificates': total_certs,
                'expiring_in_30_days': expiring_30,
                'expiring_in_7_days': expiring_7,
                'expired': expired,
                'healthy': total_certs - expiring_30 - expired
            },
            'certificates': self.results,
            'expiring_soon': self.get_expiring_certs(30),
            'expired': self.get_expired_certs(),
            'certificate_chains': self.get_certificate_chains()
        }
        
        return report
    
    def clear_results(self):
        """분석 결과 초기화"""
        with self._lock:
            self.results.clear()
    
    def export_to_csv(self, filename: str):
        """CSV 파일로 내보내기"""
        import csv
        
        fieldnames = ['host', 'port', 'subject', 'issuer', 'notBefore', 'notAfter', 'days_left', 'warn']
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for record in self.results:
                    # subject와 issuer는 복잡한 구조이므로 문자열로 변환
                    row = record.copy()
                    if 'subject' in row and row['subject']:
                        row['subject'] = str(row['subject'])
                    if 'issuer' in row and row['issuer']:
                        row['issuer'] = str(row['issuer'])
                    
                    writer.writerow({k: row.get(k, '') for k in fieldnames})
                    
            log.info(f"TLS results exported to {filename}")
        except Exception as e:
            log.error(f"Failed to export TLS results to CSV: {e}")