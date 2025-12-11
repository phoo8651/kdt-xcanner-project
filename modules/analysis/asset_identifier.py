from typing import Dict, List, Optional, Set
import logging
import ipaddress
from collections import defaultdict

log = logging.getLogger("asset_identifier")

class AssetIdentifier:
    """네트워크 자산 식별 및 인벤토리 관리"""
    
    def __init__(self):
        self.assets = {}
        self.service_patterns = self._load_service_patterns()
        self.os_fingerprints = self._load_os_patterns()
    
    def _load_service_patterns(self) -> Dict[int, str]:
        """포트별 일반적인 서비스 패턴"""
        return {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MS SQL Server",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
    
    def _load_os_patterns(self) -> Dict[str, List[str]]:
        """OS 식별 패턴"""
        return {
            "Windows": ["3389", "445", "135", "139", "1433"],
            "Linux": ["22", "80", "443", "3306", "5432"],
            "Unix": ["22", "23", "513", "514"],
            "MacOS": ["22", "548", "631"],
            "Network Device": ["23", "80", "161", "443"]
        }
    
    def identify_from_scan_results(self, scan_results: List[Dict]) -> Dict[str, Dict]:
        """스캔 결과로부터 자산 식별"""
        log.info("Starting asset identification from scan results")
        
        # 호스트별로 결과 그룹화
        host_data = defaultdict(lambda: {
            'open_ports': [],
            'closed_ports': [],
            'services': {},
            'os_hints': [],
            'protocols': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        for result in scan_results:
            host = result.get('host')
            if not host:
                continue
                
            port = result.get('port')
            state = result.get('state', 'unknown')
            protocol = result.get('protocol', 'tcp')
            
            # 호스트 정보 업데이트
            asset = host_data[host]
            asset['protocols'].add(protocol)
            
            if state == 'open':
                asset['open_ports'].append(port)
                
                # 서비스 식별
                service = self._identify_service(port, protocol)
                if service:
                    asset['services'][port] = service
                    
            elif state in ['closed', 'filtered']:
                asset['closed_ports'].append(port)
        
        # OS 힌트 추가
        for host, asset in host_data.items():
            os_hint = self._guess_os(asset['open_ports'])
            if os_hint:
                asset['os_hints'].append(os_hint)
        
        # 자산 등록
        for host, asset_data in host_data.items():
            self.register_asset(host, asset_data)
        
        log.info(f"Identified {len(host_data)} assets from scan results")
        return dict(host_data)
    
    def register_asset(self, host: str, asset_data: Dict):
        """자산 등록 또는 업데이트"""
        if host in self.assets:
            # 기존 자산 업데이트
            existing = self.assets[host]
            existing['open_ports'].extend(asset_data.get('open_ports', []))
            existing['open_ports'] = list(set(existing['open_ports']))  # 중복 제거
            existing['services'].update(asset_data.get('services', {}))
            existing['os_hints'].extend(asset_data.get('os_hints', []))
            existing['protocols'].update(asset_data.get('protocols', set()))
        else:
            # 새 자산 등록
            self.assets[host] = {
                'ip': host,
                'hostname': self._resolve_hostname(host),
                'asset_type': self._classify_asset_type(asset_data),
                'open_ports': asset_data.get('open_ports', []),
                'closed_ports': asset_data.get('closed_ports', []),
                'services': asset_data.get('services', {}),
                'os_hints': asset_data.get('os_hints', []),
                'protocols': asset_data.get('protocols', set()),
                'risk_score': self._calculate_risk_score(asset_data),
                'criticality': self._assess_criticality(asset_data),
                'last_updated': self._current_timestamp()
            }
    
    def _identify_service(self, port: int, protocol: str = 'tcp') -> Optional[str]:
        """포트와 프로토콜로 서비스 식별"""
        return self.service_patterns.get(port, f"Unknown-{protocol}-{port}")
    
    def _guess_os(self, open_ports: List[int]) -> Optional[str]:
        """열린 포트 패턴으로 OS 추측"""
        port_set = set(str(p) for p in open_ports)
        
        scores = {}
        for os_name, os_ports in self.os_fingerprints.items():
            score = len(port_set.intersection(set(os_ports)))
            if score > 0:
                scores[os_name] = score
        
        if scores:
            return max(scores, key=scores.get)
        return None
    
    def _classify_asset_type(self, asset_data: Dict) -> str:
        """자산 유형 분류"""
        open_ports = asset_data.get('open_ports', [])
        services = asset_data.get('services', {})
        
        # 서버 타입 판단
        if 80 in open_ports or 443 in open_ports:
            return "Web Server"
        elif 22 in open_ports and (3306 in open_ports or 5432 in open_ports):
            return "Database Server"
        elif 25 in open_ports or 143 in open_ports:
            return "Mail Server"
        elif 53 in open_ports:
            return "DNS Server"
        elif 3389 in open_ports:
            return "Windows Desktop/Server"
        elif 22 in open_ports:
            return "Linux/Unix Server"
        elif 161 in open_ports:
            return "Network Device"
        else:
            return "Unknown Device"
    
    def _calculate_risk_score(self, asset_data: Dict) -> int:
        """자산 위험도 점수 계산 (0-100)"""
        score = 0
        open_ports = asset_data.get('open_ports', [])
        
        # 기본 점수 (열린 포트 수)
        score += min(len(open_ports) * 5, 30)
        
        # 고위험 포트 추가 점수
        high_risk_ports = {23, 21, 135, 139, 445, 1433, 3306, 3389}
        risky_open = set(open_ports).intersection(high_risk_ports)
        score += len(risky_open) * 15
        
        # 원격 접근 포트
        remote_ports = {22, 23, 3389, 5900}
        if set(open_ports).intersection(remote_ports):
            score += 20
        
        return min(score, 100)
    
    def _assess_criticality(self, asset_data: Dict) -> str:
        """자산 중요도 평가"""
        risk_score = self._calculate_risk_score(asset_data)
        
        if risk_score >= 70:
            return "Critical"
        elif risk_score >= 40:
            return "High"
        elif risk_score >= 20:
            return "Medium"
        else:
            return "Low"
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """IP에서 호스트명 역방향 조회"""
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    
    def _current_timestamp(self) -> str:
        """현재 타임스탬프"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_assets_by_type(self, asset_type: str) -> List[Dict]:
        """자산 유형별 필터링"""
        return [asset for asset in self.assets.values() 
                if asset.get('asset_type') == asset_type]
    
    def get_high_risk_assets(self) -> List[Dict]:
        """고위험 자산 목록"""
        return [asset for asset in self.assets.values() 
                if asset.get('criticality') in ['Critical', 'High']]
    
    def get_assets_with_service(self, service: str) -> List[Dict]:
        """특정 서비스를 실행하는 자산 목록"""
        result = []
        for asset in self.assets.values():
            services = asset.get('services', {})
            if service in services.values():
                result.append(asset)
        return result
    
    def create_inventory_report(self) -> Dict:
        """자산 인벤토리 보고서 생성"""
        total_assets = len(self.assets)
        asset_types = defaultdict(int)
        criticality_dist = defaultdict(int)
        service_dist = defaultdict(int)
        
        for asset in self.assets.values():
            asset_types[asset.get('asset_type', 'Unknown')] += 1
            criticality_dist[asset.get('criticality', 'Unknown')] += 1
            
            for service in asset.get('services', {}).values():
                service_dist[service] += 1
        
        return {
            'summary': {
                'total_assets': total_assets,
                'asset_types': dict(asset_types),
                'criticality_distribution': dict(criticality_dist),
                'top_services': dict(sorted(service_dist.items(), 
                                          key=lambda x: x[1], reverse=True)[:10])
            },
            'assets': self.assets,
            'high_risk_assets': self.get_high_risk_assets(),
            'statistics': {
                'avg_open_ports': sum(len(a.get('open_ports', [])) for a in self.assets.values()) / max(total_assets, 1),
                'most_common_os': self._get_most_common_os(),
                'unique_services': len(service_dist)
            }
        }
    
    def _get_most_common_os(self) -> str:
        """가장 많이 발견된 OS"""
        os_count = defaultdict(int)
        for asset in self.assets.values():
            os_hints = asset.get('os_hints', [])
            for os_hint in os_hints:
                os_count[os_hint] += 1
        
        if os_count:
            return max(os_count, key=os_count.get)
        return "Unknown"
    
    def export_to_csv(self, filename: str):
        """자산 인벤토리를 CSV로 내보내기"""
        import csv
        
        fieldnames = ['ip', 'hostname', 'asset_type', 'open_ports', 'services', 
                     'os_hints', 'risk_score', 'criticality', 'last_updated']
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for asset in self.assets.values():
                    row = {
                        'ip': asset.get('ip', ''),
                        'hostname': asset.get('hostname', ''),
                        'asset_type': asset.get('asset_type', ''),
                        'open_ports': ','.join(map(str, asset.get('open_ports', []))),
                        'services': ','.join(asset.get('services', {}).values()),
                        'os_hints': ','.join(asset.get('os_hints', [])),
                        'risk_score': asset.get('risk_score', 0),
                        'criticality': asset.get('criticality', ''),
                        'last_updated': asset.get('last_updated', '')
                    }
                    writer.writerow(row)
                    
            log.info(f"Asset inventory exported to {filename}")
        except Exception as e:
            log.error(f"Failed to export asset inventory to CSV: {e}")
    
    def clear_assets(self):
        """자산 데이터 초기화"""
        self.assets.clear()
        log.info("Asset inventory cleared")