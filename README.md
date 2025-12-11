# Xcanner

간단한 네트워크 스캐너 프로젝트 템플릿입니다. 이 저장소는 다양한 프로브(UDP/TCP/ICMP 등)와 포착/분석 모듈을 포함한 경량 스캐너 구조를 제공합니다.

## 주요 내용
- **프로젝트:** `kdt-xcanner-project`
- **언어:** Python 3.8+
- **주요 파일:** `run.py`, `port_listener.py`, `requirements.txt`

## 요구사항
- Python 3.8 이상
- 시스템에 따라 관리자 권한(포트 스니핑/저수준 캡처 필요 시)

의존성은 `requirements.txt`에서 관리합니다.

## 설치 (Windows PowerShell 예)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 실행 방법
개발용으로 간단히 `run.py`를 사용합니다.
```powershell
python run.py
```

`run.py` 실행 시 설정 파일(`data/defaults.yaml` 등)을 참조합니다. 추가 설정이나 캡처 장치 지정이 필요하면 파일을 편집하세요.

## 개발 가이드
- 코드 스타일: 기존 스타일을 유지하세요(간단한 모듈 단위 구조).
- 주요 변경 전에는 작은 단위로 테스트를 추가하세요.
- 네트워크/패킷 캡처 관련 코드는 관리자 권한에서 동작할 수 있습니다.

## 권장 향후 작업
- 유닛 테스트 및 CI 구성(GitHub Actions / GitLab CI)
- 정적 분석(예: `flake8`, `mypy`) 추가
- `CONTRIBUTING.md`와 코드 오너십 문서 추가

## 라이선스
프로젝트 루트의 `LICENSE` 파일을 확인하세요.
