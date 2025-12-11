# modules/utils/errors.py
class ScannerError(Exception):
    """기본 스캐너 예외 베이스"""

    pass


class ConfigError(ScannerError):
    """설정 관련 오류"""

    pass


class NetworkError(ScannerError):
    """네트워크/권한/인터페이스 관련 오류"""

    pass
