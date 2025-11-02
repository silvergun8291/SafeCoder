from functools import lru_cache
from app.services.scanning.scanner_service import ScannerService
from app.core.config import Settings, get_settings

# @lru_cache를 사용하여 ScannerService 인스턴스를
# 애플리케이션 수명 주기 동안 싱글톤으로 관리합니다.
@lru_cache()
def get_scanner_service() -> ScannerService:
    """ScannerService 의존성 주입"""
    return ScannerService()

# 설정 객체도 명시적으로 의존성 주입
def get_app_settings() -> Settings:
    """Settings 객체 의존성 주입"""
    return get_settings()