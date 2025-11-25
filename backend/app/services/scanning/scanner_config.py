"""스캐너 설정 및 메타데이터"""

from pathlib import Path
from typing import Dict, List

from app.models.schemas import Language


class ScannerConfig:
    """스캐너 설정 클래스"""

    # 프로젝트 루트 경로
    BACKEND_DIR = Path(__file__).parent
    SCANNER_DIR = BACKEND_DIR / "scanners"

    # 스캐너 기본 타임아웃 (초)
    SCANNER_TIMEOUT = 300  # 5분

    # 언어별 스캐너 매핑
    LANGUAGE_SCANNERS: Dict[Language, List[Dict[str, str]]] = {
        Language.PYTHON: [
            {
                "name": "bandit",
                "image": "custom/bandit:latest",
                "build_path": str(SCANNER_DIR / "bandit"),
                "output_file": "bandit_result.json",
                "timeout": 120  # 2분
            },
            {
                "name": "dlint",
                "image": "custom/dlint:latest",
                "build_path": str(SCANNER_DIR / "dlint"),
                "output_file": "dlint_result.json",
                "timeout": 120  # 2분
            },
            {
                "name": "semgrep",
                "image": "custom/semgrep:latest",
                "build_path": str(SCANNER_DIR / "semgrep"),
                "output_file": "semgrep_result.json",
                "timeout": 180,
                "command": ["/scanner/scan_and_convert.sh", "/source", "/results/semgrep_result.json"]
            },
            {
                "name": "codeql",
                "image": "custom/codeql:latest",
                "build_path": str(SCANNER_DIR / "codeql"),
                "output_file": "codeql_result.json",
                "timeout": 300,
                "command": ["/source", "/results/codeql_result.json", "python"]
            }
        ],
        Language.JAVA: [
            {
                "name": "horusec",
                "image": "custom/horusec:latest",
                "build_path": str(SCANNER_DIR / "horusec"),
                "output_file": "horusec_result.json",
                "timeout": 180,  # 3분
                "command": ["/source", "/results/horusec_result.json"]
            },
            {
                "name": "spotbugs",
                "image": "custom/spotbugs:latest",
                "build_path": str(SCANNER_DIR / "spotbugs"),
                "output_file": "spotbugs_result.json",
                "timeout": 180  # 3분
            },
            {
                "name": "semgrep",
                "image": "custom/semgrep:latest",
                "build_path": str(SCANNER_DIR / "semgrep"),
                "output_file": "semgrep_result.json",
                "timeout": 180,  # 3분
                "command": ["/scanner/scan_and_convert.sh", "/source", "/results/semgrep_result.json"]
            },
            {
                "name": "codeql",
                "image": "custom/codeql:latest",
                "build_path": str(SCANNER_DIR / "codeql"),
                "output_file": "codeql_result.json",
                "timeout": 1200,
                "command": ["/source", "/results/codeql_result.json", "java"]
            }
        ]
    }

    # 빌드가 필요한 커스텀 이미지
    CUSTOM_IMAGES = ["custom/bandit:latest", "custom/dlint:latest", "custom/spotbugs:latest",
                     "custom/codeql:latest", "custom/horusec:latest", "custom/semgrep:latest"]

    # 심각도 가중치 (집계용)
    SEVERITY_WEIGHT = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }

    @classmethod
    def get_scanners_for_language(cls, language: Language) -> List[Dict[str, str]]:
        """언어에 해당하는 스캐너 목록 반환"""
        return cls.LANGUAGE_SCANNERS.get(language, [])

    @classmethod
    def get_scanner_names(cls, language: Language) -> List[str]:
        """언어에 해당하는 스캐너 이름 리스트 반환"""
        return [scanner["name"] for scanner in cls.get_scanners_for_language(language)]

    @classmethod
    def get_scanner_timeout(cls, scanner_config: Dict[str, str]) -> int:
        """스캐너별 타임아웃 반환"""
        return scanner_config.get("timeout", cls.SCANNER_TIMEOUT)
