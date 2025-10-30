"""
Pytest configuration and shared fixtures
"""

import pytest
import sys
from pathlib import Path

# backend 디렉터리를 sys.path에 추가
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """테스트 환경 설정"""
    import os
    os.environ["APP_ENV"] = "testing"
    os.environ["DB_NAME"] = "test_db"
