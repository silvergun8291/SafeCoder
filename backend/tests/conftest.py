"""pytest 설정 파일 - 자동으로 로드됨"""

import sys
from pathlib import Path

# backend 디렉터리를 Python 경로에 추가
backend_dir = Path(__file__).parent.parent  # tests -> backend
sys.path.insert(0, str(backend_dir))

print(f"\n✓ PYTHONPATH 설정됨: {backend_dir}")
print(f"✓ sys.path[0]: {sys.path[0]}\n")
