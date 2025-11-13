"""
Piranha Rule 모델
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Integer, String, Text, Float, func, Index
from sqlalchemy.dialects.postgresql import TIMESTAMP as PG_TIMESTAMP, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base


class PiranhaRule(Base):
    """
    Piranha Rule 저장 테이블
    LLM으로 생성된 코드 변환 룰
    """
    __tablename__ = "piranha_rules"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True, autoincrement=True)

    # Rule 식별 정보
    rule_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)  # java, python
    cwe: Mapped[Optional[str]] = mapped_column(String(20))

    # Rule 본문 (Python 코드)
    rule_code: Mapped[str] = mapped_column(Text, nullable=False)

    # Before/After 코드
    before_code: Mapped[str] = mapped_column(Text, nullable=False)
    after_code: Mapped[str] = mapped_column(Text, nullable=False)

    # 분석 결과 (JSON)
    diff_analysis: Mapped[Optional[dict]] = mapped_column(JSONB)
    ast_analysis: Mapped[Optional[dict]] = mapped_column(JSONB)

    # 검증 정보
    validation_similarity: Mapped[Optional[float]] = mapped_column(Float)
    generation_attempts: Mapped[int] = mapped_column(Integer, default=1)

    # 통계
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_execution_time: Mapped[Optional[float]] = mapped_column(Float)

    # 타임스탬프
    created_at: Mapped[datetime] = mapped_column(
        PG_TIMESTAMP(timezone=True),
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        PG_TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    # 인덱스
    __table_args__ = (
        Index("idx_piranha_language", "language"),
        Index("idx_piranha_cwe", "cwe"),
        Index("idx_piranha_success", "success_count"),
        Index("idx_piranha_similarity", "validation_similarity"),
    )
