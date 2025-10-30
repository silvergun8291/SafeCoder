from sqlalchemy import Column, Integer, String, Text, Float, TIMESTAMP, func, Index
from sqlalchemy.dialects.postgresql import TIMESTAMP as PG_TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base
from datetime import datetime
from typing import Optional

class SemgrepRule(Base):
    """
    Semgrep Autofix 룰 저장 테이블 (Phase 5)
    SQLAlchemy 2.0 (Type-Annotated) 스타일로 작성
    """
    __tablename__ = "semgrep_rules"

    # 기본 키
    id: Mapped[int] = mapped_column(primary_key=True, index=True, autoincrement=True)

    # 룰 식별 정보
    rule_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String(100), nullable=False)
    cwe: Mapped[Optional[str]] = mapped_column(String(20))

    # 룰 본문
    rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)

    # 통계
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_execution_time: Mapped[Optional[float]] = mapped_column(Float)

    created_at: Mapped[datetime] = mapped_column(
        PG_TIMESTAMP(timezone=True),  # ⭐ 타임존 포함
        server_default=func.now()
    )

    updated_at: Mapped[datetime] = mapped_column(
        PG_TIMESTAMP(timezone=True),  # ⭐ 타임존 포함
        server_default=func.now(),
        onupdate=func.now()
    )

    # 인덱스
    __table_args__ = (
        Index("idx_rule_language", "language"),
        Index("idx_rule_vuln_type", "vulnerability_type"),
        Index("idx_rule_cwe", "cwe"),
        Index("idx_rule_success_count", "success_count"),
    )