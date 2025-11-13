"""
Database CRUD operations for SemgrepRule model
SQLAlchemy 2.0 async pattern
"""

import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select, delete, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import SemgrepRule

logger = logging.getLogger(__name__)


# ==================== CREATE ====================

async def create_semgrep_rule(
        db: AsyncSession,
        rule_id: str,
        language: str,
        vulnerability_type: str,
        rule_yaml: str,
        cwe: Optional[str] = None
) -> SemgrepRule:
    """
    새로운 Semgrep 룰 생성

    Args:
        db: 비동기 DB 세션
        rule_id: 룰 ID (예: "python.lang.security.sql-injection")
        language: 언어 (예: "python", "java")
        vulnerability_type: 취약점 타입
        rule_yaml: Semgrep YAML 룰
        cwe: CWE 번호 (선택)

    Returns:
        생성된 SemgrepRule

    Raises:
        ValueError: rule_id 중복
    """
    try:
        new_rule = SemgrepRule(
            rule_id=rule_id,
            language=language,
            vulnerability_type=vulnerability_type,
            rule_yaml=rule_yaml,
            cwe=cwe,
            success_count=0,
            fail_count=0,
            avg_execution_time=0.0
        )

        db.add(new_rule)
        await db.commit()
        await db.refresh(new_rule)

        logger.info(f"✅ Semgrep 룰 생성: {rule_id}")
        return new_rule

    except IntegrityError as e:
        await db.rollback()
        logger.error(f"❌ 중복된 rule_id: {rule_id}")
        raise ValueError(f"rule_id '{rule_id}' 이미 존재") from e


# ==================== READ ====================

async def get_semgrep_rule_by_id(
        db: AsyncSession,
        rule_id: str
) -> Optional[SemgrepRule]:
    """rule_id로 조회"""
    stmt = select(SemgrepRule).where(SemgrepRule.rule_id == rule_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_all_semgrep_rules(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100
) -> List[SemgrepRule]:
    """모든 룰 조회 (페이지네이션)"""
    stmt = select(SemgrepRule).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_rules_by_language(
        db: AsyncSession,
        language: str
) -> List[SemgrepRule]:
    """언어별 룰 조회"""
    stmt = select(SemgrepRule).where(SemgrepRule.language == language)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_rules_by_vulnerability_type(
        db: AsyncSession,
        vulnerability_type: str
) -> List[SemgrepRule]:
    """취약점 타입별 룰 조회"""
    stmt = select(SemgrepRule).where(
        SemgrepRule.vulnerability_type == vulnerability_type
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_top_performing_rules(
        db: AsyncSession,
        limit: int = 10
) -> List[SemgrepRule]:
    """성공률이 높은 룰 조회"""
    stmt = (
        select(SemgrepRule)
        .where(SemgrepRule.success_count > 0)
        .order_by(
            (SemgrepRule.success_count /
             (SemgrepRule.success_count + SemgrepRule.fail_count)).desc()
        )
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ==================== UPDATE ====================

async def update_semgrep_rule(
        db: AsyncSession,
        rule_id: str,
        rule_yaml: Optional[str] = None,
        cwe: Optional[str] = None
) -> Optional[SemgrepRule]:
    """Semgrep 룰 업데이트"""
    rule = await get_semgrep_rule_by_id(db, rule_id)

    if not rule:
        logger.warning(f"⚠️ 룰 없음: {rule_id}")
        return None

    if rule_yaml is not None:
        rule.rule_yaml = rule_yaml
    if cwe is not None:
        rule.cwe = cwe

    rule.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(rule)

    logger.info(f"✅ 룰 업데이트: {rule_id}")
    return rule


async def increment_success_count(
        db: AsyncSession,
        rule_id: str,
        execution_time: float
) -> Optional[SemgrepRule]:
    """성공 카운트 증가"""
    rule = await get_semgrep_rule_by_id(db, rule_id)

    if not rule:
        return None

    rule.success_count += 1

    # 평균 실행 시간 업데이트
    total_count = rule.success_count + rule.fail_count
    rule.avg_execution_time = (
            (rule.avg_execution_time * (total_count - 1) + execution_time)
            / total_count
    )

    await db.commit()
    await db.refresh(rule)

    logger.debug(f"✅ 성공 카운트 증가: {rule_id} ({rule.success_count})")
    return rule


async def increment_fail_count(
        db: AsyncSession,
        rule_id: str
) -> Optional[SemgrepRule]:
    """실패 카운트 증가"""
    rule = await get_semgrep_rule_by_id(db, rule_id)

    if not rule:
        return None

    rule.fail_count += 1

    await db.commit()
    await db.refresh(rule)

    logger.debug(f"❌ 실패 카운트 증가: {rule_id} ({rule.fail_count})")
    return rule


# ==================== DELETE ====================

async def delete_semgrep_rule(
        db: AsyncSession,
        rule_id: str
) -> bool:
    """Semgrep 룰 삭제"""
    rule = await get_semgrep_rule_by_id(db, rule_id)

    if not rule:
        logger.warning(f"⚠️ 삭제할 룰 없음: {rule_id}")
        return False

    await db.delete(rule)
    await db.commit()

    logger.info(f"🗑️ 룰 삭제: {rule_id}")
    return True


async def delete_all_rules_by_language(
        db: AsyncSession,
        language: str
) -> int:
    """언어별 모든 룰 삭제"""
    stmt = delete(SemgrepRule).where(SemgrepRule.language == language)
    result = await db.execute(stmt)
    await db.commit()

    deleted_count = result.rowcount
    logger.info(f"🗑️ {language} 룰 {deleted_count}개 삭제")
    return deleted_count


# ==================== STATISTICS ====================

async def get_rule_statistics(db: AsyncSession) -> dict:
    """룰 통계 조회"""
    total_count_stmt = select(func.count(SemgrepRule.id))
    total_result = await db.execute(total_count_stmt)
    total_count = total_result.scalar()

    by_language_stmt = (
        select(
            SemgrepRule.language,
            func.count(SemgrepRule.id).label('count')
        )
        .group_by(SemgrepRule.language)
    )
    by_language_result = await db.execute(by_language_stmt)
    
    by_language = {
        row[0]: row[1]
        for row in by_language_result.all()
    }

    return {
        "total_rules": total_count,
        "by_language": by_language
    }
