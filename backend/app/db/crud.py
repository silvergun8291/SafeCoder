"""
Piranha Rule CRUD Operations
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict
from sqlalchemy import select, delete, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import PiranhaRule

logger = logging.getLogger(__name__)


# ==================== CREATE ====================

async def create_piranha_rule(
    db: AsyncSession,
    rule_name: str,
    language: str,
    rule_code: str,
    before_code: str,
    after_code: str,
    cwe: Optional[str] = None,
    diff_analysis: Optional[Dict] = None,
    ast_analysis: Optional[Dict] = None,
    validation_similarity: Optional[float] = None,
    generation_attempts: int = 1
) -> PiranhaRule:
    """
    새로운 Piranha Rule 생성

    Raises:
        ValueError: rule_name 중복 시
    """
    try:
        new_rule = PiranhaRule(
            rule_name=rule_name,
            language=language,
            cwe=cwe,
            rule_code=rule_code,
            before_code=before_code,
            after_code=after_code,
            diff_analysis=diff_analysis,
            ast_analysis=ast_analysis,
            validation_similarity=validation_similarity,
            generation_attempts=generation_attempts,
            success_count=0,
            fail_count=0,
            avg_execution_time=0.0
        )

        db.add(new_rule)
        await db.commit()
        await db.refresh(new_rule)

        logger.info(f"✅ Piranha Rule created: {rule_name}")
        return new_rule

    except IntegrityError as e:
        await db.rollback()
        logger.error(f"❌ Duplicate rule_name: {rule_name}")
        raise ValueError(f"Rule '{rule_name}' already exists") from e


# ==================== READ ====================

async def get_piranha_rule_by_name(
    db: AsyncSession,
    rule_name: str
) -> Optional[PiranhaRule]:
    """rule_name으로 조회"""
    stmt = select(PiranhaRule).where(PiranhaRule.rule_name == rule_name)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_piranha_rule_by_id(
    db: AsyncSession,
    rule_id: int
) -> Optional[PiranhaRule]:
    """ID로 조회"""
    stmt = select(PiranhaRule).where(PiranhaRule.id == rule_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_all_piranha_rules(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100
) -> List[PiranhaRule]:
    """모든 Rule 조회 (페이징)"""
    stmt = (
        select(PiranhaRule)
        .offset(skip)
        .limit(limit)
        .order_by(PiranhaRule.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_piranha_rules_by_language(
    db: AsyncSession,
    language: str
) -> List[PiranhaRule]:
    """언어별 조회"""
    stmt = (
        select(PiranhaRule)
        .where(PiranhaRule.language == language)
        .order_by(PiranhaRule.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_piranha_rules_by_cwe(
    db: AsyncSession,
    cwe: str
) -> List[PiranhaRule]:
    """CWE별 조회"""
    stmt = (
        select(PiranhaRule)
        .where(PiranhaRule.cwe == cwe)
        .order_by(PiranhaRule.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_top_piranha_rules(
    db: AsyncSession,
    limit: int = 10
) -> List[PiranhaRule]:
    """성공률 높은 Rule (Top N)"""
    stmt = (
        select(PiranhaRule)
        .where(PiranhaRule.success_count > 0)
        .order_by(
            (PiranhaRule.success_count /
             func.nullif(PiranhaRule.success_count + PiranhaRule.fail_count, 0)).desc()
        )
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_high_similarity_rules(
    db: AsyncSession,
    min_similarity: float = 0.9,
    limit: int = 20
) -> List[PiranhaRule]:
    """유사도 높은 Rule"""
    stmt = (
        select(PiranhaRule)
        .where(PiranhaRule.validation_similarity >= min_similarity)
        .order_by(PiranhaRule.validation_similarity.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ==================== UPDATE ====================

async def update_piranha_rule(
    db: AsyncSession,
    rule_name: str,
    rule_code: Optional[str] = None,
    validation_similarity: Optional[float] = None
) -> Optional[PiranhaRule]:
    """Rule 업데이트"""
    rule = await get_piranha_rule_by_name(db, rule_name)
    if not rule:
        logger.warning(f"⚠️ Rule not found: {rule_name}")
        return None

    if rule_code is not None:
        rule.rule_code = rule_code

    if validation_similarity is not None:
        rule.validation_similarity = validation_similarity

    rule.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(rule)

    logger.info(f"✅ Rule updated: {rule_name}")
    return rule


async def increment_success(
    db: AsyncSession,
    rule_name: str,
    execution_time: float
) -> Optional[PiranhaRule]:
    """성공 카운트 증가 + 평균 실행 시간 갱신"""
    rule = await get_piranha_rule_by_name(db, rule_name)
    if not rule:
        return None

    rule.success_count += 1

    # 평균 실행 시간 업데이트
    total = rule.success_count + rule.fail_count
    if rule.avg_execution_time:
        rule.avg_execution_time = (
            (rule.avg_execution_time * (total - 1) + execution_time) / total
        )
    else:
        rule.avg_execution_time = execution_time

    await db.commit()
    await db.refresh(rule)

    return rule


async def increment_failure(
    db: AsyncSession,
    rule_name: str
) -> Optional[PiranhaRule]:
    """실패 카운트 증가"""
    rule = await get_piranha_rule_by_name(db, rule_name)
    if not rule:
        return None

    rule.fail_count += 1

    await db.commit()
    await db.refresh(rule)

    return rule


# ==================== DELETE ====================

async def delete_piranha_rule(
    db: AsyncSession,
    rule_name: str
) -> bool:
    """Rule 삭제"""
    rule = await get_piranha_rule_by_name(db, rule_name)
    if not rule:
        logger.warning(f"⚠️ Rule not found: {rule_name}")
        return False

    await db.delete(rule)
    await db.commit()

    logger.info(f"🗑️ Rule deleted: {rule_name}")
    return True


async def delete_all_piranha_rules(db: AsyncSession) -> int:
    """모든 Rule 삭제 (주의!)"""
    stmt = delete(PiranhaRule)
    result = await db.execute(stmt)
    await db.commit()

    deleted_count = result.rowcount
    logger.warning(f"🗑️ Deleted ALL {deleted_count} rules")
    return deleted_count


# ==================== STATISTICS ====================

async def get_piranha_statistics(db: AsyncSession) -> Dict:
    """통계 정보"""
    # 전체 개수
    total_stmt = select(func.count(PiranhaRule.id))
    total_result = await db.execute(total_stmt)
    total = total_result.scalar()

    # 언어별
    lang_stmt = (
        select(
            PiranhaRule.language,
            func.count(PiranhaRule.id).label('count')
        )
        .group_by(PiranhaRule.language)
    )
    lang_result = await db.execute(lang_stmt)
    by_language = {row[0]: row[1] for row in lang_result.all()}

    # CWE별
    cwe_stmt = (
        select(
            PiranhaRule.cwe,
            func.count(PiranhaRule.id).label('count')
        )
        .where(PiranhaRule.cwe.isnot(None))
        .group_by(PiranhaRule.cwe)
        .order_by(func.count(PiranhaRule.id).desc())
    )
    cwe_result = await db.execute(cwe_stmt)
    by_cwe = {row[0]: row[1] for row in cwe_result.all()}

    # 평균 유사도
    avg_sim_stmt = select(func.avg(PiranhaRule.validation_similarity))
    avg_sim_result = await db.execute(avg_sim_stmt)
    avg_similarity = avg_sim_result.scalar()

    # 총 성공/실패
    success_stmt = select(func.sum(PiranhaRule.success_count))
    fail_stmt = select(func.sum(PiranhaRule.fail_count))

    total_success = (await db.execute(success_stmt)).scalar() or 0
    total_fail = (await db.execute(fail_stmt)).scalar() or 0

    return {
        "total_rules": total,
        "by_language": by_language,
        "by_cwe": by_cwe,
        "avg_similarity": float(avg_similarity) if avg_similarity else 0.0,
        "total_success": total_success,
        "total_fail": total_fail,
        "success_rate": (
            total_success / (total_success + total_fail)
            if (total_success + total_fail) > 0
            else 0.0
        )
    }
