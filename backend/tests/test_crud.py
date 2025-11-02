"""
CRUD operations test for SemgrepRule
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.crud import (
    create_semgrep_rule,
    get_semgrep_rule_by_id,
    get_all_semgrep_rules,
    get_rules_by_language,
    get_rules_by_vulnerability_type,
    get_top_performing_rules,
    update_semgrep_rule,
    increment_success_count,
    increment_fail_count,
    delete_semgrep_rule,
    delete_all_rules_by_language,
    get_rule_statistics
)
from app.models.models import SemgrepRule


# ==================== FIXTURES ====================

@pytest.fixture
async def async_db_engine():
    """테스트용 인메모리 SQLite 엔진"""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def async_db_session(async_db_engine):
    """테스트용 비동기 세션"""
    async_session = async_sessionmaker(
        async_db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session


# ==================== CREATE TESTS ====================

@pytest.mark.asyncio
async def test_create_semgrep_rule(async_db_session):
    """Semgrep 룰 생성 테스트"""
    rule = await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.lang.security.sql-injection",
        language="python",
        vulnerability_type="SQL Injection",
        rule_yaml="rules:\n  - id: sql-injection\n    ...",
        cwe="CWE-89"
    )

    assert rule.id is not None
    assert rule.rule_id == "python.lang.security.sql-injection"
    assert rule.language == "python"
    assert rule.vulnerability_type == "SQL Injection"
    assert rule.cwe == "CWE-89"
    assert rule.success_count == 0
    assert rule.fail_count == 0


@pytest.mark.asyncio
async def test_create_duplicate_rule(async_db_session):
    """중복 룰 생성 시 에러 테스트"""
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.lang.security.xss",
        language="python",
        vulnerability_type="XSS",
        rule_yaml="rules:\n  - id: xss\n    ..."
    )

    with pytest.raises(ValueError, match="이미 존재"):
        await create_semgrep_rule(
            db=async_db_session,
            rule_id="python.lang.security.xss",
            language="python",
            vulnerability_type="XSS",
            rule_yaml="rules:\n  - id: xss\n    ..."
        )


# ==================== READ TESTS ====================

@pytest.mark.asyncio
async def test_get_semgrep_rule_by_id(async_db_session):
    """ID로 룰 조회 테스트"""
    created_rule = await create_semgrep_rule(
        db=async_db_session,
        rule_id="java.lang.security.xxe",
        language="java",
        vulnerability_type="XXE",
        rule_yaml="rules:\n  - id: xxe\n    ..."
    )

    retrieved_rule = await get_semgrep_rule_by_id(
        async_db_session,
        "java.lang.security.xxe"
    )

    assert retrieved_rule is not None
    assert retrieved_rule.id == created_rule.id
    assert retrieved_rule.rule_id == "java.lang.security.xxe"


@pytest.mark.asyncio
async def test_get_nonexistent_rule(async_db_session):
    """존재하지 않는 룰 조회 테스트"""
    rule = await get_semgrep_rule_by_id(
        async_db_session,
        "nonexistent.rule"
    )

    assert rule is None


@pytest.mark.asyncio
async def test_get_all_semgrep_rules(async_db_session):
    """모든 룰 조회 테스트"""
    # 3개 룰 생성
    for i in range(3):
        await create_semgrep_rule(
            db=async_db_session,
            rule_id=f"python.test.rule{i}",
            language="python",
            vulnerability_type="Test",
            rule_yaml=f"rule{i}"
        )

    rules = await get_all_semgrep_rules(async_db_session)

    assert len(rules) == 3


@pytest.mark.asyncio
async def test_get_rules_by_language(async_db_session):
    """언어별 룰 조회 테스트"""
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test1",
        language="python",
        vulnerability_type="Test",
        rule_yaml="py1"
    )
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="java.test1",
        language="java",
        vulnerability_type="Test",
        rule_yaml="java1"
    )
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test2",
        language="python",
        vulnerability_type="Test",
        rule_yaml="py2"
    )

    python_rules = await get_rules_by_language(async_db_session, "python")
    java_rules = await get_rules_by_language(async_db_session, "java")

    assert len(python_rules) == 2
    assert len(java_rules) == 1


@pytest.mark.asyncio
async def test_get_rules_by_vulnerability_type(async_db_session):
    """취약점 타입별 룰 조회 테스트"""
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.sql1",
        language="python",
        vulnerability_type="SQL Injection",
        rule_yaml="sql1"
    )
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.xss1",
        language="python",
        vulnerability_type="XSS",
        rule_yaml="xss1"
    )

    sql_rules = await get_rules_by_vulnerability_type(
        async_db_session,
        "SQL Injection"
    )

    assert len(sql_rules) == 1
    assert sql_rules[0].vulnerability_type == "SQL Injection"


# ==================== UPDATE TESTS ====================

@pytest.mark.asyncio
async def test_update_semgrep_rule(async_db_session):
    """룰 업데이트 테스트"""
    rule = await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test.update",
        language="python",
        vulnerability_type="Test",
        rule_yaml="old_yaml"
    )

    updated_rule = await update_semgrep_rule(
        db=async_db_session,
        rule_id="python.test.update",
        rule_yaml="new_yaml",
        cwe="CWE-123"
    )

    assert updated_rule is not None
    assert updated_rule.rule_yaml == "new_yaml"
    assert updated_rule.cwe == "CWE-123"


@pytest.mark.asyncio
async def test_increment_success_count(async_db_session):
    """성공 카운트 증가 테스트"""
    rule = await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test.success",
        language="python",
        vulnerability_type="Test",
        rule_yaml="yaml"
    )

    updated_rule = await increment_success_count(
        db=async_db_session,
        rule_id="python.test.success",
        execution_time=1.5
    )

    assert updated_rule.success_count == 1
    assert updated_rule.avg_execution_time == 1.5


@pytest.mark.asyncio
async def test_increment_fail_count(async_db_session):
    """실패 카운트 증가 테스트"""
    rule = await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test.fail",
        language="python",
        vulnerability_type="Test",
        rule_yaml="yaml"
    )

    updated_rule = await increment_fail_count(
        db=async_db_session,
        rule_id="python.test.fail"
    )

    assert updated_rule.fail_count == 1


@pytest.mark.asyncio
async def test_get_top_performing_rules(async_db_session):
    """성공률 높은 룰 조회 테스트"""
    # 성공률 100%
    rule1 = await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.best",
        language="python",
        vulnerability_type="Test",
        rule_yaml="yaml"
    )
    await increment_success_count(async_db_session, "python.best", 1.0)
    await increment_success_count(async_db_session, "python.best", 1.0)

    # 성공률 50%
    rule2 = await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.medium",
        language="python",
        vulnerability_type="Test",
        rule_yaml="yaml"
    )
    await increment_success_count(async_db_session, "python.medium", 1.0)
    await increment_fail_count(async_db_session, "python.medium")

    top_rules = await get_top_performing_rules(async_db_session, limit=2)

    assert len(top_rules) == 2
    assert top_rules[0].rule_id == "python.best"


# ==================== DELETE TESTS ====================

@pytest.mark.asyncio
async def test_delete_semgrep_rule(async_db_session):
    """룰 삭제 테스트"""
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test.delete",
        language="python",
        vulnerability_type="Test",
        rule_yaml="yaml"
    )

    deleted = await delete_semgrep_rule(
        async_db_session,
        "python.test.delete"
    )

    assert deleted is True

    rule = await get_semgrep_rule_by_id(
        async_db_session,
        "python.test.delete"
    )

    assert rule is None


@pytest.mark.asyncio
async def test_delete_nonexistent_rule(async_db_session):
    """존재하지 않는 룰 삭제 테스트"""
    deleted = await delete_semgrep_rule(
        async_db_session,
        "nonexistent.rule"
    )

    assert deleted is False


@pytest.mark.asyncio
async def test_delete_all_rules_by_language(async_db_session):
    """언어별 모든 룰 삭제 테스트"""
    # Python 룰 2개 생성
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test1",
        language="python",
        vulnerability_type="Test",
        rule_yaml="py1"
    )
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test2",
        language="python",
        vulnerability_type="Test",
        rule_yaml="py2"
    )

    # Java 룰 1개 생성
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="java.test1",
        language="java",
        vulnerability_type="Test",
        rule_yaml="java1"
    )

    deleted_count = await delete_all_rules_by_language(
        async_db_session,
        "python"
    )

    assert deleted_count == 2

    remaining_rules = await get_all_semgrep_rules(async_db_session)
    assert len(remaining_rules) == 1
    assert remaining_rules[0].language == "java"


# ==================== STATISTICS TESTS ====================

@pytest.mark.asyncio
async def test_get_rule_statistics(async_db_session):
    """룰 통계 조회 테스트"""
    # Python 룰 2개
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test1",
        language="python",
        vulnerability_type="Test",
        rule_yaml="py1"
    )
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="python.test2",
        language="python",
        vulnerability_type="Test",
        rule_yaml="py2"
    )

    # Java 룰 1개
    await create_semgrep_rule(
        db=async_db_session,
        rule_id="java.test1",
        language="java",
        vulnerability_type="Test",
        rule_yaml="java1"
    )

    stats = await get_rule_statistics(async_db_session)

    assert stats["total_rules"] == 3
    assert stats["by_language"]["python"] == 2
    assert stats["by_language"]["java"] == 1
