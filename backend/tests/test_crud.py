"""
Piranha Rule CRUD 테스트 (PostgreSQL)
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.db.crud import (
    create_piranha_rule,
    get_piranha_rule_by_name,
    get_all_piranha_rules,
    update_piranha_rule,
    delete_piranha_rule
)
from app.db.database import Base


# ==================== FIXTURES ====================

@pytest.fixture(scope="function")  # ⭐ session → function
async def async_db_engine():
    """PostgreSQL 테스트 엔진"""
    engine = create_async_engine(
        "postgresql+asyncpg://postgres:postgres@localhost:5432/safecoder_test",
        echo=False,
    )

    # 테이블 생성
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # 정리
    await engine.dispose()


@pytest.fixture
async def db(async_db_engine):
    """DB 세션"""
    async_session = async_sessionmaker(
        async_db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session
        await session.rollback()


# ==================== CREATE ====================

@pytest.mark.asyncio
async def test_create_rule(db):
    """Rule 생성"""
    rule = await create_piranha_rule(
        db=db,
        rule_name="test_rule",
        language="java",
        rule_code="Rule(...)",
        before_code="Statement stmt",
        after_code="PreparedStatement stmt",
        cwe="CWE-89"
    )

    assert rule.id is not None
    assert rule.rule_name == "test_rule"


@pytest.mark.asyncio
async def test_create_duplicate_rule(db):
    """중복 생성 시 에러"""
    await create_piranha_rule(
        db=db,
        rule_name="duplicate",
        language="java",
        rule_code="Rule(...)",
        before_code="old",
        after_code="new"
    )

    with pytest.raises(ValueError):
        await create_piranha_rule(
            db=db,
            rule_name="duplicate",
            language="python",
            rule_code="Rule(...)",
            before_code="old2",
            after_code="new2"
        )


# ==================== READ ====================

@pytest.mark.asyncio
async def test_read_rule(db):
    """Rule 조회"""
    await create_piranha_rule(
        db=db,
        rule_name="read_test",
        language="python",
        rule_code="Rule(...)",
        before_code="eval(x)",
        after_code="ast.literal_eval(x)"
    )

    rule = await get_piranha_rule_by_name(db, "read_test")

    assert rule is not None
    assert rule.rule_name == "read_test"


@pytest.mark.asyncio
async def test_read_all_rules(db):
    """모든 Rule 조회"""
    await create_piranha_rule(
        db=db,
        rule_name="rule_1",
        language="java",
        rule_code="Rule(...)",
        before_code="a",
        after_code="b"
    )

    await create_piranha_rule(
        db=db,
        rule_name="rule_2",
        language="python",
        rule_code="Rule(...)",
        before_code="c",
        after_code="d"
    )

    rules = await get_all_piranha_rules(db)
    assert len(rules) == 2


# ==================== UPDATE ====================

@pytest.mark.asyncio
async def test_update_rule(db):
    """Rule 업데이트"""
    await create_piranha_rule(
        db=db,
        rule_name="update_test",
        language="java",
        rule_code="old_code",
        before_code="before",
        after_code="after"
    )

    updated = await update_piranha_rule(
        db=db,
        rule_name="update_test",
        rule_code="new_code"
    )

    assert updated is not None
    assert updated.rule_code == "new_code"


# ==================== DELETE ====================

@pytest.mark.asyncio
async def test_delete_rule(db):
    """Rule 삭제"""
    await create_piranha_rule(
        db=db,
        rule_name="delete_test",
        language="java",
        rule_code="Rule(...)",
        before_code="before",
        after_code="after"
    )

    deleted = await delete_piranha_rule(db, "delete_test")
    assert deleted is True

    rule = await get_piranha_rule_by_name(db, "delete_test")
    assert rule is None
