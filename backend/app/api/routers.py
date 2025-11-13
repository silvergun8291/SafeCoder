from fastapi import APIRouter

from app.api.routes import health, scan, rag, pipeline, quality, patch

api_router = APIRouter()

# 헬스 체스트 라우터
api_router.include_router(
    health.router,
    prefix="/health",  # ⬅️ /api/health/shallow, /api/health/deep
    tags=["Health"]
)

# 스캔 라우터
api_router.include_router(
    scan.router,
    prefix="",  # ⬅️ /api/secure-coding
    tags=["Secure Coding"]
)

# LLM (scan + prompt + ask) 라우터
api_router.include_router(
    rag.router,
    prefix="",  # ⬅️ /api/secure-coding/llm-*
    tags=["LLM"]
)

# One-shot Pipeline (Scan → LLM → Semgrep Rule)
api_router.include_router(
    pipeline.router,
    prefix="",  # ⬅️ /api/secure-coding/pipeline/*
    tags=["Pipeline"]
)

# LLM Prompt Strategy Quality Comparison
api_router.include_router(
    quality.router,
    prefix="",  # ⬅️ /api/secure-coding/llm-quality/*
    tags=["Quality"]
)

# Semgrep-related routes have been deprecated and moved to legacy; not registered.

# Patch pipeline (LLM → AST → Rescan → Diff → Patch)
api_router.include_router(
    patch.router,
    prefix="",  # ⬅️ /api/secure-coding/patch
    tags=["Patch"]
)