# Dockerfile

# --- 1. Build Stage (종속성 설치) ---
FROM python:3.11-slim as builder

ENV PYTHONUNBUFFERED 1
ENV APP_HOME=/app
WORKDIR $APP_HOME

# requirements.txt 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# --- 2. Runtime Stage (최종 실행 환경) ---
FROM python:3.11-slim

ENV PYTHONUNBUFFERED 1
ENV APP_HOME=/app
ENV PORT 8000
ENV GUNICORN_WORKERS 4

WORKDIR $APP_HOME

# 빌드 스테이지에서 설치된 종속성 복사
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# 애플리케이션 코드 및 데이터 복사
COPY app ./app
COPY scripts ./scripts
# scripts/load_qdrant_vectors.py가 사용하는 데이터 파일 경로
COPY data/processed ./data/processed

# API 서비스 실행 명령어
# Gunicorn + Uvicorn Worker를 사용합니다.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "$GUNICORN_WORKERS", "--worker-class", "uvicorn.workers.UvicornWorker", "app.main:app"]