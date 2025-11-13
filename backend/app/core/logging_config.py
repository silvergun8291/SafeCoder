import logging.config
import sys

from app.core.config import get_settings

# Uvicorn 기본 포맷과 유사하게 맞추되, 레벨과 모듈 이름 추가
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)-8s %(name)-20s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": sys.stdout,
        },
    },
    "loggers": {
        # 애플리케이션 루트 로거
        "app": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        # Uvicorn, FastAPI 로거
        "uvicorn": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.error": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        # SQLAlchemy (쿼리 로깅이 필요하면 "INFO"로 변경)
        "sqlalchemy.engine": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
}


def setup_logging():
    """
    main.py의 lifespan에서 호출할 로깅 설정 함수
    """
    settings = get_settings()
    log_level = "DEBUG" if settings.APP_ENV == "development" else "INFO"

    LOGGING_CONFIG["loggers"]["app"]["level"] = log_level

    logging.config.dictConfig(LOGGING_CONFIG)
    logging.getLogger("app").info(f"로깅 시스템 초기화 완료 (Level: {log_level})")