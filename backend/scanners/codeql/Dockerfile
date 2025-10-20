FROM mcr.microsoft.com/cstsectools/codeql-container:latest

# root 권한으로 전환
USER root

WORKDIR /scanner

# Python 설치
RUN apt-get update && \
    apt-get install -y python3 && \
    rm -rf /var/lib/apt/lists/*

# entrypoint 스크립트 복사
COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/entrypoint.sh

# 디렉터리 생성
RUN mkdir -p /results /tmp/codeql_db

# CodeQL 사용자로 다시 전환 (선택사항, 보안 강화)
# USER codeql

ENTRYPOINT ["/scanner/entrypoint.sh"]
