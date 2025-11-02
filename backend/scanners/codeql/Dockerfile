FROM ubuntu:22.04

# 비대화형 설치
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /scanner

# 기본 패키지 + Java 17 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget \
        unzip \
        git \
        python3 \
        python3-pip \
        default-jdk \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 최신 CodeQL CLI 다운로드 (v2.22.4 - 2025년 8월 최신)
ENV CODEQL_HOME=/opt/codeql
ENV CODEQL_VERSION=v2.22.4

RUN mkdir -p ${CODEQL_HOME} && \
    wget -q https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip -O /tmp/codeql.zip && \
    unzip -q /tmp/codeql.zip -d ${CODEQL_HOME} && \
    rm /tmp/codeql.zip

# CodeQL 쿼리 라이브러리 다운로드
RUN git clone --depth 1 https://github.com/github/codeql ${CODEQL_HOME}/codeql-repo

# CodeQL을 PATH에 추가
ENV PATH="${CODEQL_HOME}/codeql:${PATH}"

# 쿼리 사전 컴파일 (선택사항 - 실행 속도 향상)
RUN codeql query compile --threads=0 \
    ${CODEQL_HOME}/codeql-repo/java/ql/src/codeql-suites/java-security-extended.qls && \
    codeql query compile --threads=0 \
    ${CODEQL_HOME}/codeql-repo/python/ql/src/codeql-suites/python-security-extended.qls

# entrypoint 스크립트 복사
COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/entrypoint.sh

# 결과 디렉터리 생성
RUN mkdir -p /results /tmp/codeql_db

# CodeQL 버전 확인 (빌드 로그용)
RUN codeql version

ENTRYPOINT ["/scanner/entrypoint.sh"]
