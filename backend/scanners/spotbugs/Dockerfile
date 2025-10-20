FROM eclipse-temurin:17-jdk-jammy

# SpotBugs와 Find-Sec-Bugs 버전
ENV SPOTBUGS_VERSION=4.8.6

WORKDIR /opt

# 필요 패키지 설치
RUN apt-get update && \
    apt-get install -y wget python3 python3-pip && \
    pip3 install --no-cache-dir defusedxml && \
    rm -rf /var/lib/apt/lists/*

# SpotBugs 다운로드 및 설치
RUN wget https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz && \
    tar -xzf spotbugs-${SPOTBUGS_VERSION}.tgz && \
    mv spotbugs-${SPOTBUGS_VERSION} spotbugs && \
    rm spotbugs-${SPOTBUGS_VERSION}.tgz && \
    chmod +x /opt/spotbugs/bin/spotbugs

# Find-Sec-Bugs 플러그인 다운로드 (정확한 URL 사용)
RUN mkdir -p /opt/spotbugs/plugin && \
    wget https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar \
    -O /opt/spotbugs/plugin/findsecbugs-plugin.jar

# entrypoint 스크립트 복사 및 실행 권한 부여
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/scan_and_convert.sh

# 환경 변수 설정
ENV PATH="/opt/spotbugs/bin:${PATH}"
ENV SPOTBUGS_HOME="/opt/spotbugs"

WORKDIR /work

# 기본 명령어
ENTRYPOINT ["/opt/entrypoint.sh"]
CMD ["/source", "/results/spotbugs_result.json"]
