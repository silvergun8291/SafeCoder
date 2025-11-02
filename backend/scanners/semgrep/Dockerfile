FROM returntocorp/semgrep:latest

WORKDIR /scanner

# wrapper 스크립트 복사
COPY scan_and_convert.sh /scanner/scan_and_convert.sh
RUN chmod +x /scanner/scan_and_convert.sh

# 결과 디렉터리 생성
RUN mkdir -p /results
