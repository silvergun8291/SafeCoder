FROM horuszup/horusec-cli:latest

WORKDIR /scanner

# Python 설치
RUN apk add --no-cache python3

COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/scan_and_convert.sh

RUN mkdir -p /results

ENTRYPOINT ["/scanner/entrypoint.sh"]
