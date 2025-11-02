FROM python:3.11-slim

WORKDIR /scanner

RUN pip install --no-cache-dir bandit==1.7.9

COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/entrypoint.sh

RUN mkdir -p /results

ENTRYPOINT ["/scanner/entrypoint.sh"]
