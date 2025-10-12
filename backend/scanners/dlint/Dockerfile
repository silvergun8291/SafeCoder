FROM python:3.11-slim

WORKDIR /scanner

RUN pip install --no-cache-dir \
    dlint==0.15.0 \
    flake8==7.1.1

COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/entrypoint.sh

RUN mkdir -p /results

ENTRYPOINT ["/scanner/entrypoint.sh"]
