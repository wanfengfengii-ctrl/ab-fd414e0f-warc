# WARC 1.1 audit service. Stdlib-only Python; no third-party packages needed.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy source and tests (the verify service needs them).
COPY app/ ./app/
COPY tests/ ./tests/
COPY verify.sh ./verify.sh
RUN chmod +x ./verify.sh

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import os,urllib.request;port=os.environ.get('PORT','8080');urllib.request.urlopen('http://127.0.0.1:%s/healthz' % port, timeout=2)" || exit 1

CMD ["python3", "-m", "app.server"]
