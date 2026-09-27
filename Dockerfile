FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    COOKIE_SECURE=1 \
    REQUIRE_PRIVILEGED_MFA=1 \
    IDLE_TIMEOUT_MINUTES=20 \
    LOGIN_FAILURE_LIMIT=5 \
    LOGIN_LOCKOUT_MINUTES=15 \
    AUDIT_RETENTION_YEARS=6
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr libzbar0 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()" || exit 1
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT} --workers ${WEB_CONCURRENCY:-2} --threads 4 --timeout 120"]
