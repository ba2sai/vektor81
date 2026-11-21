# Hardened On-Premise Collector Dockerfile for Vektor81 v2
# Build context must be the repository root so packages/panama-pii-py is included:
#   docker build -f onprem-collector/Dockerfile -t vektor81-onprem-collector .
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALLOC_TRIM_THRESHOLD_=65536 \
    PYTHONPATH=/app:/app/packages/panama-pii-py

WORKDIR /app

# Native dependencies for WeasyPrint (Pango/Cairo/GDK-PixBuf) and Tesseract OCR (English + Spanish)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-dejavu-core \
    tesseract-ocr \
    tesseract-ocr-spa \
    && rm -rf /var/lib/apt/lists/*

COPY onprem-collector/requirements.txt ./requirements.txt
COPY onprem-collector/requirements-docker.txt ./requirements-docker.txt
RUN pip install --no-cache-dir -r requirements-docker.txt

# Download Spanish spaCy model for Presidio; pii_bridge degrades gracefully if unavailable
RUN python -m spacy download es_core_news_lg || true

# Install local Panama PII engine from repo root context
COPY packages/panama-pii-py /app/packages/panama-pii-py
RUN pip install --no-cache-dir --no-deps /app/packages/panama-pii-py

COPY onprem-collector/app /app/app

# Persistent directory for SQLite WAL storage and offline sync queue
RUN mkdir -p /app/data \
    && useradd --create-home --shell /usr/sbin/nologin vektor81 \
    && chown -R vektor81:vektor81 /app

USER vektor81

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
