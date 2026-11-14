# Backend Dockerfile para Vektor81: Shadow AI & Ley 81 Audit Appliance
# Optimizado para < 250MB RAM en reposo y < 400MB durante compilación PDF con WeasyPrint
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALLOC_TRIM_THRESHOLD_=65536

WORKDIR /app

# Dependencias nativas mínimas requeridas por WeasyPrint (Pango, Cairo, GDK-PixBuf)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Directorio persistente para la base de datos SQLite
RUN mkdir -p /app/data

EXPOSE 8000

# 2 workers Uvicorn para soportar ingesta concurrente de GPO + escaneo SMB + compilación PDF en VM de 4-8GB RAM
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--limit-max-requests", "5000"]
