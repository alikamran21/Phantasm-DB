# ── Phantasm-DB Backend Dockerfile ───────────────────────────
# Python 3.11 slim — matches what Vercel uses for Python functions
FROM python:3.11-slim

# Keeps Python from buffering stdout/stderr (important for Docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install OS-level build deps needed by some Python packages (bcrypt, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer caching — only re-runs if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir flask python-dotenv gunicorn

# Copy application source
COPY app.py .
COPY api/ ./api/

# Expose Flask port
EXPOSE 5000

# Run with Gunicorn in production mode.
# --workers 1 because the async SQLAlchemy engines are per-process; scale via Docker replicas instead.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
