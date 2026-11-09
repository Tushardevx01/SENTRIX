FROM python:3.12-slim

WORKDIR /app

# Install security libraries and curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-privileged security user
RUN useradd -u 10001 -m -s /bin/sh appuser && chown -R appuser:appuser /app
USER appuser

ENV PYTHONPATH="/app/services/scanner:/app"

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8001}/health || exit 1

CMD ["sh", "-c", "if [ -d services/scanner ]; then cd services/scanner; fi && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
