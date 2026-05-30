FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps for spaCy (optional PII detection).
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install ".[pii]" && python -m spacy download en_core_web_lg

COPY llmguard/ llmguard/
RUN mkdir -p /app/logs

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://127.0.0.1:8000/health').raise_for_status()"

CMD ["uvicorn", "llmguard.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
