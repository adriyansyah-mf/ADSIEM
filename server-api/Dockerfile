FROM python:3.12-slim

WORKDIR /app

# Build context is the repo root (see Dockerfile.dockerignore) so the API can
# share the worker's Sigma and decoder engines instead of keeping copies.
COPY server-api/requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

COPY worker/worker/__init__.py worker/worker/sigma_engine.py worker/worker/decoder_engine.py ./worker/
COPY server-api/app/ ./app/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

RUN adduser --disabled-password --gecos "" appuser
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
