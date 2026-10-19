FROM python:3.12-slim

WORKDIR /app

# Build context is the repo root (see Dockerfile.dockerignore) so the API can
# share the worker's Sigma and decoder engines instead of keeping copies.
COPY server-api/requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

# Embedding model for semantic SOP search (app/services/embeddings.py), same
# one the worker indexes with; baked in so search works offline
# Same sources and fallback as worker/Dockerfile (worker/bake_embedding_model.py);
# never fails the build.
ARG EMBED_MODEL_URL=https://github.com/adriyansyah-mf/ADSIEM/releases/download/embedding-model-v1/fastembed-bge-small-en-v1.5.tar.gz
ARG EMBED_MODEL_SHA256=c4f901a9d5f159fd7b79c8fd091817b7eff5cf72fa0ef9f38da4f1058c2d8473
ARG HF_ENDPOINT=
ENV FASTEMBED_CACHE_PATH=/opt/fastembed
COPY worker/bake_embedding_model.py /tmp/
RUN python /tmp/bake_embedding_model.py /opt/fastembed; chmod -R a+rX /opt/fastembed

COPY worker/worker/__init__.py worker/worker/sigma_engine.py worker/worker/sigma_logsource.py worker/worker/decoder_engine.py worker/worker/agent_health.py worker/worker/knowledge_query.py ./worker/
COPY server-api/app/ ./app/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

RUN adduser --disabled-password --gecos "" appuser
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
