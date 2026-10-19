FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

# RAG embedding model (worker/rag.py), baked in so retrieval works offline and
# survives container recreation. Sources and fallbacks: bake_embedding_model.py.
# Never fails the build.
ARG EMBED_MODEL_URL=https://github.com/adriyansyah-mf/ADSIEM/releases/download/embedding-model-v1/fastembed-bge-small-en-v1.5.tar.gz
ARG EMBED_MODEL_SHA256=c4f901a9d5f159fd7b79c8fd091817b7eff5cf72fa0ef9f38da4f1058c2d8473
ARG HF_ENDPOINT=
ENV FASTEMBED_CACHE_PATH=/opt/fastembed
COPY bake_embedding_model.py /tmp/
RUN python /tmp/bake_embedding_model.py /opt/fastembed; chmod -R a+rX /opt/fastembed

COPY worker/ ./worker/

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"

CMD ["python", "-m", "worker.main"]
