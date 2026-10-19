FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

# RAG embedding model (worker/rag.py), baked in so retrieval works offline and
# survives container recreation instead of downloading on first use
# Sources in order: HF_ENDPOINT (build arg), huggingface.co, hf-mirror.com —
# huggingface.co rate-limits (429) some server IPs. Never fails the build:
# without the model RAG retrieval is skipped and SOP search uses keywords.
ARG HF_ENDPOINT=
ENV FASTEMBED_CACHE_PATH=/opt/fastembed
RUN mkdir -p /opt/fastembed; \
    for ep in $HF_ENDPOINT https://huggingface.co https://hf-mirror.com; do \
      HF_ENDPOINT=$ep python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5', cache_dir='/opt/fastembed')" \
        && echo "embedding model from $ep" && break; \
      echo "embedding model: $ep failed"; \
    done; \
    chmod -R a+rX /opt/fastembed

COPY worker/ ./worker/

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"

CMD ["python", "-m", "worker.main"]
