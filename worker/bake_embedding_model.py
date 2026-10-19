"""Put the RAG embedding model into the image (worker/Dockerfile, server-api/Dockerfile).

Sources, first that works:
1. EMBED_MODEL_URL — a fastembed cache tarball (the repo's embedding-model-v1
   release by default; GitHub stays reachable where HuggingFace does not:
   huggingface.co answers 429 to some server IPs, and hf-mirror.com sends
   those back to huggingface.co). Checked against EMBED_MODEL_SHA256.
2. HF_ENDPOINT, huggingface.co, hf-mirror.com.

Never fails the build: without the model, triage skips semantic retrieval and
searches fall back to keywords.

    python bake_embedding_model.py /opt/fastembed
"""
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import urllib.request

MODEL = "BAAI/bge-small-en-v1.5"


def loads(cache_dir: str) -> bool:
    try:
        from fastembed import TextEmbedding
        TextEmbedding(MODEL, cache_dir=cache_dir)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"embedding model: not loadable ({str(exc)[:120]})")
        return False


def from_tarball(url: str, sha256: str, cache_dir: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=300) as resp:
            data = resp.read()
    except Exception as exc:  # noqa: BLE001
        print(f"embedding model: {url} failed ({exc})")
        return False
    digest = hashlib.sha256(data).hexdigest()
    if sha256 and digest != sha256:
        print(f"embedding model: {url} checksum {digest} != {sha256}, ignored")
        return False
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(cache_dir, filter="data")
    return True


def from_hub(endpoint: str, cache_dir: str) -> bool:
    """A fresh process per endpoint: huggingface_hub reads HF_ENDPOINT once, at import."""
    code = f"from fastembed import TextEmbedding; TextEmbedding({MODEL!r}, cache_dir={cache_dir!r})"
    done = subprocess.run([sys.executable, "-c", code], env={**os.environ, "HF_ENDPOINT": endpoint},
                          capture_output=True, text=True, timeout=900)
    if done.returncode:
        print(f"embedding model: {endpoint} failed ({done.stderr.strip().splitlines()[-1:] or ['?']})")
    return done.returncode == 0


def main(cache_dir: str) -> None:
    os.makedirs(cache_dir, exist_ok=True)
    url = os.environ.get("EMBED_MODEL_URL", "").strip()
    if url and from_tarball(url, os.environ.get("EMBED_MODEL_SHA256", "").strip(), cache_dir) and loads(cache_dir):
        print(f"embedding model from {url}")
        return
    for endpoint in (os.environ.get("HF_ENDPOINT", "").strip(), "https://huggingface.co", "https://hf-mirror.com"):
        if endpoint and from_hub(endpoint, cache_dir):
            print(f"embedding model from {endpoint}")
            return
    print("WARNING: embedding model not in the image; RAG falls back to keyword search")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/opt/fastembed")
