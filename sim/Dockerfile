FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

COPY scenarios.py scenario_gen.py main.py ./

CMD ["python", "-u", "main.py"]
