FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002

CMD ["uvicorn", "anomaly_detection_orchestrator:app", "--host", "0.0.0.0", "--port", "8002"]