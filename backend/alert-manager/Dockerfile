FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8003

CMD ["uvicorn", "incident_alert_dispatcher:app", "--host", "0.0.0.0", "--port", "8003"]