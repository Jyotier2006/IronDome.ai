# IronDome.ai passive sensor. Build from the repository root (it needs the shared
# irondome/ core and the trained models):
#   docker build -f backend/sensor-service/Dockerfile -t irondome-sensor .
#   docker run -p 3001:3001 -p 2055:2055/udp irondome-sensor
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY backend/sensor-service/requirements.txt backend/sensor-service/requirements.txt
RUN pip install --no-cache-dir -r backend/sensor-service/requirements.txt

COPY irondome/ irondome/
COPY model_microservice/models/ model_microservice/models/
COPY backend/sensor-service/ backend/sensor-service/

WORKDIR /app/backend/sensor-service
# the sensor writes nothing at runtime, so it runs unprivileged on a read-only root fs
USER 65534:65534
EXPOSE 3001/tcp 2055/udp
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3001/health', timeout=2)"
CMD ["python", "sensor_service.py"]
