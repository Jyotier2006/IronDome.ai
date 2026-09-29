# IronDome.ai model training + evaluation job. Build from the repository root:
#   docker build -f model_microservice/Dockerfile -t irondome-training .
#   docker run --rm -v "$PWD/model_microservice/models:/app/model_microservice/models" \
#              -v "$PWD/docs:/app/docs" irondome-training
# Override the command to evaluate instead:  ... irondome-training python evaluate_pipeline.py
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY model_microservice/requirements.txt model_microservice/requirements.txt
RUN pip install --no-cache-dir -r model_microservice/requirements.txt

COPY irondome/ irondome/
COPY model_microservice/ model_microservice/
COPY backend/sensor-service/intel/ backend/sensor-service/intel/

WORKDIR /app/model_microservice
CMD ["python", "model_training_pipeline.py"]
