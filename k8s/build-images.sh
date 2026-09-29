#!/bin/bash
# Build the IronDome.ai images for a local cluster (Docker Desktop / kind / minikube).
set -e
cd "$(dirname "$0")/.."

docker build -f backend/sensor-service/Dockerfile -t irondome-sensor:latest .
docker build -t irondome-dashboard:latest ${VITE_SENSOR_URL:+--build-arg VITE_SENSOR_URL=$VITE_SENSOR_URL} frontend
docker build -f model_microservice/Dockerfile -t irondome-training:latest .

echo "Built irondome-sensor, irondome-dashboard and irondome-training."
