#!/bin/bash
# Build the IronDome.ai images for a local cluster (Docker Desktop / kind / minikube).
set -e
cd "$(dirname "$0")/.."

docker build -f backend/sensor-service/Dockerfile -t irondome-sensor:latest .
docker build -t irondome-dashboard:latest ${VITE_SENSOR_URL:+--build-arg VITE_SENSOR_URL=$VITE_SENSOR_URL} frontend
docker build -f model_microservice/Dockerfile -t irondome-training:latest .
echo "Built irondome-sensor, irondome-dashboard and irondome-training."

# Docker Desktop's kind-based Kubernetes (and plain kind) run their nodes as containers
# with their own image store: copy the images into every node so imagePullPolicy: Never works.
if command -v kubectl >/dev/null 2>&1; then
  for node in $(kubectl get nodes -o name 2>/dev/null | sed 's#node/##'); do
    if docker exec "$node" ctr --version >/dev/null 2>&1; then
      for img in irondome-sensor:latest irondome-dashboard:latest; do
        echo "loading $img into node $node ..."
        docker save "$img" | docker exec -i "$node" ctr -n k8s.io images import --all-platforms - >/dev/null
      done
    fi
  done
fi
