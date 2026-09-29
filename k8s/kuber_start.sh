#!/bin/bash
# Deploy IronDome.ai to the current cluster and open port-forwards (run ./build-images.sh first).
set -e
cd "$(dirname "$0")"

echo "Starting IronDome.ai on Kubernetes..."

if ! command -v kubectl &> /dev/null; then
    echo "kubectl not found. Install Docker Desktop with Kubernetes enabled (or kind / minikube)."
    exit 1
fi
if ! kubectl cluster-info &> /dev/null; then
    echo "No Kubernetes cluster reachable. Enable Kubernetes in Docker Desktop and try again."
    exit 1
fi
if ! docker image inspect irondome-sensor:latest &> /dev/null; then
    echo "Images not found. Run ./build-images.sh first."
    exit 1
fi

./deploy-k8s.sh

echo "Waiting for the sensor and dashboard to become ready..."
kubectl -n irondome wait --for=condition=available deployment --all --timeout=300s

pkill -f "kubectl -n irondome port-forward" || true
kubectl -n irondome port-forward svc/frontend 8080:80 >/dev/null 2>&1 &
kubectl -n irondome port-forward svc/sensor-service 3001:3001 >/dev/null 2>&1 &

echo ""
echo "IronDome.ai is up:"
echo "  Dashboard:                  http://localhost:8080"
echo "  Sensor API:                 http://localhost:3001/health"
echo "  Flow collector (UDP only):  <node-ip>:30055   e.g. python scripts/replay_capture.py captures/kill_chain.jsonl.gz --sensor 127.0.0.1:30055"
echo ""
echo "Stop the port-forwards: pkill -f 'kubectl -n irondome port-forward'"
