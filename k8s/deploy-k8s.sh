#!/bin/bash
# Apply the IronDome.ai manifests (namespace "irondome").
set -e
cd "$(dirname "$0")"

kubectl apply -f namespace.yaml
kubectl apply -f sensor-service.yaml
kubectl apply -f network-policy.yaml
kubectl apply -f frontend.yaml
if [ "$1" == "--ingress" ]; then
  kubectl apply -f ingress.yaml
fi

echo "IronDome.ai deployed to namespace irondome."
