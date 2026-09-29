#!/bin/bash
# Stop port-forwards and scale IronDome.ai down to zero (./kuber_start.sh brings it back).
pkill -f "kubectl -n irondome port-forward" || echo "No port-forwards running"
kubectl -n irondome scale deployment --all --replicas=0
echo "IronDome.ai scaled down. Remove it completely with ./cleanup.sh"
