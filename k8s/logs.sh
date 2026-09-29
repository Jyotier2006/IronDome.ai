#!/bin/bash
# Usage: ./logs.sh <sensor-service|frontend> [lines]
if [ $# -lt 1 ]; then
    echo "Usage: $0 <sensor-service|frontend> [lines]"
    exit 1
fi
kubectl -n irondome logs deployment/$1 --tail=${2:-50}
