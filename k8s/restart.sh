#!/bin/bash
# Usage: ./restart.sh <sensor-service|frontend>
if [ $# -ne 1 ]; then
    echo "Usage: $0 <sensor-service|frontend>"
    exit 1
fi
kubectl -n irondome rollout restart deployment $1 && kubectl -n irondome get pods -l app=$1
