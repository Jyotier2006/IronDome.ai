#!/bin/bash
# Usage: ./scale.sh frontend <replicas>
# The sensor stays at 1 replica: its detectors keep per-process streaming state, and
# multi-sensor sharding is not implemented yet (see docs/THROUGHPUT.md).
if [ $# -ne 2 ]; then
    echo "Usage: $0 frontend <replicas>"
    exit 1
fi
if [ "$1" == "sensor-service" ] && [ "$2" != "0" ] && [ "$2" != "1" ]; then
    echo "The sensor runs as a single replica (per-process streaming state)."
    exit 1
fi
kubectl -n irondome scale deployment $1 --replicas=$2 && kubectl -n irondome get pods -l app=$1
