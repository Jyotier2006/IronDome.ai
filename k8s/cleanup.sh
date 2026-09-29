#!/bin/bash
# Remove everything IronDome.ai created (the whole "irondome" namespace).
pkill -f "kubectl -n irondome port-forward" || true
kubectl delete namespace irondome --ignore-not-found
echo "IronDome.ai removed. Redeploy with ./kuber_start.sh"
