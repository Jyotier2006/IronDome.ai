#!/bin/bash
# Apply the IronDome.ai manifests (namespace "irondome").
#   ./deploy-k8s.sh             sensor + dashboard + egress-deny policy
#   ./deploy-k8s.sh --ingress   also the irondome.local ingress
set -e
cd "$(dirname "$0")"

kubectl apply -f namespace.yaml

# signing key for the tamper-evident alert archive (created once, kept across redeploys)
if ! kubectl -n irondome get secret irondome-archive >/dev/null 2>&1; then
  KEY=$(python -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
  kubectl -n irondome create secret generic irondome-archive --from-literal=signing-key="$KEY"
  echo "created archive signing key (secret irondome-archive) - back it up to verify the archive later"
fi

kubectl apply -f sensor-service.yaml
kubectl apply -f network-policy.yaml
kubectl apply -f frontend.yaml
if [ "$1" == "--ingress" ]; then
  kubectl apply -f ingress.yaml
fi

echo "IronDome.ai deployed to namespace irondome."
