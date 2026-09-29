#!/bin/bash
# Show the state of the IronDome.ai deployment.
kubectl -n irondome get deployments,pods,services,networkpolicies,ingress
