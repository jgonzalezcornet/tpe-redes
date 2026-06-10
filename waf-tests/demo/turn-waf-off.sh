#!/usr/bin/env bash
set -euo pipefail

kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge -p '{"data":{"enable-modsecurity":"false"}}'
