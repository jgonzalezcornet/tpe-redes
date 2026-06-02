#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge --patch-file "$REPO_ROOT/dist/modsecurity-configmap.yaml"
