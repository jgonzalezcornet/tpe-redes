#!/usr/bin/env bash
#
# demo-flip.sh — live walkthrough of CRS false-positive tuning (pre-entrega 3.4).
#
# Three acts, run against the local cluster (http://localhost):
#   1. PL1 (baseline): a legit search with math symbols passes.
#   2. PL2: the SAME search now 403s — a false positive introduced by raising
#      the paranoia level. Show the ModSecurity log (rule 932200 -> 949110).
#   3. Fix it two ways:
#        a) surgical rule exclusion  -> FP passes, SQLi/XSS still blocked.
#        b) raise anomaly threshold  -> FP passes too, but globally (blunt).
#   Restores the committed config at the end.
#
# Pauses between acts so you can narrate. Set AUTO=1 to run without pauses.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BASE="${WAF_TEST_URL:-http://localhost}"
FP_Q="1+2-3*4/5=6"          # benign: product/model code with math symbols
SQLI_Q="' OR 1=1--"
XSS_Q="<img src=x onerror=alert(1)>"

pause() { [ "${AUTO:-0}" = "1" ] || { read -rp $'\n[enter para continuar]\n' _; }; }
hit()   { curl -s -o /dev/null -w "%{http_code}" --max-time 10 --get --data-urlencode "q=$1" "$BASE/catalog/search"; }
show()  { printf "    %-38s -> HTTP %s\n" "q=$1" "$(hit "$1")"; }

echo "=================================================================="
echo " CRS false-positive tuning demo  (target: $BASE)"
echo "=================================================================="

echo ""
echo "ACTO 1 — Paranoia Level 1 (baseline). Búsqueda legítima con símbolos:"
"$DIR/set-crs.sh" --pl 1 >/dev/null
show "$FP_Q"
echo "  -> pasa (200): un cliente buscando un código de producto."
pause

echo ""
echo "ACTO 2 — Subimos a Paranoia Level 2. La MISMA búsqueda:"
"$DIR/set-crs.sh" --pl 2 >/dev/null
show "$FP_Q"
echo "  -> 403: FALSO POSITIVO. Lo dispara la regla CRS 932200 (RCE bypass)."
echo ""
echo "  Log de ModSecurity para esa request:"
hit "$FP_Q" >/dev/null; sleep 2
kubectl -n ingress-nginx logs deploy/ingress-nginx-controller --since=15s 2>/dev/null \
  | grep -i "ModSecurity: Access denied" | tail -1 \
  | grep -oE '\[id "[0-9]+"\] \[rev[^]]*\] \[msg "[^"]+"\]' || echo "    (revisar: kubectl -n ingress-nginx logs deploy/ingress-nginx-controller)"
pause

echo ""
echo "ACTO 3a — Fix correcto: exclusión quirúrgica (drop 932200 solo en ARGS:q):"
"$DIR/set-crs.sh" --pl 2 --exclude-fp >/dev/null
show "$FP_Q";  echo "      ^ el FP vuelve a pasar"
show "$SQLI_Q"; echo "      ^ SQLi SIGUE bloqueado"
show "$XSS_Q";  echo "      ^ XSS SIGUE bloqueado"
echo "  -> arreglamos el FP sin perder protección."
pause

echo ""
echo "ACTO 3b — Alternativa: subir el anomaly threshold 5 -> 20 (instrumento grueso):"
"$DIR/set-crs.sh" --pl 2 --threshold 20 >/dev/null
show "$FP_Q";  echo "      ^ pasa porque su score (10) < 20"
show "$SQLI_Q"; echo "      ^ ataque fuerte (score >> 20) sigue bloqueado"
echo "  -> funciona, pero es global: cualquier ataque que sume < 20 se filtraría."
pause

echo ""
echo "Restaurando el ConfigMap committeado (PL2 + exclusiones 932200/932236 + scanner en detección)..."
kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge --patch-file "$ROOT/dist/modsecurity-configmap.yaml" >/dev/null
echo "Listo."
