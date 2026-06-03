#!/usr/bin/env bash
#
# paranoia-sweep.sh — measure the CRS detection-vs-false-positive tradeoff
# across paranoia levels 1..4 (pre-entrega 3.4 false-positive analysis).
#
# For each PL it runs an attack corpus (should be blocked) and a benign "edge"
# corpus (should pass), and reports how many of each got a 403. Writes a CSV
# (paranoia-sweep.csv) for plotting and restores the committed config at the end.
#
# Requires the local cluster up (./local.sh create-cluster). Tuning is applied
# in-process via the ConfigMap — see demo-scripts/crs-tuning/set-crs.sh for the
# mechanism and gotchas.
set -u
NS=ingress-nginx
BASE="${WAF_TEST_URL:-http://localhost}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
CSV="$DIR/paranoia-sweep.csv"

# Attacks the WAF must block.
declare -a ATTACKS=(
  "' OR 1=1--"
  "' UNION SELECT password FROM users--"
  "<img src=x onerror=alert(1)>"
  "<script>alert(1)</script>"
  "1; DROP TABLE products--"
  "admin'--"
)
# Benign "edge" queries a real shopper might type — must pass.
declare -a BENIGN=(
  "ceramic blue mug"
  "AT&T"
  "cup & saucer"
  "size: 10; color: red"
  "50% off (buy 1+1)"
  "1+2-3*4/5=6"
  "O'Reilly mug"
  "user@example.com"
  "rock & roll"
  "best-seller 2024"
)

apply_pl() { "$ROOT/demo-scripts/crs-tuning/set-crs.sh" --pl "$1" >/dev/null 2>&1; }
code() { curl -s -o /dev/null -w "%{http_code}" --max-time 10 --get --data-urlencode "q=$1" "$BASE/catalog/search"; }

echo "pl,attacks_total,attacks_blocked,benign_total,benign_blocked_fp" > "$CSV"
printf "%-4s | %-20s | %-20s\n" "PL" "Attacks blocked" "Benign blocked (FP)"
echo "-----+----------------------+----------------------"
for pl in 1 2 3 4; do
  apply_pl "$pl"
  ab=0; for a in "${ATTACKS[@]}"; do [ "$(code "$a")" = "403" ] && ab=$((ab+1)); done
  fp=0; for b in "${BENIGN[@]}"; do [ "$(code "$b")" = "403" ] && fp=$((fp+1)); done
  printf "%-4s | %-2d / %-15d | %-2d / %-15d\n" "$pl" "$ab" "${#ATTACKS[@]}" "$fp" "${#BENIGN[@]}"
  echo "$pl,${#ATTACKS[@]},$ab,${#BENIGN[@]},$fp" >> "$CSV"
done

echo ""
echo "CSV escrito en: $CSV"
echo "Restaurando ConfigMap committeado..."
kubectl patch configmap ingress-nginx-controller -n "$NS" \
  --type merge --patch-file "$ROOT/dist/modsecurity-configmap.yaml" >/dev/null
echo "Listo. Graficar con: python3 $DIR/plot-paranoia.py"
