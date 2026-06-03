#!/usr/bin/env bash
#
# anomaly-scores.sh — mide el inbound anomaly score real de cada request a PL2.
#
# Truco: con threshold=1 la regla 949110 del CRS bloquea y loguea el "Total
# Score" de cualquier request que sume >=1, así que se puede leer el score
# acumulado de cada payload (los que suman 0 no disparan 949110 -> score 0).
#
# Escribe anomaly-scores.csv (label,score,payload). De ahí salen, por aritmética
# (bloqueado a threshold T  <=>  score >= T), tanto la distribución de scores
# como el tradeoff detección/FP vs threshold — ver plot-anomaly.py.
# Restaura el ConfigMap committeado al final.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
SET="$ROOT/demo-scripts/crs-tuning/set-crs.sh"
BASE="${WAF_TEST_URL:-http://localhost}"
CSV="$DIR/anomaly-scores.csv"

# "label|payload"  — label = attack | benign
CORPUS=(
  # benignos (deberian sumar poco)
  "benign|rock and roll"
  "benign|shoes like nike"
  "benign|ceramic blue mug"
  "benign|size: 10; color: red"
  "benign|salt & pepper"
  "benign|O'Reilly mug"
  "benign|user@example.com"
  "benign|1+2-3*4/5=6"          # FP realista (simbolos aritmeticos en busqueda)
  # ataques debiles (los que PL1 deja pasar y PL2 toma; suman ~poco)
  "attack|1 regexp 1"
  "attack|1 like 1"
  "attack|@@version"
  "attack|1 OR 1"
  "attack|0x73716c696e6a656374696f6e"
  # ataques fuertes (suman mucho: varias reglas)
  "attack|' OR 1=1--"
  "attack|' UNION SELECT password FROM users--"
  "attack|<img src=x onerror=alert(1)>"
  "attack|<script>alert(1)</script>"
  "attack|admin'--"
  "attack|1; DROP TABLE products--"
)

echo "Seteando PL2 + threshold=1 (para loguear todos los scores)..."
"$SET" --pl 2 --threshold 1 >/dev/null 2>&1

echo "label,score,payload" > "$CSV"
printf "%-7s %-6s %s\n" "label" "score" "payload"
echo "-------------------------------------------------------------"
for e in "${CORPUS[@]}"; do
  label="${e%%|*}"; p="${e#*|}"
  curl -s -o /dev/null --max-time 10 --get --data-urlencode "q=$p" "$BASE/catalog/search"
  sleep 1
  score=$(kubectl -n ingress-nginx logs deploy/ingress-nginx-controller --since=4s 2>/dev/null \
            | grep -oE "Total Score: [0-9]+" | tail -1 | grep -oE "[0-9]+$")
  score="${score:-0}"
  printf "%-7s %-6s %s\n" "$label" "$score" "$p"
  # escapar comas del payload para el CSV
  echo "$label,$score,\"${p//\"/\"\"}\"" >> "$CSV"
done

echo ""
echo "CSV: $CSV"
echo "Restaurando ConfigMap committeado..."
kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge --patch-file "$ROOT/dist/modsecurity-configmap.yaml" >/dev/null
echo "Listo. Graficar: python3 $DIR/plot-anomaly.py"
