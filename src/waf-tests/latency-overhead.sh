#!/usr/bin/env bash
#
# latency-overhead.sh — mide el costo de performance del WAF (pregunta del jefe:
# "¿esto me enlentece el sitio?"). Corre ApacheBench (ab) contra un endpoint
# legítimo con el WAF apagado y prendido, y compara latencia (p50/p95/p99/media)
# y throughput (req/s).
#
# El resultado esperado es que el overhead de inspección L7 sea chico (unos pocos
# ms), que es el argumento para el jefe: la protección no degrada la experiencia.
#
# Escribe latency-overhead.csv (scenario,p50,p95,p99,mean_ms,rps). Graficar con
# plot-latency.py. Restaura el WAF prendido (default committeado) al final.
#
# Uso:
#   ./latency-overhead.sh [endpoint] [requests] [concurrency]
#   ./latency-overhead.sh /catalog 3000 25          # default
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BASE="${WAF_TEST_URL:-http://localhost}"
CSV="$DIR/latency-overhead.csv"

ENDPOINT="${1:-/catalog}"
N="${2:-3000}"
C="${3:-25}"
URL="$BASE$ENDPOINT"

# ApacheBench en macOS falla contra `localhost` (resuelve a ::1 -> "Invalid
# argument"). Apuntamos a 127.0.0.1 y mandamos el Host original por header, que
# además es necesario porque el ingress rutea por Host.
AB_URL="${URL/localhost/127.0.0.1}"
HOST_HDR=$(printf '%s' "$BASE" | sed -E 's#https?://##; s#/.*##; s#:.*##')

command -v ab >/dev/null 2>&1 || { echo "ERROR: ApacheBench (ab) no está instalado." >&2; exit 1; }

# Espera a que el WAF quede en el estado deseado (on => /info da 403; off => 200).
# Exige 3 lecturas consecutivas: el reload graceful de nginx convive workers
# viejos y nuevos unos segundos, así que un solo acierto no garantiza el cambio.
wait_waf() {
  local want="$1"  # on | off
  local expect; [ "$want" = on ] && expect=403 || expect=200
  local hits=0
  for _ in $(seq 1 40); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/info" 2>/dev/null)" = "$expect" ]; then
      hits=$((hits+1)); [ "$hits" -ge 3 ] && return 0
    else hits=0; fi
    sleep 1
  done
  echo "WARN: el WAF no llegó al estado '$want' a tiempo" >&2
}

# Corre ab y devuelve "p50 p95 p99 mean_ms rps"
run_ab() {
  local out; out=$(ab -n "$N" -c "$C" -H "Host: $HOST_HDR" "$AB_URL" 2>/dev/null)
  local p50 p95 p99 mean rps
  p50=$(echo "$out"  | awk '/^  50%/{print $2}')
  p95=$(echo "$out"  | awk '/^  95%/{print $2}')
  p99=$(echo "$out"  | awk '/^  99%/{print $2}')
  mean=$(echo "$out" | awk '/Time per request:.*\(mean\)/{print $4; exit}')
  rps=$(echo "$out"  | awk '/Requests per second:/{print $4}')
  echo "${p50:-0} ${p95:-0} ${p99:-0} ${mean:-0} ${rps:-0}"
}

echo "=================================================================="
echo " Overhead de latencia del WAF  (target: $URL, n=$N, c=$C)"
echo "=================================================================="
echo "scenario,p50,p95,p99,mean_ms,rps" > "$CSV"

echo ""
echo "[warm-up]"
ab -n 500 -c 10 -H "Host: $HOST_HDR" "$AB_URL" >/dev/null 2>&1 || true

echo "[1/2] WAF OFF — midiendo baseline..."
"$ROOT/demo-scripts/turn-waf-off.sh" >/dev/null
wait_waf off
read -r o50 o95 o99 omean orps <<<"$(run_ab)"
echo "      p50=${o50}ms p95=${o95}ms p99=${o99}ms media=${omean}ms  ${orps} req/s"
echo "sin_waf,$o50,$o95,$o99,$omean,$orps" >> "$CSV"

echo "[2/2] WAF ON — midiendo con inspección L7..."
"$ROOT/demo-scripts/turn-waf-on.sh" >/dev/null
wait_waf on
read -r n50 n95 n99 nmean nrps <<<"$(run_ab)"
echo "      p50=${n50}ms p95=${n95}ms p99=${n99}ms media=${nmean}ms  ${nrps} req/s"
echo "con_waf,$n50,$n95,$n99,$nmean,$nrps" >> "$CSV"

dmean=$(awk -v a="$nmean" -v b="$omean" 'BEGIN{printf "%.2f", a-b}')
dp95=$(awk -v a="$n95" -v b="$o95" 'BEGIN{printf "%.1f", a-b}')
echo ""
echo "------------------------------------------------------------------"
printf " Overhead (media):  %s ms -> %s ms  (Δ %s ms)\n" "$omean" "$nmean" "$dmean"
printf " Overhead (p95):    %s ms -> %s ms  (Δ %s ms)\n" "$o95" "$n95" "$dp95"
echo "------------------------------------------------------------------"
echo "CSV: $CSV"
echo "Graficar: python3 $DIR/plot-latency.py"
