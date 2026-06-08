#!/usr/bin/env bash
#
# availability.sh — demuestra continuidad de negocio bajo ataque (la demo más
# "boss-legible": la tienda se cae vs sigue vendiendo).
#
# Mientras llega tráfico legítimo constante (que muestreamos: latencia + status a
# lo largo del tiempo), a mitad de la corrida se dispara un ataque a un endpoint
# administrativo (/utility/panic por default: crashea el pod de UI, que sirve TODA
# la tienda). Se corre dos veces:
#   - SIN WAF: el ataque llega al backend -> la tienda cae (502/timeout) hasta que
#     Kubernetes reinicia el pod -> ventana de downtime visible.
#   - CON WAF: el ataque se corta en el borde (403) -> el tráfico legítimo sigue
#     plano. El WAF protege la DISPONIBILIDAD, no solo los datos.
#
# Escribe availability-off.csv / availability-on.csv (t_sec,latency_ms,http_code).
# Graficar con plot-availability.py. Restaura el WAF prendido al final.
#
# Uso:
#   ./availability.sh                      # ataque = panic (default)
#   ./availability.sh --attack stress      # ataque = burst de CPU-burn
#   DURATION=40 ATTACK_AT=12 ./availability.sh
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BASE="${WAF_TEST_URL:-http://localhost}"
NS=the-store

ATTACK=panic
[ "${1:-}" = "--attack" ] && ATTACK="${2:-panic}"

DURATION="${DURATION:-40}"     # segundos de muestreo por corrida
ATTACK_AT="${ATTACK_AT:-12}"   # segundo en que se dispara el ataque
INTERVAL="${INTERVAL:-0.3}"    # cadencia del sampler
PROBE="$BASE/catalog"          # página legítima (servida por UI)

fire_attack() {
  case "$ATTACK" in
    panic)  curl -s -o /dev/null --max-time 5 "$BASE/utility/panic" >/dev/null 2>&1 ;;
    stress) for _ in $(seq 1 8); do
              curl -s -o /dev/null --max-time 5 "$BASE/utility/stress/5000000" >/dev/null 2>&1 &
            done ;;
  esac
}

wait_waf() {  # on|off — exige 3 lecturas consecutivas (reload graceful de nginx)
  local expect; [ "$1" = on ] && expect=403 || expect=200
  local hits=0
  for _ in $(seq 1 40); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/info")" = "$expect" ]; then
      hits=$((hits+1)); [ "$hits" -ge 3 ] && return 0
    else hits=0; fi
    sleep 1
  done
}

wait_healthy() {  # espera a que la tienda vuelva a responder 200
  for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$PROBE")" = "200" ] && return 0
    sleep 2
  done
  echo "WARN: la tienda no volvió a 200 a tiempo" >&2
}

run_scenario() {  # $1 = csv file, $2 = etiqueta
  local csv="$1" label="$2"
  echo "t_sec,latency_ms,http_code" > "$csv"
  local t=0 fired=0 ok=0 fail=0
  echo "  [$label] muestreando ${DURATION}s, ataque ($ATTACK) en t=${ATTACK_AT}s..."
  while awk "BEGIN{exit !($t < $DURATION)}"; do
    local res code tt ms
    res=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" --max-time 4 "$PROBE" 2>/dev/null || echo "000 4")
    code="${res%% *}"; tt="${res##* }"
    ms=$(awk "BEGIN{printf \"%.0f\", $tt*1000}")
    echo "$t,$ms,$code" >> "$csv"
    [ "$code" = "200" ] && ok=$((ok+1)) || fail=$((fail+1))
    if [ "$fired" -eq 0 ] && awk "BEGIN{exit !($t >= $ATTACK_AT)}"; then
      fire_attack & fired=1
      echo "  [$label] >>> ataque disparado en t≈${t}s"
    fi
    t=$(awk "BEGIN{printf \"%.2f\", $t + $tt + $INTERVAL}")
    sleep "$INTERVAL"
  done
  local total=$((ok+fail))
  local avail
  avail=$(awk -v ok="$ok" -v total="$total" 'BEGIN{printf "%.1f", (total>0 ? 100.0*ok/total : 0)}')
  echo "  [$label] requests OK: $ok/$total  -> disponibilidad ${avail}%"
}

echo "=================================================================="
echo " Disponibilidad bajo ataque  (probe: $PROBE, ataque: $ATTACK)"
echo "=================================================================="

echo ""
echo "[1/2] SIN WAF"
"$ROOT/demo-scripts/turn-waf-off.sh" >/dev/null
wait_waf off
wait_healthy
run_scenario "$DIR/availability-off.csv" "sin WAF"

echo ""
echo "  Esperando que la tienda se recupere antes de la 2da corrida..."
kubectl -n "$NS" rollout status deploy/ui --timeout=120s >/dev/null 2>&1 || true
wait_healthy

echo ""
echo "[2/2] CON WAF"
"$ROOT/demo-scripts/turn-waf-on.sh" >/dev/null
wait_waf on
wait_healthy
run_scenario "$DIR/availability-on.csv" "con WAF"

echo ""
echo "Restaurando WAF prendido (default committeado)..."
"$ROOT/demo-scripts/turn-waf-on.sh" >/dev/null
wait_healthy
echo "Graficar: python3 $DIR/plot-availability.py"
