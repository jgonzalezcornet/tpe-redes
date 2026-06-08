#!/usr/bin/env bash
#
# show-damage.sh — demo del DAÑO REAL que el WAF previene (para el jefe).
#
# Para cada vulnerabilidad muestra, lado a lado:
#   SIN WAF -> el dato que se filtra de verdad (contenido de /etc/passwd, el
#              catálogo entero por SQLi, los headers de sesión, el carrito de
#              otro cliente).
#   CON WAF -> 403: el atacante no obtiene nada.
#
# No es "200 vs 403": es "esto es lo que se llevarían vs no se llevan nada".
# Restaura el WAF prendido al final.
#
# Pausas entre actos para narrar. AUTO=1 corre sin pausas.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BASE="${WAF_TEST_URL:-http://localhost}"

pause() { [ "${AUTO:-0}" = "1" ] || { read -rp $'\n[enter para continuar]\n' _; }; }
code()  { curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$@"; }

waf() {  # waf off | on   (+ espera la recarga graceful de nginx)
  if [ "$1" = off ]; then "$ROOT/demo-scripts/turn-waf-off.sh" >/dev/null
  else "$ROOT/demo-scripts/turn-waf-on.sh" >/dev/null; fi
  local expect; [ "$1" = on ] && expect=403 || expect=200
  # Exigir 3 lecturas consecutivas del estado esperado: durante el reload
  # conviven workers viejos y nuevos y un solo acierto no garantiza el cambio.
  local hits=0
  for _ in $(seq 1 40); do
    if [ "$(code "$BASE/info")" = "$expect" ]; then hits=$((hits+1)); [ "$hits" -ge 3 ] && return 0
    else hits=0; fi
    sleep 1
  done
}

hr() { printf '%s\n' "------------------------------------------------------------------"; }

echo "=================================================================="
echo " EL DAÑO QUE EL WAF PREVIENE   (target: $BASE)"
echo "=================================================================="

# ---------------------------------------------------------------------------
echo ""; echo "### 1. PATH TRAVERSAL — leer archivos del servidor"
echo "    GET /catalog/image?file=../../../../etc/passwd"
waf off
echo ""; echo "  SIN WAF — el servidor devuelve el archivo del sistema:"; hr
curl -s --max-time 8 "$BASE/catalog/image?file=../../../../etc/passwd" | head -n 6 | sed 's/^/    /'
echo "    ..."; hr
waf on
echo ""; printf "  CON WAF — el ataque se corta en el borde:  HTTP %s\n" "$(code "$BASE/catalog/image?file=../../../../etc/passwd")"
pause

# ---------------------------------------------------------------------------
echo ""; echo "### 2. SQL INJECTION — vaciar la base de datos"
echo "    GET /catalog/search?q=' OR 1=1--"
waf off
norm=$(curl -s --max-time 8 --get --data-urlencode "q=quill" "$BASE/catalog/search" | jq '.products | length' 2>/dev/null)
inj=$(curl -s --max-time 8 --get --data-urlencode "q=' OR 1=1--" "$BASE/catalog/search" | jq '.products | length' 2>/dev/null)
echo ""; echo "  SIN WAF:"; hr
printf "    búsqueda normal (q=quill):     %s producto(s)\n" "${norm:-?}"
printf "    inyección (q=' OR 1=1--):      %s producto(s)  <- el catálogo ENTERO\n" "${inj:-?}"
hr
waf on
echo ""; printf "  CON WAF — la inyección se bloquea:  HTTP %s\n" "$(code --get --data-urlencode "q=' OR 1=1--" "$BASE/catalog/search")"
pause

# ---------------------------------------------------------------------------
echo ""; echo "### 3. FUGA DE DATOS DE SESIÓN — /utility/headers"
echo "    GET /utility/headers  (expone X-Session-ID, X-Real-IP, X-Forwarded-*)"
waf off
echo ""; echo "  SIN WAF — headers internos y de sesión:"; hr
curl -s --max-time 8 "$BASE/utility/headers" \
  | jq '{"X-Session-ID":.["X-Session-ID"],"X-Real-IP":.["X-Real-IP"],"X-Request-ID":.["X-Request-ID"]}' 2>/dev/null \
  | sed 's/^/    /' || curl -s --max-time 8 "$BASE/utility/headers" | head -c 300 | sed 's/^/    /'
hr
waf on
echo ""; printf "  CON WAF:  HTTP %s\n" "$(code "$BASE/utility/headers")"
pause

# ---------------------------------------------------------------------------
echo ""; echo "### 4. IDOR — endpoint interno expuesto (/proxy/carts/{id})"
echo "    GET /proxy/carts/123  — el carrito de CUALQUIER cliente, sin auth"
waf off
echo ""; echo "  SIN WAF — el endpoint interno responde a quien sea:"; hr
curl -s --max-time 8 "$BASE/proxy/carts/123" | sed 's/^/    /'
echo "    (se puede enumerar el carrito de cualquier customerId manipulando la URL)"; hr
waf on
echo ""; printf "  CON WAF — el endpoint interno no es accesible desde afuera:  HTTP %s\n" "$(code "$BASE/proxy/carts/123")"
pause

# ---------------------------------------------------------------------------
echo ""; echo "### 5. DISPONIBILIDAD — endpoint destructivo (/utility/panic)"
echo "    Sin WAF, una sola request crashea el pod de UI y tira la tienda."
echo "    (Para verlo medido, correr: src/waf-tests/availability.sh)"
echo ""; printf "  CON WAF, el ataque ni llega a la app:  /utility/panic -> HTTP %s\n" "$(code "$BASE/utility/panic")"

echo ""
echo "Restaurando el WAF prendido (default committeado)..."
waf on
echo "Listo."
