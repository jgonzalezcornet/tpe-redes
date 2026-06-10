#!/usr/bin/env bash
#
# scanner-mode.sh — alterna la regla de scanner por User-Agent (id 4001) entre
# modo DETECCIÓN y modo BLOQUEO sobre el WAF en vivo, de forma reversible.
#
#   detect (default committeado): los User-Agent de scanner (sqlmap/nikto/nmap/
#           wpscan) PASAN al backend (200) pero quedan registrados en el audit
#           log. ctl:ruleEngine=DetectionOnly pone la transacción en detección,
#           lo que además neutraliza la regla de scanner del CRS (913100) y la
#           colisión de "nmap" con unix-shell.data en fase 2. Un UA es
#           trivialmente falsificable: el valor está en la visibilidad, no en el
#           bloqueo.
#   block:  los UA de scanner se rechazan con 403 (regla 4001 con deny).
#
# El estado committeado en dist/modsecurity-configmap.yaml ya es 'detect'; para
# volver al default también sirve waf-tests/demo/turn-waf-on.sh.
#
# Uso: ./scanner-mode.sh <detect|block>
set -euo pipefail

NS=ingress-nginx
BASE="${WAF_TEST_URL:-http://localhost}"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_ROOT="$( cd "$DIR/../.." >/dev/null 2>&1 && pwd )"
SRC="$REPO_ROOT/dist/modsecurity-configmap.yaml"

DETECT_ACTIONS='id:4001,phase:1,pass,log,auditlog,t:none,tag:scanner,msg:malicious_scanner_detected,ctl:ruleEngine=DetectionOnly'
BLOCK_ACTIONS='id:4001,phase:1,deny,status:403,log,tag:scanner,msg:malicious_scanner_detected'

mode="${1:-}"
patch_file="$(mktemp)"
case "$mode" in
  detect) cp "$SRC" "$patch_file"; want='id:4001,phase:1,pass' ;;
  block)  sed "s|\"$DETECT_ACTIONS\"|\"$BLOCK_ACTIONS\"|" "$SRC" > "$patch_file"; want='id:4001,phase:1,deny' ;;
  *) echo "Uso: $0 <detect|block>" >&2; rm -f "$patch_file"; exit 1 ;;
esac

echo "Aplicando modo scanner: $mode"
kubectl patch configmap ingress-nginx-controller -n "$NS" --type merge --patch-file "$patch_file" >/dev/null
rm -f "$patch_file"

# Esperar el reload in-process del ingress (sin downtime; ~6s).
for _ in $(seq 1 40); do
  if kubectl -n "$NS" exec deploy/ingress-nginx-controller -- \
       sh -c "grep -q '$want' /etc/nginx/nginx.conf" 2>/dev/null; then
    sleep 2; break
  fi
  sleep 2
done

# Verificación desde el cliente.
status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -A "sqlmap/1.7.2" "$BASE/" || echo 000)
echo "  sqlmap UA -> HTTP $status  (detect espera 200, block espera 403)"

# En modo detección, mostrar la evidencia en el audit log (el scanner pasa pero
# queda registrado: es la única señal, porque no hay 403).
if [ "$mode" = detect ]; then
  curl -s -o /dev/null -A "sqlmap/scanner-mode-probe" "$BASE/catalog/search?q=test" || true
  sleep 1
  echo "  Audit log (match registrado sin bloqueo):"
  kubectl -n "$NS" exec deploy/ingress-nginx-controller -- \
    sh -c 'cat $(find /var/log/audit -type f | sort | tail -1)' 2>/dev/null \
    | grep -o 'id "4001"\|msg "malicious_scanner_detected"' | sort -u | sed 's/^/    /' \
    || echo "    (no encontrado todavía; reintentar en unos segundos)"
fi
