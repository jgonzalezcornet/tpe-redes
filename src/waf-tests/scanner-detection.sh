#!/bin/bash
# scanner-detection.sh — verifica que la regla 4001 esté en modo DETECCIÓN:
# cada User-Agent de scanner pasa (no se bloquea con 403) Y queda registrado en
# el audit log con id 4001. El gate (cases.sh) solo mira el status; esto confirma
# la otra mitad (que el match se registra). Requiere el cluster local (kubectl).
set -uo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
BASE="${WAF_TEST_URL:-http://localhost}"
NS=ingress-nginx
UAS=("sqlmap/1.7.2" "Nikto/2.5.0" "Nmap NSE" "WPScan v3.8")
TOTAL=0; OK=0

echo "Scanner detection (regla 4001, modo detección) — target: $BASE"
for ua in "${UAS[@]}"; do
    TOTAL=$((TOTAL + 1))
    marker="scandet${TOTAL}$$"
    status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -A "$ua" "$BASE/?m=$marker" 2>/dev/null || echo 000)
    sleep 1
    logged=$(kubectl -n "$NS" exec deploy/ingress-nginx-controller -- sh -c \
        "f=\$(grep -rl '$marker' /var/log/audit 2>/dev/null | head -1); if [ -n \"\$f\" ]; then grep -c 'id \"4001\"' \"\$f\"; else echo 0; fi" 2>/dev/null || echo 0)
    if [ "$status" != "403" ] && [ "${logged:-0}" -ge 1 ]; then
        printf "  ${GREEN}✓${NC} %-16s -> HTTP %s, registrado en audit log (id 4001)\n" "$ua" "$status"
        OK=$((OK + 1))
    else
        printf "  ${RED}✗${NC} %-16s -> HTTP %s, match en log=%s (se esperaba ≠403 + id 4001)\n" "$ua" "$status" "${logged:-0}"
    fi
done
echo ""
printf "Resultado: %d/%d scanners detectados y registrados sin bloqueo\n" "$OK" "$TOTAL"
[ "$OK" -eq "$TOTAL" ]
