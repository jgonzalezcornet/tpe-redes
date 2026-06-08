#!/bin/bash
# Shared test runner for WAF validation scripts.
# Each test case calls run_case with a name, expected outcome
# ("block" or "allow"), and the curl arguments for the request.
# Stats are printed at the end via print_stats.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL=0
CORRECT=0
MISSED=0
FALSE_POS=0
BACKEND_ERR=0

BASE="${WAF_TEST_URL:-http://localhost}"

run_case() {
    local name="$1"
    local expected="$2"
    shift 2

    TOTAL=$((TOTAL + 1))

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" 2>/dev/null || echo "000")

    if [ "$expected" = "block" ]; then
        if [ "$status" = "403" ]; then
            printf "  ${GREEN}✓ BLOCK${NC}  %-40s (HTTP %s)\n" "$name" "$status"
            CORRECT=$((CORRECT + 1))
        else
            printf "  ${RED}✗ MISS ${NC}  %-40s (expected 403, got %s)\n" "$name" "$status"
            MISSED=$((MISSED + 1))
        fi
    elif [ "$expected" = "detect" ]; then
        # Regla en modo detección (p. ej. el scanner UA 4001): el WAF registra el
        # match en el audit log pero NO bloquea (la transacción pasa al backend).
        # Ambos resultados cuentan como correctos según el modo del toggle
        # (demo-scripts/scanner-mode.sh): 403 = la regla está en bloqueo; ≠403 =
        # en detección. La evidencia de detección (entrada con id 4001 en el
        # audit log) la verifica demo-scripts/scanner-mode.sh.
        if [ "$status" = "403" ]; then
            printf "  ${BLUE}⊙ BLOCK ${NC} %-40s (regla en modo bloqueo, HTTP %s)\n" "$name" "$status"
        else
            printf "  ${BLUE}⊙ DETECT${NC} %-40s (no bloqueado; match en audit log, HTTP %s)\n" "$name" "$status"
        fi
        CORRECT=$((CORRECT + 1))
    else
        if [ "$status" = "403" ]; then
            printf "  ${RED}✗ FP   ${NC}  %-40s (expected pass, got %s)\n" "$name" "$status"
            FALSE_POS=$((FALSE_POS + 1))
        elif [ "$status" -ge 500 ] 2>/dev/null; then
            # No es un falso positivo del WAF (no lo bloqueó), pero la request
            # falló en el backend: se reporta aparte para no contarlo como pass limpio.
            printf "  ${YELLOW}⚠ PASS*${NC}  %-40s (sin bloqueo del WAF, pero backend %s)\n" "$name" "$status"
            CORRECT=$((CORRECT + 1))
            BACKEND_ERR=$((BACKEND_ERR + 1))
        else
            printf "  ${GREEN}✓ PASS ${NC}  %-40s (HTTP %s)\n" "$name" "$status"
            CORRECT=$((CORRECT + 1))
        fi
    fi
}

print_header() {
    echo ""
    echo "======================================================"
    echo " $1"
    echo " Target: $BASE"
    echo "======================================================"
    echo ""
}

print_section() {
    echo ""
    printf "${BLUE}-- %s --${NC}\n" "$1"
}

print_stats() {
    echo ""
    echo "======================================================"
    echo " Results"
    echo "======================================================"
    printf "  %-22s %d\n" "Total cases:"     "$TOTAL"
    printf "  %-22s %d\n" "Correct:"         "$CORRECT"
    printf "  %-22s %d\n" "Missed attacks:"  "$MISSED"
    printf "  %-22s %d\n" "False positives:" "$FALSE_POS"
    printf "  %-22s %d\n" "Backend errors (5xx):" "$BACKEND_ERR"

    local pct=0
    [ $TOTAL -gt 0 ] && pct=$((CORRECT * 100 / TOTAL))
    printf "  %-22s %d/%d (%d%%)\n" "Accuracy:" "$CORRECT" "$TOTAL" "$pct"
    echo ""

    if [ $MISSED -eq 0 ] && [ $FALSE_POS -eq 0 ]; then
        if [ $BACKEND_ERR -gt 0 ]; then
            # El WAF se comportó bien (sin falsos negativos ni positivos); el 5xx
            # es del backend (p.ej. la SQLi rompe búsquedas con apóstrofe). No
            # afecta el exit code, que mide la corrección del WAF.
            printf "  ${GREEN}WAF OK (sin falsos positivos ni negativos).${NC} ${YELLOW}%d request(s) pasaron el WAF pero el backend devolvió 5xx — ver arriba.${NC}\n\n" "$BACKEND_ERR"
        else
            printf "  ${GREEN}All cases handled as expected.${NC}\n\n"
        fi
        return 0
    else
        printf "  ${YELLOW}Some cases need attention.${NC}\n\n"
        return 1
    fi
}
