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
    else
        if [ "$status" = "403" ]; then
            printf "  ${RED}✗ FP   ${NC}  %-40s (expected pass, got %s)\n" "$name" "$status"
            FALSE_POS=$((FALSE_POS + 1))
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
    local attacks=$((CORRECT + MISSED - 0))
    echo ""
    echo "======================================================"
    echo " Results"
    echo "======================================================"
    printf "  %-22s %d\n" "Total cases:"     "$TOTAL"
    printf "  %-22s %d\n" "Correct:"         "$CORRECT"
    printf "  %-22s %d\n" "Missed attacks:"  "$MISSED"
    printf "  %-22s %d\n" "False positives:" "$FALSE_POS"

    local pct=0
    [ $TOTAL -gt 0 ] && pct=$((CORRECT * 100 / TOTAL))
    printf "  %-22s %d/%d (%d%%)\n" "Accuracy:" "$CORRECT" "$TOTAL" "$pct"
    echo ""

    if [ $MISSED -eq 0 ] && [ $FALSE_POS -eq 0 ]; then
        printf "  ${GREEN}All cases handled as expected.${NC}\n\n"
        return 0
    else
        printf "  ${YELLOW}Some cases need attention.${NC}\n\n"
        return 1
    fi
}
