#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR/lib.sh"
source "$DIR/cases.sh"

print_header "WAF Tests — Mixed (full validation)"
happy_cases
attack_cases
print_stats
