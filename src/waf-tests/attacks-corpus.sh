#!/bin/bash
# Corpus amplio de ataques (100+) -> tasa de detección del WAF.
# Ver corpus.sh. Para el gate 1-a-1 del pre-entrega usar attacks.sh.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR/lib.sh"
source "$DIR/corpus.sh"

print_header "WAF Tests — Corpus de ataques (tasa de detección, 100+)"
attack_corpus
print_stats
