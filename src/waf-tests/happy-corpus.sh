#!/bin/bash
# Corpus amplio de tráfico legítimo (100+) -> tasa de falsos positivos del WAF.
# Ver corpus.sh. Para el gate 1-a-1 del pre-entrega usar happy-path.sh.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR/lib.sh"
source "$DIR/corpus.sh"

print_header "WAF Tests — Corpus legítimo (tasa de falsos positivos, 100+)"
happy_corpus
print_stats
