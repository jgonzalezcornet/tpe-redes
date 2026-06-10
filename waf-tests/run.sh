#!/bin/bash
# WAF test runner. Unifica attacks / happy-path / mixed / *-corpus en un solo
# entrypoint con flags. Sin flags corre el gate curado completo (happy + ataques).
# Los conjuntos de casos viven en cases.sh (gate del pre-entrega) y corpus.sh
# (corpus amplio, 100+); el runner compartido está en lib.sh.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR/lib.sh"
source "$DIR/cases.sh"
source "$DIR/corpus.sh"

usage() {
  cat <<'EOF'
Uso: run.sh [--attacks | --happy] [--corpus | --full]
  (sin flags)   casos curados (gate pre-entrega): happy + ataques
  --attacks     solo ataques            (deben dar 403)
  --happy       solo tráfico legítimo   (no debe dar 403)
  --corpus      corpus amplio (100+) en vez de los casos curados
  --full        ambos conjuntos: casos curados + corpus
Los flags de tráfico y de conjunto se combinan (p. ej. --attacks --corpus).
Target http://localhost por defecto; override con WAF_TEST_URL.
EOF
}

traffic=both    # both | attacks | happy
set_mode=cases  # cases | corpus | full

for arg in "$@"; do
  case "$arg" in
    --attacks) traffic=attacks ;;
    --happy)   traffic=happy ;;
    --corpus)  set_mode=corpus ;;
    --full)    set_mode=full ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Flag desconocido: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

case "$traffic" in
  both)    run_attacks=true;  run_happy=true  ;;
  attacks) run_attacks=true;  run_happy=false ;;
  happy)   run_attacks=false; run_happy=true  ;;
esac

print_header "WAF Tests — tráfico=$traffic, conjunto=$set_mode"

if [ "$run_happy" = true ]; then
  case "$set_mode" in
    cases)  happy_cases ;;
    corpus) happy_corpus ;;
    full)   happy_cases; happy_corpus ;;
  esac
fi

if [ "$run_attacks" = true ]; then
  case "$set_mode" in
    cases)  attack_cases ;;
    corpus) attack_corpus ;;
    full)   attack_cases; attack_corpus ;;
  esac
fi

print_stats
