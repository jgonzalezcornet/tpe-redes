#!/usr/bin/env bash
#
# pl-detection-gap.sh — justifica empíricamente PL2 sobre PL1.
#
# Lanza un corpus de payloads ofuscados/exóticos (libinjection blind spots,
# operadores SQL, hex, XSS raros, RCE/LFI) y reporta los "flips": ataques que
# PL1 deja pasar (no-403) pero PL2 bloquea (403) — la ganancia de detección de
# subir a PL2. Después chequea frases benignas con palabras "gatillo"
# (like/and/or/&) para confirmar que PL2 no las convierte en falsos positivos.
# Restaura el ConfigMap committeado al final.
#
# Requiere el cluster local arriba. Resultado de referencia (2026-06-03):
#   11 flips (PL1 45/58 -> PL2 56/58 bloqueados), 0 FP sobre frases benignas.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
SET="$ROOT/demo-scripts/crs-tuning/set-crs.sh"
BASE="${WAF_TEST_URL:-http://localhost}"

# "tipo|payload"  (q = /catalog/search?q= , f = /catalog/image?file=)
PAYLOADS=(
  "q|1 AND 1=1"        "q|1 OR 1"            "q|1) OR (1=1"
  "q|1 AND substring(version(),1,1)=5"       "q|1 AND ascii(1)"
  "q|1 PROCEDURE ANALYSE(1,1)"               "q|1 INTO OUTFILE '/tmp/x'"
  "q|1;SELECT SLEEP(5)"                      "q|1 AND extractvalue(1,concat(0x7e,version()))"
  "q|1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)"
  "q|0x73716c696e6a656374696f6e"            "q|1 div 1"
  "q|/*!50000SELECT*/ 1"                     "q|1 union all select null,null"
  "q|@@version"        "q|char(83)+char(81)+char(76)"
  "q|1 like 1"         "q|1 rlike 1"         "q|1 regexp 1"        "q|1 sounds like 1"
  "q|1 between 1 and 2" "q|concat(0x3a,user(),0x3a)" "q|1 xor 1"   "q|1 && 1"
  "q|a';--"            "q|1' /*comment*/ OR /*x*/ '1'='1"         "q|1'#"
  "q|name';WAITFOR DELAY '0:0:5'--"
  "q|<a href=javascript:alert(1)>x</a>"      "q|<details open ontoggle=alert(1)>"
  "q|<marquee onstart=alert(1)>"             "q|<video><source onerror=alert(1)>"
  "q|<input autofocus onfocus=alert(1)>"     "q|<select autofocus onfocus=alert(1)>"
  "q|<svg><animate onbegin=alert(1)>"        "q|<x onclick=alert(1)>click</x>"
  "q|<img src=x:y onerror=eval(name)>"       "q|&#60;script&#62;alert(1)&#60;/script&#62;"
  "q|<scr<script>ipt>alert(1)</scr</script>ipt>" "q|<style>@import'http://x'</style>"
  "q|<isindex action=javascript:alert(1) type=submit>"
  "q|<form><button formaction=javascript:alert(1)>x"
  "q|';:--()[]{}|&\$#@!"                      "q|a=b;c=d;e=f;g=h"
  "q|; ls -la /"       "q|\`id\`"            "q|\$(whoami)"
  "q|\${IFS}cat\${IFS}/etc/passwd"           "q|x|| ping -c1 127.0.0.1"
  "q|x && curl http://x"
  "f|../../../../etc/passwd%00.jpg"          "f|php://filter/convert.base64-encode/resource=index"
  "f|file:///etc/passwd"                     "f|/proc/self/environ"
  "f|..\\..\\..\\windows\\win.ini"           "f|....//....//....//etc/shadow"
  "f|; cat /etc/passwd"                      "f|\$(id)"
)
BENIGN=(
  "shoes like nike" "sounds like teen spirit" "blue like jazz" "looks like new"
  "items similar to this" "phone like iphone" "and or but" "rock and roll"
  "salt & pepper" "tom & jerry mug"
)

hit(){ if [ "$1" = "q" ]; then
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 --get --data-urlencode "q=$2" "$BASE/catalog/search"
  else
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 --get --data-urlencode "file=$2" "$BASE/catalog/image"; fi; }
run_pl(){ "$SET" --pl "$1" >/dev/null 2>&1; for e in "${PAYLOADS[@]}"; do echo "$(hit "${e%%|*}" "${e#*|}")"; done; }

P1=($(run_pl 1)); P2=($(run_pl 2))

flips=0; b1=0; b2=0; i=0
echo "FLIPS — PL1 deja pasar, PL2 bloquea (ganancia de detección de PL2):"
echo "----------------------------------------------------------------"
for e in "${PAYLOADS[@]}"; do
  a="${P1[$i]}"; b="${P2[$i]}"
  [ "$a" = "403" ] && b1=$((b1+1)); [ "$b" = "403" ] && b2=$((b2+1))
  if [ "$a" != "403" ] && [ "$b" = "403" ]; then printf "  PL1=%-4s PL2=%-4s  %s\n" "$a" "$b" "${e#*|}"; flips=$((flips+1)); fi
  i=$((i+1))
done
[ "$flips" = "0" ] && echo "  (ninguno — PL2 no aportaría detección)"
echo "----------------------------------------------------------------"
printf "Bloqueados: PL1 %d/%d | PL2 %d/%d | FLIPS: %d\n" "$b1" "${#PAYLOADS[@]}" "$b2" "${#PAYLOADS[@]}" "$flips"

echo ""
echo "Frases benignas con palabras gatillo @ PL2 (403 = FP nuevo):"
"$SET" --pl 2 >/dev/null 2>&1; fp=0
for q in "${BENIGN[@]}"; do
  c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --get --data-urlencode "q=$q" "$BASE/catalog/search")
  [ "$c" = "403" ] && { printf "  FP: %s\n" "$q"; fp=$((fp+1)); }
done
[ "$fp" = "0" ] && echo "  (0 FP — PL2 no rompe lenguaje natural)"

echo ""
echo "Restaurando ConfigMap committeado..."
kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge --patch-file "$ROOT/dist/modsecurity-configmap.yaml" >/dev/null
echo "Listo."
