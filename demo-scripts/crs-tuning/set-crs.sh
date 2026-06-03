#!/usr/bin/env bash
#
# set-crs.sh — apply a CRS tuning variant to the live ingress-nginx WAF.
#
# Demonstrates pre-entrega 3.4: OWASP CRS paranoia level + anomaly-score
# threshold + rule exclusions, all driven from the ingress ConfigMap.
#
# Why this works: the ingress `modsecurity-snippet` is loaded BEFORE the CRS
# (nginx.conf: inline `modsecurity_rules` comes before the CRS
# `modsecurity_rules_file`), and the CRS init is set-if-unset
# (`SecRule &TX:blocking_paranoia_level "@eq 0" ... setvar:...=1`). So a
# `SecAction setvar:tx.blocking_paranoia_level=N` in our snippet wins.
#
# Usage:
#   ./set-crs.sh --pl <1-4> [--threshold <N>] [--exclude-fp]
#
#   --pl N         CRS blocking paranoia level (default 1)
#   --threshold N  inbound_anomaly_score_threshold (default CRS = 5)
#   --exclude-fp   add a scoped exclusion: drop rule 932200 for ARGS:q on
#                  /catalog/search (fixes the math-query false positive)
#
# Gotchas (learned the hard way):
#   * Use backslash line-continuation for SecRule operator+actions. Single-line
#     rules break the modsecurity_rules parser and crashloop the controller.
#   * Do NOT `kubectl rollout restart` the controller to apply changes: it has
#     one replica bound to hostPort 80 in kind, so a restart causes downtime.
#     Patching the ConfigMap reloads nginx in-process (~6s) with no downtime.
set -euo pipefail

NS=ingress-nginx
BASE="${WAF_TEST_URL:-http://localhost}"
PL=1
THRESHOLD=""
EXCLUDE_FP=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pl)         PL="$2"; shift 2 ;;
    --threshold)  THRESHOLD="$2"; shift 2 ;;
    --exclude-fp) EXCLUDE_FP=true; shift ;;
    -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

tmp=$(mktemp)

# Header + paranoia level (always). Literal heredoc: backslashes are literal.
cat > "$tmp" <<'YAML'
data:
  enable-modsecurity: "true"
  enable-owasp-modsecurity-crs: "true"
  modsecurity-snippet: |
    Include /etc/nginx/modsecurity/modsecurity.conf
    SecRuleEngine On
    SecAuditEngine RelevantOnly
    SecAuditLogParts ABIJDEFHZ

    SecAction \
        "id:900100,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=__PL__"
YAML

if [[ -n "$THRESHOLD" ]]; then
  cat >> "$tmp" <<'YAML'

    SecAction \
        "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=__THR__"
YAML
fi

if [[ "$EXCLUDE_FP" == true ]]; then
  cat >> "$tmp" <<'YAML'

    # FP tuning: drop ONLY rule 932200 for the search arg `q` — keeps SQLi/XSS
    # protection on the search box and keeps 932200 active everywhere else.
    SecRule REQUEST_URI "@beginsWith /catalog/search" \
        "id:900200,phase:1,pass,nolog,ctl:ruleRemoveTargetById=932200;ARGS:q"
YAML
fi

# The five custom rules from dist/modsecurity-configmap.yaml (always present).
cat >> "$tmp" <<'YAML'

    SecRule REQUEST_URI "@beginsWith /proxy/" \
        "id:1001,phase:1,deny,status:403,log,tag:IDOR,msg:IDOR_proxy_endpoint_blocked"

    SecRule REQUEST_URI "@beginsWith /utility/" \
        "id:2002,phase:1,deny,status:403,log,tag:admin_endpoint,msg:utility_endpoint_blocked,chain"
        SecRule REMOTE_ADDR "!@ipMatch 127.0.0.1"

    SecRule REQUEST_URI "@streq /info" \
        "id:1003,phase:1,deny,status:403,log,tag:info_endpoint,msg:info_endpoint_blocked"
    SecRule REQUEST_URI "@streq /topology" \
        "id:1004,phase:1,deny,status:403,log,tag:info_endpoint,msg:topology_endpoint_blocked"

    SecRule REQUEST_HEADERS:User-Agent "@rx (?i:(sqlmap|nikto|nmap|wpscan))" \
        "id:4001,phase:1,deny,status:403,log,tag:scanner,msg:malicious_scanner_detected"
YAML

sed -i.bak "s/__PL__/$PL/; s/__THR__/${THRESHOLD:-5}/" "$tmp" && rm -f "$tmp.bak"

echo "Applying: PL=$PL${THRESHOLD:+ threshold=$THRESHOLD}$([ "$EXCLUDE_FP" == true ] && echo ' +exclusion(932200/ARGS:q)')"
kubectl patch configmap ingress-nginx-controller -n "$NS" --type merge --patch-file "$tmp" >/dev/null
rm -f "$tmp"

# Wait for in-process reload (config test must pass for the marker to appear).
for _ in $(seq 1 40); do
  if kubectl -n "$NS" exec deploy/ingress-nginx-controller -- \
       sh -c "grep -q 'blocking_paranoia_level=$PL' /etc/nginx/nginx.conf" 2>/dev/null; then
    sleep 2
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/" 2>/dev/null)" != "000" ] && { echo "Reloaded."; exit 0; }
  fi
  sleep 2
done
echo "WARN: reload not confirmed (controller kept previous config — check 'kubectl -n $NS logs deploy/ingress-nginx-controller')" >&2
exit 1
