#!/bin/bash
# Test cases derived from the pre-entrega document.
# attack_cases: requests that the WAF must block (403).
# happy_cases:  legitimate traffic that the WAF must let through.

attack_cases() {
    print_section "3.1 IDOR — internal proxy endpoints"
    run_case "IDOR /proxy/carts"        block "$BASE/proxy/carts/123"
    run_case "IDOR /proxy/orders"       block "$BASE/proxy/orders/123"

    print_section "3.2 Admin endpoints (DoS / arbitrary store / CPU burn)"
    run_case "DoS /utility/panic"       block "$BASE/utility/panic"
    run_case "DoS /utility/health/down" block "$BASE/utility/health/down"
    run_case "CPU /utility/stress"      block "$BASE/utility/stress/2000000"
    run_case "Arbitrary /utility/store" block -X POST -H "Content-Type: application/json" -d '{"a":"b"}' "$BASE/utility/store"

    print_section "3.3 Sensitive info exposure"
    run_case "Info /info"               block "$BASE/info"
    run_case "Topology /topology"       block "$BASE/topology"
    run_case "Leak /utility/headers"    block "$BASE/utility/headers"

    print_section "3.4.1 SQL Injection"
    run_case "SQLi tautology"           block "$BASE/catalog/search?q=' OR 1=1--"
    run_case "SQLi union select"        block "$BASE/catalog/search?q=' UNION SELECT password FROM users--"

    print_section "3.4.1 XSS"
    run_case "XSS img onerror"          block "$BASE/catalog/search?q=<img src=x onerror=alert(1)>"

    print_section "3.4.2 Path traversal"
    run_case "Traversal /etc/passwd"    block "$BASE/catalog/image?file=../../../../etc/passwd"
    run_case "Traversal /proc/self"     block "$BASE/catalog/image?file=../../../../proc/self/environ"

    print_section "3.4.3 Scanner User-Agent detection"
    run_case "Scanner sqlmap UA"        block -A "sqlmap/1.7" "$BASE/catalog/search?q=test"
    run_case "Scanner nikto UA"         block -A "Nikto/2.5"  "$BASE/catalog/search?q=test"
    run_case "Scanner nmap UA"          block -A "Nmap NSE"   "$BASE/"
    run_case "Scanner wpscan UA"        block -A "WPScan"     "$BASE/"
}

happy_cases() {
    print_section "Browsing — public pages"
    run_case "Home page"                allow "$BASE/"
    run_case "Catalog listing"          allow "$BASE/catalog"
    run_case "Product detail"           allow "$BASE/catalog/d27cf49f-b689-4a75-a249-d373e0330bb5"
    run_case "Cart page"                allow "$BASE/cart"
    run_case "Checkout page"            allow "$BASE/checkout"

    print_section "Legitimate search queries"
    run_case "Search single word"       allow "$BASE/catalog/search?q=quill"
    run_case "Search with space"        allow "$BASE/catalog/search?q=aqua+ace"
    run_case "Search numeric"           allow "$BASE/catalog/search?q=150"
    run_case "Search apostrophe"        allow "$BASE/catalog/search?q=john%27s"

    print_section "Legitimate image fetch"
    run_case "Image normal filename"    allow "$BASE/catalog/image?file=product.jpg"

    print_section "Browser User-Agents"
    run_case "Chrome UA"                allow -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" "$BASE/catalog"
    run_case "Firefox UA"               allow -A "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" "$BASE/catalog"
}
