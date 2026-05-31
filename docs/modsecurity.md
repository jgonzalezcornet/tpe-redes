# Integración de ModSecurity en The Store

Roadmap completo de la integración de ModSecurity como WAF sobre el ingress de nginx en el cluster local de Kind.

---

## Contexto inicial

- El ingress en uso es el oficial [`kubernetes/ingress-nginx`](https://github.com/kubernetes/ingress-nginx) v1.13.1, instalado desde `local.sh` con el manifiesto `provider/kind/deploy.yaml`.
- Hay un único `Ingress` (`ui`) definido en `dist/kubernetes.yaml`, sin anotaciones de WAF.
- La imagen del controller de `ingress-nginx` **ya viene con el módulo ModSecurity y el OWASP Core Rule Set (CRS) compilados**. No hace falta cambiar imagen ni agregar sidecars: alcanza con habilitarlo por configuración.

## Decisiones de diseño

1. **Modo de arranque: `DetectionOnly`, luego `On`.** Se arrancó en `DetectionOnly` (ModSecurity loguea las reglas que matchean pero no bloquea) para observar el comportamiento del WAF contra los tests e2e y el load generator. Validado eso, se pasó a `SecRuleEngine On` (modo blocking) — estado actual del ConfigMap. Ver [Fase 2 + 3](#fase-2--3--modo-blocking--reglas-custom-restantes).
2. **Alcance: global vía ConfigMap del controller.** Como hay un único Ingress en el proyecto, configurar globalmente es más simple que anotación por anotación. Si en el futuro hace falta WAF diferenciado por servicio, se puede mover a annotations.
3. **Formato: manifiesto separado + patch.** Mantenemos la config de ModSecurity en `dist/modsecurity-configmap.yaml` (separado del `dist/kubernetes.yaml` de la app) y la aplicamos con `kubectl patch --type merge`, no con `kubectl apply`. Razón: el ConfigMap `ingress-nginx-controller` lo crea upstream con labels y keys propias (`allow-snippet-annotations`), y un `apply` con un manifiesto parcial las borraría. El merge patch sólo toca las keys que nos interesan.

---

## Fase 1 — Habilitar ModSecurity + CRS en modo Detect

### Cambios

#### 1. Nuevo archivo: `dist/modsecurity-configmap.yaml`

> El snippet de abajo es el estado **inicial** de Fase 1 (`DetectionOnly` + reglas 1001/2002). El contenido actual del archivo —modo `On` y las reglas 1003/1004/4001 agregadas— está en [Fase 2 + 3](#fase-2--3--modo-blocking--reglas-custom-restantes).

Merge patch que agrega tres keys al ConfigMap del ingress controller:

```yaml
data:
  enable-modsecurity: "true"
  enable-owasp-modsecurity-crs: "true"
  modsecurity-snippet: |
    Include /etc/nginx/modsecurity/modsecurity.conf
    SecRuleEngine DetectionOnly
    SecAuditEngine RelevantOnly
    SecAuditLogParts ABIJDEFHZ

    # 3.1 IDOR — block external access to internal /proxy/* endpoints
    SecRule REQUEST_URI "@beginsWith /proxy/" \
        "id:1001,phase:1,deny,status:403,log,tag:IDOR,msg:IDOR_proxy_endpoint_blocked"

    # 3.2 Admin endpoints — block /utility/* unless source IP is in the allowlist
    SecRule REQUEST_URI "@beginsWith /utility/" \
        "id:2002,phase:1,deny,status:403,log,tag:admin_endpoint,msg:utility_endpoint_blocked,chain"
        SecRule REMOTE_ADDR "!@ipMatch 127.0.0.1"
```

Qué hace cada key:

| Key | Efecto |
|-----|--------|
| `enable-modsecurity: "true"` | Carga el módulo ModSecurity en nginx. |
| `enable-owasp-modsecurity-crs: "true"` | Activa el OWASP CRS que viene bundleado en la imagen del controller. |
| `modsecurity-snippet` | Bloque de directivas que se inyecta en la config principal de ModSecurity. |

Directivas del snippet:

| Directiva | Efecto |
|-----------|--------|
| `Include /etc/nginx/modsecurity/modsecurity.conf` | Carga la configuración base de ModSecurity (`SecRequestBodyAccess`, defaults, etc.). **Necesario**: cuando definimos `modsecurity-snippet` reemplazamos el snippet default del controller, que incluía este archivo. Sin este Include, ModSecurity carga el módulo y las reglas pero no inspecciona los requests. |
| `SecRuleEngine DetectionOnly` | Evalúa reglas y registra matches en el audit log pero no bloquea. |
| `SecAuditEngine RelevantOnly` | Audita sólo requests que disparan reglas relevantes (filtra por `SecAuditLogRelevantStatus`, que por default matchea 4xx/5xx excepto 404). |
| `SecAuditLogParts ABIJDEFHZ` | Qué partes del request/response incluir en el audit log (headers, body, info de matching, etc.). |

Regla custom **id:1001** (mitigación 3.1 IDOR del pre-entrega): bloquea cualquier request cuyo `REQUEST_URI` empiece con `/proxy/` — endpoints internos (`/proxy/carts/{id}`, `/proxy/orders/{id}`) que la UI usa para hablar con cart/orders y que no deberían ser accesibles desde afuera. Es *virtual patching*: la vulnerabilidad real es de autorización en la aplicación, pero el WAF reduce la superficie cerrando el endpoint en el borde.

Regla custom **id:2002** (mitigación 3.2 Admin endpoints del pre-entrega): regla *chained* — dispara cuando `REQUEST_URI` empieza con `/utility/` **y** la IP de origen no está en el allowlist. Cubre los endpoints administrativos expuestos (`/utility/panic`, `/utility/health/down`, `/utility/stress/{n}`, `/utility/store`) y también `/utility/headers` del caso 3.3.3 (el pre-entrega aclara que ese caso queda cubierto acá).

> Nota sobre la fuente de IP: el pre-entrega propone `REQUEST_HEADERS:X-Forwarded-For` y plantea que nginx sobrescriba ese header con la IP real del cliente para evitar spoofing. En ingress-nginx esa "sobrescritura" sólo aplica al header forwardeado al upstream — ModSecurity en `phase:1` ve los headers tal como los mandó el cliente. Cuando el cliente no manda XFF (caso típico), la variable queda *undefined* y el chain no matchea, por lo que el `deny` nunca dispara. Para cerrar esto usamos `REMOTE_ADDR`, que es la IP que nginx ve en la conexión TCP — no es spoofable a nivel HTTP y siempre existe. En producción detrás de un LB habría que volver a XFF + configurar `trusted-proxies` para que ese valor sea confiable. Allowlist actual: `127.0.0.1` (mínima para el PoC; ningún test corre desde loopback dentro del cluster).

> Nota sobre `msg`: el pre-entrega usa `msg:'...'`. La directiva `modsecurity_rules` de la imagen del ingress controller envuelve el snippet en comillas simples a nivel nginx, así que cualquier `'` adentro lo corta y rompe el reload (`nginx: [emerg] unexpected "I" in ...`). Para mantener todo inline en el ConfigMap usamos `msg:IDOR_proxy_endpoint_blocked` / `msg:utility_endpoint_blocked` (sin espacios, sin comillas) — mismo efecto, mensaje sin espacios en el audit log.

#### 2. Modificación: `local.sh`

Se agregó la función `configure_modsecurity` y se la enganchó en el flujo de `create_cluster_and_deploy`, justo después de `install_ingress`:

```bash
create_cluster_and_deploy() {
    create_cluster
    install_ingress
    configure_modsecurity   # ← nuevo
    build_images
    load_images
    deploy_services
    ...
}

configure_modsecurity() {
    print_status "Configuring ModSecurity (DetectionOnly + OWASP CRS) on ingress controller..."
    kubectl patch configmap ingress-nginx-controller \
        -n ingress-nginx \
        --type merge \
        --patch-file "$DIR/dist/modsecurity-configmap.yaml"
    print_success "ModSecurity configured"
}
```

El controller detecta el cambio en el ConfigMap y recarga nginx automáticamente — no hace falta reiniciarlo manualmente.

### Cómo verificar

1. Levantar/recrear el cluster:
   ```bash
   ./local.sh rebuild-cluster --skip-tests
   ```
   > Si el cluster ya existe (la función `install_ingress` skipea cuando el namespace `ingress-nginx` ya está), aplicar el patch a mano: `kubectl patch configmap ingress-nginx-controller -n ingress-nginx --type merge --patch-file dist/modsecurity-configmap.yaml && kubectl -n ingress-nginx rollout restart deploy/ingress-nginx-controller`.

2. Confirmar que el módulo está cargado y las reglas se cargaron al init:
   ```bash
   kubectl -n ingress-nginx exec deploy/ingress-nginx-controller -- nginx -V 2>&1 | grep -i modsecurity
   kubectl -n ingress-nginx exec deploy/ingress-nginx-controller -- nginx -t 2>&1 | grep -i "rules loaded"
   ```
   En el segundo comando tiene que aparecer algo como `ModSecurity-nginx ... (rules loaded inline/local/remote: N/801/0)` — los ~800 locales son el CRS.

3. Disparar un ataque con URL-encoding correcto:
   ```bash
   curl -s -o /dev/null -w "HTTP %{http_code}\n" --get --data-urlencode "q=' OR 1=1--" "http://localhost/catalog/search"
   ```
   > Importante: usar `--data-urlencode`. Si se pasan caracteres como `'`, espacios o `<>` sin escapar directo en la URL, curl puede mandar un request line malformado y nginx lo rechaza antes de que llegue a ModSecurity (status 000 o 400).

4. **Mirar el audit log dentro del pod del controller** (en DetectionOnly los warnings NO se duplican a stderr, así que `kubectl logs` no los muestra):
   ```bash
   kubectl -n ingress-nginx exec deploy/ingress-nginx-controller -- sh -c 'find /var/log/audit -type f | tail -5 | xargs cat'
   ```
   En DetectionOnly el request pasa al backend (status del backend, p.ej. 200 o 500), pero el audit log captura cada regla matcheada con el formato `ModSecurity: Warning. ... [id "942100"] [msg "..."]`. Estructura del directorio: `/var/log/audit/<YYYYMMDD>/<YYYYMMDD-HHMM>/<timestamp>-<uniqueid>`.

5. **Validación end-to-end** confirmada al armar esta fase: poniendo temporalmente `SecRuleEngine On`, los 4 vectores principales devuelven `403` y el tráfico legítimo pasa con `200`:
   - SQLi `q=' OR 1=1--` → 403 (rule 942100)
   - XSS `q=<script>alert(1)</script>` → 403 (rule 941xxx)
   - Path traversal `file=../../../../etc/passwd` → 403 (rule 930xxx)
   - Scanner UA `Nikto/2.5` → 403 (rule 913xxx)
   - `GET /catalog` legítimo → 200

6. **Validación de la regla 1001 (IDOR)**:

   *En `DetectionOnly`* (estado por default en el ConfigMap):
   ```bash
   curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost/proxy/carts/123    # → backend (200/404)
   curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost/proxy/orders/123   # → backend (200/404)
   ```
   El request pasa al backend (no se bloquea), pero el audit log captura el match. Como en DetectionOnly el backend responde con su status real (404 normalmente, porque /proxy es interno), `SecAuditEngine RelevantOnly` filtra los 404. Para ver el match en DetectionOnly hay que cambiar temporalmente a `SecAuditEngine On` en el snippet o consultar el audit log cuando el backend devuelve 5xx/4xx≠404. Cuando matchea, la entrada se ve así:
   ```
   ModSecurity: Warning. Matched "Operator `BeginsWith' with parameter `/proxy/' against variable `REQUEST_URI' (Value: `/proxy/carts/123' ) [id "1001"] [msg "IDOR_proxy_endpoint_blocked"] [tag "IDOR"] [uri "/proxy/carts/123"]
   ```

   *En `On`* (probado temporalmente al armar esta sección, después se revirtió):
   ```
   /proxy/carts/123  → HTTP 403
   /proxy/orders/123 → HTTP 403
   /proxy/whatever   → HTTP 403
   /                 → HTTP 200
   /catalog          → HTTP 200
   /cart             → HTTP 200
   ```
   El `attacks.sh` reporta los dos casos 3.1 como `BLOCK` y `happy-path.sh` no genera falsos positivos por esta regla (ningún path legítimo empieza con `/proxy/`).

7. **Validación de la regla 2002 (admin endpoints)**:

   *En `DetectionOnly`* — los requests pasan al backend (`/utility/headers` → 200, `/utility/store` POST → 200) y el audit log captura el match. Para verlo hay que poner `SecAuditEngine On` temporalmente (los 200 no son "relevantes" para `RelevantOnly`). Entrada típica:
   ```
   ModSecurity: Warning. Matched "Operator `IpMatch' with parameter `127.0.0.1' against variable `REMOTE_ADDR' (Value: `192.168.65.1' ) [id "2002"] [msg "utility_endpoint_blocked"] [tag "admin_endpoint"] [uri "/utility/headers"]
   ```
   El `REMOTE_ADDR` que ve nginx en este entorno es `192.168.65.1` (gateway interno de Docker Desktop), que no está en el allowlist → la regla matchea.

   > Cuidado en DetectionOnly: `/utility/panic` y `/utility/health/down` afectan al pod de UI (crashea / lo marca unhealthy). En DetectionOnly el request llega al backend igual, así que **no probar esos dos endpoints en este modo** salvo que se quiera ver al UI reiniciarse. Para validación usar `/utility/headers` y `/utility/store`.

   *En `On`* (probado temporalmente, después se revirtió):
   ```
   /utility/panic        → HTTP 403
   /utility/health/down  → HTTP 403
   /utility/stress/N     → HTTP 403
   /utility/store POST   → HTTP 403
   /utility/headers      → HTTP 403
   /                     → HTTP 200
   /catalog              → HTTP 200
   /cart                 → HTTP 200
   ```
   `/utility/panic` no llega a la UI (queda en el WAF), así que el pod no crashea — efecto positivo del modo blocking. `attacks.sh` reporta los 4 casos 3.2 + el `Leak /utility/headers` de 3.3 como `BLOCK`. `happy-path.sh` no genera falsos positivos.

---

## Fase 2 + 3 — Modo blocking + reglas custom restantes

Confirmado el comportamiento en `DetectionOnly`, se pasó el WAF a modo blocking y se completaron las reglas custom pendientes del pre-entrega. Estado actual de `dist/modsecurity-configmap.yaml`:

```yaml
data:
  enable-modsecurity: "true"
  enable-owasp-modsecurity-crs: "true"
  modsecurity-snippet: |
    Include /etc/nginx/modsecurity/modsecurity.conf
    SecRuleEngine On
    SecAuditEngine RelevantOnly
    SecAuditLogParts ABIJDEFHZ

    # 3.1 IDOR — block external access to internal /proxy/* endpoints
    SecRule REQUEST_URI "@beginsWith /proxy/" \
        "id:1001,phase:1,deny,status:403,log,tag:IDOR,msg:IDOR_proxy_endpoint_blocked"

    # 3.2 Admin endpoints — block /utility/* unless source IP is in the allowlist
    SecRule REQUEST_URI "@beginsWith /utility/" \
        "id:2002,phase:1,deny,status:403,log,tag:admin_endpoint,msg:utility_endpoint_blocked,chain"
        SecRule REMOTE_ADDR "!@ipMatch 127.0.0.1"

    # 3.3 Sensitive info exposure — block /info and /topology
    SecRule REQUEST_URI "@streq /info" \
        "id:1003,phase:1,deny,status:403,log,tag:info_endpoint,msg:info_endpoint_blocked"
    SecRule REQUEST_URI "@streq /topology" \
        "id:1004,phase:1,deny,status:403,log,tag:info_endpoint,msg:topology_endpoint_blocked"

    # 3.4.3 Malicious scanner User-Agent detection
    SecRule REQUEST_HEADERS:User-Agent "@rx (?i:(sqlmap|nikto|nmap|wpscan))" \
        "id:4001,phase:1,deny,status:403,log,tag:scanner,msg:malicious_scanner_detected"
```

Cambios respecto de Fase 1:

| Cambio | Detalle |
|--------|---------|
| `SecRuleEngine On` | Pasa de detectar a **bloquear**: las reglas que matchean devuelven `403` antes de llegar al backend. |
| Reglas **1003** / **1004** (mitigación 3.3) | `@streq /info` y `@streq /topology` — match exacto del path. Bloquean los endpoints que filtran metadata interna (`/info`) y la topología de microservicios (`/topology`). Se usa `@streq` (igualdad exacta) en lugar de `@beginsWith` para no pisar otros paths legítimos que pudieran empezar con esos prefijos. El caso 3.3.3 (`/utility/headers`) ya queda cubierto por la regla 2002. |
| Regla **4001** (mitigación 3.4.3) | `@rx (?i:(sqlmap\|nikto\|nmap\|wpscan))` sobre el header `User-Agent` — bloquea herramientas de scanning automatizado por su firma de UA, case-insensitive. |

### Cómo verificar (modo blocking)

Con el cluster corriendo (`kind-the-store`), los vectores de 3.1, 3.2 y 3.3 devuelven `403` y el tráfico legítimo pasa con `200`:

```bash
# 3.1 IDOR
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/proxy/carts/123     # 403
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/proxy/orders/123    # 403
# 3.2 Admin (no probar /utility/panic ni /utility/health/down salvo que se quiera; en On igual quedan en el WAF)
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/utility/store       # 403
# 3.3 Info
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/info                # 403
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/topology            # 403
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/utility/headers     # 403 (vía regla 2002)
# Happy path
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/                    # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/catalog             # 200
```

Verificado el 2026-05-30 contra el cluster local: `rules loaded inline: 12/801/0` (12 reglas custom + ~800 del CRS) y todos los vectores 3.1/3.2/3.3 devolviendo `403`, happy path `200`. En modo `On` ya no hace falta mirar el audit log para confirmar detección — el status code lo refleja directo, así que `attacks.sh` y `happy-path.sh` sirven como validación directa.

---

## Testing del WAF

Los Cypress e2e (`src/e2e/`) sólo cubren happy path funcional — no disparan payloads maliciosos. Para validar el WAF se incluyen tres scripts de bash en `src/waf-tests/` que ejercitan los casos del pre-entrega.

### Estructura

```
src/waf-tests/
├── lib.sh           # runner compartido (run_case, print_stats)
├── cases.sh         # define attack_cases() y happy_cases()
├── happy-path.sh    # corre sólo happy_cases
├── attacks.sh       # corre sólo attack_cases
└── mixed.sh         # corre ambos
```

### Scripts

| Script | Propósito | Métrica clave |
|--------|-----------|---------------|
| `happy-path.sh` | Tráfico legítimo. | Falsos positivos (tráfico bloqueado que no debería). |
| `attacks.sh` | Ataques del pre-entrega. | Falsos negativos (ataques que no detectó). |
| `mixed.sh` | Ambos juntos. | Visión end-to-end. |

### Cobertura de ataques (`attacks.sh`)

Mapeo 1-a-1 con las vulnerabilidades del pre-entrega:

| Sección | Caso del pre-entrega | Test en script |
|---------|----------------------|----------------|
| 3.1 IDOR | `/proxy/carts/{id}` | `IDOR /proxy/carts` |
| 3.1 IDOR | `/proxy/orders/{id}` | `IDOR /proxy/orders` |
| 3.2 Admin | `/utility/panic` | `DoS /utility/panic` |
| 3.2 Admin | `/utility/health/down` | `DoS /utility/health/down` |
| 3.2 Admin | `/utility/stress/{n}` | `CPU /utility/stress` |
| 3.2 Admin | `POST /utility/store` | `Arbitrary /utility/store` |
| 3.3 Info | `/info` | `Info /info` |
| 3.3 Info | `/topology` | `Topology /topology` |
| 3.3 Info | `/utility/headers` | `Leak /utility/headers` |
| 3.4.1 SQLi | `q=' OR 1=1--` | `SQLi tautology` |
| 3.4.1 SQLi | `q=' UNION SELECT password FROM users--` | `SQLi union select` |
| 3.4.1 XSS | `q=<img src=x onerror=alert(1)>` | `XSS img onerror` |
| 3.4.2 Traversal | `file=../../../../etc/passwd` | `Traversal /etc/passwd` |
| 3.4.2 Traversal | `file=../../../../proc/self/environ` | `Traversal /proc/self` |
| 3.4.3 Scanner | `User-Agent: sqlmap` | `Scanner sqlmap UA` |
| 3.4.3 Scanner | `User-Agent: nikto` | `Scanner nikto UA` |
| 3.4.3 Scanner | `User-Agent: nmap` | `Scanner nmap UA` |
| 3.4.3 Scanner | `User-Agent: wpscan` | `Scanner wpscan UA` |

### Cómo decide el script si "detectó"

El runner mira el HTTP status code de la respuesta:

- **Caso `block`** (ataques): éxito si status = `403`. Cualquier otra cosa cuenta como **missed attack**.
- **Caso `allow`** (legítimo): éxito si status ≠ `403`. Si vuelve `403` cuenta como **false positive**.

> Nota: este criterio asume `SecRuleEngine On` — que es el modo actual del ConfigMap, así que los scripts corren directo. (Si se volviera a `DetectionOnly` el WAF nunca bloquea y todos los ataques contarían como "missed"; ahí habría que mirar los logs del controller con `kubectl -n ingress-nginx logs deploy/ingress-nginx-controller | grep ModSecurity`.)

### Estadísticas que imprime

```
======================================================
 Results
======================================================
  Total cases:           N
  Correct:               N
  Missed attacks:        N
  False positives:       N
  Accuracy:              N/N (NN%)
```

Exit code = 0 si todo OK, 1 si hubo missed o false positives — apto para CI.

### Uso

```bash
# Apuntando al cluster local (default: http://localhost)
./src/waf-tests/happy-path.sh
./src/waf-tests/attacks.sh
./src/waf-tests/mixed.sh

# Apuntando a otro target
WAF_TEST_URL=http://otro-host ./src/waf-tests/attacks.sh
```

### Estado actual

El WAF está en modo blocking (`SecRuleEngine On`) con el CRS completo + las cuatro reglas custom: **1001** (IDOR `/proxy/*`), **2002** (admin `/utility/*` con IP allowlist, cubre también 3.3.3 `/utility/headers`), **1003** (`/info`), **1004** (`/topology`) y **4001** (scanner UA). Cubre los casos 3.1, 3.2, 3.3 y 3.4.3 del pre-entrega; los vectores genéricos de 3.4.1 (SQLi/XSS) y 3.4.2 (path traversal) los maneja el CRS. Con esto, `attacks.sh` debería reportar todos los casos como `BLOCK` y `happy-path.sh` sin falsos positivos.

---

## Próximas fases (pendientes)

- [x] **Fase 2** — Pasar a modo blocking (`SecRuleEngine On`). Hecho (commit `a0bacce`), validado contra el cluster local: vectores 3.1/3.2/3.3 → 403, happy path → 200. Pendiente seguir tuneando falsos positivos del CRS con `happy-path.sh` si aparecen (ver Fase 4).
- [x] **Fase 3** — Reglas custom específicas:
  - [x] IDOR: bloquear `/proxy/*` (id 1001) — implementada, validada en DetectionOnly y blocking
  - [x] Admin endpoints: bloquear `/utility/*` salvo IPs autorizadas (id 2002) — implementada con `REMOTE_ADDR` (en vez de XFF), validada en DetectionOnly y blocking
  - [x] Info: bloquear `/info` y `/topology` (id 1003, 1004) — implementada con `@streq`, validada en blocking
  - [x] Scanner UA: bloquear `sqlmap|nikto|nmap|wpscan` en User-Agent (id 4001) — implementada
- [ ] **Fase 4** — Tuning del anomaly scoring (`inbound_anomaly_score_threshold`) y rule exclusions según falsos positivos que reporte `happy-path.sh`. (Pre-entrega 3.4: paranoia level 2 + análisis de falsos positivos — pendiente.)
- [ ] **Fase 5** — Observabilidad: enviar el audit log a un sink centralizado (stdout estructurado, o un sidecar tipo Fluent Bit).
