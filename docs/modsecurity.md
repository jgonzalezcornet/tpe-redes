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

> Para reproducir los ataques paso a paso (con vs sin WAF, cómo togglear el WAF, tabla de resultados esperados) ver la guía de demostración: [`waf-demo.md`](./waf-demo.md).

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
- **Caso `allow`** (legítimo): éxito si el WAF no bloquea (status ≠ `403`). Si vuelve `403` cuenta como **false positive**. Si vuelve `5xx` se reporta aparte como **backend error** (`⚠ PASS*`): el WAF no lo bloqueó —no es FP— pero la request falló en el backend, así que no se presenta como un pass limpio. No afecta el exit code (que mide la corrección del WAF).

> El caso `Search apostrophe` (`q=john's`) es justamente un backend error: el WAF correctamente **no** bloquea un apóstrofe benigno (bloquear toda comilla sería un falso positivo sobre nombres legítimos tipo *O'Brien*; el WAF filtra *patrones de inyección*, no metacaracteres sueltos), pero la SQLi de `SearchProductsUnsafe` arma `... LIKE '%john's%'` y SQLite devuelve `500` (`near "s": syntax error`). Es decir, la vulnerabilidad intencional de 3.4.1 además degrada la disponibilidad para inputs legítimos con apóstrofe. El fix de fondo sería parametrizar la query; queda fuera de scope porque la vuln es deliberada. El WAF mitiga la *explotación* (`' OR 1=1--` → 403) pero no corrige la causa raíz — alcance vs. límites del WAF.

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

El WAF está en modo blocking (`SecRuleEngine On`) con el CRS en **paranoia level 2** (anomaly threshold default 5) + las cuatro reglas custom: **1001** (IDOR `/proxy/*`), **2002** (admin `/utility/*` con IP allowlist, cubre también 3.3.3 `/utility/headers`), **1003** (`/info`), **1004** (`/topology`) y **4001** (scanner UA), más el seteo de PL (**900100**) y una rule exclusion scopeada (**900200**) — ver [Fase 4](#fase-4--paranoia-level-anomaly-scoring-y-rule-exclusions-pre-entrega-34) para la justificación. Cubre los casos 3.1, 3.2, 3.3 y 3.4.3 del pre-entrega; los vectores genéricos de 3.4.1 (SQLi/XSS) y 3.4.2 (path traversal) los maneja el CRS. Validado el 2026-06-03 contra el cluster local: `attacks.sh` 18/18 (`BLOCK`) y `happy-path.sh` 13/13 sin falsos positivos (`rules loaded inline: 14`).

---

## Fase 4 — Paranoia level, anomaly scoring y rule exclusions (pre-entrega 3.4)

Tuning fino del CRS: análisis de falsos positivos variando el **paranoia level**, el **anomaly-score threshold** y, donde hace falta, **rule exclusions** scopeadas. Validado contra el cluster local el 2026-06-03.

### Mecanismo: todo desde el ConfigMap

El paranoia level y el threshold se setean con un `SecAction` en el `modsecurity-snippet`, sin tocar la imagen ni `crs-setup.conf`:

```
SecAction \
    "id:900100,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=2"
SecAction \
    "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=20"
```

Funciona porque en `nginx.conf` el `modsecurity_rules` inline (nuestro snippet) se carga **antes** del `modsecurity_rules_file` del CRS, y el `REQUEST-901-INITIALIZATION.conf` del CRS usa *set-if-unset* (`SecRule &TX:blocking_paranoia_level "@eq 0" ... setvar:tx.blocking_paranoia_level=1`). Como ya lo seteamos antes, el default del CRS no lo pisa. En `crs-setup.conf` esas líneas vienen comentadas.

### Análisis de falsos positivos: detección vs. paranoia level

Sweep PL1→PL4 con un corpus de 6 ataques (deben bloquearse) y 10 búsquedas benignas "de borde" (deben pasar), vía `src/waf-tests/paranoia-sweep.sh`:

| Paranoia Level | Ataques bloqueados | Falsos positivos |
|----------------|--------------------|------------------|
| PL1 (default)  | 6/6                | 0/10             |
| PL2            | 6/6                | 1/10             |
| PL3            | 6/6                | 2/10             |
| PL4            | 6/6                | 9/10             |

![Detección vs falsos positivos por paranoia level](./images/paranoia-fp.png)

La detección de los ataques obvios se mantiene al 100% en todos los niveles; los falsos positivos crecen con el paranoia level y explotan en PL4. El punto óptimo para un e-commerce es **PL2** (lo que recomienda la doc del CRS para un "off-the-shelf online shop"), aceptando algún FP puntual que se corrige con exclusiones.

### Caso de falso positivo y su corrección

La búsqueda benigna `q=1+2-3*4/5=6` (un código de producto con símbolos matemáticos) pasa en PL1 pero en PL2 dispara la regla CRS **932200 "RCE Bypass Technique"** (por el `*` y el `/`), que suma anomaly score 10 ≥ threshold 5 → la **949110** bloquea (403).

| Estado | FP `1+2-3*4/5=6` | SQLi `' OR 1=1--` | XSS |
|--------|------------------|-------------------|-----|
| PL1 | 200 | 403 | 403 |
| PL2 | **403** (FP) | 403 | 403 |
| PL2 + exclusión | 200 | 403 | 403 |
| PL2 + threshold 5→20 | 200 | 403 | 403 |

Dos formas de tunearlo:

1. **Rule exclusion quirúrgica (preferida):** dropear *sólo* la regla 932200 para el arg `q` de `/catalog/search`. Mantiene SQLi/XSS en la barra y mantiene 932200 en el resto:
   ```
   SecRule REQUEST_URI "@beginsWith /catalog/search" \
       "id:900200,phase:1,pass,nolog,ctl:ruleRemoveTargetById=932200;ARGS:q"
   ```
2. **Subir el anomaly threshold (instrumento grueso):** `tx.inbound_anomaly_score_threshold=20`. Arregla el FP pero globalmente — cualquier ataque que sume < 20 se filtraría. Útil para mostrar *por qué* la exclusión scopeada es mejor.

### Anomaly scoring: cómo se acumula el score y por qué el threshold queda en 5

El CRS no bloquea por una regla suelta: cada regla que matchea suma su severidad (CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2) a un **inbound anomaly score**, y la regla 949110 bloquea si el score ≥ `inbound_anomaly_score_threshold` (default 5). Medimos el score real de cada request a PL2 (truco: con threshold=1 la 949110 loguea el "Total Score" de todo lo que sume ≥1). Script: `src/waf-tests/anomaly-scores.sh` → `anomaly-scores.csv`; gráficos con `plot-anomaly.py`.

![Anomaly score por request](./images/anomaly-scores.png)

Lo que se ve: los benignos suman **0** (muy por debajo del threshold); los ataques fuertes suman 25-45 (varias reglas); los ataques débiles que PL2 agrega (`1 like 1`, `@@version`, `1 OR 1`, `0x…`) suman exactamente **5** — una sola regla crítica, justo en el límite; y el FP `1+2-3*4/5=6` suma **10** (la 932200), el único benigno por encima del threshold.

Como el score de cada request es fijo, el tradeoff de threshold sale por aritmética (bloqueado ⇔ score ≥ threshold):

![Detección vs FP por threshold](./images/anomaly-threshold.png)

- **Threshold 5 (elegido):** bloquea los 11 ataques (incluidos los débiles de score 5) → máxima detección; costo: el FP de score 10.
- **Subir el threshold para limpiar el FP** exige T ≥ 11, y ahí la detección cae de 11 a 6 ataques: se pierden los 5 ataques débiles (score 5) y `1 regexp 1` (score 10). Mal negocio.

**Conclusión:** el threshold se deja en **5** (la postura más sensible); el FP se ataca con la exclusión scopeada de 932200, que no toca la detección del resto. Esto cierra el análisis de anomaly scoring del pre-entrega 3.4.

### ¿PL2 detecta más que PL1? Sí — 11 ataques que PL1 deja pasar

Un primer corpus de ataques *obvios* daba 6/6 en ambos PLs, lo que sugería que PL2 no agregaba nada. Probando **a fondo** con payloads ofuscados/exóticos (libinjection blind spots) la diferencia aparece. Script reproducible: `src/waf-tests/pl-detection-gap.sh` (corpus de 58 payloads).

Resultado (2026-06-03): **PL1 bloquea 45/58, PL2 bloquea 56/58**. Los 11 que PL1 deja pasar y PL2 sí corta:

| Payload (en `q=`) | PL1 | PL2 | Por qué PL1 lo deja pasar |
|---|---|---|---|
| `1 OR 1`, `1 like 1`, `1 rlike 1`, `1 regexp 1`, `1 sounds like 1`, `1 xor 1`, `1 && 1` | 200 | 403 | operadores SQL que libinjection no marca; los toman las reglas 942xxx de PL2 |
| `@@version` | 200 | 403 | variable global SQL, sin sintaxis clásica de inyección |
| `0x73716c696e...` | 200 | 403 | string hex-encoded |
| `1'#` | 500 | 403 | comentario MySQL: en PL1 llega al backend (error SQL → 500); PL2 lo corta en el borde |
| `` `id` `` | 200 | 403 | RCE por backticks — lo toma la 932200 (la misma regla del FP, acá con valor real) |

Control del otro lado: esas reglas matchean el **patrón** de inyección, no la palabra suelta. Frases benignas con `like`/`and`/`&` (`shoes like nike`, `sounds like teen spirit`, `rock and roll`, `salt & pepper`…) dan **0 FP en PL2**. O sea, la ganancia de detección de PL2 **no** trae falsos positivos en lenguaje natural.

> Honestidad: una versión previa de este análisis (con un corpus de ataques obvios) concluía que PL2 "no aportaba detección medible". Era un error por corpus insuficiente — al probar variantes ofuscadas la ganancia de PL2 es clara (11 ataques). *Esto* es lo que justifica PL2 con datos, no el "margen defensivo".

Dos payloads no los bloquea ningún PL (`1 div 1`, `a=b;c=d;e=f;g=h`): no son exploits funcionales (operador de división / pares clave=valor), pero quedan anotados como límite del corpus.

### Decisión: valor por default elegido

**`dist/modsecurity-configmap.yaml` queda en paranoia level 2 + anomaly threshold 5 (default) + una exclusión scopeada de la regla 932200 sobre `ARGS:q` en `/catalog/search`.**

| Variable | Valor | Por qué |
|----------|-------|---------|
| `blocking_paranoia_level` | **2** | Aporta detección real: bloquea **11 ataques ofuscados que PL1 deja pasar** (operadores SQL, hex, RCE backtick — ver §"¿PL2 detecta más que PL1?"), con **0 FP nuevos** en lenguaje natural. Recomendado por la doc del CRS para un "off-the-shelf online shop" y comprometido en el pre-entrega. Pasa `attacks.sh` 18/18 y `happy-path.sh` 13/13. PL3/PL4 suman FPs sin detección extra medible (ver sweep). |
| `inbound_anomaly_score_threshold` | **5** (default CRS) | Postura más segura: bloquea ante una sola regla crítica. El sweep muestra que subirlo solo cambia FP por detección de señales débiles → no se toca. |
| Exclusión 932200 / `ARGS:q` | **sí** | Único FP realista que introduce PL2 (símbolos aritméticos en el buscador, p.ej. códigos de producto). Quirúrgica: 932200 es "RCE Bypass Technique", de bajo valor en un campo de búsqueda de texto, mientras SQLi/XSS (942xxx/941xxx) siguen activos ahí. Preferida sobre subir el threshold (que es global). |

Criterios que cumple: (1) bloquea los 18 vectores del pre-entrega, (2) 0 FP sobre el corpus legítimo del proyecto, (3) máximo margen defensivo razonable (PL2) (4) sin debilitar la detección globalmente (threshold en 5; el tuning es una exclusión puntual). Validado el 2026-06-03: `rules loaded inline: 14`, `attacks.sh` 18/18, `happy-path.sh` 13/13, FP matemático → 200.

### Reproducir / demo en vivo

- Sweep + gráfico: `./src/waf-tests/paranoia-sweep.sh` (escribe `paranoia-sweep.csv`), luego `python3 src/waf-tests/plot-paranoia.py`.
- Justificación de PL2 (ataques que PL1 deja pasar): `./src/waf-tests/pl-detection-gap.sh`.
- Anomaly scoring (score por request + tradeoff de threshold): `./src/waf-tests/anomaly-scores.sh`, luego `python3 src/waf-tests/plot-anomaly.py`.
- Demo en 3 actos (PL1 pasa → PL2 FP → fix): `./demo-scripts/crs-tuning/demo-flip.sh`.
- Estados sueltos: `./demo-scripts/crs-tuning/set-crs.sh --pl 2 [--threshold N] [--exclude-fp]`.

### Gotchas

- **Formato de reglas:** usar continuación de línea `\` entre el operador y las acciones de cada `SecRule`. Reglas en una sola línea rompen el parser de `modsecurity_rules` y dejan el controller en crashloop.
- **Aplicar cambios:** patchear el ConfigMap recarga nginx **in-process (~6s)** sin downtime. **No** usar `kubectl rollout restart` sobre el controller: tiene un solo replica con hostPort 80 en kind → reiniciar corta el tráfico (502/000). Si un snippet es inválido, la recarga in-process falla el config test y mantiene el config anterior (sin downtime).

> Nota: el ConfigMap committeado (`dist/modsecurity-configmap.yaml`) **ya está en el default elegido** (PL2 + threshold 5 + exclusión 932200/`ARGS:q`) — ver [Decisión](#decisión-valor-por-default-elegido). Los scripts de `demo-scripts/crs-tuning/` permiten togglear otros valores (PL1/PL3/PL4, threshold, con/sin exclusión) para la demo en vivo.

---

## Próximas fases (pendientes)

- [x] **Fase 2** — Pasar a modo blocking (`SecRuleEngine On`). Hecho (commit `a0bacce`), validado contra el cluster local: vectores 3.1/3.2/3.3 → 403, happy path → 200. Pendiente seguir tuneando falsos positivos del CRS con `happy-path.sh` si aparecen (ver Fase 4).
- [x] **Fase 3** — Reglas custom específicas:
  - [x] IDOR: bloquear `/proxy/*` (id 1001) — implementada, validada en DetectionOnly y blocking
  - [x] Admin endpoints: bloquear `/utility/*` salvo IPs autorizadas (id 2002) — implementada con `REMOTE_ADDR` (en vez de XFF), validada en DetectionOnly y blocking
  - [x] Info: bloquear `/info` y `/topology` (id 1003, 1004) — implementada con `@streq`, validada en blocking
  - [x] Scanner UA: bloquear `sqlmap|nikto|nmap|wpscan` en User-Agent (id 4001) — implementada
- [x] **Fase 4** — Tuning del anomaly scoring (`inbound_anomaly_score_threshold`), paranoia level y rule exclusions. Analizado y validado contra el cluster local (ver [Fase 4](#fase-4--paranoia-level-anomaly-scoring-y-rule-exclusions-pre-entrega-34)): sweep PL1→PL4, caso de FP `932200` y dos fixes (exclusión scopeada / threshold). Scripts en `demo-scripts/crs-tuning/` y `src/waf-tests/paranoia-sweep.sh`. Pendiente decidir si el ConfigMap por default pasa a PL2 + exclusiones para la entrega final.
- [ ] **Fase 5** — Observabilidad: enviar el audit log a un sink centralizado (stdout estructurado, o un sidecar tipo Fluent Bit).
