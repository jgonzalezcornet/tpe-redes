# Integración de ModSecurity en The Store

Roadmap completo de la integración de ModSecurity como WAF sobre el ingress de nginx en el cluster local de Kind.

---

## Contexto inicial

- El ingress en uso es el oficial [`kubernetes/ingress-nginx`](https://github.com/kubernetes/ingress-nginx) v1.13.1, instalado desde `local.sh` con el manifiesto `provider/kind/deploy.yaml`.
- Hay un único `Ingress` (`ui`) definido en `dist/kubernetes.yaml`, sin anotaciones de WAF.
- La imagen del controller de `ingress-nginx` **ya viene con el módulo ModSecurity y el OWASP Core Rule Set (CRS) compilados**. No hace falta cambiar imagen ni agregar sidecars: alcanza con habilitarlo por configuración.

## Decisiones de diseño

1. **Modo de arranque: `DetectionOnly`.** ModSecurity loguea las reglas que matchean pero no bloquea requests. Permite observar el comportamiento del WAF contra los tests e2e y el load generator antes de pasar a modo blocking.
2. **Alcance: global vía ConfigMap del controller.** Como hay un único Ingress en el proyecto, configurar globalmente es más simple que anotación por anotación. Si en el futuro hace falta WAF diferenciado por servicio, se puede mover a annotations.
3. **Formato: manifiesto separado + patch.** Mantenemos la config de ModSecurity en `dist/modsecurity-configmap.yaml` (separado del `dist/kubernetes.yaml` de la app) y la aplicamos con `kubectl patch --type merge`, no con `kubectl apply`. Razón: el ConfigMap `ingress-nginx-controller` lo crea upstream con labels y keys propias (`allow-snippet-annotations`), y un `apply` con un manifiesto parcial las borraría. El merge patch sólo toca las keys que nos interesan.

---

## Fase 1 — Habilitar ModSecurity + CRS en modo Detect

### Cambios

#### 1. Nuevo archivo: `dist/modsecurity-configmap.yaml`

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

> Nota: este criterio asume `SecRuleEngine On`. En modo `DetectionOnly` el WAF nunca bloquea (siempre devuelve el status del backend), entonces todos los ataques cuentan como "missed". Para verificar detección sin bloquear hay que mirar los logs del controller (`kubectl -n ingress-nginx logs deploy/ingress-nginx-controller | grep ModSecurity`).

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

Hoy sólo está el CRS en `DetectionOnly`. Las reglas custom (IDOR, admin, info, scanner UA) son fases siguientes del roadmap. Si se corren los scripts ahora se esperan muchos "missed" — funciona como checklist: cada fase nueva debería convertir un grupo de `MISS` en `BLOCK`.

---

## Próximas fases (pendientes)

- [ ] **Fase 2** — Pasar a modo blocking (`SecRuleEngine On`) y validar que los tests e2e siguen pasando. Tunear falsos positivos del CRS con exclusiones si hace falta. `happy-path.sh` es la herramienta para esto.
- [ ] **Fase 3** — Reglas custom específicas:
  - IDOR: bloquear `/proxy/*` (id 1001)
  - Admin endpoints: bloquear `/utility/*` salvo IPs autorizadas (id 2002)
  - Info: bloquear `/info` y `/topology` (id 1003, 1004)
  - Scanner UA: bloquear `sqlmap|nikto|nmap|wpscan` en User-Agent (id 4001)
- [ ] **Fase 4** — Tuning del anomaly scoring (`inbound_anomaly_score_threshold`) y rule exclusions según falsos positivos que reporte `happy-path.sh`.
- [ ] **Fase 5** — Observabilidad: enviar el audit log a un sink centralizado (stdout estructurado, o un sidecar tipo Fluent Bit).
