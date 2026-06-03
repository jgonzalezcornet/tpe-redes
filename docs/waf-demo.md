# Demo del WAF — cómo replicar los ataques

Runbook para reproducir los casos del pre-entrega y mostrar el efecto del WAF (ModSecurity + OWASP CRS sobre el ingress-nginx). Cada ataque incluye el comando, el resultado **sin WAF** (el request llega al backend) y **con WAF** (bloqueado en el borde con `403`).

Para el detalle de las reglas y la implementación ver [`modsecurity.md`](./modsecurity.md). Este documento es solo la guía de demostración.

## Prerrequisitos

- Cluster local levantado (`./local.sh create-cluster`) y la app accesible en `http://localhost`.
- El WAF queda activo en modo blocking (`SecRuleEngine On`) por default tras `create-cluster`, con el CRS en **paranoia level 2** + una **exclusión scopeada** (regla 932200 sobre `ARGS:q` en `/catalog/search`). La justificación de esos valores está en [`modsecurity.md` → Fase 4](./modsecurity.md#fase-4--paranoia-level-anomaly-scoring-y-rule-exclusions-pre-entrega-34).

---

## Opción A — automatizado (recomendado)

Los scripts en `src/waf-tests/` ejercitan todos los casos del pre-entrega (mapeo 1-a-1 en `cases.sh`):

```bash
./src/waf-tests/attacks.sh      # ataques → se esperan 403 (18/18 con WAF on)
./src/waf-tests/happy-path.sh   # tráfico legítimo → se esperan 200 (13/13)
./src/waf-tests/mixed.sh        # ambos
```

El runner compara el HTTP status: para ataques éxito = `403`; para tráfico legítimo éxito = ≠ `403`.

---

## Opción B — manual, comparando con vs sin WAF

### Togglear el WAF

**Apagar** (los ataques llegan al backend):

```bash
kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge -p '{"data":{"enable-modsecurity":"false"}}'
```

**Encender** (re-aplica el patch-file: `SecRuleEngine On` + todas las reglas custom):

```bash
kubectl patch configmap ingress-nginx-controller -n ingress-nginx \
  --type merge --patch-file dist/modsecurity-configmap.yaml
```

El controller recarga nginx solo al detectar el cambio en el ConfigMap (tarda unos segundos). Verificar el toggle con un caso conocido:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/info   # 200 sin WAF, 403 con WAF
```

### Tabla de ataques

| Sección | Comando | Sin WAF | Con WAF |
|---------|---------|:-------:|:-------:|
| 3.1 IDOR | `curl http://localhost/proxy/carts/123` | 200 | **403** |
| 3.1 IDOR | `curl http://localhost/proxy/orders/123` | 404¹ | **403** |
| 3.2 Admin | `curl -X POST -H "Content-Type: application/json" -d '{"a":"b"}' http://localhost/utility/store` | 200 | **403** |
| 3.3 / 3.3.3 | `curl http://localhost/utility/headers` | 200 | **403** |
| 3.3 Info | `curl http://localhost/info` | 200 | **403** |
| 3.3 Topology | `curl http://localhost/topology` | 200 | **403** |
| 3.4.1 SQLi | `curl --get --data-urlencode "q=' OR 1=1--" http://localhost/catalog/search` | 200² (todos los productos) | **403** |
| 3.4.1 SQLi | `curl --get --data-urlencode "q=' UNION SELECT password FROM users--" http://localhost/catalog/search` | 200 o 500² | **403** |
| 3.4.1 XSS | `curl --get --data-urlencode "q=<img src=x onerror=alert(1)>" http://localhost/catalog/search` | 200² (`query` reflejado en JSON) | **403** |
| 3.4.2 Traversal | `curl "http://localhost/catalog/image?file=../../../../etc/passwd"` | 200² (contenido del archivo) | **403** |
| 3.4.2 Traversal | `curl "http://localhost/catalog/image?file=../../../../proc/self/environ"` | 200² (contenido del archivo) | **403** |
| 3.4.3 Scanner | `curl -A "sqlmap/1.7" "http://localhost/catalog/search?q=test"` | 200 | **403** |
| 3.4.3 Scanner | `curl -A "Nikto/2.5" "http://localhost/catalog/search?q=test"` | 200 | **403** |

¹ `/proxy/orders/123` devuelve `404` sin WAF porque el backend no tiene órdenes para ese id, pero el request **llegó al backend** — el punto es que el endpoint es accesible. Con WAF se corta con `403` antes de llegar.

² Sin WAF el request **llega al catalog** y la vulnerabilidad se manifiesta de verdad: SQLi puede devolver el catálogo completo (`200` + JSON), XSS refleja el payload en el campo `query`, y path traversal devuelve el contenido del archivo leído (`200`). Con WAF el CRS bloquea en el ingress con `403` y el backend no ejecuta nada. Para ver el impacto: `curl -s ... | head` (SQLi/XSS) o `curl -s .../image?file=../../../../etc/passwd | head` (traversal).

### 3.4 — Protección de inputs (implementación)

| Endpoint | Servicio | Descripción |
|----------|----------|-------------|
| `GET /catalog/search?q=` | Catalog (Go) → expuesto vía UI (proxy) | Búsqueda con SQL concatenado; respuesta JSON con campo `query` sin escapar |
| `GET /catalog/image?file=` | Catalog (Go) → expuesto vía UI (proxy) | `filepath.Join` + `ReadFile` sin validar `..`; devuelve bytes del path resuelto |
| Scanner UA | Solo WAF (regla `4001`) | `sqlmap`, `nikto`, `nmap`, `wpscan` en `User-Agent` |

Prueba manual desde el browser: en `http://localhost/catalog` hay un formulario de búsqueda que hace GET a `/catalog/search` (muestra JSON). Para ataques usar `curl` con `--data-urlencode` como en la tabla.

> **Importante (SQLi/XSS):** usar `--get --data-urlencode`. Si se pasa el payload crudo en la URL (`...?q=' OR 1=1--`), `curl` arma un request line malformado y nginx lo rechaza antes de ModSecurity (status `000`/`400`) — no es un resultado válido para la demo.

### Endpoints destructivos (3.2 DoS / CPU)

Estos **afectan el cluster** sin WAF, así que en la demo conviene mostrarlos solo **con WAF** (donde se cortan con `403` y nunca llegan a la app):

| Sección | Comando | Sin WAF | Con WAF |
|---------|---------|---------|:-------:|
| 3.2.1 DoS | `curl http://localhost/utility/panic` | crashea el pod de UI | **403** |
| 3.2.1 DoS | `curl http://localhost/utility/health/down` | marca el pod unhealthy → 502 hasta reinicio | **403** |
| 3.2.3 CPU | `curl http://localhost/utility/stress/2000000` | CPU-burn, degrada rendimiento | **403** |

Si se quiere demostrar el impacto sin WAF, hacerlo en un cluster descartable y recrearlo después (`./local.sh rebuild-cluster`).

---

## Opción C — Demo del tuning del CRS (3.4: paranoia / anomaly / exclusiones)

Para demostrar el ajuste fino del CRS (no solo el bloqueo binario) hay scripts dedicados en `demo-scripts/crs-tuning/` y `src/waf-tests/`.

**Walkthrough en vivo (3 actos, con pausas para narrar):**

```bash
./demo-scripts/crs-tuning/demo-flip.sh
```

Muestra cómo una búsqueda legítima con símbolos (`q=1+2-3*4/5=6`) **pasa en PL1**, se vuelve un **falso positivo (403) en PL2** (regla CRS 932200), y se arregla de dos formas: la **exclusión quirúrgica** (el FP pasa y SQLi/XSS siguen bloqueados) vs. subir el **anomaly threshold** (instrumento grueso). Restaura el ConfigMap al final.

**Aplicar estados sueltos a mano:**

```bash
./demo-scripts/crs-tuning/set-crs.sh --pl 2                 # sube paranoia a 2
./demo-scripts/crs-tuning/set-crs.sh --pl 2 --exclude-fp    # + exclusión (= default)
./demo-scripts/crs-tuning/set-crs.sh --pl 2 --threshold 20  # + threshold alto
./demo-scripts/turn-waf-on.sh                               # restaura el default committeado
```

**Datos y gráficos (análisis del pre-entrega 3.4):**

```bash
./src/waf-tests/paranoia-sweep.sh        # detección vs FP por paranoia level → paranoia-fp.png
./src/waf-tests/pl-detection-gap.sh      # 11 ataques que PL1 deja pasar y PL2 bloquea
./src/waf-tests/anomaly-scores.sh        # score real por request → anomaly-scores.png + anomaly-threshold.png
python3 src/waf-tests/plot-paranoia.py
python3 src/waf-tests/plot-anomaly.py
```

Los gráficos quedan en `docs/images/`. El análisis completo (por qué PL2, por qué threshold 5, por qué la exclusión) está en [`modsecurity.md` → Fase 4](./modsecurity.md#fase-4--paranoia-level-anomaly-scoring-y-rule-exclusions-pre-entrega-34).

---

## Ver qué regla matcheó

Con `SecRuleEngine On` el bloqueo se ve directo en el status `403`. Para ver la regla específica que disparó, mirar el audit log dentro del pod del controller:

```bash
kubectl -n ingress-nginx exec deploy/ingress-nginx-controller -- \
  sh -c 'find /var/log/audit -type f | tail -1 | xargs cat'
```

Cada entrada tiene el `[id "..."]` y `[msg "..."]` de la regla (p. ej. `id "1001"`, `msg "IDOR_proxy_endpoint_blocked"`).
