# Demo del WAF — cómo replicar los ataques

Runbook para reproducir los casos del pre-entrega y mostrar el efecto del WAF (ModSecurity + OWASP CRS sobre el ingress-nginx). Cada ataque incluye el comando, el resultado **sin WAF** (el request llega al backend) y **con WAF** (bloqueado en el borde con `403`).

Para el detalle de las reglas y la implementación ver [`modsecurity.md`](./modsecurity.md). Este documento es solo la guía de demostración.

## Prerrequisitos

- Cluster local levantado (`./local.sh create-cluster`) y la app accesible en `http://localhost`.
- El WAF queda activo en modo blocking (`SecRuleEngine On`) por default tras `create-cluster`.

---

## Opción A — automatizado (recomendado)

Los scripts en `src/waf-tests/` ejercitan todos los casos del pre-entrega (mapeo 1-a-1 en `cases.sh`):

```bash
./src/waf-tests/attacks.sh      # ataques → se esperan 403 (18/18 con WAF on)
./src/waf-tests/happy-path.sh   # tráfico legítimo → se esperan 200 (12/12)
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
| 3.4.1 SQLi | `curl --get --data-urlencode "q=' OR 1=1--" http://localhost/catalog/search` | 500² | **403** |
| 3.4.1 SQLi | `curl --get --data-urlencode "q=' UNION SELECT password FROM users--" http://localhost/catalog/search` | 500² | **403** |
| 3.4.1 XSS | `curl --get --data-urlencode "q=<img src=x onerror=alert(1)>" http://localhost/catalog/search` | 500² | **403** |
| 3.4.2 Traversal | `curl "http://localhost/catalog/image?file=../../../../etc/passwd"` | 500² | **403** |
| 3.4.2 Traversal | `curl "http://localhost/catalog/image?file=../../../../proc/self/environ"` | 500² | **403** |
| 3.4.3 Scanner | `curl -A "sqlmap/1.7" "http://localhost/catalog/search?q=test"` | 200 | **403** |
| 3.4.3 Scanner | `curl -A "Nikto/2.5" "http://localhost/catalog/search?q=test"` | 200 | **403** |

¹ `/proxy/orders/123` devuelve `404` sin WAF porque el backend no tiene órdenes para ese id, pero el request **llegó al backend** — el punto es que el endpoint es accesible. Con WAF se corta con `403` antes de llegar.

² Los vectores de input (SQLi/XSS/traversal) devuelven `500` sin WAF porque la app no sanitiza el input y rompe — justamente la vulnerabilidad que el pre-entrega demuestra. Con WAF el CRS los frena con `403`.

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

## Ver qué regla matcheó

Con `SecRuleEngine On` el bloqueo se ve directo en el status `403`. Para ver la regla específica que disparó, mirar el audit log dentro del pod del controller:

```bash
kubectl -n ingress-nginx exec deploy/ingress-nginx-controller -- \
  sh -c 'find /var/log/audit -type f | tail -1 | xargs cat'
```

Cada entrada tiene el `[id "..."]` y `[msg "..."]` de la regla (p. ej. `id "1001"`, `msg "IDOR_proxy_endpoint_blocked"`).
