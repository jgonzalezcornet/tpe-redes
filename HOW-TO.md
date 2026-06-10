# Cómo agregar ModSecurity (WAF) al ingress

Guía paso a paso para habilitar el WAF con **ModSecurity + OWASP CRS** en **ingress-nginx**, partiendo de un cluster que aún no tiene ModSecurity configurado.

> Para levantar el cluster y desplegar la aplicación, seguí el [README](./README.md) (sección *Prerrequisitos* y *Puesta en marcha*). Esta guía asume que el cluster ya está corriendo y que **ingress-nginx** está instalado.

## Resumen del enfoque

En ingress-nginx, ModSecurity se configura de dos maneras posibles:

| Enfoque | Dónde se define | Alcance |
|---------|-----------------|---------|
| **ConfigMap del controller** (este proyecto) | `ingress-nginx-controller` en el namespace `ingress-nginx` | Global: todo el tráfico que pasa por el ingress |
| **Anotaciones por Ingress** | `metadata.annotations` de cada recurso `Ingress` | Por host/ruta |

Este repositorio usa el **ConfigMap global**: un único parche aplica el WAF a todo el tráfico sin tocar los manifiestos de la aplicación. Las anotaciones equivalentes (`nginx.ingress.kubernetes.io/enable-modsecurity`, etc.) están documentadas en la [sección ModSecurity de ingress-nginx](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#modsecurity).

## Prerrequisitos

1. Cluster Kubernetes en ejecución (p. ej. con `./local.sh create-cluster --skip-tests` o el cluster que ya tengas).
2. **ingress-nginx** instalado y listo. La imagen del controller **v1.13.1** (la que usa `local.sh`) trae ModSecurity embebido; no hace falta instalar un módulo aparte.
3. `kubectl` apuntando al cluster correcto.

Verificá que el controller esté arriba:

```bash
kubectl -n ingress-nginx get pods -l app.kubernetes.io/component=controller
```

## Paso 1 — Preparar el archivo de configuración

El archivo [`dist/modsecurity-configmap.yaml`](./dist/modsecurity-configmap.yaml) contiene las claves que ingress-nginx lee en su ConfigMap:

- `enable-modsecurity: "true"` — activa ModSecurity en todas las rutas.
- `enable-owasp-modsecurity-crs: "true"` — carga el OWASP Core Rule Set.
- `modsecurity-snippet` — directivas y reglas custom (`SecRuleEngine On`, tuning del CRS, reglas del TP, etc.).

**Importante:** no es un manifiesto de ConfigMap completo (`apiVersion` / `kind` / `metadata`). Es un fragmento con la sección `data:` pensado para un **merge patch** sobre el ConfigMap que ingress-nginx crea al instalarse (`ingress-nginx-controller`).

Ejemplo mínimo (solo para entender la forma; el archivo del repo incluye además reglas custom y tuning del CRS):

```yaml
data:
  enable-modsecurity: "true"
  enable-owasp-modsecurity-crs: "true"
  modsecurity-snippet: |
    Include /etc/nginx/modsecurity/modsecurity.conf
    SecRuleEngine On
```

Las mismas opciones existen como anotaciones en un `Ingress` si preferís habilitar ModSecurity solo en rutas concretas; ver [documentación oficial](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#modsecurity).

## Paso 2 — Aplicar la configuración al cluster

No se hace `kubectl apply` de un ConfigMap nuevo. Se **parchea** el ConfigMap existente del controller:

```bash
kubectl patch configmap ingress-nginx-controller \
  -n ingress-nginx \
  --type merge \
  --patch-file dist/modsecurity-configmap.yaml
```

Equivalente al script del repo:

```bash
./waf-tests/demo/turn-waf-on.sh
```

El controller observa cambios en ese ConfigMap y recarga nginx en caliente (unos segundos). No hace falta `kubectl rollout restart` del deployment.

## Paso 3 — Verificar que el WAF está activo

Con la aplicación desplegada y accesible en `http://localhost`:

```bash
# Endpoint bloqueado por regla custom (id 1003): debe devolver 403 con WAF activo
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/info
```

- **403** → ModSecurity en modo bloqueo (`SecRuleEngine On`) y reglas aplicadas.
- **200** → el WAF no está activo o el parche no se aplicó.

Para contrastar con/sin WAF:

```bash
./waf-tests/demo/turn-waf-off.sh   # desactiva (enable-modsecurity: "false")
./waf-tests/demo/turn-waf-on.sh    # reaplica la configuración completa
```

Suite de pruebas automatizada: ver sección *Probar el WAF* del [README](./README.md).

## Paso 4 (opcional) — Inspeccionar logs de ModSecurity

Si un request devuelve `403`, la regla que disparó queda en el audit log del pod del controller:

```bash
kubectl -n ingress-nginx exec deploy/ingress-nginx-controller -- \
  sh -c 'find /var/log/audit -type f | sort | tail -1 | xargs cat'
```

## Checklist rápido

| # | Acción |
|---|--------|
| 1 | Cluster corriendo ([README](./README.md)) |
| 2 | ingress-nginx instalado y pod `Ready` |
| 3 | Revisar/editar `dist/modsecurity-configmap.yaml` si hace falta |
| 4 | `kubectl patch configmap ingress-nginx-controller -n ingress-nginx --type merge --patch-file dist/modsecurity-configmap.yaml` |
| 5 | Verificar con `curl` o `./waf-tests/run.sh` |

## Notas

- **Orden en `local.sh`:** al crear el entorno desde cero, el script instala ingress-nginx y luego ejecuta este mismo parche (`configure_modsecurity`).
- **Desactivar solo ModSecurity** sin perder el snippet guardado: `turn-waf-off.sh` pone `enable-modsecurity: "false"`; `turn-waf-on.sh` vuelve a aplicar el archivo completo.
- **Anotaciones vs ConfigMap:** si en vez del enfoque global quisieras WAF solo en un `Ingress`, agregarías anotaciones como `nginx.ingress.kubernetes.io/enable-modsecurity: "true"` en ese recurso; el módulo igual debe estar habilitado a nivel controller (ConfigMap o anotación por ruta).
