# CRS tuning demo (pre-entrega 3.4)

Live demonstration of OWASP CRS **paranoia level**, **anomaly-score threshold**
and **rule exclusions** (false-positive tuning) on the ingress-nginx WAF.

Requires the local cluster up (`./local.sh create-cluster`) serving at
`http://localhost`.

## Scripts

| Script | Qué hace |
|--------|----------|
| `set-crs.sh` | Aplica una variante de tuning al WAF vivo. `--pl <1-4>`, `--threshold <N>`, `--exclude-fp`. |
| `demo-flip.sh` | Walkthrough en 3 actos (PL1 pasa → PL2 falso positivo → fix con exclusión / threshold). Restaura al final. |

```bash
# Demo completa, con pausas para narrar:
./demo-scripts/crs-tuning/demo-flip.sh

# Aplicar estados sueltos a mano:
./demo-scripts/crs-tuning/set-crs.sh --pl 2                 # sube paranoia a 2
./demo-scripts/crs-tuning/set-crs.sh --pl 2 --exclude-fp    # + exclusión quirúrgica
./demo-scripts/crs-tuning/set-crs.sh --pl 2 --threshold 20  # + threshold alto
./demo-scripts/turn-waf-on.sh                               # restaura el config committeado
```

## El caso

Búsqueda benigna `q=1+2-3*4/5=6` (un código de producto con símbolos):

| Estado | FP `1+2-3*4/5=6` | SQLi `' OR 1=1--` | XSS |
|--------|------------------|-------------------|-----|
| PL1 | 200 ✅ | 403 | 403 |
| PL2 (sin tuning) | **403** ❌ FP | 403 | 403 |
| **PL2 + exclusión** (default committeado) | 200 ✅ | 403 | 403 |
| PL2 + threshold 20 | 200 ✅ | 403 | 403 |

> El default committeado (`dist/modsecurity-configmap.yaml`) es **PL2 + threshold 5 + exclusión 932200/`ARGS:q`** (la 3.ª fila). Justificación completa en `docs/modsecurity.md` → Fase 4 → Decisión.

En PL2 la regla CRS **932200 "RCE Bypass Technique"** suma anomaly score 10 ≥
threshold 5 → la **949110** bloquea. La exclusión scopeada (`ctl:ruleRemoveTargetById=932200;ARGS:q`)
arregla el FP sin tocar SQLi/XSS; subir el threshold también lo arregla pero es global.

Datos de detección-vs-FP por paranoia level: `src/waf-tests/paranoia-sweep.sh`
(+ `paranoia-sweep.csv`, `plot-paranoia.py`).

## Cómo funciona (y gotchas)

- El **paranoia level / threshold se setean desde el ConfigMap** con un
  `SecAction setvar:tx.blocking_paranoia_level=N`. Funciona porque el
  `modsecurity-snippet` se carga **antes** del CRS (en `nginx.conf` el
  `modsecurity_rules` inline va antes del `modsecurity_rules_file` del CRS) y el
  init del CRS es *set-if-unset*.
- **Usar continuación de línea `\`** entre el operador y las acciones de cada
  `SecRule`. Reglas en una sola línea rompen el parser de `modsecurity_rules` y
  dejan el controller en crashloop.
- **No usar `kubectl rollout restart`** para aplicar cambios: el controller
  tiene un solo replica con hostPort 80 en kind → reiniciar causa downtime
  (502/000). El patch al ConfigMap recarga nginx **in-process (~6s)** sin downtime.
