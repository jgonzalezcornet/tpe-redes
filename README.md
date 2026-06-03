# The Store

[![Build](https://github.com/jupmoreno/the-store/actions/workflows/main.yml/badge.svg)](https://github.com/jupmoreno/the-store/actions/workflows/main.yml)

**The Store** is a modern e-commerce platform built with microservices architecture.

Our platform provides a complete shopping experience with:
- **Beautiful storefront** with customizable themes and responsive design
- **Scalable microservices** built with multiple languages and frameworks
- **Real-time inventory management** and order processing

## 🏗️ Architecture

The Store is built with a microservices architecture that uses different technologies:

![Architecture](/docs/images/architecture.png)

| Service | Language | Description |
|---------|----------|-------------|
| [UI](./src/ui/) | Java (Spring Boot) | Modern web interface with themes and chat bot |
| [Catalog](./src/catalog/) | Go | Product catalog API with search and filtering |
| [Cart](./src/cart/) | Java (Spring Boot) | Shopping cart management with Redis/DynamoDB |
| [Orders](./src/orders/) | Java (Spring Boot) | Order processing and management |
| [Checkout](./src/checkout/) | Node.js (NestJS) | Checkout orchestration and payment processing |


## 🛠️ Development

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) running
- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) installed
- [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) installed

### Cluster Management

Use the `local.sh` script to manage your local Kubernetes cluster:

```bash
# Create a new cluster and deploy all services
./local.sh create-cluster

# Rebuild the entire cluster (delete and recreate)
./local.sh rebuild-cluster

# Delete the cluster
./local.sh delete-cluster

# Check cluster status
./local.sh status

# Build and load Docker images only
./local.sh reload-images
```

After running `./local.sh create-cluster`, access The Store at: **http://localhost**.

### Testing

#### E2E Testing

Run end-to-end tests to validate the complete system:

```bash
# Run e2e tests on existing cluster
./local.sh e2e-test
```

**Note**: These tests are run automatically when creating or rebuilding the cluster. You can skip them using the `--skip-tests` parameter for faster setup:

```bash
# Create cluster without running tests (faster setup)
./local.sh create-cluster --skip-tests

# Rebuild cluster without running tests
./local.sh rebuild-cluster --skip-tests
```

#### Load Testing
Run load generator tests to validate system performance:

```bash
# Run load generator tests
./local.sh load-test
```

The load generator will run performance tests against your local cluster for 10 minutes (or until manually stopped) to validate system behavior under load.

## 🛡️ WAF (ModSecurity + OWASP CRS)

El cluster despliega un Web Application Firewall en el borde (ModSecurity + OWASP CRS sobre el ingress-nginx), configurado vía `dist/modsecurity-configmap.yaml` y aplicado automáticamente por `local.sh`. Cubre los casos del pre-entrega (IDOR, endpoints administrativos, exposición de info sensible, SQLi/XSS/path-traversal, detección de scanners) y corre en **paranoia level 2** con anomaly threshold 5 y una exclusión scopeada.

```bash
# Validar el WAF (con el cluster levantado):
./src/waf-tests/attacks.sh       # ataques del pre-entrega → 403 (18/18)
./src/waf-tests/happy-path.sh    # tráfico legítimo → 200 (13/13)
```

Documentación:
- [`docs/modsecurity.md`](./docs/modsecurity.md) — reglas, implementación y el análisis de tuning del CRS (paranoia level, anomaly scoring, rule exclusions).
- [`docs/waf-demo.md`](./docs/waf-demo.md) — runbook para reproducir los ataques (con vs. sin WAF) y la demo del tuning.

---

**The Store** - Built with ❤️ for modern e-commerce
