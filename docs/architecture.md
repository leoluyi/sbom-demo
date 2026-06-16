# Architecture

## Multi-layer approach

Each application language is inventoried with its **official CycloneDX
language-specific generator**, and the container's operating-system layer is
inventoried with **syft**. This keeps every layer's SBOM produced by the tool
that understands that ecosystem best.

| Layer | Tool | Format |
|-------|------|--------|
| **Node.js** (app) | [`@cyclonedx/cyclonedx-npm`](https://github.com/CycloneDX/cyclonedx-node-npm) | CycloneDX JSON |
| **Go** (app) | [`cyclonedx-gomod`](https://github.com/CycloneDX/cyclonedx-gomod) | CycloneDX JSON |
| **Java** (app) | [`cyclonedx-maven-plugin`](https://github.com/CycloneDX/cyclonedx-maven-plugin) | CycloneDX JSON |
| **Python** (app) | [`cyclonedx-py`](https://github.com/CycloneDX/cyclonedx-python) | CycloneDX JSON |
| **OS / container** | [`syft`](https://github.com/anchore/syft) | SPDX JSON |

Every generator runs as a pinned local Docker container. No SBOM data is sent to
any external analysis API; the only outbound traffic is to package registries
(npm / Go proxy / Maven Central / PyPI) while resolving dependencies, which an
on-prem mirror can serve in an air-gapped setup.

## Project layout

```
sbom-demo/
├── poc-app/
│   ├── backend/                 # Node.js service (express + lodash)
│   │   ├── package.json
│   │   ├── package-lock.json    # real, npm-generated lockfile (v3)
│   │   └── index.js
│   ├── service/                 # Go microservice (net/http + google/uuid)
│   │   ├── go.mod
│   │   ├── go.sum
│   │   └── main.go
│   ├── java-service/            # Java service (guava + slf4j)
│   │   ├── pom.xml              # declares the cyclonedx-maven-plugin
│   │   └── src/main/java/com/pocapp/App.java
│   ├── python-service/          # Python service (flask + requests)
│   │   ├── requirements.txt
│   │   └── main.py
│   ├── Dockerfile               # multi-stage: Go build + Node deps -> Alpine runtime
│   └── .dockerignore
├── generate-sbom.sh             # runs the four CycloneDX generators + syft
├── validate-sbom.py             # compliance validation + per-layer dependency counts
├── docs/                        # this documentation
└── sbom-outputs/                # generated artifacts (created on first run)
```

## The container image

`poc-app/Dockerfile` is a three-stage build that produces the image scanned for
the **OS layer**:

1. **go-builder** (`golang:1.26-alpine`) — compiles a static `microservice` binary.
2. **node-deps** (`node:20-alpine`) — runs `npm ci --omit=dev` for a deterministic
   production dependency set.
3. **runtime** (`node:20-alpine`) — carries both workloads. Alpine is chosen over
   distroless on purpose: it ships a real `apk`/`musl` OS package layer, giving
   syft a meaningful OS-level inventory.

The **Java** and **Python** services are application-level SBOM targets; they are
generated directly from source and are intentionally not baked into this image,
which stays minimal for the OS-layer demonstration.
