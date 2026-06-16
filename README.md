# Multi-Layer SBOM Generation PoC

A self-contained, on-premises proof of concept for **automated, multi-layer
Software Bill of Materials (SBOM) generation**. It demonstrates how to inventory
a multi-language application across two distinct layers:

| Layer | Tool | Format | What it captures |
|-------|------|--------|------------------|
| **Application** (Node.js) | [cdxgen](https://github.com/CycloneDX/cdxgen) | CycloneDX JSON | npm dependency tree + licenses |
| **Application** (Go) | cdxgen | CycloneDX JSON | Go module dependencies |
| **OS / Container** | [syft](https://github.com/anchore/syft) | SPDX JSON | apk/OS packages in the built image |

All tooling runs as **pinned local Docker containers**. No SBOM data is sent to
any external analysis API. The only outbound traffic is to package registries
(npm / Go proxy) while resolving dependencies — an on-prem mirror can serve these
in an air-gapped setup.

---

## 1. Project layout

```
sbom-demo/
├── poc-app/                     # the mock multi-language application
│   ├── backend/                 # Node.js service
│   │   ├── package.json
│   │   ├── package-lock.json    # real, npm-generated lockfile (v3)
│   │   └── index.js             # express + lodash
│   ├── service/                 # Go microservice
│   │   ├── go.mod
│   │   ├── go.sum
│   │   └── main.go              # net/http + google/uuid
│   ├── Dockerfile               # multi-stage: Go build + Node deps -> Alpine runtime
│   └── .dockerignore
├── generate-sbom.sh             # orchestrates cdxgen + syft, writes ./sbom-outputs/
├── validate-sbom.py             # compliance validation + per-layer dependency counts
├── sbom-outputs/                # generated artifacts (created on first run)
└── README.md
```

### The container image

`poc-app/Dockerfile` is a three-stage build:

1. **go-builder** (`golang:1.26-alpine`) — compiles a static `microservice` binary.
2. **node-deps** (`node:20-alpine`) — runs `npm ci --omit=dev` for a deterministic
   production dependency set.
3. **runtime** (`node:20-alpine`) — carries **both** workloads. Alpine is chosen
   over distroless on purpose: it ships a real `apk`/`musl` OS package layer, which
   gives syft a meaningful OS-level inventory to demonstrate the OS-vs-application
   separation.

---

## 2. Prerequisites

| Requirement | Used for | Notes |
|-------------|----------|-------|
| **Docker** (daemon running) | building the image; running cdxgen & syft | the only hard requirement for generation |
| **Bash** | `generate-sbom.sh` | ships with macOS/Linux |
| **Python 3.8+** | `validate-sbom.py` | standard library only, no `pip install` |

You do **not** need `node`, `go`, `cdxgen`, or `syft` installed on the host —
they run inside containers. The container images are pulled automatically on
first run and pinned to specific versions for reproducibility:

- `ghcr.io/cyclonedx/cdxgen:v11.7.0`
- `anchore/syft:v1.18.1`

---

## 3. Generating the SBOMs

From the repository root:

```bash
./generate-sbom.sh
```

This will:

1. Build the container image (`poc-app:sbom-demo`).
2. Run **cdxgen** against a throwaway staged copy of the Node and Go sources
   (so dependency installation never pollutes your working tree) and write
   CycloneDX SBOMs.
3. Export the image to a local `docker-archive` tarball and run **syft** against
   it offline, writing an SPDX SBOM.

### Output artifacts (`./sbom-outputs/`)

| File | Format | Layer |
|------|--------|-------|
| `node-backend.cdx.json` | CycloneDX 1.6 | Node.js application |
| `go-service.cdx.json`   | CycloneDX 1.6 | Go application |
| `container-os.spdx.json`| SPDX 2.3      | Container OS packages |

### Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `IMAGE_NAME` | `poc-app:sbom-demo` | tag of the image to build & scan |
| `OUTPUT_DIR` | `./sbom-outputs` | where artifacts are written |
| `CDXGEN_IMAGE` | `ghcr.io/cyclonedx/cdxgen:v11.7.0` | cdxgen container |
| `SYFT_IMAGE` | `anchore/syft:v1.18.1` | syft container |
| `SBOM_AUTHOR` | `SBOM PoC Team` | document author recorded in the CycloneDX metadata |
| `SKIP_BUILD` | `0` | set to `1` to reuse an already-built image and skip `docker build` |

Example — reuse an existing image and point at an internal mirror:

```bash
SKIP_BUILD=1 \
CDXGEN_IMAGE=registry.internal/cyclonedx/cdxgen:v11.7.0 \
./generate-sbom.sh
```

---

## 4. Validating compliance

```bash
python3 validate-sbom.py
```

With no arguments it scans `./sbom-outputs/`. You can also pass explicit files:

```bash
python3 validate-sbom.py sbom-outputs/node-backend.cdx.json
```

For each artifact it checks the **mandatory regulatory fields** (NTIA minimum
elements / EU CRA style) and reports per-layer dependency counts.

### How to read the output

```
[PASS] node-backend.cdx.json  (CycloneDX / Application)
        author        : SBOM PoC Team          <- document Author present
        components     : 69                     <- total dependencies in this layer
        with name      : 69/69                  <- Component Name coverage
        with version   : 69/69                  <- Version coverage
        with license   : 69/69 (100%)           <- License coverage
...
Dependency totals by layer:
    Application components (CycloneDX) : 70     <- Node + Go application deps
    OS / container packages (SPDX)     : 297    <- OS packages from syft
    Combined                           : 367
RESULT: PASS (all 3 artifact(s) meet mandatory-field checks)
```

Severity model:

- **`fail`** (non-zero exit): a hard requirement is missing — no document
  author, or an application component with no name/version. Breaks CI.
- **`warn`** (still passes): license coverage below 80%, or OS packages without
  a version. Surfaced as a compliance gap to review, not a blocker.

The script exits `0` when every artifact passes and `1` when any artifact has a
hard error, so it can be wired directly into a pipeline gate.

> **Known gap — Go licenses.** cdxgen cannot resolve Go module licenses without
> network access to each module's source, so `go-service.cdx.json` shows 0%
> license coverage and a warning. This is an accurate compliance finding, not a
> tooling failure. Resolving it requires a license-enrichment pass (e.g. an
> on-prem `go-licenses` cache) which is out of scope for this PoC.

---

## 5. End-to-end run

```bash
./generate-sbom.sh        # produces ./sbom-outputs/*.json
python3 validate-sbom.py  # prints the compliance report, exits 0/1
```

Both steps are local and idempotent. Re-running regenerates the artifacts in
place; staging directories are cleaned up automatically on exit.
