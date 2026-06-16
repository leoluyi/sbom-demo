# Generating the SBOMs

From the repository root:

```bash
./generate-sbom.sh
```

For each application component the script stages a throwaway copy of the sources
(so dependency resolution never pollutes your working tree), runs the matching
CycloneDX generator in its toolchain container, and stamps a document-level
author into the result. It then builds the container image, exports it to a
local `docker-archive` tarball, and runs syft against it offline.

See [implementation-notes.md](implementation-notes.md) for the per-language
details (Go license assertion, Python `uv` flow, author stamping).

## Output artifacts (`./sbom-outputs/`)

| File | Format | Layer |
|------|--------|-------|
| `node-backend.cdx.json`  | CycloneDX | Node.js application |
| `go-service.cdx.json`    | CycloneDX | Go application |
| `java-service.cdx.json`  | CycloneDX | Java application |
| `python-service.cdx.json`| CycloneDX | Python application |
| `container-os.spdx.json` | SPDX      | Container OS packages |

## Configuration

All settings are environment variables with sensible defaults.

| Variable | Default | Purpose |
|----------|---------|---------|
| `IMAGE_NAME` | `poc-app:sbom-demo` | tag of the image to build & scan |
| `OUTPUT_DIR` | `./sbom-outputs` | where artifacts are written |
| `SBOM_AUTHOR` | `SBOM PoC Team` | document author stamped into each CycloneDX BOM |
| `SKIP_BUILD` | `0` | set to `1` to reuse an existing image and skip `docker build` |
| `NODE_IMAGE` / `GO_IMAGE` / `MAVEN_IMAGE` / `PYTHON_IMAGE` / `SYFT_IMAGE` | see [prerequisites.md](prerequisites.md#pinned-tool-versions) | override any toolchain image (e.g. point at an internal mirror) |
| `CYCLONEDX_NPM_VERSION` / `CYCLONEDX_GOMOD_VERSION` / `CYCLONEDX_PY_VERSION` | see [prerequisites.md](prerequisites.md#pinned-tool-versions) | override a generator version |

Example — reuse an existing image and pull tools from an internal registry:

```bash
SKIP_BUILD=1 \
PYTHON_IMAGE=registry.internal/astral-sh/uv:python3.12-alpine \
./generate-sbom.sh
```
