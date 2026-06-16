# Prerequisites

## Host requirements

| Requirement | Used for | Notes |
|-------------|----------|-------|
| **Docker** (daemon running) | building the image; running every generator & syft | the only requirement for SBOM generation |
| **jq** | stamping the document author into each CycloneDX BOM | invoked by `generate-sbom.sh` |
| **uv** | running `validate-sbom.py` | [Astral uv](https://docs.astral.sh/uv/); provides the Python runtime, no separate `python3` needed |

You do **not** need `node`, `go`, `java`/`maven`, `python`, `cyclonedx-*`, or
`syft` installed on the host — they all run inside containers, pulled
automatically on first run.

## Pinned tool versions

Every toolchain image and generator is pinned for reproducibility. Each is
overridable via an environment variable (see
[generating-sboms.md](generating-sboms.md#configuration)).

| Component | Pinned version |
|-----------|----------------|
| `node:20-alpine` + `@cyclonedx/cyclonedx-npm` | `1.19.3` |
| `golang:1.26-alpine` + `cyclonedx-gomod` | `v1.9.0` |
| `maven:3.9-eclipse-temurin-21` + `cyclonedx-maven-plugin` | `2.9.1` (pinned in `pom.xml`) |
| `ghcr.io/astral-sh/uv:python3.12-alpine` + `cyclonedx-bom` | `7.3.0` |
| `anchore/syft` | `v1.18.1` |
