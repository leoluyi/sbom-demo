#!/usr/bin/env bash
#
# generate-sbom.sh
# -----------------------------------------------------------------------------
# Local, on-premises SBOM generation for the poc-app multi-language project,
# using the OFFICIAL CycloneDX language-specific generators (one per language)
# for the application layers and syft for the OS / container layer.
#
#   Layer            Tool                                  Output
#   ---------------- ------------------------------------- --------------------------
#   Node.js  (app)   @cyclonedx/cyclonedx-npm              node-backend.cdx.json
#   Next.js  (app)   @cyclonedx/cyclonedx-npm              nextjs-frontend.cdx.json
#   Go       (app)   cyclonedx-gomod                       go-service.cdx.json
#   Java     (app)   cyclonedx-maven-plugin                java-service.cdx.json
#   Python   (app)   cyclonedx-py (cyclonedx-bom)          python-service.cdx.json
#   OS / image       syft                                  container-os.spdx.json
#
# Every generator runs as a pinned Docker container; nothing is sent to an
# external SBOM/analysis API. The only network calls are to package registries
# (npm / Go proxy / Maven Central / PyPI) while resolving dependencies, which an
# on-prem mirror can serve.
#
# Usage:   ./generate-sbom.sh
# Host requirements: docker (daemon running), jq, bash.
# -----------------------------------------------------------------------------
set -euo pipefail

# --- configuration -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}/poc-app"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/sbom-outputs}"

IMAGE_NAME="${IMAGE_NAME:-poc-app:sbom-demo}"
SBOM_AUTHOR="${SBOM_AUTHOR:-SBOM PoC Team}"
SKIP_BUILD="${SKIP_BUILD:-0}"
# Set to 1 to skip the HTML rendering step (SBOM JSON is still produced).
SKIP_RENDER="${SKIP_RENDER:-0}"

# Base images carrying each language toolchain (pinned for reproducibility).
NODE_IMAGE="${NODE_IMAGE:-node:20-alpine}"
GO_IMAGE="${GO_IMAGE:-golang:1.26-alpine}"
MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}"
PYTHON_IMAGE="${PYTHON_IMAGE:-ghcr.io/astral-sh/uv:python3.12-alpine}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.18.1}"

# HTML rendering: sbom-utility (CycloneDX inventory/licenses) is go-installed in a Go
# toolchain image; the renderer runs under the uv image so it can resolve spdx-tools.
SBOM_UTILITY_IMAGE="${SBOM_UTILITY_IMAGE:-${GO_IMAGE}}"
SBOM_UTILITY_VERSION="${SBOM_UTILITY_VERSION:-v0.19.1}"
PYTHON_RENDER_IMAGE="${PYTHON_RENDER_IMAGE:-${PYTHON_IMAGE}}"

# Generator versions (the Maven plugin version is pinned in poc-app/java-service/pom.xml).
CYCLONEDX_NPM_VERSION="${CYCLONEDX_NPM_VERSION:-1.19.3}"
CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}"
# cyclonedx-bom 7.x reads PEP 639 License-Expression metadata; older lines miss it.
CYCLONEDX_PY_VERSION="${CYCLONEDX_PY_VERSION:-7.3.0}"

NODE_SBOM="${OUTPUT_DIR}/node-backend.cdx.json"
GO_SBOM="${OUTPUT_DIR}/go-service.cdx.json"
JAVA_SBOM="${OUTPUT_DIR}/java-service.cdx.json"
PYTHON_SBOM="${OUTPUT_DIR}/python-service.cdx.json"
FRONTEND_SBOM="${OUTPUT_DIR}/nextjs-frontend.cdx.json"
OS_SBOM="${OUTPUT_DIR}/container-os.spdx.json"

HTML_DIR="${OUTPUT_DIR}/html"
RENDER_TMP="${OUTPUT_DIR}/.render-tmp"

# --- logging helpers ---------------------------------------------------------
log()  { printf '\033[1;34m[sbom]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[sbom][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[sbom][error]\033[0m %s\n' "$*" >&2; exit 1; }

# --- cleanup -----------------------------------------------------------------
# Staging dirs are tracked here and removed by a single EXIT trap, so cleanup
# survives early exits without leaking per-function RETURN traps.
STAGES=()
cleanup() {
  local rc=$? d
  for d in "${STAGES[@]:-}"; do
    [ -n "${d}" ] && rm -rf "${d}"
  done
  return "${rc}"
}
trap cleanup EXIT

# --- preflight ---------------------------------------------------------------
preflight() {
  command -v docker >/dev/null 2>&1 || die "docker is required but not found on PATH"
  command -v jq >/dev/null 2>&1 || die "jq is required but not found on PATH"
  docker info >/dev/null 2>&1 || die "docker daemon is not reachable (is Docker running?)"
  for d in backend frontend service java-service python-service; do
    [ -d "${APP_DIR}/${d}" ] || die "missing ${APP_DIR}/${d}"
  done
  mkdir -p "${OUTPUT_DIR}"
  log "output directory: ${OUTPUT_DIR}"
}

# --- stamp a document-level author/supplier onto a CycloneDX BOM -------------
# The CycloneDX language generators do not populate metadata.authors, which is a
# mandatory compliance field, so we stamp it post-generation (idempotent).
stamp_author() {
  local file="$1" tmp
  tmp="$(mktemp)"
  jq --arg a "${SBOM_AUTHOR}" '
    .metadata = (.metadata // {})
    | .metadata.authors = [{"name": $a}]
    | .metadata.supplier = {"name": $a}
  ' "${file}" > "${tmp}" || die "failed to stamp author into ${file}"
  mv "${tmp}" "${file}"
}

finalize_app_sbom() {
  local out="$1" name="$2"
  [ -s "${out}" ] || die "no SBOM produced for ${name} at ${out}"
  stamp_author "${out}"
  log "wrote ${out}"
}

# --- per-language application SBOMs ------------------------------------------
generate_node_sbom() {
  log "Node.js  -> cyclonedx-npm"
  local stage; stage="$(mktemp -d)"; STAGES+=("${stage}")
  cp "${APP_DIR}/backend/package.json" "${APP_DIR}/backend/package-lock.json" "${stage}/"
  docker run --rm -i -e VER="${CYCLONEDX_NPM_VERSION}" -v "${stage}:/work" -w /work "${NODE_IMAGE}" sh -s <<'EOSH' \
    || die "cyclonedx-npm failed"
set -e
npm ci --omit=dev --no-audit --no-fund >/dev/null 2>&1
npx --yes "@cyclonedx/cyclonedx-npm@${VER}" \
  --omit dev --spec-version 1.6 --output-format JSON --output-file /work/out.json >/dev/null 2>&1
EOSH
  cp "${stage}/out.json" "${NODE_SBOM}"
  finalize_app_sbom "${NODE_SBOM}" "poc-app-backend"
}

generate_frontend_sbom() {
  log "Next.js  -> cyclonedx-npm (frontend)"
  local stage; stage="$(mktemp -d)"; STAGES+=("${stage}")
  cp "${APP_DIR}/frontend/package.json" "${APP_DIR}/frontend/package-lock.json" "${stage}/"
  docker run --rm -i -e VER="${CYCLONEDX_NPM_VERSION}" -v "${stage}:/work" -w /work "${NODE_IMAGE}" sh -s <<'EOSH' \
    || die "cyclonedx-npm (frontend) failed"
set -e
npm ci --omit=dev --no-audit --no-fund >/dev/null 2>&1
npx --yes "@cyclonedx/cyclonedx-npm@${VER}" \
  --omit dev --spec-version 1.6 --output-format JSON --output-file /work/out.json >/dev/null 2>&1
EOSH
  cp "${stage}/out.json" "${FRONTEND_SBOM}"
  finalize_app_sbom "${FRONTEND_SBOM}" "poc-app-frontend"
}

generate_go_sbom() {
  log "Go       -> cyclonedx-gomod"
  local stage; stage="$(mktemp -d)"; STAGES+=("${stage}")
  cp -R "${APP_DIR}/service/." "${stage}/"
  # cyclonedx-gomod (app mode) needs a VCS to version the main module; the stage
  # is a throwaway copy, so initialising a git repo here is harmless.
  docker run --rm -i -e VER="${CYCLONEDX_GOMOD_VERSION}" -v "${stage}:/work" -w /work "${GO_IMAGE}" sh -s <<'EOSH' \
    || die "cyclonedx-gomod failed"
set -e
apk add --no-cache git >/dev/null 2>&1
git init -q
git config user.email sbom@poc.local && git config user.name sbom-poc
git add -A && git commit -qm "sbom snapshot" && git tag v0.0.0
go install "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@${VER}" >/dev/null 2>&1
go mod download
# -assert-licenses promotes heuristically detected licenses from
# component.evidence.licenses into the conventional component.licenses field.
"$(go env GOPATH)/bin/cyclonedx-gomod" app -json -licenses -assert-licenses -output /work/out.json .
EOSH
  cp "${stage}/out.json" "${GO_SBOM}"
  finalize_app_sbom "${GO_SBOM}" "poc-app-microservice"
}

generate_java_sbom() {
  log "Java     -> cyclonedx-maven-plugin"
  local stage; stage="$(mktemp -d)"; STAGES+=("${stage}")
  cp -R "${APP_DIR}/java-service/." "${stage}/"
  docker run --rm -i -v "${stage}:/work" -w /work "${MAVEN_IMAGE}" sh -s <<'EOSH' \
    || die "cyclonedx-maven-plugin failed"
set -e
mvn -q -B -DskipTests cyclonedx:makeBom
cp /work/target/bom.json /work/out.json
EOSH
  cp "${stage}/out.json" "${JAVA_SBOM}"
  finalize_app_sbom "${JAVA_SBOM}" "poc-app-java-service"
}

generate_python_sbom() {
  log "Python   -> cyclonedx-py (via uv)"
  local stage; stage="$(mktemp -d)"; STAGES+=("${stage}")
  cp -R "${APP_DIR}/python-service/." "${stage}/"
  # uv builds an isolated venv with only the application's dependencies; cyclonedx-py
  # runs through `uvx` in its own ephemeral env, so the generator's own packages
  # never leak into the SBOM that introspects the app venv.
  docker run --rm -i -e PY_VER="${CYCLONEDX_PY_VERSION}" -v "${stage}:/work" -w /work "${PYTHON_IMAGE}" sh -s <<'EOSH' \
    || die "cyclonedx-py failed"
set -e
uv venv /tmp/venv >/dev/null 2>&1
uv pip install --python /tmp/venv -r requirements.txt >/dev/null 2>&1
uvx --from "cyclonedx-bom==${PY_VER}" cyclonedx-py environment /tmp/venv -o /work/out.json
EOSH
  cp "${stage}/out.json" "${PYTHON_SBOM}"
  finalize_app_sbom "${PYTHON_SBOM}" "poc-app-python-service"
}

# --- container image + OS-level SBOM -----------------------------------------
build_image() {
  if [ "${SKIP_BUILD}" = "1" ]; then
    log "SKIP_BUILD=1; reusing existing image ${IMAGE_NAME}"
    return
  fi
  log "building container image ${IMAGE_NAME} (Node + Go runtime)"
  docker build -t "${IMAGE_NAME}" -f "${APP_DIR}/Dockerfile" "${APP_DIR}"
}

generate_os_sbom() {
  log "OS layer -> syft (SPDX)"
  local tar="${OUTPUT_DIR}/.image.tar"
  docker save -o "${tar}" "${IMAGE_NAME}"
  docker run --rm -v "${OUTPUT_DIR}:/scan" "${SYFT_IMAGE}" \
    scan "docker-archive:/scan/$(basename "${tar}")" -o spdx-json -q \
    > "${OS_SBOM}" || die "syft failed for ${IMAGE_NAME}"
  rm -f "${tar}"
  [ -s "${OS_SBOM}" ] || die "syft produced no output at ${OS_SBOM}"
  log "wrote ${OS_SBOM}"
}

# --- HTML reports ------------------------------------------------------------
# Two stages: sbom-utility extracts CycloneDX inventory/license data as CSV/JSON,
# then render-sbom.py (under uv, so spdx-tools resolves) turns every artifact -
# including the SPDX OS layer - into a per-artifact HTML report plus an index.
render_html() {
  if [ "${SKIP_RENDER}" = "1" ]; then
    log "SKIP_RENDER=1; skipping HTML rendering"
    return
  fi
  mkdir -p "${HTML_DIR}" "${RENDER_TMP}"
  STAGES+=("${RENDER_TMP}")

  log "HTML stage 1/2 -> sbom-utility (CycloneDX inventory + licenses)"
  docker run --rm -i -e VER="${SBOM_UTILITY_VERSION}" -v "${OUTPUT_DIR}:/out" -w /out \
    "${SBOM_UTILITY_IMAGE}" sh -s <<'EOSH' || die "sbom-utility extraction failed"
set -e
apk add --no-cache git >/dev/null 2>&1
go install "github.com/CycloneDX/sbom-utility@${VER}" >/dev/null 2>&1
SU="$(go env GOPATH)/bin/sbom-utility"
for f in /out/*.cdx.json; do
  base="$(basename "${f}" .cdx.json)"
  "${SU}" component list -i "${f}" --format csv -q > "/out/.render-tmp/${base}.components.csv"
  "${SU}" license list -i "${f}" --summary --format json -q > "/out/.render-tmp/${base}.licenses.json"
done
EOSH

  log "HTML stage 2/2 -> render-sbom.py (CycloneDX + SPDX -> HTML)"
  docker run --rm -v "${SCRIPT_DIR}:/app" -v "${OUTPUT_DIR}:/out" -w /app \
    "${PYTHON_RENDER_IMAGE}" \
    uv run render-sbom.py --input-dir /out --util-dir /out/.render-tmp --output-dir /out/html \
    || die "render-sbom.py failed"
  log "wrote HTML reports to ${HTML_DIR}"
}

main() {
  preflight
  build_image
  generate_node_sbom
  generate_frontend_sbom
  generate_go_sbom
  generate_java_sbom
  generate_python_sbom
  generate_os_sbom
  render_html
  log "done. artifacts:"
  ls -1 "${OUTPUT_DIR}"
}

main "$@"
