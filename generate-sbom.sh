#!/usr/bin/env bash
#
# generate-sbom.sh
# -----------------------------------------------------------------------------
# Local, on-premises SBOM generation for the poc-app multi-language project.
#
# Produces three artifacts under ./sbom-outputs/ :
#   * node-backend.cdx.json   - application SBOM for the Node.js backend (CycloneDX)
#   * go-service.cdx.json     - application SBOM for the Go microservice  (CycloneDX)
#   * container-os.spdx.json  - OS-level SBOM of the built image          (SPDX)
#
# All tooling runs as pinned Docker containers; nothing is sent to an external
# SBOM/analysis API. The only network calls are to package registries (npm /
# Go proxy) while resolving dependencies, which an on-prem mirror can serve.
#
# Usage:   ./generate-sbom.sh
# Env overrides:
#   IMAGE_NAME      final image tag to build & scan   (default: poc-app:sbom-demo)
#   OUTPUT_DIR      artifact directory                (default: ./sbom-outputs)
#   CDXGEN_IMAGE    cdxgen container image            (default: ghcr.io/cyclonedx/cdxgen:v11)
#   SYFT_IMAGE      syft container image              (default: anchore/syft:v1.18.1)
#   SBOM_AUTHOR     document author metadata          (default: SBOM PoC Team)
#   SKIP_BUILD      set to 1 to reuse an existing image
# -----------------------------------------------------------------------------
set -euo pipefail

# --- configuration -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}/poc-app"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/sbom-outputs}"

IMAGE_NAME="${IMAGE_NAME:-poc-app:sbom-demo}"
CDXGEN_IMAGE="${CDXGEN_IMAGE:-ghcr.io/cyclonedx/cdxgen:v11.7.0}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.18.1}"
SBOM_AUTHOR="${SBOM_AUTHOR:-SBOM PoC Team}"
SKIP_BUILD="${SKIP_BUILD:-0}"

NODE_SBOM="${OUTPUT_DIR}/node-backend.cdx.json"
GO_SBOM="${OUTPUT_DIR}/go-service.cdx.json"
OS_SBOM="${OUTPUT_DIR}/container-os.spdx.json"

# --- logging helpers ---------------------------------------------------------
log()  { printf '\033[1;34m[sbom]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[sbom][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[sbom][error]\033[0m %s\n' "$*" >&2; exit 1; }

# --- cleanup -----------------------------------------------------------------
# Staging dirs are tracked here and removed by a single EXIT trap, so cleanup
# survives early exits without leaking per-function RETURN traps.
STAGES=()
cleanup() {
  local d
  for d in "${STAGES[@]:-}"; do
    [ -n "${d}" ] && rm -rf "${d}"
  done
}
trap cleanup EXIT

# --- preflight ---------------------------------------------------------------
preflight() {
  command -v docker >/dev/null 2>&1 || die "docker is required but not found on PATH"
  docker info >/dev/null 2>&1 || die "docker daemon is not reachable (is Docker running?)"
  [ -d "${APP_DIR}/backend" ] || die "missing ${APP_DIR}/backend"
  [ -d "${APP_DIR}/service" ] || die "missing ${APP_DIR}/service"
  mkdir -p "${OUTPUT_DIR}"
  log "output directory: ${OUTPUT_DIR}"
}

# --- build the container image so syft has something to scan ------------------
build_image() {
  if [ "${SKIP_BUILD}" = "1" ]; then
    log "SKIP_BUILD=1; reusing existing image ${IMAGE_NAME}"
    return
  fi
  log "building container image ${IMAGE_NAME}"
  docker build -t "${IMAGE_NAME}" -f "${APP_DIR}/Dockerfile" "${APP_DIR}"
}

# --- run cdxgen against a staged copy of a component --------------------------
# Args: <component-subdir> <cdxgen-type> <output-file> <component-name>
# The component is copied to a throwaway staging dir so that --install-deps does
# not pollute the source tree; licenses are read from locally resolved packages.
generate_app_sbom() {
  local subdir="$1" ctype="$2" outfile="$3" cname="$4"
  local src="${APP_DIR}/${subdir}"
  local stage
  stage="$(mktemp -d)"
  STAGES+=("${stage}")

  log "generating CycloneDX SBOM for ${cname} (type=${ctype})"
  # Copy source (lockfiles + sources) into the staging dir.
  cp -R "${src}/." "${stage}/"

  # cdxgen writes the BOM to /out inside the container.
  docker run --rm \
    -v "${stage}:/app" \
    -v "${OUTPUT_DIR}:/out" \
    -e FETCH_LICENSE=false \
    "${CDXGEN_IMAGE}" \
      -t "${ctype}" \
      --install-deps \
      --author "${SBOM_AUTHOR}" \
      --project-name "${cname}" \
      -o "/out/$(basename "${outfile}")" \
      /app \
    || die "cdxgen failed for ${cname}"

  [ -s "${outfile}" ] || die "cdxgen produced no output at ${outfile}"
  log "wrote ${outfile}"
}

# --- scan the final image for OS-level packages with syft --------------------
generate_os_sbom() {
  log "exporting ${IMAGE_NAME} to a docker-archive for offline scanning"
  local tar="${OUTPUT_DIR}/.image.tar"
  docker save -o "${tar}" "${IMAGE_NAME}"

  log "generating SPDX OS-level SBOM with syft"
  # syft reads the archive scheme directly; SBOM goes to stdout, logs to stderr.
  docker run --rm \
    -v "${OUTPUT_DIR}:/scan" \
    "${SYFT_IMAGE}" \
      scan "docker-archive:/scan/$(basename "${tar}")" \
      -o spdx-json \
      -q \
    > "${OS_SBOM}" \
    || die "syft failed for ${IMAGE_NAME}"

  rm -f "${tar}"
  [ -s "${OS_SBOM}" ] || die "syft produced no output at ${OS_SBOM}"
  log "wrote ${OS_SBOM}"
}

main() {
  preflight
  build_image
  generate_app_sbom "backend" "javascript" "${NODE_SBOM}" "poc-app-backend"
  generate_app_sbom "service" "golang"     "${GO_SBOM}"   "poc-app-microservice"
  generate_os_sbom
  log "done. artifacts:"
  ls -1 "${OUTPUT_DIR}"
}

main "$@"
