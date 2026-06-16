# Implementation notes

These are the non-obvious decisions behind reliable, license-complete output.

## Author stamping

The CycloneDX language generators populate `metadata.tools` but not a
document-level `metadata.authors`, which is a mandatory compliance field.
`generate-sbom.sh` stamps `metadata.authors` and `metadata.supplier` (from
`SBOM_AUTHOR`) into each BOM with `jq` after generation.

## Go licenses

`cyclonedx-gomod` detects module licenses heuristically and, by default, records
them under `component.evidence.licenses`. The script passes `-assert-licenses`
so detected licenses are promoted into the conventional `component.licenses`
field as well. The validator counts a license in either location.

## Python licenses & uv

The Python SBOM is built from an isolated `uv` venv containing only the app's
dependencies, and `cyclonedx-py` runs through `uvx` in its own ephemeral
environment, so the generator's packages never leak into the SBOM. `cyclonedx-bom`
is pinned to `7.x` because earlier lines do not read PEP 639 `License-Expression`
metadata used by several common packages (e.g. MarkupSafe, Werkzeug, click,
idna, urllib3).
