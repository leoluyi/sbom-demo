#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Validate generated SBOM artifacts for basic regulatory compliance.

For each SBOM it verifies the presence of the mandatory fields commonly
required by SBOM regulations (NTIA minimum elements / EU CRA style):

    * Author / Creator of the document
    * Component Name
    * Component Version
    * Licenses

It then reports the dependency counts per layer so the OS-level inventory
(SPDX, produced by syft) can be compared against the application-level
inventory (CycloneDX, produced by cdxgen).

The parsing/validation core lives in `sbom_common.py` so the HTML renderer
(`render-sbom.py`) reuses the exact same compliance logic.

Pure standard library; no network access; reads only local JSON files.

Usage:
    uv run validate-sbom.py [sbom-file ...]

With no arguments it scans ./sbom-outputs for *.cdx.json and *.spdx.json.
Exit code is non-zero when any hard requirement (author, or per-component
name/version) is missing, so the script is CI-friendly.
"""
from __future__ import annotations

import sys

from sbom_common import DEFAULT_DIR, Report, detect_and_validate, discover_files


def print_report(rep: Report) -> None:
    status = "PASS" if rep.ok else "FAIL"
    color = "\033[1;32m" if rep.ok else "\033[1;31m"
    reset = "\033[0m"
    total = rep.component_count or 1  # avoid divide-by-zero in display
    print(f"{color}[{status}]{reset} {rep.path.name}  ({rep.sbom_format} / {rep.layer})")
    print(f"        author        : {rep.author or '<missing>'}")
    print(f"        components     : {rep.component_count}")
    print(f"        with name      : {rep.with_name}/{rep.component_count}")
    print(f"        with version   : {rep.with_version}/{rep.component_count}")
    print(
        f"        with license   : {rep.with_license}/{rep.component_count} "
        f"({rep.with_license / total:.0%})"
    )
    for w in rep.warnings:
        print(f"        \033[1;33mwarn\033[0m: {w}")
    for e in rep.errors:
        print(f"        \033[1;31mfail\033[0m: {e}")


def main(argv: list[str]) -> int:
    files = discover_files(argv)
    if not files:
        print(f"No SBOM files found (looked in {DEFAULT_DIR}).", file=sys.stderr)
        return 2

    reports = [r for r in (detect_and_validate(p) for p in files) if r is not None]

    print("=" * 72)
    print("SBOM Compliance Validation")
    print("=" * 72)
    for rep in reports:
        print_report(rep)
        print("-" * 72)

    app_total = sum(r.component_count for r in reports if r.layer == "Application")
    os_total = sum(r.component_count for r in reports if r.layer == "OS / Container")
    print("Dependency totals by layer:")
    print(f"    Application components (CycloneDX) : {app_total}")
    print(f"    OS / container packages (SPDX)     : {os_total}")
    print(f"    Combined                           : {app_total + os_total}")
    print("=" * 72)

    failed = [r for r in reports if not r.ok]
    if failed:
        print(f"RESULT: FAIL ({len(failed)}/{len(reports)} artifact(s) have errors)")
        return 1
    print(f"RESULT: PASS (all {len(reports)} artifact(s) meet mandatory-field checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
