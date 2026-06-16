"""Shared SBOM parsing and compliance core.

Used by both `validate-sbom.py` (CLI compliance gate) and `render-sbom.py`
(HTML report renderer) so the regulatory-field checks live in one place.

Pure standard library; no network access; reads only local JSON files.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Resolve the default scan directory relative to the repository root (this file
# lives at the root next to the SBOM scripts).
DEFAULT_DIR = Path(__file__).resolve().parent / "sbom-outputs"
# Components below this license-coverage ratio raise a warning (not a failure).
LICENSE_WARN_THRESHOLD = 0.80


@dataclass
class Report:
    path: Path
    sbom_format: str  # "CycloneDX" | "SPDX"
    layer: str  # "Application" | "OS / Container"
    component_count: int = 0
    author: str | None = None
    with_name: int = 0
    with_version: int = 0
    with_license: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _license_list_has_data(licenses) -> bool:
    if not isinstance(licenses, list) or not licenses:
        return False
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        if entry.get("expression"):
            return True
        lic = entry.get("license")
        if isinstance(lic, dict) and (lic.get("id") or lic.get("name")):
            return True
    return False


def has_cyclonedx_license(component: dict) -> bool:
    # A license counts whether it is asserted on the component or only carried as
    # tool-detected evidence (component.evidence.licenses), since both identify
    # the license for compliance purposes.
    if _license_list_has_data(component.get("licenses")):
        return True
    evidence = component.get("evidence")
    if isinstance(evidence, dict) and _license_list_has_data(evidence.get("licenses")):
        return True
    return False


def cyclonedx_author(data: dict) -> str | None:
    """Resolve a document-level author from the most authoritative location."""
    meta = data.get("metadata", {}) or {}
    authors = meta.get("authors")
    if isinstance(authors, list) and authors:
        names = [a.get("name") for a in authors if isinstance(a, dict) and a.get("name")]
        if names:
            return ", ".join(names)
    supplier = meta.get("supplier")
    if isinstance(supplier, dict) and supplier.get("name"):
        return supplier["name"]
    # Fall back to the generating tool as the "author" of record.
    tools = meta.get("tools")
    if isinstance(tools, dict):  # CycloneDX 1.5 tools.components form
        comps = tools.get("components") or []
        names = [c.get("name") for c in comps if isinstance(c, dict) and c.get("name")]
        if names:
            return "tool:" + ", ".join(names)
    if isinstance(tools, list) and tools:  # legacy tools[] form
        names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
        if names:
            return "tool:" + ", ".join(names)
    return None


def validate_cyclonedx(path: Path, data: dict) -> Report:
    rep = Report(path=path, sbom_format="CycloneDX", layer="Application")
    rep.author = cyclonedx_author(data)
    if not rep.author:
        rep.errors.append("missing document author (metadata.authors/supplier/tools)")

    components = data.get("components")
    if not isinstance(components, list):
        components = []
    rep.component_count = len(components)
    if rep.component_count == 0:
        rep.warnings.append("no components found in SBOM")

    for comp in components:
        if comp.get("name"):
            rep.with_name += 1
        if comp.get("version"):
            rep.with_version += 1
        if has_cyclonedx_license(comp):
            rep.with_license += 1

    _check_component_fields(rep)
    return rep


def has_spdx_license(pkg: dict) -> bool:
    for key in ("licenseConcluded", "licenseDeclared"):
        val = pkg.get(key)
        if val and val not in ("NOASSERTION", "NONE"):
            return True
    return False


def spdx_author(data: dict) -> str | None:
    creators = (data.get("creationInfo", {}) or {}).get("creators")
    if isinstance(creators, list) and creators:
        return "; ".join(str(c) for c in creators)
    return None


def validate_spdx(path: Path, data: dict) -> Report:
    rep = Report(path=path, sbom_format="SPDX", layer="OS / Container")
    rep.author = spdx_author(data)
    if not rep.author:
        rep.errors.append("missing creator (creationInfo.creators)")

    packages = data.get("packages")
    if not isinstance(packages, list):
        packages = []
    rep.component_count = len(packages)
    if rep.component_count == 0:
        rep.warnings.append("no packages found in SBOM")

    for pkg in packages:
        if pkg.get("name"):
            rep.with_name += 1
        # SPDX stores the version under versionInfo.
        if pkg.get("versionInfo"):
            rep.with_version += 1
        if has_spdx_license(pkg):
            rep.with_license += 1

    _check_component_fields(rep)
    return rep


def _check_component_fields(rep: Report) -> None:
    total = rep.component_count
    if total == 0:
        return
    if rep.with_name < total:
        rep.errors.append(f"{total - rep.with_name} component(s) missing a name")
    if rep.with_version < total:
        # Some OS packages legitimately lack a version; treat as warning for SPDX.
        msg = f"{total - rep.with_version} component(s) missing a version"
        (rep.warnings if rep.sbom_format == "SPDX" else rep.errors).append(msg)
    coverage = rep.with_license / total
    if coverage < LICENSE_WARN_THRESHOLD:
        rep.warnings.append(
            f"license coverage {coverage:.0%} below {LICENSE_WARN_THRESHOLD:.0%} "
            f"({rep.with_license}/{total} components have license data)"
        )


def detect_and_validate(path: Path) -> Report | None:
    try:
        data = load_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        rep = Report(path=path, sbom_format="unknown", layer="unknown")
        rep.errors.append(f"could not parse JSON: {exc}")
        return rep

    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        return validate_cyclonedx(path, data)
    if "spdxVersion" in data or "SPDXID" in data:
        return validate_spdx(path, data)

    rep = Report(path=path, sbom_format="unknown", layer="unknown")
    rep.errors.append("unrecognized SBOM format (not CycloneDX or SPDX)")
    return rep


def discover_files(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    if not DEFAULT_DIR.is_dir():
        return []
    return sorted(
        p for p in DEFAULT_DIR.iterdir()
        if p.suffix == ".json" and (".cdx" in p.name or ".spdx" in p.name)
    )
