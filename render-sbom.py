#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["spdx-tools>=0.8"]
# ///
"""Render SBOM artifacts into per-artifact HTML reports.

Division of labour (see docs/rendering-html.md):

  * CycloneDX layers -> sbom-utility extracts the inventory and license data:
      - `component list --format csv`        (type/version/publisher/purl)
      - `license list --summary --format json` (per-bom-ref license + usage policy)
    This script joins those two by `bom-ref`.
  * SPDX (OS) layer -> parsed with the `spdx-tools` library (sbom-utility cannot
    read SPDX).
  * The compliance verdict in every report comes from `sbom_common` (the exact
    same checks as `validate-sbom.py`), so the Validation summary matches the gate.

Each report carries a 摘要/Summary block, a Components table, a Licenses table, a
Resources overview, and the Validation summary. An `index.html` links them all and
rolls the figures up across artifacts.

Usage:
    uv run render-sbom.py [--input-dir DIR] [--util-dir DIR] [--output-dir DIR] [files...]

With no files it scans the input dir (default ./sbom-outputs) for *.cdx.json /
*.spdx.json and writes HTML into the output dir (default ./sbom-outputs/html).
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from sbom_common import Report, detect_and_validate, load_json

DEFAULT_INPUT_DIR = Path(__file__).resolve().parent / "sbom-outputs"
# License values that mean "no license information", filtered out everywhere.
_NULL_LICENSES = {"", "NOASSERTION", "NONE"}
# sbom-utility license-type values that carry an actual identifier/expression.
_VALID_LICENSE_TYPES = {"id", "name", "expression"}


@dataclass(frozen=True)
class ComponentRow:
    name: str
    ctype: str
    version: str
    license: str
    publisher: str
    purl: str


@dataclass
class ArtifactView:
    path: Path
    base: str
    sbom_format: str  # display string, e.g. "CycloneDX 1.6" / "SPDX-2.3"
    layer: str
    author: str
    report: Report
    rows: list[ComponentRow] = field(default_factory=list)
    # Each license occurrence on a displayed component: (license, usage-policy).
    license_occurrences: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.rows)

    @property
    def with_license(self) -> int:
        return sum(1 for r in self.rows if r.license)

    @property
    def coverage(self) -> float:
        return self.with_license / self.total if self.total else 0.0

    @property
    def distinct_licenses(self) -> int:
        return len({lic for lic, _ in self.license_occurrences})

    def license_table(self) -> list[tuple[str, int, str]]:
        """(license, component-count, usage-policy) sorted by descending count."""
        counts: Counter[str] = Counter(lic for lic, _ in self.license_occurrences)
        policies: dict[str, str] = {}
        for lic, pol in self.license_occurrences:
            if pol and lic not in policies:
                policies[lic] = pol
        return [
            (lic, n, policies.get(lic, ""))
            for lic, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]

    def type_table(self) -> list[tuple[str, int]]:
        counts: Counter[str] = Counter(r.ctype or "(unspecified)" for r in self.rows)
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


# --- artifact naming ---------------------------------------------------------
def artifact_base(path: Path) -> str:
    """`sbom-outputs/node-backend.cdx.json` -> `node-backend`."""
    name = path.name
    for suffix in (".cdx.json", ".spdx.json"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


# --- CycloneDX path (sbom-utility outputs) -----------------------------------
def _cdx_license_map(lic_json: Path) -> dict[str, list[tuple[str, str]]]:
    """bom-ref -> [(license, usage-policy), ...] from `license list --summary`."""
    mapping: dict[str, list[tuple[str, str]]] = {}
    if not lic_json.exists():
        return mapping
    try:
        entries = json.loads(lic_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return mapping
    if not isinstance(entries, list):
        return mapping
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("license-type") not in _VALID_LICENSE_TYPES:
            continue
        lic = (entry.get("license") or "").strip()
        if lic in _NULL_LICENSES:
            continue
        bom_ref = entry.get("bom-ref") or ""
        mapping.setdefault(bom_ref, []).append((lic, entry.get("usage-policy") or ""))
    return mapping


def load_cdx(view: ArtifactView, util_dir: Path) -> None:
    comp_csv = util_dir / f"{view.base}.components.csv"
    lic_json = util_dir / f"{view.base}.licenses.json"
    if not comp_csv.exists():
        view.notes.append(
            f"sbom-utility component CSV not found ({comp_csv.name}); "
            "inventory unavailable."
        )
        return
    license_map = _cdx_license_map(lic_json)
    with comp_csv.open(encoding="utf-8", newline="") as fh:
        for record in csv.DictReader(fh):
            # The application component itself is shown in the header, not the
            # dependency table.
            if record.get("type") == "application":
                continue
            bom_ref = record.get("bom-ref") or ""
            occurrences = license_map.get(bom_ref, [])
            view.license_occurrences.extend(occurrences)
            licenses = sorted({lic for lic, _ in occurrences})
            view.rows.append(
                ComponentRow(
                    name=record.get("name") or "",
                    ctype=record.get("type") or "",
                    version=record.get("version") or "",
                    license=", ".join(licenses),
                    publisher=record.get("publisher") or record.get("supplier-name") or "",
                    purl=record.get("purl") or "",
                )
            )


# --- SPDX path (spdx-tools) --------------------------------------------------
def load_spdx(view: ArtifactView) -> None:
    from spdx_tools.spdx.model import SpdxNoAssertion, SpdxNone
    from spdx_tools.spdx.parser.parse_anything import parse_file

    doc = parse_file(str(view.path))
    spdx_version = getattr(doc.creation_info, "spdx_version", "") or ""
    view.sbom_format = spdx_version or "SPDX"

    def actor_name(actor) -> str:
        if actor is None or isinstance(actor, (SpdxNoAssertion, SpdxNone)):
            return ""
        return getattr(actor, "name", "") or ""

    def license_str(pkg) -> str:
        for value in (pkg.license_concluded, pkg.license_declared):
            if value is None or isinstance(value, (SpdxNoAssertion, SpdxNone)):
                continue
            text = str(value).strip()
            if text and text not in _NULL_LICENSES:
                return text
        return ""

    for pkg in doc.packages:
        purl = next(
            (
                ref.locator
                for ref in (pkg.external_references or [])
                if ref.reference_type == "purl"
            ),
            "",
        )
        purpose = pkg.primary_package_purpose
        ctype = purpose.name.lower() if purpose is not None else "package"
        lic = license_str(pkg)
        if lic:
            view.license_occurrences.append((lic, ""))
        view.rows.append(
            ComponentRow(
                name=pkg.name or "",
                ctype=ctype,
                version=pkg.version or "",
                license=lic,
                publisher=actor_name(pkg.supplier) or actor_name(pkg.originator),
                purl=purl or "",
            )
        )


# --- view assembly -----------------------------------------------------------
def build_view(path: Path, util_dir: Path) -> ArtifactView:
    report = detect_and_validate(path) or Report(path=path, sbom_format="unknown", layer="unknown")
    view = ArtifactView(
        path=path,
        base=artifact_base(path),
        sbom_format=report.sbom_format,
        layer=report.layer,
        author=report.author or "<missing>",
        report=report,
    )
    if report.sbom_format == "CycloneDX":
        raw = load_json(path)
        spec = (raw.get("specVersion") or "").strip()
        view.sbom_format = f"CycloneDX {spec}".strip()
        load_cdx(view, util_dir)
    elif report.sbom_format == "SPDX":
        load_spdx(view)
    else:
        view.notes.append("unrecognized SBOM format; nothing to render.")
    return view


# --- HTML rendering ----------------------------------------------------------
def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


_STYLE = """
:root { --bg:#f6f7f9; --card:#fff; --line:#e2e6ea; --ink:#1f2933; --muted:#5c6773;
  --accent:#2b6cb0; --pass:#1f7a4d; --fail:#b42318; --warn:#9a6700; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans TC",sans-serif; }
.wrap { max-width:1100px; margin:0 auto; padding:32px 24px 64px; }
h1 { font-size:24px; margin:0 0 4px; }
h2 { font-size:18px; margin:32px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }
.sub { color:var(--muted); margin:0 0 20px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.card .k { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.card .v { font-size:22px; font-weight:600; margin-top:4px; word-break:break-word; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:13px; font-weight:600; }
.badge.pass { background:#e6f4ec; color:var(--pass); }
.badge.fail { background:#fbe9e7; color:var(--fail); }
table { width:100%; border-collapse:collapse; background:var(--card);
  border:1px solid var(--line); border-radius:10px; overflow:hidden; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line);
  font-size:13.5px; vertical-align:top; }
th { background:#eef1f4; font-weight:600; position:sticky; top:0; }
tr:last-child td { border-bottom:none; }
td.purl { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px;
  color:var(--muted); word-break:break-all; }
.msg { margin:4px 0; padding:8px 12px; border-radius:8px; font-size:13.5px; }
.msg.warn { background:#fff8e6; color:var(--warn); }
.msg.fail { background:#fbe9e7; color:var(--fail); }
.note { background:#eef4fb; color:var(--accent); padding:10px 14px; border-radius:8px; margin:10px 0; }
.muted { color:var(--muted); }
footer { margin-top:40px; color:var(--muted); font-size:12px; }
""".strip()


def _doc(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="zh-Hant"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc(title)}</title>\n<style>{_STYLE}</style>\n</head><body>\n"
        f'<div class="wrap">\n{body}\n</div>\n</body></html>\n'
    )


def _card(label: str, value: object) -> str:
    return f'<div class="card"><div class="k">{esc(label)}</div><div class="v">{esc(value)}</div></div>'


def _summary_cards(view: ArtifactView) -> str:
    status = "PASS" if view.report.ok else "FAIL"
    badge = f'<span class="badge {status.lower()}">{status}</span>'
    cards = [
        _card("格式規格 Format", view.sbom_format),
        _card("套件元件總數 Components", view.total),
        _card("不重複授權條款 Distinct licenses", view.distinct_licenses),
        _card("授權涵蓋率 License coverage", f"{view.coverage:.0%}"),
        f'<div class="card"><div class="k">合規狀態 Status</div><div class="v">{badge}</div></div>',
    ]
    return f'<div class="cards">{"".join(cards)}</div>'


def _components_section(view: ArtifactView) -> str:
    if not view.rows:
        return "<h2>Components</h2><p class=\"muted\">No components to display.</p>"
    head = (
        "<tr><th>名稱 Name</th><th>類型 Type</th><th>版本 Version</th>"
        "<th>授權 License</th><th>供應商/發布者 Publisher</th><th>PURL</th></tr>"
    )
    body = "".join(
        "<tr>"
        f"<td>{esc(r.name)}</td><td>{esc(r.ctype)}</td><td>{esc(r.version)}</td>"
        f"<td>{esc(r.license) or '<span class=\"muted\">—</span>'}</td>"
        f"<td>{esc(r.publisher) or '<span class=\"muted\">—</span>'}</td>"
        f'<td class="purl">{esc(r.purl)}</td>'
        "</tr>"
        for r in view.rows
    )
    return f"<h2>Components 清單 ({view.total})</h2><table>{head}{body}</table>"


def _licenses_section(view: ArtifactView) -> str:
    rows = view.license_table()
    if not rows:
        return "<h2>Licenses</h2><p class=\"muted\">No license data.</p>"
    head = "<tr><th>授權條款 License</th><th>元件數 Components</th><th>使用政策 Usage policy</th></tr>"
    body = "".join(
        f"<tr><td>{esc(lic)}</td><td>{n}</td>"
        f"<td>{esc(pol) or '<span class=\"muted\">—</span>'}</td></tr>"
        for lic, n, pol in rows
    )
    return f"<h2>Licenses 清單 ({view.distinct_licenses})</h2><table>{head}{body}</table>"


def _resources_section(view: ArtifactView) -> str:
    rows = view.type_table()
    if not rows:
        return ""
    head = "<tr><th>資源類型 Resource type</th><th>數量 Count</th></tr>"
    body = "".join(f"<tr><td>{esc(t)}</td><td>{n}</td></tr>" for t, n in rows)
    return f"<h2>Resources 清單</h2><table>{head}{body}</table>"


def _validation_section(view: ArtifactView) -> str:
    rep = view.report
    status = "PASS" if rep.ok else "FAIL"
    total = rep.component_count or 1
    lines = [
        f'<p>合規檢查 (validate-sbom.py / NTIA): '
        f'<span class="badge {status.lower()}">{status}</span></p>',
        "<table>"
        "<tr><th>項目 Field</th><th>結果 Result</th></tr>"
        f"<tr><td>文件作者 Author</td><td>{esc(rep.author or '<missing>')}</td></tr>"
        f"<tr><td>元件數 Components (top-level)</td><td>{rep.component_count}</td></tr>"
        f"<tr><td>具名稱 With name</td><td>{rep.with_name}/{rep.component_count}</td></tr>"
        f"<tr><td>具版本 With version</td><td>{rep.with_version}/{rep.component_count}</td></tr>"
        f"<tr><td>具授權 With license</td><td>{rep.with_license}/{rep.component_count} "
        f"({rep.with_license / total:.0%})</td></tr>"
        "</table>",
    ]
    for warning in rep.warnings:
        lines.append(f'<div class="msg warn">warn: {esc(warning)}</div>')
    for error in rep.errors:
        lines.append(f'<div class="msg fail">fail: {esc(error)}</div>')
    return "<h2>Validation 摘要</h2>" + "".join(lines)


def render_artifact(view: ArtifactView) -> str:
    parts = [
        f"<h1>{esc(view.base)}</h1>",
        f'<p class="sub">{esc(view.sbom_format)} · {esc(view.layer)} · '
        f"作者 {esc(view.author)}</p>",
    ]
    parts.extend(f'<div class="note">{esc(note)}</div>' for note in view.notes)
    parts.append("<h2>摘要 Summary</h2>")
    parts.append(_summary_cards(view))
    parts.append(_validation_section(view))
    parts.append(_components_section(view))
    parts.append(_licenses_section(view))
    parts.append(_resources_section(view))
    parts.append(
        '<footer>Generated by render-sbom.py · CycloneDX via sbom-utility · '
        "SPDX via spdx-tools · compliance via validate-sbom.py</footer>"
    )
    return _doc(view.base, "\n".join(p for p in parts if p))


def render_index(views: list[ArtifactView]) -> str:
    app_total = sum(v.total for v in views if v.layer == "Application")
    os_total = sum(v.total for v in views if v.layer == "OS / Container")
    all_licenses = {lic for v in views for lic, _ in v.license_occurrences}
    overall_ok = all(v.report.ok for v in views)
    status = "PASS" if overall_ok else "FAIL"

    cards = "".join(
        [
            _card("Artifacts", len(views)),
            _card("應用層元件 Application", app_total),
            _card("OS 套件 OS packages", os_total),
            _card("合計 Combined", app_total + os_total),
            _card("不重複授權 Distinct licenses", len(all_licenses)),
            f'<div class="card"><div class="k">整體狀態 Status</div>'
            f'<div class="v"><span class="badge {status.lower()}">{status}</span></div></div>',
        ]
    )
    head = (
        "<tr><th>Artifact</th><th>格式 Format</th><th>層 Layer</th>"
        "<th>元件數 Components</th><th>狀態 Status</th></tr>"
    )
    body = "".join(
        "<tr>"
        f'<td><a href="{esc(v.base)}.html">{esc(v.base)}</a></td>'
        f"<td>{esc(v.sbom_format)}</td><td>{esc(v.layer)}</td><td>{v.total}</td>"
        f'<td><span class="badge {"pass" if v.report.ok else "fail"}">'
        f'{"PASS" if v.report.ok else "FAIL"}</span></td>'
        "</tr>"
        for v in views
    )
    body_html = (
        "<h1>SBOM Reports</h1>"
        '<p class="sub">CycloneDX 應用層 (sbom-utility) + SPDX OS 層 (spdx-tools)</p>'
        "<h2>摘要 Summary</h2>"
        f'<div class="cards">{cards}</div>'
        f"<h2>Artifacts</h2><table>{head}{body}</table>"
        '<footer>Generated by render-sbom.py</footer>'
    )
    return _doc("SBOM Reports", body_html)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Render SBOM artifacts to HTML.")
    parser.add_argument("files", nargs="*", help="SBOM files (default: scan input dir)")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--util-dir", type=Path, default=None,
                        help="dir with sbom-utility CSV/JSON (default: <input-dir>/.render-tmp)")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="HTML output dir (default: <input-dir>/html)")
    args = parser.parse_args(argv)

    util_dir = args.util_dir or (args.input_dir / ".render-tmp")
    output_dir = args.output_dir or (args.input_dir / "html")

    if args.files:
        files = [Path(f) for f in args.files]
    else:
        # Reuse discover_files semantics but against the chosen input dir.
        if not args.input_dir.is_dir():
            print(f"Input dir not found: {args.input_dir}", file=sys.stderr)
            return 2
        files = sorted(
            p for p in args.input_dir.iterdir()
            if p.suffix == ".json" and (".cdx" in p.name or ".spdx" in p.name)
        )
    if not files:
        print("No SBOM files found to render.", file=sys.stderr)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    views: list[ArtifactView] = []
    for path in files:
        view = build_view(path, util_dir)
        (output_dir / f"{view.base}.html").write_text(render_artifact(view), encoding="utf-8")
        views.append(view)
        print(f"rendered {view.base}.html  ({view.sbom_format}, {view.total} components)")

    (output_dir / "index.html").write_text(render_index(views), encoding="utf-8")
    print(f"rendered index.html  ({len(views)} artifacts) -> {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
