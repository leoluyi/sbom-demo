# Rendering HTML reports

The SBOM JSON artifacts are turned into human-readable, self-contained HTML
reports — one per artifact plus an `index.html` roll-up.

```bash
./generate-sbom.sh        # the final step renders HTML automatically
```

or standalone, against an existing `./sbom-outputs/`:

```bash
uv run render-sbom.py
```

Output lands in `./sbom-outputs/html/`. The files are self-contained (inline CSS,
no external assets), so they open directly in a browser or behind any static host.

## Why two tools

No single off-the-shelf tool renders the required report. `sbom-utility` and
`cyclonedx-cli` have **no HTML output** (CSV / Markdown / JSON only), and neither
can carry this repo's own compliance verdict. The rendering therefore splits the
work:

| Concern | Tool | Notes |
|---------|------|-------|
| CycloneDX inventory + licenses | **sbom-utility** | `component list --format csv` (type/version/publisher/PURL) + `license list --summary --format json` (per-`bom-ref` license + usage policy), joined on `bom-ref` |
| SPDX (OS layer) inventory | **spdx-tools** | sbom-utility cannot read SPDX; the `spdx-tools` Python library parses it |
| Compliance verdict | **validate-sbom.py** | the Validation summary reuses `sbom_common` so it matches the CI gate exactly |
| HTML assembly | **render-sbom.py** | joins the above into per-artifact reports + index |

`sbom-utility`'s `component`/`license`/`resource list` commands are CycloneDX-only;
on SPDX input they error (`format not supported: SPDX`), which is why the OS layer
is parsed natively via `spdx-tools`.

## What each report shows

- **摘要 / Summary** — 格式規格 (format & spec), 套件元件總數 (component count),
  不重複授權條款 (distinct licenses), 授權涵蓋率 (license coverage), 合規狀態 (PASS/FAIL).
- **Validation 摘要** — the `validate-sbom.py` / NTIA mandatory-field result
  (author, name/version/license coverage, warnings, errors).
- **Components 清單** — per component: 名稱, 類型 (Type), 版本, 授權 (License),
  供應商/發布者 (Publisher), PURL.
- **Licenses 清單** — each license, the number of components using it, and the
  sbom-utility usage policy (CycloneDX only).
- **Resources 清單** — a resource-type breakdown (component / package counts).

The `index.html` aggregates application-layer vs OS-layer component totals,
combined distinct licenses, and an overall status.

> The Summary component count is sbom-utility's dependency inventory (it excludes
> the application's own root component and flattens nested components), so it can
> differ by a small margin from the top-level `components[]` count shown in the
> Validation summary. Both are reported as-is.

## Pipeline mechanics

`generate-sbom.sh` renders in two containerized stages, keeping the host
requirement at Docker + jq + uv:

1. **Extract** — `sbom-utility` is `go install`ed in the Go toolchain image and run
   against each `*.cdx.json`, writing CSV/JSON into `sbom-outputs/.render-tmp/`
   (a transient directory, cleaned on exit).
2. **Render** — `render-sbom.py` runs under the uv image (`uv run` resolves the
   `spdx-tools` dependency from the script's PEP 723 header) and writes
   `sbom-outputs/html/`.

Set `SKIP_RENDER=1` to skip rendering entirely (the SBOM JSON is still produced).
