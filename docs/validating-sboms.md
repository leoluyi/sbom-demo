# Validating compliance

```bash
uv run validate-sbom.py
```

With no arguments it scans `./sbom-outputs/`. You can also pass explicit files:

```bash
uv run validate-sbom.py sbom-outputs/java-service.cdx.json
```

For each artifact it checks the **mandatory regulatory fields** (NTIA minimum
elements / EU CRA style) and reports per-layer dependency counts. License
presence is recognised whether a license is **asserted** on a component or only
carried as tool-detected **evidence** (`component.evidence.licenses`).

## How to read the output

```
[PASS] java-service.cdx.json  (CycloneDX / Application)
        author        : SBOM PoC Team          <- document Author present
        components     : 8                      <- total dependencies in this layer
        with name      : 8/8                    <- Component Name coverage
        with version   : 8/8                    <- Version coverage
        with license   : 8/8 (100%)             <- License coverage
...
Dependency totals by layer:
    Application components (CycloneDX) : 89     <- Node + Go + Java + Python deps
    OS / container packages (SPDX)     : 297    <- OS packages from syft
    Combined                           : 386
RESULT: PASS (all 5 artifact(s) meet mandatory-field checks)
```

## Severity model

- **`fail`** (non-zero exit): a hard requirement is missing — no document
  author, or an application component with no name/version. Breaks CI.
- **`warn`** (still passes): license coverage below 80%, or OS packages without
  a version. Surfaced as a compliance gap to review, not a blocker.

The script exits `0` when every artifact passes and `1` when any artifact has a
hard error, so it can be wired directly into a pipeline gate.
