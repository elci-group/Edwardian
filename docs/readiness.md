# Readiness

Readiness quantifies how portable a repository is to the chosen target platform. It is the primary output of the Score stage and the `readiness` command.

## Dimensions

10 dimensions, each scored 0–100:

| Dimension | Label | Covers |
|---|---|---|
| Architecture | Architecture | `PlatformDependency::Architecture` |
| Source | Source | `Compiler`, `Configuration` |
| Runtime | Runtime | `Runtime` |
| Build | Build | `BuildSystem` |
| Tooling | Tooling | `Tooling` |
| Filesystem | Filesystem | `Filesystem` |
| ProcessModel | Process model | `Process`, `Shell`, `Service`, `Kernel` |
| NativeDependencies | Native dependencies | `NativeLibrary`, `ABI` |
| CI | CI | `CI` |
| Distribution | Distribution | `PackageManager`, `Container`, `Deployment` |

Mapping is defined in `edwardian-report::Dimension::of`.

## Overall score and status

```rust
pub struct ReadinessReport {
    pub overall: u8,                    // 0–100
    pub status: ReadinessStatus,        // READY | CONDITIONAL | BLOCKED
    pub blocker_count: usize,
    pub dimensions: Vec<DimensionScore>,
}
pub struct DimensionScore {
    pub dimension: Dimension,
    pub score: u8,
    pub blocker_count: usize,
    pub major_count: usize,
}
```

Rules:

- Any finding with `Severity::Blocker` makes the overall status `BLOCKED`, regardless of the numeric score.
- No blockers but at least one `Major` makes it `CONDITIONAL`.
- No blockers and no majors makes it `READY`.
- Each dimension score starts at 100 and is decremented per finding weighted by severity; a dimension with a blocker scores lowest.

## Example

```bash
edwardian --path ./my-repo readiness
# READY (87%) — 0 blockers
#   Architecture    95%  (0 blockers, 1 major)
#   Filesystem      70%  (1 blocker, 2 majors)
#   ...

edwardian --path ./my-repo --format json readiness | python3 -m json.tool
```

JSON shape (abridged):

```json
{
  "overall": 42,
  "status": "BLOCKED",
  "blocker_count": 3,
  "dimensions": [
    { "dimension": "filesystem", "score": 30, "blocker_count": 2, "major_count": 1 },
    { "dimension": "build", "score": 80, "blocker_count": 0, "major_count": 1 }
  ]
}
```

## Store compliance

`edwardian store` checks Microsoft Store policy items. Its report is advisory — it is shown alongside readiness by `analyse`, `readiness`, and `export` but never changes `overall` or `status`. Treat Store failures as distribution hygiene, not portability blockers.

## Using readiness in CI

Gate on status or overall:

```bash
edwardian --format json readiness > readiness.json
python3 -c "
import json
r = json.load(open('readiness.json'))
assert r['status'] != 'BLOCKED', f\"blocked: {r['blocker_count']} blockers\"
assert r['overall'] >= 70, f\"overall {r['overall']} below 70\"
"
```

Or use `validate` for structural completeness without scoring:

```bash
edwardian validate --format json
```

## Improving a score

Work through `edwardian directive` in priority order (P0 first). Each directive's `remediation` names the top-ranked alternative and its rationale; `validation_plan` lists concrete verification steps. Proposals (`edwardian propose`) describe architectural work for capabilities where no drop-in crate suffices (for example `fs-watch`).
