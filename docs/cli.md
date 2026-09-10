# CLI Reference

Binary: `edwardian` (crate `edwardian-cli`).

## Global flags

| Flag | Default | Values | Description |
|---|---|---|---|
| `--target` | `windows` | `windows`, `linux`, `macos`, `freebsd`, `openbsd`, `android`, `ios`, `wasm` | Target platform to assess |
| `--path` | `.` | path | Repository to inspect (canonicalized) |
| `--format` | `human` | `human`, `json` | Output rendering |
| `--out` | `.` | path | Output directory for artefacts (`<out>/edwardian/`) |

## Commands

### `inspect`

Discovers workspace layout: Cargo workspaces, package managers, CI config, scripts, and manifests. No findings are produced.

```bash
edwardian --path ./my-repo inspect
edwardian --path ./my-repo --format json inspect
```

### `analyse`

Full pipeline run. Prints findings, evidence, directives, proposals, and readiness. When `--format json`, emits the complete AnalysisReport JSON. Also runs Store compliance checks and includes them in the output.

```bash
edwardian analyse
edwardian --target linux analyse --format json
edwardian --out ./out analyse
```

### `explain <FINDING_ID>`

Shows one finding by ID (for example `FND-00001`) with its evidence, dependency, state, severity, and remediation.

```bash
edwardian explain FND-00003
edwardian --format json explain FND-00003
```

Fails with a message when the ID does not exist.

### `alternatives`

Lists ranked FOSS alternatives per capability found, with maturity, strategy, and rationale. JSON mode emits the registry slice for the report's capabilities.

```bash
edwardian alternatives
edwardian --format json alternatives
```

### `readiness`

Readiness score by dimension. Human mode prints overall percentage, status (READY/CONDITIONAL/BLOCKED), blocker count, and per-dimension scores. JSON mode emits the ReadinessReport.

```bash
edwardian readiness
edwardian --format json readiness
```

Scoring uses `edwardian-report::score_readiness`; the Store report, when present, is rendered alongside but never changes the score.

### `directive`

Lists remediation directives `EWD-D001` etc. Human mode prints priority, objective, state transition, components, evidence IDs, remediation, validation plan, and dependencies. JSON mode emits the directive array.

Severity mapping: Blocker→P0, Major→P1, Minor→P2; Info findings produce no directive.

```bash
edwardian directive
edwardian --format json directive
```

### `propose`

Lists capability proposals (`EWP-NNN`) for architectural gaps. Currently emits `fs-watch` when Kernel + `inotify` findings exist.

Human fields: id, capability, effort days, state, current_impl, required_impl, recommended_architecture, required_interface, compatibility_invariant, risk.

```bash
edwardian propose
```

### `validate`

Structurally validates the report and directives. Checks include evidence completeness, finding classification, and that every P0 directive has at least 3 validation steps. Nothing is executed.

```bash
edwardian validate
edwardian --format json validate
# JSON: { valid, problems, directives_checked, findings_checked }
```

Exits with an error message listing problems when validation fails.

### `export`

Writes machine artefacts to `<out>/edwardian/` (default `<out>` is `.`). Artefacts include the JSON report, readiness, directives, proposals, and Store report. Prints the list of written paths; JSON mode emits `{ written: [...] }`.

```bash
edwardian --out ./out export
edwardian --format json --out ./out export
```

### `daemon`

Watches the repository and emits incremental analysis events. Each `cycle()` diffs a content-hash snapshot over the bounded inventory, re-detects only new or changed files, and keeps IDs stable for unchanged content. Events are `FileAdded`, `FileChanged`, `FileRemoved`, `FindingAdded`, `FindingRemoved`, `ReadinessChanged`, `StatusChanged`.

```bash
edwardian daemon --interval 2
edwardian daemon --once
edwardian daemon --once --format json   # JSON lines per event: { cycle, kind, ... }
```

Termination: no signal handlers are installed (std-only); stop with SIGKILL/SIGTERM or Ctrl-C.

### `store`

Advisory Microsoft Store compliance checks. Never affects readiness. Human mode prints a summary; JSON mode emits the StoreReport.

```bash
edwardian store
edwardian --format json store
```

### `release`

Produces a release after the standard pipeline. Two subcommands:

#### `release standalone`

Windows-centric fork: bounded source copy + transforms + dependency injection. Writes to `<out>/standalone-fork/` (or the configured fork dir) and reports files copied, transforms applied, and remaining manual work items.

```bash
edwardian release standalone
edwardian --out ./out release standalone
```

#### `release compatible`

Additive scaffolding on a development branch. By default creates `edwardian/compat-<target>` via `git`; with `--no-git`, writes branch content to `<out>/compat-branch/` instead.

```bash
edwardian release compatible
edwardian release compatible --branch-name my-compat --no-git
edwardian --format json release compatible
```

JSON fields: `branch`, `proposals`, `deps`, `written_paths`, `applied_via` (`git` or `dir`), `nothing_to_do`, `note`.

## Exit codes

- `0` on success.
- Non-zero when `run()` reports `pipeline failed: ...`, `validate` finds problems, or a subcommand cannot canonicalize `--path`.

## Artefacts on disk

When a command writes artefacts (analyse with `--out`, readiness with `--out`, export), they land under `<out>/edwardian/`. The daemon does not write artefacts unless a command explicitly requests it.
