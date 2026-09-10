# Edwardian

Platform-portability intelligence for Linux-first repositories. Edwardian inspects a repository, detects Linux-specific dependencies, classifies their Windows compatibility, and produces a readiness report with remediation directives and architectural proposals.

## What it does

Given a repository path and a target platform (default: Windows), Edwardian runs a 10-stage pipeline:

1. Discovers workspace layout, package managers, CI, and scripts
2. Inventories the bounded file set
3. Runs platform-dependency detectors
4. Normalises and classifies findings by severity and compatibility state
5. Resolves each finding to ranked FOSS alternatives
6. Scores readiness by dimension
7. Generates remediation directives (P0/P1/P2)
8. Generates capability proposals for architectural gaps
9. Renders a readiness report and machine artefacts

It never executes inspected-project code. The only processes it spawns are `git` commands in `compatible` release mode, operating on its own generated content.

## Quick start

```bash
cargo install --path crates/edwardian-cli
edwardian --path . --target windows analyse
edwardian --path . --target windows readiness
edwardian --path . --target windows --format json export --out ./out
```

## CLI commands

| Command | Purpose |
|---|---|
| `inspect` | Discover workspace layout |
| `analyse` | Full analysis with findings and evidence |
| `explain <FINDING_ID>` | Show one finding with evidence |
| `alternatives` | Ranked alternatives per capability |
| `readiness` | Readiness score by dimension |
| `directive` | Remediation directives |
| `propose` | Capability proposals |
| `validate` | Structural validation (no execution) |
| `export` | Write artefacts to `<out>/edwardian/` |
| `daemon [--interval N] [--once]` | Watch and emit incremental events |
| `store` | Microsoft Store compliance checks (advisory, never affects readiness) |
| `release standalone` | Windows-centric fork with transforms |
| `release compatible [--branch-name X] [--no-git]` | Additive dev branch or fallback directory |

Global flags: `--target <windows|linux|macos|freebsd|openbsd|android|ios|wasm>`, `--path <dir>`, `--format <human|json>`, `--out <dir>`.

## Workspace crates

| Crate | Role |
|---|---|
| `edwardian-core` | Domain types: Platform, PlatformDependency, Severity, CompatibilityState, Finding, Evidence, Directive, Proposal |
| `edwardian-evidence` | Deterministic ID allocator (`EWD-NNNNN`, `FND-NNNNN`) and EvidenceFactory |
| `edwardian-platform` | Static PlatformProfile per target (shell, path separator, service manager, FS watch API, package managers, ABI) |
| `edwardian-detectors` | FileContext and Detector trait; detectors for fs, fs-semantics, win-paths, shell, services, ipc, build, env |
| `edwardian-resolver` | Capability key mapping and seeded Alternative registry with decision strategies |
| `edwardian-directives` | Directive generation from findings (Blocker→P0, Major→P1, Minor→P2) |
| `edwardian-proposals` | Proposal generation for `fs-watch` (inotify → FileWatcher trait) |
| `edwardian-padagonia` | Ontology knowledge graph over components, findings, directives, proposals |
| `edwardian-elci` | CapabilityRegistry for ELCI facade; FindingsProvider |
| `edwardian-report` | Dimension scoring, ReadinessReport, markdown rendering, artefact writing |
| `edwardian-engine` | 10-stage pipeline orchestration (PipelineConfig, AnalysisReport) |
| `edwardian-cli` | CLI binary `edwardian` |
| `edwardian-daemon` | Incremental analysis daemon with stable IDs and event stream |
| `edwardian-release` | Standalone and compatible release modes; DEP_MAPPINGS whitelist |
| `edwardian-store` | Store compliance checks (advisory) |
| `edwardian-test` | Shared test helpers and fixtures |

See [docs/architecture.md](docs/architecture.md) for pipeline detail, [docs/cli.md](docs/cli.md) for CLI reference, and [docs/detectors.md](docs/detectors.md) for detector catalog.

## Schemas

JSON schemas live in `schemas/`:

- `finding.schema.json`
- `directive.schema.json`
- `platform.schema.json`
- `proposal.schema.json`
- `store-compliance.schema.json`

See [docs/schemas.md](docs/schemas.md).

## Development

```bash
cargo test --workspace
cargo test --manifest-path crates/edwardian-cli/Cargo.toml  # CLI integration tests
```

Versioning and pushes are managed by `kaptaind` (see `kaptaind.toml`). The watcher ignores `target/`, `.kaptaind/`, `.uni/`, and `snapshot-*.json`.

## License

MIT OR Apache-2.0
