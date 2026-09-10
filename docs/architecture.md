# Architecture

## Workspace layout

Edwardian is a Cargo workspace with 16 crates. Dependencies flow from `edwardian-core` outward; `edwardian-engine` orchestrates, `edwardian-cli` and `edwardian-daemon` are the user-facing entry points.

```
edwardian-core          ← domain types (no dependencies beyond serde)
edwardian-evidence      ← deterministic IDs
edwardian-platform      ← PlatformProfile per target
edwardian-detectors     ← file-level detectors
edwardian-resolver      ← capability → alternatives registry
edwardian-directives    ← findings → directives
edwardian-proposals     ← findings → proposals
edwardian-padagonia     ← ontology graph
edwardian-elci          ← capability registry facade
edwardian-report        ← readiness scoring and rendering
edwardian-engine        ← 10-stage pipeline
edwardian-cli           ← binary `edwardian`
edwardian-daemon        ← incremental daemon
edwardian-release       ← standalone / compatible releases
edwardian-store         ← Store compliance (advisory)
edwardian-test          ← test helpers
```

## 10-stage pipeline

Defined in `crates/edwardian-engine/src/lib.rs` as `Stage`:

| Stage | Label | What happens |
|---|---|---|
| Discover | DISCOVER | Walk the repository, identify manifests, CI, scripts, workspace layout |
| Inventory | INVENTORY | Build bounded FileRecord list (path, size, hash) |
| Detect | DETECT | Run all detectors over each FileContext (path, content, target) |
| Normalise | NORMALISE | Deduplicate and normalise evidence |
| Classify | CLASSIFY | Assign PlatformDependency, CompatibilityState, Severity per finding |
| Resolve | RESOLVE | Map findings to capability keys, look up ranked alternatives |
| Score | SCORE | Score each Dimension and compute overall readiness (0–100) and ReadinessStatus |
| Direct | DIRECT | Generate directives (Blocker→P0, Major→P1, Minor→P2; Info skipped) |
| Propose | PROPOSE | Generate proposals for architectural gaps (currently `fs-watch`) |
| Report | REPORT | Assemble AnalysisReport with JSON and markdown renderers |

`PipelineConfig` carries the target platform and bounded inventory limits. `AnalysisReport` holds the inventory, findings, alternatives, directives, proposals, readiness, and ontology, with helpers `to_json()`, `readiness_json()`, `directives_json()`, `proposals_json()`, `platform_map_json()`, and `alternatives_json()`.

`inventory()` and `validate_report()` are public helpers for daemon and CLI validation paths.

## Core types (edwardian-core)

- **Platform**: `linux`, `windows`, `macos`, `freebsd`, `openbsd`, `android`, `ios`, `wasm`.
- **PlatformDependency**: 20 variants including `Filesystem`, `Shell`, `Service`, `IPC`, `Kernel`, `NativeLibrary`, `ABI`, `Compiler`, `Container`, `CI`, `Deployment`, `Architecture`, and `Unknown`. Each has a `label()` in kebab-case.
- **CompatibilityState**: `Portable`, `WindowsCompatible`, `Configurable`, `Adaptable`, `Replaceable`, `RequiresImplementation`, `ArchitecturallyIncompatible`, `Unknown`.
- **Severity**: `Info`, `Minor`, `Major`, `Blocker` (ordered).
- **Evidence**: `id` (`EWD-NNNNN`), `source` (FileScan, Manifest, RepoLayout, Heuristic), `location` (path, line, column), `observation`, `confidence` (clamped 0.0–1.0), `detector`.
- **Finding**: `id` (`FND-NNNNN`), `evidence: Vec<Evidence>`, `dependency`, `state`, `severity`, `description`, `remediation_hint`. `has_material_evidence()` checks non-empty evidence with positive confidence.
- **Directive**: `id` (`EWD-DNNN`), `priority` (P0–P3), `objective`, `evidence_ids`, `affected_components`, `current_state`, `target_state`, `remediation`, `validation_plan`, `dependencies`. `validation_plan_is_complete()` enforces non-empty objective, remediation, validation steps, evidence, and EWD-D dependency format.
- **Proposal**: `id` (`EWP-NNN`), `capability`, `current_impl`, `required_impl`, `recommended_architecture`, `required_interface`, `compatibility_invariant`, `estimated_effort_days`, `risk`, `state` (Analysed → Recommended → Implemented → Compiles → Tested → Validated).
- **Alternative**: `name`, `capability`, `platforms`, `license`, `maturity` (Experimental, Incubating, Mature, Legacy), `integration_cost` (1–5), `operational_risk` (1–5), `strategy` (DropIn, Adapter, Rewrite, Polyfill), `rationale`.

## Evidence and IDs (edwardian-evidence)

`IdAllocator` counts from 1 per pipeline run: `EWD-00001` for evidence, `FND-00001` for findings. `EvidenceFactory` stamps `Evidence::file_scan` with the next ID. IDs are deterministic within a run.

## Platform profiles (edwardian-platform)

`profile_for(Platform) -> PlatformProfile` returns shell, default_shell, path_separator, supports_unix_sockets, supports_posix_signals, service_manager, fs_watch_api, package_managers, and native_abi. For example, Windows reports `cmd.exe / PowerShell`, `\\`, `ReadDirectoryChangesW`, and `PE / MSVC x64`.

## Detectors (edwardian-detectors)

`FileContext { path, content, target }` with helpers `basename()`, `extension()`, `is_shell_flavored()`. `Detector` trait has `id()` and `run(ctx, factory) -> Vec<Finding>`. `all_detectors()` registers: Filesystem, FilesystemSemantics, WindowsPath, ShellProcess, Service, Ipc, BuildSystem, Env. Each detector is target-aware and classifies evidence by consequence on the chosen target.

## Resolver (edwardian-resolver)

`capability_key(finding) -> Option<&'static str>` maps dependency + description to a capability such as `process:spawn-shell`, `service:manager`, `fs:watch`, `shell:interpreter`, `build:make`, `env:dirs`, or `None` for portable tooling. `AlternativeRegistry::seeded()` and `seed_registry()` hold the in-code seed table of capability → ranked alternatives. `AlternativeRegistry::alternatives_for(cap)` returns the ranked list.

## Directives (edwardian-directives)

`generate_directives(findings, registry)` walks findings in order, maps Blocker→P0, Major→P1, Minor→P2 (Info skipped), assigns `EWD-D001` etc., derives `affected_components` from evidence paths, and seeds `remediation` from the finding hint plus the top-ranked alternative's strategy, name, and rationale. Returns an empty vec when there are no actionable findings.

## Proposals (edwardian-proposals)

`generate_proposals(findings) -> Vec<Proposal>` checks for Kernel + `inotify` findings and, if present, emits a single `EWP-001` proposal for `fs-watch`: a `FileWatcher` trait with `InotifyBackend` and `RdcwBackend` selected via `cfg(target_os)`, with a compatibility invariant that no event type is silently dropped.

## Readiness (edwardian-report)

`Dimension` enumerates 10 dimensions: Architecture, Source, Runtime, Build, Tooling, Filesystem, ProcessModel, NativeDependencies, CI, Distribution. `Dimension::of(PlatformDependency)` maps each dependency to a dimension. `score_readiness(findings)` produces a `ReadinessReport { overall: u8, status: ReadinessStatus, blocker_count, dimensions: Vec<DimensionScore> }` with READY/CONDITIONAL/BLOCKED. `render_markdown(report)` and `write_artifacts(report, out)` (writes under `<out>/edwardian/`) are the report outputs.

## ELCI and Padagonia

- `edwardian-elci`: `CapabilityRegistry` maps capability names to `CapabilityProvider` boxes; first registration wins, duplicates are rejected. `FindingsProvider` exposes read-only lookup over findings.
- `edwardian-padagonia`: `Ontology` is a directed graph with `Entity { id, kind, name }` (Component, Finding, Dependency, Directive, Proposal, Platform) and `Relation { from, to, kind }` (Exhibits, DependsOn, RemediatedBy, Proposes, Targets). Entity IDs reuse the deterministic finding/directive/proposal IDs.

## Daemon (edwardian-daemon)

Incremental analysis daemon. It holds a content-hash snapshot of the bounded inventory, re-detects only new or changed files on each `cycle()`, and keeps evidence/finding IDs stable for unchanged content. Events are emitted as `EventKind` variants: `FileAdded`, `FileChanged`, `FileRemoved`, `FindingAdded`, `FindingRemoved`, `ReadinessChanged`, `StatusChanged`. Termination is via SIGKILL/SIGTERM/default Ctrl-C; `--once` runs a single cycle for scripting.

## Release (edwardian-release)

Two modes that run after the standard pipeline:

- **Standalone**: Windows-centric fork. Copies the bounded source set into a fork directory, applies transforms, injects whitelisted crate dependencies (`DEP_MAPPINGS`), and writes a manifest. Reports `StandaloneReport { fork_dir, files_copied, transforms, manual_work }`.
- **Compatible**: Additive scaffolding on a dev branch. Creates `edwardian/compat-<target>` (or `compat-branch/` with `--no-git`), injects deps, and records branch, proposals, deps, written_paths, applied_via, nothing_to_do, and note.

`DEP_MAPPINGS` whitelist (capability → crate):

| Capability | Crate | Version | Substitutable |
|---|---|---|---|
| `fs:watch` | `notify` | 8 | true |
| `service:manager` | `service-manager` | 0.8 | false |
| `ipc:local-socket` | `interprocess` | 2 | true |
| `env:dirs` | `directories` | 6 | true |

`substitutable = true` means adding the crate is the fix; `false` means code changes remain.

## Store (edwardian-store)

Advisory Microsoft Store compliance checks. Never affects readiness scores. Accessed via `edwardian store` and included in `analyse` and `export` outputs.

## Engine entry points

```rust
use edwardian_engine::{PipelineConfig, run, inventory, validate_report};
use edwardian_core::Platform;

let config = PipelineConfig { target: Platform::Windows, ..Default::default() };
let report = run(&root, &config)?;
let inventory = inventory(&root, &config)?;
let problems = validate_report(&report);
```
