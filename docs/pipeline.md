# Pipeline

## Overview

The engine pipeline (`crates/edwardian-engine`) is a deterministic, 10-stage batch that turns a repository path into an `AnalysisReport`. It is the only place that calls detectors, the resolver, directive and proposal generators, and the readiness scorer. The CLI, daemon, and release crates all delegate to it.

## Configuration

```rust
pub struct PipelineConfig {
    pub target: Platform,          // default: Windows
    pub max_files: Option<usize>,  // bounded inventory limit
    pub max_file_size: Option<u64>,
    pub ignore_hidden: bool,
}
```

`PipelineConfig::default()` targets Windows with bounded limits suitable for large repositories. The inventory walker respects `.gitignore`-style hidden-file rules and skips `target/`, `.git/`, and similar output directories.

## Stages in order

### 1. Discover

Walks the repository tree from the canonicalized `root`. Identifies package manifests (`Cargo.toml`, `package.json`), CI directories (`.github/workflows`), shell scripts, and build files. Produces `Discovery { manifests, ci, scripts }`.

### 2. Inventory

Builds `Vec<FileRecord { path, size, hash }>` — the bounded file set that all later stages use. Each record stores the repo-relative forward-slash path, byte size, and a content hash used by the daemon for stable IDs. Files exceeding `max_file_size` are skipped.

### 3. Detect

For every `FileRecord`, reads the file as text (lossy UTF-8 where needed), builds a `FileContext { path, content, target }`, and runs `all_detectors()`. Each detector emits `Vec<Finding>` with one or more `Evidence` records stamped by `EvidenceFactory`.

### 4. Normalise

Deduplicates evidence by location and observation. Merges findings that share evidence and dependency. This stage is intentionally conservative: it never drops a finding that has material evidence (`has_material_evidence()`).

### 5. Classify

Ensures every finding has `dependency`, `state` (`CompatibilityState`), `severity` (`Severity`), and `description`. Severity ordering is `Info < Minor < Major < Blocker`. Dependency defaults to `Unknown` only when no detector classified it.

### 6. Resolve

Calls `capability_key(finding)` per finding and looks up `AlternativeRegistry::seeded()`. Populates `report.alternatives` — the ranked alternatives per capability. The registry is seeded in-code; there is no external config file.

### 7. Score

Calls `score_readiness(findings)` to produce `ReadinessReport { overall, status, blocker_count, dimensions }`. Overall is 0–100; status is `READY` (no blockers/majors), `CONDITIONAL` (majors but no blockers), or `BLOCKED` (any blocker). Each `Dimension` carries its own score and blocker/major counts.

### 8. Direct

Calls `generate_directives(findings, registry)`. Blocker→P0, Major→P1, Minor→P2; Info produces no directive. Each directive `EWD-DNNN` records the top-ranked alternative's strategy, name, and rationale in its `remediation` field.

### 9. Propose

Calls `generate_proposals(findings)`. Today this is narrowly scoped: any `Kernel` finding mentioning `inotify` yields a single `EWP-001` proposal for `fs-watch` with a `FileWatcher` trait design, `InotifyBackend`/`RdcwBackend` via `cfg(target_os)`, and an invariant that no event type is silently dropped.

### 10. Report

Assembles `AnalysisReport { inventory, findings, alternatives, directives, proposals, readiness, ontology }`. Attaches an `Ontology` graph linking components, findings, directives, and proposals. Provides render helpers: `to_json()`, `readiness_json()`, `directives_json()`, `proposals_json()`, `platform_map_json()`, `alternatives_json()`, and `render_markdown(report)`. Validates via `validate_report(report)`.

## Report types

`AnalysisReport` implements:

- `to_json() -> Value` — full report with stages, inventory summary, findings, directives, proposals, readiness.
- `readiness_json()` — readiness slice.
- `directives_json()` — directive array.
- `proposals_json()` — proposal array.
- `platform_map_json()` — per-finding platform mapping.
- `alternatives_json()` — ranked alternatives per capability found.

## Running the pipeline

```rust
use std::path::Path;
use edwardian_engine::{PipelineConfig, run, inventory, validate_report};
use edwardian_core::Platform;

let root = Path::new("/path/to/repo").canonicalize()?;
let config = PipelineConfig { target: Platform::Windows, ..Default::default() };
let report = run(&root, &config)?;
println!("findings: {}", report.findings.len());
println!("overall: {} {}", report.readiness.overall, report.readiness.status.label());

let problems = validate_report(&report);
assert!(problems.is_empty(), "validation failed: {:?}", problems);
```

## Daemon interaction

The daemon reuses the same inventory definition. Each `cycle()` recomputes `FileRecord` hashes, diffs against the snapshot, re-detects only new or changed files, and reuses IDs for unchanged content. It still calls the same scoring and directive/proposal generators, so readiness and event streams stay consistent with batch runs.

## Release interaction

Both release modes call the pipeline first, then act on its findings:

- `standalone` resolves `DEP_MAPPINGS` via `resolve_deps(report, target)`, copies the bounded source set, and applies transforms.
- `compatible` may invoke `git` (branch creation, commits) on the output branch or, with `--no-git`, write to `<out>/compat-branch/` instead.

## Error handling

`run(root, config)` returns `io::Result<AnalysisReport>`. Failures include unreadable root, detector panics (propagated as errors), and artefact write failures. Validation (`validate_report`) is advisory and never fails the pipeline — it returns `Vec<String>` problems for the CLI `validate` command to surface.
