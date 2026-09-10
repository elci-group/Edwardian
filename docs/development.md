# Development

## Prerequisites

- Rust stable (edition 2021, resolver 2)
- No external service dependencies; all analysis is static

## Build

```bash
cargo build --workspace
cargo build -p edwardian-cli   # binary `edwardian`
```

## Test

```bash
cargo test --workspace
```

The project has detector unit tests (40+ in `edwardian-detectors`), daemon tests, resolver tests, proposal tests, and CLI integration tests (`crates/edwardian-cli/tests/daemon_cli.rs`). Store, engine, and report crates have additional unit coverage.

The configured test command in `kaptaind.toml` is:

```toml
[test]
command = "cargo test --workspace"
required = true
```

## Workspace members

16 crates under `crates/`:

```
edwardian-core
edwardian-evidence
edwardian-platform
edwardian-detectors
edwardian-resolver
edwardian-directives
edwardian-proposals
edwardian-padagonia
edwardian-elci
edwardian-report
edwardian-engine
edwardian-cli
edwardian-daemon
edwardian-release
edwardian-store
edwardian-test
```

Shared dependencies in the root `Cargo.toml` `[workspace.dependencies]`: `serde`, `serde_json`, `clap`, `tempfile`, plus intra-workspace path deps.

## Running locally

```bash
cargo run -p edwardian-cli -- --path /tmp/my-repo analyse
cargo run -p edwardian-cli -- --path /tmp/my-repo --target windows readiness
cargo run -p edwardian-cli -- --path /tmp/my-repo --format json export --out /tmp/out
cargo run -p edwardian-cli -- daemon --once --path /tmp/my-repo
```

## Versioning

`VERSION` at the repository root holds the current workspace version (for example `0.1.4`). It is managed by `kaptaind` and must not be edited by hand. Thresholds in `kaptaind.toml`:

```toml
[version_thresholds]
minor = 0.6
patch = 0.1
```

Scores at or above `minor` bump Minor; scores at or above `patch` bump Patch; below `patch`, no commit.

## Kaptaind daemon

Kaptaind watches the repository, clusters filesystem events, scores the change, and commits/pushes when thresholds are met.

Configuration in `kaptaind.toml`:

- `watch.path = "."`, `recursive = true`, ignore file `.kaptainignore`
- `push.enabled = true`, `branch = "main"`, `capabilities.network_push = true`
- `operation.mode = "actuate"` (real commits)
- `ratelimit.min_commit_interval = 10`
- `weights: s=0.35, a=0.30, d=0.20, r=0.15`

State lives in `.kaptaind/` (ignored by `.kaptainignore` and `.gitignore`). Useful commands:

```bash
kaptaind-cli status
kaptaind-cli analyze
kaptaind-cli log --limit 20
kaptaind-cli validate
```

## Lint and style

- No workspace-level formatter config is enforced; follow `rustfmt` defaults.
- Schemas in `schemas/` must remain valid JSON Schema 2020-12.
- Documentation in `docs/` is Markdown with ATX headings; see `goglz.yaml` for style guidelines.

## Adding a detector

1. Create a module in `crates/edwardian-detectors/src/` with a struct implementing `Detector`.
2. Register it in `all_detectors()` in `crates/edwardian-detectors/src/lib.rs`.
3. Add unit tests in the module covering positive, negative, and edge cases.
4. Map the finding's dependency to a capability in `crates/edwardian-resolver/src/lib.rs` if it needs a ranked alternative; otherwise return `None` for portable cases.
5. Optionally add a `DEP_MAPPINGS` entry in `crates/edwardian-release/src/lib.rs` if a crate can be auto-injected.
6. Run `cargo test --workspace` and `edwardian --path . analyse` to verify.

## Adding a proposal

Extend `generate_proposals()` in `crates/edwardian-proposals/src/lib.rs`: check for the new capability's findings and emit a `Proposal` with a compatibility invariant and estimated effort. Add tests mirroring `inotify_finding_yields_fs_watch_proposal`.

## Goglz

Documentation is revised via [goglz](https://github.com/elci-group/goglz):

```bash
goglz revise -d .          # revise docs in place (via Groq API)
goglz revise -d docs       # revise only docs/
```

Revision is AI-backed and requires `~/.goglz` to hold a Groq API key. `goglz.yaml` in the project root configures purpose, scope, writing style, and formatting rules. The `revise` pipeline creates `.backup` files before overwriting; it only writes a backup after a successful AI response and leaves files untouched on AI failure.
