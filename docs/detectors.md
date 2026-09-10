# Detectors

Detectors are target-aware file scanners that produce evidence-backed findings. They run during the Detect stage over each `FileContext { path, content, target }`.

## Trait

```rust
pub trait Detector {
    fn id(&self) -> &'static str;
    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding>;
}
```

`FileContext` helpers: `basename()`, `extension()`, `is_shell_flavored()` (matches `.sh`, `.bash`, `.zsh`, `.ksh`, `Makefile*`, `.mk`).

`all_detectors()` registers the full set. Each detector stamps evidence via `EvidenceFactory::file_scan(location, observation, confidence, detector_id)`.

## Catalog

### Filesystem (`fs`)

Hardcoded Unix paths and path construction patterns.

- Detects: `/etc`, `/home`, `/var` literals, `Path::join` with Unix literals, case-collision pairs (case-sensitive shadowed paths).
- Ignores comments and non-literal occurrences where possible.
- Dependency: `Filesystem`; severities vary by pattern.

### FilesystemSemantics (`fs_semantics`)

POSIX filesystem semantics.

- Detects: `ln -s` in shell scripts, symlink API usage, file permission/mode literals, extension assumptions.
- Dependency: `Kernel` or `Filesystem` depending on pattern; `Unix symlink API is Major`.

### WindowsPath (`win_paths`)

Windows path handling.

- Flags Windows path separators and related portability concerns.

### ShellProcess (`shell`)

Shell and process spawning.

- Detects: absolute Unix shell paths (`/bin/bash`, `/usr/bin/sh`), `Command::new("sh")`, bare `bash` invocations, shell pipelines and shebangs.
- Severity: absolute paths are Blocker; bare `bash` is Major; `git` invocations are classified as Tooling, not blockers.
- Capability mapping: `process:spawn-shell`, `script:entrypoint`, `shell:interpreter`.

### Service (`services`)

Service and scheduling dependencies.

- Detects: `systemd` unit references, `cron` scheduling.
- Severity: `systemd` is Blocker.
- Capability: `service:manager`, `service:scheduler`.

### IPC (`ipc`)

Inter-process communication.

- Detects: Unix domain socket types, D-Bus, POSIX signals, `inotify` watches.
- Capability: `ipc:local-socket`, `ipc:bus`, `process:signals`, `fs:watch`.

### BuildSystem (`build`)

Build tooling.

- Detects: `Makefile` presence, `pkg-config` content, `CMake` usage (Minor), GitHub workflow files (CI).
- Dependency: `BuildSystem`, `Tooling`, `CI`.
- Capability: `build:make`, `build:meson`, `tooling:pkg-config`, `tooling:compiler-abi`.

### Env (`env`)

Configuration and environment.

- Detects: `$HOME`, `~` expansion, `XDG_*` patterns, `home_dir` API usage.
- Dependency: `Configuration`.
- Capability: `env:dirs`.

## Negative cases

Detectors are tested for false-positive resistance: comments, non-literal strings, plain words that resemble keywords, and portable tool invocations (for example `git` as a shell command) are not flagged beyond their correct dependency class.

## Capability mapping

After detection, `edwardian-resolver::capability_key(finding)` maps each finding's dependency and description to a capability string. Findings that need no alternative (for example portable CI or `git` tooling) map to `None`.

| Dependency pattern | Capability |
|---|---|
| Shell + absolute path / spawns | `process:spawn-shell` |
| Shell + shebang / pipeline | `script:entrypoint` |
| Shell (other) | `shell:interpreter` |
| Service + systemd | `service:manager` |
| Service + cron | `service:scheduler` |
| Kernel + inotify | `fs:watch` |
| Kernel (other) | `kernel:device-events` |
| IPC + D-Bus | `ipc:bus` |
| IPC (other) | `ipc:local-socket` |
| Process | `process:signals` |
| Filesystem | `fs:portable-paths` |
| Tooling + pkg-config | `tooling:pkg-config` |
| BuildSystem + Makefile | `build:make` |
| Configuration | `env:dirs` |
| CI | `None` (portable) |

Enable/disable detectors by editing `all_detectors()` in `crates/edwardian-detectors/src/lib.rs`. All detectors participate in every pipeline run; there is no per-detector flag at the CLI layer.
