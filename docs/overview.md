# Overview

Edwardian answers one question: how ready is this Linux-first repository for Windows (or another target platform), and what must change?

## Problem

Linux-first codebases accumulate implicit platform dependencies: hardcoded `/etc` or `/var` paths, `inotify` watches, `systemd` units, `SIGTERM`/`SIGKILL` handling, Unix domain sockets, `pkg-config` build hooks, and POSIX shell assumptions. These compile on Linux but fail or behave differently elsewhere. Edwardian makes them visible before a port begins.

## Approach

- **Static analysis only.** Edwardian reads files and never executes project code. The single exception is `release compatible` mode, which may run `git` commands on the output branch content it owns.
- **Evidence-backed findings.** Every finding carries one or more Evidence records with a deterministic ID (`EWD-NNNNN`), a location (path, line, column), an observation, confidence, and the detector that produced it.
- **Ranked remediation.** Each finding maps to a capability key (for example `fs:watch`, `service:manager`, `shell:interpreter`). The resolver registry holds ranked FOSS alternatives with maturity, integration cost, operational risk, supported platforms, and decision strategy. Directives embed the top-ranked alternative.
- **Readiness scoring.** Findings feed dimension scores (Architecture, Source, Runtime, Build, Tooling, Filesystem, ProcessModel, NativeDependencies, CI, Distribution) and an overall 0–100 score with a status of READY, CONDITIONAL, or BLOCKED.

## Key concepts

| Term | Meaning |
|---|---|
| Evidence | A single observation from a detector, with location and confidence |
| Finding | A grouped, classified platform dependency with severity and compatibility state |
| Alternative | A candidate replacement for a capability, ranked by strategy and maturity |
| Directive | A remediation task (EWD-DNNN) derived from a finding, with priority P0/P1/P2 |
| Proposal | An architectural gap requiring a new abstraction (for example FileWatcher trait for `fs-watch`) |
| Readiness | Per-dimension and overall portability score with status |
| Ontology | Knowledge graph linking components, findings, directives, and proposals |

## Target platforms

`linux`, `windows` (default), `macos`, `freebsd`, `openbsd`, `android`, `ios`, `wasm`. Each has a PlatformProfile describing shell, path separator, Unix socket and POSIX signal support, service manager, FS watch API, package managers, and native ABI. See `crates/edwardian-platform`.

## When to use which command

- Exploring an unknown repo: `edwardian inspect`
- Full assessment: `edwardian analyse` then `edwardian readiness`
- Planning work: `edwardian directive` and `edwardian propose`
- CI gate: `edwardian validate --format json` or check `readiness.status`
- Continuous feedback: `edwardian daemon --once` or `edwardian daemon --interval 5`
- Forking for Windows: `edwardian release standalone` or `edwardian release compatible`
