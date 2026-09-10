//! Release modes for Edwardian: `standalone` (Windows-centric fork) and
//! `compatible` (additive development branch). Both run after the standard
//! analysis pipeline and act only on its findings/directives/proposals.
//! Edwardian never executes inspected-project code; the only processes it
//! spawns are `git` commands in `compatible` mode (Edwardian acting on its
//! own generated content).

use edwardian_core::{Platform, Severity};
use edwardian_engine::{AnalysisReport, PipelineConfig, inventory};
use edwardian_resolver::{AlternativeRegistry, capability_key};

pub mod compatible;
use serde::Serialize;
use std::fs;
use std::io;
use std::path::Path;

/// A crate that can be auto-injected for a detected capability.
#[derive(Debug, Clone, Copy)]
pub struct DepMapping {
    pub capability: &'static str,
    pub crate_name: &'static str,
    pub version: &'static str,
    /// True when adding the dependency *is* the fix (the crate substitutes
    /// for the unix mechanism directly). False when the dependency only
    /// enables the fix — code changes still required (manual work remains).
    pub substitutable: bool,
}

/// Conservative whitelist of FOSS alternatives from the resolver registry
/// that map 1:1 to crates injectable into a Cargo manifest.
pub const DEP_MAPPINGS: &[DepMapping] = &[
    DepMapping { capability: "fs:watch", crate_name: "notify", version: "8", substitutable: true },
    DepMapping {
        capability: "service:manager",
        crate_name: "service-manager",
        version: "0.8",
        substitutable: false,
    },
    DepMapping {
        capability: "ipc:local-socket",
        crate_name: "interprocess",
        version: "2",
        substitutable: true,
    },
    DepMapping { capability: "env:dirs", crate_name: "directories", version: "6", substitutable: true },
];

/// Resolve the dep mappings implied by the report: for every capability
/// detected (in finding order), the highest-ranked registry alternative that
/// includes the target platform and has a whitelist mapping wins.
pub fn resolve_deps(report: &AnalysisReport, target: Platform) -> Vec<DepMapping> {
    let registry = AlternativeRegistry::seeded();
    let mut out: Vec<DepMapping> = Vec::new();
    for f in &report.findings {
        let Some(cap) = capability_key(f) else { continue };
        if out.iter().any(|m| m.capability == cap) {
            continue;
        }
        let Some(mapping) = DEP_MAPPINGS.iter().find(|m| m.capability == cap) else {
            continue;
        };
        let alts = registry.alternatives_for(cap);
        let usable = alts
            .iter()
            .any(|a| a.platforms.contains(&target) && a.name.contains(mapping.crate_name));
        if usable {
            out.push(*mapping);
        }
    }
    out
}

/// Evidence ids backing every finding of a capability (sorted, deduped).
pub fn capability_evidence(report: &AnalysisReport, capability: &str) -> Vec<String> {
    let mut ids: Vec<String> = report
        .findings
        .iter()
        .filter(|f| capability_key(f) == Some(capability))
        .flat_map(|f| f.evidence.iter().map(|e| e.id.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

pub const TARGET_SECTION_HEADER: &str = "[target.'cfg(windows)'.dependencies]";

/// Render the manifest section to append to a Cargo.toml. Empty when there is
/// nothing to add (or the section/dep already exists in `existing`).
pub fn render_dep_section(existing: &str, deps: &[DepMapping]) -> String {
    if deps.is_empty() || !existing.contains("[package]") && !existing.contains("[workspace]") {
        return String::new();
    }
    if existing.contains(TARGET_SECTION_HEADER) {
        return String::new();
    }
    let mut names: Vec<(&str, &str)> = deps.iter().map(|m| (m.crate_name, m.version)).collect();
    names.sort_by_key(|(n, _)| *n);
    names.dedup_by_key(|(n, _)| *n);
    let mut out = String::from("\n") ;
    out.push_str(TARGET_SECTION_HEADER);
    out.push('\n');
    for (name, version) in names {
        if existing.lines().any(|l| l.trim_start().starts_with(&format!("{} =", name))) {
            continue;
        }
        out.push_str(&format!("{} = \"{}\"\n", name, version));
    }
    // If every dep was already present individually, drop the section again.
    let body_lines = out.lines().count();
    if body_lines <= 2 {
        String::new()
    } else {
        out
    }
}

fn ensure_outside_source(source: &Path, out: &Path) -> io::Result<()> {
    let src = fs::canonicalize(source)?;
    let dst = fs::canonicalize(out).or_else(|_| {
        // Canonicalize the nearest existing ancestor of `out`.
        let mut p = out.to_path_buf();
        while !p.exists() {
            if !p.pop() {
                break;
            }
        }
        fs::canonicalize(p)
    })?;
    if dst.starts_with(&src) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output directory must not be inside the inspected source tree",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Transform {
    pub transform_id: &'static str,
    pub file: String,
    pub evidence_ids: Vec<String>,
    pub change: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ManualItem {
    pub finding_id: String,
    pub evidence_ids: Vec<String>,
    pub what: String,
    pub why: String,
    pub location: String,
    pub validation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StandaloneReport {
    pub mode: &'static str,
    pub files_copied: usize,
    pub transforms: Vec<Transform>,
    pub manual_work: Vec<ManualItem>,
    pub fork_dir: String,
}

fn default_validation(severity: Severity) -> Vec<String> {
    let mut plan = vec![
        "Linux build passes (cargo build)".to_string(),
        "Windows build passes (cargo build --target x86_64-pc-windows-msvc)".to_string(),
    ];
    if severity >= Severity::Major {
        plan.push("Output equivalence test: Linux vs Windows behaviour identical on a golden input".to_string());
        plan.push("CI matrix (ubuntu-latest, windows-latest) passes".to_string());
    }
    plan
}

/// Build the manual-work list: every Blocker/Major finding not resolved by a
/// transform, sorted by finding id.
pub fn manual_work(report: &AnalysisReport, resolved_caps: &[&str]) -> Vec<ManualItem> {
    let mut items = Vec::new();
    for f in &report.findings {
        if f.severity < Severity::Major {
            continue;
        }
        let cap = capability_key(f);
        if let Some(cap) = cap {
            if resolved_caps.contains(&cap) {
                continue;
            }
        }
        let directive = report
            .directives
            .iter()
            .find(|d| d.evidence_ids.iter().any(|e| f.evidence.iter().any(|fe| fe.id == *e)));
        let validation = directive
            .map(|d| d.validation_plan.clone())
            .unwrap_or_else(|| default_validation(f.severity));
        let location = f
            .evidence
            .first()
            .map(|e| format!("{}:{}:{}", e.location.path, e.location.line, e.location.column))
            .unwrap_or_else(|| "?".to_string());
        items.push(ManualItem {
            finding_id: f.id.clone(),
            evidence_ids: f.evidence.iter().map(|e| e.id.clone()).collect(),
            what: f.description.clone(),
            why: format!(
                "{} / {} on target {}",
                f.severity.label(),
                f.state.label(),
                report.target.label()
            ),
            location,
            validation,
        });
    }
    items.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    items
}

fn render_fork_markdown(report: &StandaloneReport, objective: &str) -> String {
    let mut md = String::from("# Edwardian standalone fork\n\n");
    md.push_str(&format!("Objective: {}\n\n", objective));
    md.push_str(&format!("Files copied: {}\n\n", report.files_copied));
    md.push_str("## Applied transforms\n\n");
    if report.transforms.is_empty() {
        md.push_str("_None._\n\n");
    } else {
        for t in &report.transforms {
            md.push_str(&format!(
                "- **{}** `{}` (evidence: {}): {}\n",
                t.transform_id,
                t.file,
                t.evidence_ids.join(", "),
                t.change
            ));
        }
        md.push('\n');
    }
    md.push_str("## MANUAL WORK\n\n");
    if report.manual_work.is_empty() {
        md.push_str("_None — no unresolved blocker or major findings._\n");
    } else {
        for m in &report.manual_work {
            md.push_str(&format!(
                "- **{}** {} — {} @ `{}`\n  - evidence: {}\n  - validation: {}\n",
                m.finding_id,
                m.what,
                m.why,
                m.location,
                m.evidence_ids.join(", "),
                m.validation.join("; ")
            ));
        }
    }
    md
}

/// Mode 1: standalone release. Bounded copy of the source tree plus
/// mechanically applicable transforms and a manifest. Symlinks are copied as
/// regular files (their in-root resolved content); broken links are skipped.
pub fn standalone(report: &AnalysisReport, source: &Path, out: &Path) -> io::Result<StandaloneReport> {
    let fork_dir = out.join("standalone-fork");
    ensure_outside_source(source, &fork_dir)?;
    fs::create_dir_all(&fork_dir)?;

    let config = PipelineConfig {
        target: report.target,
        ..PipelineConfig::default()
    };
    let (files, _bin, _limits) = inventory(source, &config)?;
    for rec in &files {
        let from = source.join(&rec.path);
        let to = fork_dir.join(&rec.path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&from, &to)?;
    }

    let mut transforms = Vec::new();
    let mut resolved_caps: Vec<&str> = Vec::new();

    // T1: inject cfg(windows) dependencies at the root manifest.
    if report.target == Platform::Windows {
        let deps = resolve_deps(report, report.target);
        let manifest_path = fork_dir.join("Cargo.toml");
        if !deps.is_empty() && manifest_path.is_file() {
            let existing = fs::read_to_string(&manifest_path)?;
            let section = render_dep_section(&existing, &deps);
            if !section.is_empty() {
                let mut patched = existing.clone();
                patched.push_str(&section);
                fs::write(&manifest_path, patched)?;
                for m in &deps {
                    transforms.push(Transform {
                        transform_id: "T1",
                        file: "Cargo.toml".to_string(),
                        evidence_ids: capability_evidence(report, m.capability),
                        change: format!(
                            "added `{} = \"{}\"` under {}",
                            m.crate_name, m.version, TARGET_SECTION_HEADER
                        ),
                    });
                    if m.substitutable {
                        resolved_caps.push(m.capability);
                    }
                }
            }
        }
    }

    let manual = manual_work(report, &resolved_caps);
    let result = StandaloneReport {
        mode: "standalone",
        files_copied: files.len(),
        transforms,
        manual_work: manual,
        fork_dir: fork_dir.display().to_string(),
    };
    let md = render_fork_markdown(
        &result,
        &format!(
            "Windows-centric standalone fork of the {} analysis (target {})",
            report.discovery.repo_root,
            report.target.label()
        ),
    );
    fs::write(fork_dir.join("EDWARDIAN-FORK.md"), md)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_dep_section_is_deterministic_and_idempotent() {
        let deps = &DEP_MAPPINGS[..2];
        let section = render_dep_section("[package]\nname = \"x\"\n", deps);
        assert!(section.contains(TARGET_SECTION_HEADER));
        // Sorted by crate name: notify < service-manager.
        let ni = section.find("notify").unwrap();
        let si = section.find("service-manager").unwrap();
        assert!(ni < si);
        // Second pass: section already present -> nothing to add.
        assert!(render_dep_section("[package]\n", &[]).is_empty());
        assert!(render_dep_section(&section, deps).is_empty());
    }

    #[test]
    fn render_dep_section_skips_preexisting_dep_lines() {
        let deps = &DEP_MAPPINGS[..1];
        let existing = "[package]\n\n[dependencies]\nnotify = \"6\"\n";
        assert!(render_dep_section(existing, deps).is_empty());
    }

    #[test]
    fn module_and_trait_name_extraction() {
        assert_eq!(compatible::module_name("fs-watch"), "fs_watch");
        assert_eq!(compatible::module_name("ipc:bus"), "ipc_bus");
        let iface = "pub trait FileWatcher { fn watch(&mut self, path: &Path) -> Result<()>; }";
        assert_eq!(compatible::trait_name(iface), Some("FileWatcher"));
        assert!(compatible::trait_name("no trait here").is_none());
    }
}
