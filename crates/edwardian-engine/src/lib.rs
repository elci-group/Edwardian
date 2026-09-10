use edwardian_core::{
    Alternative, Directive, Finding, Platform, Proposal, Severity,
};
use edwardian_detectors::{all_detectors, FileContext};
use edwardian_evidence::{EvidenceFactory, IdAllocator};
use edwardian_padagonia::Ontology;
use edwardian_report::{ReadinessReport, score_readiness};
use edwardian_resolver::{capability_key, AlternativeRegistry};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Stage {
    Discover,
    Inventory,
    Detect,
    Normalise,
    Classify,
    Resolve,
    Score,
    Direct,
    Propose,
    Report,
}

impl Stage {
    pub fn all() -> Vec<Stage> {
        vec![
            Stage::Discover,
            Stage::Inventory,
            Stage::Detect,
            Stage::Normalise,
            Stage::Classify,
            Stage::Resolve,
            Stage::Score,
            Stage::Direct,
            Stage::Propose,
            Stage::Report,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            Stage::Discover => "DISCOVER",
            Stage::Inventory => "INVENTORY",
            Stage::Detect => "DETECT",
            Stage::Normalise => "NORMALISE",
            Stage::Classify => "CLASSIFY",
            Stage::Resolve => "RESOLVE",
            Stage::Score => "SCORE",
            Stage::Direct => "DIRECT",
            Stage::Propose => "PROPOSE",
            Stage::Report => "REPORT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub target: Platform,
    pub max_file_size: u64,
    pub max_files: usize,
    pub skip_dirs: Vec<String>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            target: Platform::Windows,
            max_file_size: 1024 * 1024,
            max_files: 50_000,
            skip_dirs: vec![
                ".git".into(),
                "node_modules".into(),
                "target".into(),
                "vendor".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Discovery {
    pub repo_root: String,
    pub is_cargo_workspace: bool,
    pub workspace_members: Vec<String>,
    pub package_managers: Vec<String>,
    pub ci_systems: Vec<String>,
    pub scripts: Vec<String>,
    pub entrypoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
}

#[derive(Debug)]
pub struct AnalysisReport {
    pub target: Platform,
    pub discovery: Discovery,
    pub inventory: Vec<FileRecord>,
    pub files_skipped_binary: usize,
    pub files_skipped_limits: usize,
    pub findings: Vec<Finding>,
    pub alternatives: BTreeMap<String, Vec<Alternative>>,
    pub directives: Vec<Directive>,
    pub proposals: Vec<Proposal>,
    pub readiness: ReadinessReport,
    pub ontology: Ontology,
}

impl AnalysisReport {
    /// Serialise the full run for `edwardian.json`.
    pub fn to_json(&self) -> Value {
        json!({
            "tool": { "name": "edwardian", "version": env!("CARGO_PKG_VERSION") },
            "target": self.target,
            "stages": Stage::all().iter().map(|s| s.label()).collect::<Vec<_>>(),
            "discovery": self.discovery,
            "inventory": {
                "files": self.inventory.len(),
                "skipped_binary": self.files_skipped_binary,
                "skipped_limits": self.files_skipped_limits,
            },
            "findings": self.findings,
            "directives": self.directives,
            "proposals": self.proposals,
            "readiness": self.readiness,
            "ontology": self.ontology,
        })
    }

    pub fn platform_map_json(&self) -> Value {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for f in &self.findings {
            for e in &f.evidence {
                map.entry(e.location.path.clone())
                    .or_default()
                    .push(f.id.clone());
            }
        }
        json!({
            "target": self.target,
            "source_platform": Platform::Linux,
            "file_to_findings": map,
        })
    }

    pub fn alternatives_json(&self) -> Value {
        let entries: Vec<Value> = self
            .alternatives
            .iter()
            .map(|(finding_id, alts)| {
                json!({
                    "finding_id": finding_id,
                    "alternatives": alts,
                })
            })
            .collect();
        json!({ "target": self.target, "resolutions": entries })
    }

    pub fn readiness_json(&self) -> Value {
        serde_json::to_value(&self.readiness).unwrap_or(Value::Null)
    }

    pub fn directives_json(&self) -> Value {
        json!({ "target": self.target, "directives": self.directives })
    }

    pub fn proposals_json(&self) -> Value {
        json!({ "proposals": self.proposals })
    }

    pub fn find_finding(&self, id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| f.id == id)
    }

    pub fn artefact_values(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("edwardian.json", self.to_json()),
            ("platform-map.json", self.platform_map_json()),
            ("windows-readiness.json", self.readiness_json()),
            ("alternatives.json", self.alternatives_json()),
            ("directives.json", self.directives_json()),
            ("proposals.json", self.proposals_json()),
        ]
    }
}

/// Run the full pipeline over `root`. Static inspection only: nothing inside
/// the inspected repository is ever executed.
///
/// Not yet implemented (v1 scope): long-running daemon mode, filesystem watch
/// mode, and Dreamsequence integration. The ELCI facade (`edwardian-elci`) is
/// the intended seam for those frontends.
pub fn run(root: &Path, config: &PipelineConfig) -> io::Result<AnalysisReport> {
    // DISCOVER
    let discovery = discover(root)?;

    // INVENTORY
    let (inventory, skipped_binary, skipped_limits) = inventory(root, config)?;

    // DETECT
    let detectors = all_detectors();
    let mut factory = EvidenceFactory::new();
    let mut ids = IdAllocator::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut errors = 0usize;
    for rec in &inventory {
        let full = root.join(&rec.path);
        let Ok(content) = fs::read_to_string(&full) else {
            errors += 1;
            continue;
        };
        let ctx = FileContext::new(&rec.path, &content, config.target);
        for det in &detectors {
            for mut finding in det.run(&ctx, &mut factory) {
                finding.id = ids.next_finding_id();
                findings.push(finding);
            }
        }
    }
    let _ = errors;

    // Case-sensitivity check over the whole inventory (one finding per
    // directory with case-colliding filenames).
    let all_paths: Vec<String> = inventory.iter().map(|f| f.path.clone()).collect();
    for mut finding in
        edwardian_detectors::fs::case_collision_findings(&all_paths, config.target, &mut factory)
    {
        finding.id = ids.next_finding_id();
        findings.push(finding);
    }

    // NORMALISE: drop empty findings and duplicate evidence lines.
    findings.retain(|f| !f.evidence.is_empty());
    for f in &mut findings {
        let mut seen = BTreeSet::new();
        f.evidence
            .retain(|e| seen.insert((e.location.path.clone(), e.location.line, e.detector.clone())));
    }

    // CLASSIFY: deterministic ordering by descending severity, then id.
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));

    // RESOLVE
    let registry = AlternativeRegistry::seeded();
    let mut alternatives: BTreeMap<String, Vec<Alternative>> = BTreeMap::new();
    for f in &findings {
        if let Some(cap) = capability_key(f) {
            let alts = registry.alternatives_for(cap);
            if !alts.is_empty() {
                alternatives.insert(f.id.clone(), alts);
            }
        }
    }

    // SCORE
    let readiness = score_readiness(config.target, &findings);

    // DIRECT
    let directives = edwardian_directives::generate_directives(&findings, &registry);

    // PROPOSE
    let proposals = edwardian_proposals::generate_proposals(&findings);

    // REPORT (ontology index + artefact assembly)
    let mut components: BTreeSet<String> = BTreeSet::new();
    for f in &findings {
        for e in &f.evidence {
            if let Some(i) = e.location.path.rfind('/') {
                components.insert(e.location.path[..i].to_string());
            } else {
                components.insert(".".to_string());
            }
        }
    }
    let mut ontology = Ontology::new();
    ontology.index(
        &components.into_iter().collect::<Vec<_>>(),
        &findings,
        &directives,
        &proposals,
    );

    Ok(AnalysisReport {
        target: config.target,
        discovery,
        inventory,
        files_skipped_binary: skipped_binary,
        files_skipped_limits: skipped_limits,
        findings,
        alternatives,
        directives,
        proposals,
        readiness,
        ontology,
    })
}

fn discover(root: &Path) -> io::Result<Discovery> {
    let mut d = Discovery {
        repo_root: root.display().to_string(),
        ..Discovery::default()
    };
    let read = |name: &str| -> Option<String> {
        fs::read_to_string(root.join(name)).ok()
    };

    if let Some(cargo) = read("Cargo.toml") {
        d.package_managers.push("cargo".to_string());
        if cargo.contains("[workspace]") {
            d.is_cargo_workspace = true;
            let in_members = cargo
                .lines()
                .skip_while(|l| !l.trim_start().starts_with("members"))
                .skip(1)
                .skip_while(|l| l.trim_start().starts_with('#'));
            let mut in_members = in_members.peekable();
            for line in in_members.by_ref() {
                let t = line.trim();
                if t.starts_with(']') {
                    break;
                }
                for part in t.split(',') {
                    let name = part.trim().trim_matches('"').trim_matches('\'');
                    if !name.is_empty() && !name.starts_with('#') {
                        d.workspace_members.push(name.to_string());
                    }
                }
                if t.ends_with(']') {
                    break;
                }
            }
        }
    }
    for pm in ["package.json", "pyproject.toml", "go.mod", "Makefile", "requirements.txt"] {
        if root.join(pm).is_file() {
            d.package_managers.push(pm.to_string());
        }
    }
    if root.join(".github/workflows").is_dir() {
        d.ci_systems.push("github-actions".to_string());
    }
    if root.join(".gitlab-ci.yml").is_file() {
        d.ci_systems.push("gitlab-ci".to_string());
    }
    if root.join("Jenkinsfile").is_file() {
        d.ci_systems.push("jenkins".to_string());
    }
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if (name.ends_with(".sh") || name.ends_with(".bash")) && e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                d.scripts.push(name.clone());
            }
            if name == "src" && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                for entry in ["main.rs", "lib.rs", "main.py", "index.js"] {
                    if root.join("src").join(entry).is_file() {
                        d.entrypoints.push(format!("src/{}", entry));
                    }
                }
            }
            if name == "main.py" || name == "index.js" {
                d.entrypoints.push(name);
            }
        }
    }
    d.scripts.sort();
    d.package_managers.sort();
    d.package_managers.dedup();
    Ok(d)
}

/// Bounded, deterministic file walk shared by batch and daemon pipelines.
pub fn inventory(root: &Path, config: &PipelineConfig) -> io::Result<(Vec<FileRecord>, usize, usize)> {
    let root_canon = fs::canonicalize(root)?;
    let mut files = Vec::new();
    let mut skipped_binary = 0usize;
    let mut skipped_limits = 0usize;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if files.len() >= config.max_files {
            skipped_limits += 1;
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().to_string();
            let ft = match e.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let path = e.path();
            if ft.is_symlink() {
                // Protect against symlink escapes outside the inspected root.
                match fs::canonicalize(&path) {
                    Ok(target) if target.starts_with(&root_canon) => {
                        if target.is_dir() {
                            if config.skip_dirs.iter().any(|s| {
                                target.file_name().map(|n| n == s.as_str()).unwrap_or(false)
                            }) {
                                continue;
                            }
                            stack.push(target);
                        } else if target.is_file() {
                            push_file(&target, &root_canon, config, &mut files, &mut skipped_binary, &mut skipped_limits);
                        }
                    }
                    _ => skipped_limits += 1,
                }
                continue;
            }
            if ft.is_dir() {
                if config.skip_dirs.iter().any(|s| s == &name) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                push_file(&path, &root_canon, config, &mut files, &mut skipped_binary, &mut skipped_limits);
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((files, skipped_binary, skipped_limits))
}

fn push_file(
    path: &Path,
    root_canon: &Path,
    config: &PipelineConfig,
    files: &mut Vec<FileRecord>,
    skipped_binary: &mut usize,
    skipped_limits: &mut usize,
) {
    if files.len() >= config.max_files {
        *skipped_limits += 1;
        return;
    }
    let Ok(meta) = fs::metadata(path) else { return };
    if meta.len() > config.max_file_size {
        *skipped_limits += 1;
        return;
    }
    if let Ok(head) = fs::read(path) {
        if head.iter().take(8192).any(|b| *b == 0) {
            *skipped_binary += 1;
            return;
        }
    }
    let rel = path
        .strip_prefix(root_canon)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    files.push(FileRecord { path: rel, size: meta.len() });
}

pub fn format_readiness_console(report: &AnalysisReport) -> String {
    let r = &report.readiness;
    let mut out = String::new();
    out.push_str(&format!("Target: {}\n", r.target.label()));
    out.push_str(&format!(
        "Status: {} (overall {}%, blockers: {})\n",
        r.status.label(),
        r.overall,
        r.blocker_count
    ));
    for d in &r.dimensions {
        out.push_str(&format!(
            "  {:<18} {:>3}%  ({} findings)\n",
            d.dimension.label(),
            d.score,
            d.finding_count
        ));
    }
    out
}

/// Count findings at or above a severity — handy for tests and CLI summaries.
pub fn count_at_least(report: &AnalysisReport, severity: Severity) -> usize {
    report.findings.iter().filter(|f| f.severity >= severity).count()
}

/// Placeholder-free validation of a full report (used by `validate`).
pub fn validate_report(report: &AnalysisReport) -> Vec<String> {
    let mut problems = Vec::new();
    for f in &report.findings {
        if f.id.is_empty() || !f.has_material_evidence() {
            problems.push(format!("finding {} lacks material evidence", f.id));
        }
        if f.description.contains("TODO") || f.description.contains("placeholder") {
            problems.push(format!("finding {} has placeholder text", f.id));
        }
    }
    for d in &report.directives {
        if !d.validation_plan_is_complete() {
            problems.push(format!("directive {} has an incomplete validation plan", d.id));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for f in &report.findings {
        if !seen.insert(f.id.clone()) {
            problems.push(format!("duplicate finding id {}", f.id));
        }
    }
    problems
}

#[allow(dead_code)]
fn _keep_pathbuf(_: PathBuf) {}
