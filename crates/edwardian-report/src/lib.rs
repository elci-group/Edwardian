use edwardian_core::{
    Directive, Finding, Platform, PlatformDependency, Proposal, ReadinessStatus, Severity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dimension {
    Architecture,
    Source,
    Runtime,
    Build,
    Tooling,
    Filesystem,
    ProcessModel,
    NativeDependencies,
    CI,
    Distribution,
}

impl Dimension {
    pub fn all() -> Vec<Dimension> {
        vec![
            Dimension::Architecture,
            Dimension::Source,
            Dimension::Runtime,
            Dimension::Build,
            Dimension::Tooling,
            Dimension::Filesystem,
            Dimension::ProcessModel,
            Dimension::NativeDependencies,
            Dimension::CI,
            Dimension::Distribution,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            Dimension::Architecture => "Architecture",
            Dimension::Source => "Source",
            Dimension::Runtime => "Runtime",
            Dimension::Build => "Build",
            Dimension::Tooling => "Tooling",
            Dimension::Filesystem => "Filesystem",
            Dimension::ProcessModel => "Process model",
            Dimension::NativeDependencies => "Native dependencies",
            Dimension::CI => "CI",
            Dimension::Distribution => "Distribution",
        }
    }

    pub fn of(dep: PlatformDependency) -> Dimension {
        match dep {
            PlatformDependency::Architecture => Dimension::Architecture,
            PlatformDependency::Compiler | PlatformDependency::Configuration => Dimension::Source,
            PlatformDependency::Runtime => Dimension::Runtime,
            PlatformDependency::BuildSystem => Dimension::Build,
            PlatformDependency::Tooling => Dimension::Tooling,
            PlatformDependency::Filesystem => Dimension::Filesystem,
            PlatformDependency::Process | PlatformDependency::Shell | PlatformDependency::Service => {
                Dimension::ProcessModel
            }
            PlatformDependency::IPC
            | PlatformDependency::Kernel
            | PlatformDependency::NativeLibrary
            | PlatformDependency::ABI => Dimension::NativeDependencies,
            PlatformDependency::CI => Dimension::CI,
            PlatformDependency::PackageManager
            | PlatformDependency::Container
            | PlatformDependency::Deployment => Dimension::Distribution,
            PlatformDependency::None | PlatformDependency::Unknown => Dimension::Source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DimensionScore {
    pub dimension: Dimension,
    pub score: u8,
    pub finding_count: usize,
    pub highest_severity: Option<Severity>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub target: Platform,
    pub status: ReadinessStatus,
    pub overall: u8,
    pub dimensions: Vec<DimensionScore>,
    pub blocker_count: usize,
}

fn deduction(severity: Severity) -> u8 {
    match severity {
        Severity::Blocker => 100,
        Severity::Major => 40,
        Severity::Minor => 10,
        Severity::Info => 2,
    }
}

/// Readiness thresholds: READY at >=85 overall with no blockers,
/// CONDITIONAL at >=55, otherwise BLOCKED. Any single Blocker-severity finding
/// forces BLOCKED regardless of percentages — the aggregate can never conceal
/// a blocker.
pub fn score_readiness(target: Platform, findings: &[Finding]) -> ReadinessReport {
    let mut dimensions = Vec::new();
    for dim in Dimension::all() {
        let relevant: Vec<&Finding> = findings
            .iter()
            .filter(|f| Dimension::of(f.dependency) == dim)
            .collect();
        let penalty: u32 = relevant
            .iter()
            .map(|f| deduction(f.severity) as u32)
            .sum();
        let score = 100u32.saturating_sub(penalty).min(100) as u8;
        dimensions.push(DimensionScore {
            dimension: dim,
            score,
            finding_count: relevant.len(),
            highest_severity: relevant.iter().map(|f| f.severity).max(),
        });
    }
    let overall = if dimensions.is_empty() {
        100
    } else {
        (dimensions.iter().map(|d| d.score as u32).sum::<u32>() / dimensions.len() as u32) as u8
    };
    let blocker_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Blocker)
        .count();
    let status = if blocker_count > 0 {
        ReadinessStatus::Blocked
    } else if overall >= 85 {
        ReadinessStatus::Ready
    } else if overall >= 55 {
        ReadinessStatus::Conditional
    } else {
        ReadinessStatus::Blocked
    };
    ReadinessReport {
        target,
        status,
        overall,
        dimensions,
        blocker_count,
    }
}

/// Render the human-readable Markdown report.
pub fn render_markdown(
    readiness: &ReadinessReport,
    findings: &[Finding],
    directives: &[Directive],
    proposals: &[Proposal],
) -> String {
    let mut out = String::new();
    out.push_str("# Edwardian platform-readiness report\n\n");
    out.push_str(&format!("- Target platform: **{}**\n", readiness.target.label()));
    out.push_str(&format!("- Overall readiness: **{}%**\n", readiness.overall));
    out.push_str(&format!("- Status: **{}**\n", readiness.status.label()));
    out.push_str(&format!("- Blockers: {}\n", readiness.blocker_count));
    out.push_str(&format!("- Findings: {}, directives: {}, proposals: {}\n\n", findings.len(), directives.len(), proposals.len()));

    out.push_str("## Readiness by dimension\n\n");
    out.push_str("| Dimension | Score | Findings | Highest severity |\n");
    out.push_str("|---|---|---|---|\n");
    for d in &readiness.dimensions {
        out.push_str(&format!(
            "| {} | {}% | {} | {} |\n",
            d.dimension.label(),
            d.score,
            d.finding_count,
            d.highest_severity.map(|s| s.label()).unwrap_or("-")
        ));
    }

    out.push_str("\n## Blocker and major findings\n\n");
    let material: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Major)
        .collect();
    if material.is_empty() {
        out.push_str("_None._\n");
    } else {
        for f in material {
            out.push_str(&format!(
                "- **{}** [{} / {}] {} ({} evidence)\n",
                f.id,
                f.severity.label(),
                f.dependency.label(),
                f.description,
                f.evidence.len()
            ));
        }
    }

    out.push_str("\n## Dependency chains\n\n");
    if directives.is_empty() {
        out.push_str("_None._\n");
    } else {
        for (n, idx) in edwardian_directives::topo_order(directives).iter().enumerate() {
            let d = &directives[*idx];
            let predecessors = if d.dependencies.is_empty() {
                "no predecessors".to_string()
            } else {
                format!("after: {}", d.dependencies.join(", "))
            };
            out.push_str(&format!(
                "{}. **{}** ({}) {} — {}\n",
                n + 1,
                d.id,
                d.priority.label(),
                d.objective,
                predecessors
            ));
        }
    }

    out.push_str("\n## Directives\n\n");
    if directives.is_empty() {
        out.push_str("_None._\n");
    } else {
        for d in directives {
            out.push_str(&format!(
                "- **{}** ({}): {} — {} validation step(s)\n",
                d.id,
                d.priority.label(),
                d.objective,
                d.validation_plan.len()
            ));
        }
    }

    out.push_str("\n## Proposals\n\n");
    if proposals.is_empty() {
        out.push_str("_None._\n");
    } else {
        for p in proposals {
            out.push_str(&format!(
                "- **{}** ({}): {} (~{} days, {})\n",
                p.id, p.capability, p.required_impl, p.estimated_effort_days, p.risk
            ));
        }
    }
    out.push('\n');
    out
}

/// Write all machine artefacts under `<out>/edwardian/`.
pub fn write_artifacts(
    out: &Path,
    artifacts: &[(&str, &Value)],
    markdown: &str,
) -> io::Result<Vec<PathBuf>> {
    let dir = out.join("edwardian");
    fs::create_dir_all(&dir)?;
    let mut written = Vec::new();
    for (name, value) in artifacts {
        let path = dir.join(name);
        let text = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
        fs::write(&path, format!("{}\n", text))?;
        written.push(path);
    }
    let md_path = dir.join("report.md");
    fs::write(&md_path, markdown)?;
    written.push(md_path);
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::{CompatibilityState, Directive, Evidence, Location};

    fn finding(dep: PlatformDependency, sev: Severity) -> Finding {
        let mut f = Finding::new(dep, CompatibilityState::Unknown, sev, "test", None);
        f.evidence.push(Evidence::file_scan(
            "EWD-00001",
            Location::new("x.rs", 1, 1),
            "obs",
            0.5,
            "det",
        ));
        f
    }

    #[test]
    fn blocker_forces_blocked_regardless_of_percentage() {
        let findings = vec![finding(PlatformDependency::Shell, Severity::Blocker)];
        let r = score_readiness(Platform::Windows, &findings);
        assert_eq!(r.status, ReadinessStatus::Blocked);
        assert_eq!(r.blocker_count, 1);
        assert!(r.dimensions.iter().any(|d| d.score == 0));
        // Other dimensions stay at 100, so overall is high — yet BLOCKED.
        assert!(r.overall >= 80);
    }

    #[test]
    fn clean_repo_is_ready_at_100() {
        let r = score_readiness(Platform::Windows, &[]);
        assert_eq!(r.status, ReadinessStatus::Ready);
        assert_eq!(r.overall, 100);
    }

    #[test]
    fn minors_keep_repo_conditional_or_ready() {
        let findings = vec![finding(PlatformDependency::Filesystem, Severity::Minor)];
        let r = score_readiness(Platform::Windows, &findings);
        assert_eq!(r.status, ReadinessStatus::Ready);
        let fs = r
            .dimensions
            .iter()
            .find(|d| d.dimension == Dimension::Filesystem)
            .unwrap();
        assert_eq!(fs.score, 90);
    }

    #[test]
    fn markdown_mentions_status_and_findings() {
        let findings = vec![finding(PlatformDependency::Service, Severity::Blocker)];
        let r = score_readiness(Platform::Windows, &findings);
        let directives = vec![Directive {
            id: "EWD-D001".to_string(),
            priority: edwardian_core::DirectivePriority::P0,
            objective: "fix the service".to_string(),
            evidence_ids: vec!["EWD-00001".to_string()],
            affected_components: vec!["src".to_string()],
            current_state: CompatibilityState::RequiresImplementation,
            target_state: CompatibilityState::WindowsCompatible,
            remediation: "do the thing".to_string(),
            validation_plan: vec!["step".to_string()],
            dependencies: Vec::new(),
        }];
        let md = render_markdown(&r, &findings, &directives, &[]);
        assert!(md.contains("BLOCKED"));
        assert!(md.contains("service"));
        assert!(md.contains("## Dependency chains"));
        assert!(md.contains("no predecessors"));
        // Directives section still present after the chains section.
        assert!(md.contains("## Directives"));
    }
}
