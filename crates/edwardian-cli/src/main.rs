use clap::{Parser, Subcommand, ValueEnum};
use edwardian_core::{DirectivePriority, Platform, Severity};
use edwardian_elci::{CapabilityRegistry, FindingsProvider};
use edwardian_engine::{AnalysisReport, PipelineConfig, Stage};
use edwardian_report::{render_markdown, write_artifacts};
use serde_json::json;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "edwardian", version, about = "Platform-portability intelligence for Linux-first repositories")]
struct Cli {
    /// Target platform to assess readiness for.
    #[arg(long, global = true, default_value = "windows")]
    target: TargetArg,

    /// Repository path to inspect.
    #[arg(long, global = true, default_value = ".")]
    path: PathBuf,

    /// Output format.
    #[arg(long, global = true, default_value = "human")]
    format: FormatArg,

    /// Output directory for machine artefacts (written under <out>/edwardian/).
    #[arg(long, global = true, default_value = ".")]
    out: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, ValueEnum)]
enum TargetArg {
    Windows,
    Linux,
    MacOs,
    FreeBsd,
    OpenBsd,
    Android,
    Ios,
    Wasm,
}

impl From<TargetArg> for Platform {
    fn from(t: TargetArg) -> Platform {
        match t {
            TargetArg::Windows => Platform::Windows,
            TargetArg::Linux => Platform::Linux,
            TargetArg::MacOs => Platform::MacOs,
            TargetArg::FreeBsd => Platform::FreeBsd,
            TargetArg::OpenBsd => Platform::OpenBsd,
            TargetArg::Android => Platform::Android,
            TargetArg::Ios => Platform::Ios,
            TargetArg::Wasm => Platform::Wasm,
        }
    }
}

#[derive(Clone, ValueEnum, PartialEq)]
enum FormatArg {
    Human,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Discover repository layout: workspaces, package managers, CI, scripts.
    Inspect,
    /// Full analysis: findings, evidence, classification.
    Analyse,
    /// Show one finding with its evidence and resolution.
    Explain { finding_id: String },
    /// List ranked alternatives per capability found.
    Alternatives,
    /// Windows readiness score by dimension.
    Readiness,
    /// List generated remediation directives.
    Directive,
    /// List capability proposals (architectural gaps).
    Propose,
    /// Structurally validate directives and the report (nothing is executed).
    Validate,
    /// Write machine artefacts to <out>/edwardian/.
    Export,
    /// Watch a repository and emit incremental analysis events.
    /// Runs until killed (no signal handlers are installed, std-only);
    /// use --once for a single poll cycle.
    Daemon {
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Run a single poll cycle and exit.
        #[arg(long)]
        once: bool,
    },
    /// Produce a release: a standalone Windows fork or a compatible dev branch.
    Release {
        #[command(subcommand)]
        mode: ReleaseMode,
    },
}

#[derive(Subcommand)]
enum ReleaseMode {
    /// Windows-centric fork: bounded source copy + transforms + manifest.
    Standalone,
    /// Additive scaffolding on a development branch (or fallback dir).
    Compatible {
        /// Branch name (default edwardian/compat-<target>).
        #[arg(long)]
        branch_name: Option<String>,
        /// Never invoke git; write branch content to <out>/compat-branch/.
        #[arg(long)]
        no_git: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("edwardian: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let config = PipelineConfig {
        target: cli.target.into(),
        ..PipelineConfig::default()
    };
    let root = std::fs::canonicalize(&cli.path)
        .map_err(|e| format!("cannot access path {}: {}", cli.path.display(), e))?;
    let report = edwardian_engine::run(&root, &config)
        .map_err(|e| format!("pipeline failed: {}", e))?;

    let json = cli.format == FormatArg::Json;
    let out = match &cli.command {
        Command::Inspect => cmd_inspect(&report, json),
        Command::Analyse => cmd_analyse(&report, json, &cli.out),
        Command::Explain { finding_id } => cmd_explain(&report, finding_id, json),
        Command::Alternatives => cmd_alternatives(&report, json),
        Command::Readiness => cmd_readiness(&report, json, &cli.out),
        Command::Directive => cmd_directive(&report, json),
        Command::Propose => cmd_propose(&report, json),
        Command::Validate => cmd_validate(&report, json),
        Command::Export => cmd_export(&report, &cli.out, json),
        Command::Daemon { interval, once } => {
            return cmd_daemon(&root, &config, *interval, *once, json);
        }
        Command::Release { mode } => {
            return cmd_release(&report, &root, &cli.out, mode, json);
        }
    }?;
    print!("{}", out);
    Ok(())
}

fn maybe_write_artifacts(report: &AnalysisReport, out: &Path) -> Result<Vec<PathBuf>, String> {
    let markdown = render_markdown(
        &report.readiness,
        &report.findings,
        &report.directives,
        &report.proposals,
    );
    let values = report.artefact_values();
    let artifacts: Vec<(&'static str, &serde_json::Value)> =
        values.iter().map(|(n, v)| (*n, v)).collect();
    write_artifacts(out, &artifacts, &markdown).map_err(|e| format!("writing artefacts: {}", e))
}

fn cmd_inspect(report: &AnalysisReport, json: bool) -> Result<String, String> {
    let d = &report.discovery;
    if json {
        return Ok(serde_json::to_string_pretty(&json!({
            "discovery": d,
            "inventory": {
                "files": report.inventory.len(),
                "skipped_binary": report.files_skipped_binary,
                "skipped_limits": report.files_skipped_limits,
            },
            "stages": Stage::all().iter().map(|s| s.label()).collect::<Vec<_>>(),
        }))
        .map_err(|e| e.to_string())?);
    }
    Ok(format!(
        "Repository: {}\nStages: {}\nPackage managers: {}\nWorkspace members: {}\nCI systems: {}\nScripts: {}\nEntrypoints: {}\nFiles inventoried: {} ({} binary skipped, {} over limits)\n",
        d.repo_root,
        Stage::all().iter().map(|s| s.label()).collect::<Vec<_>>().join(" → "),
        d.package_managers.join(", "),
        if d.workspace_members.is_empty() { "-".into() } else { d.workspace_members.join(", ") },
        if d.ci_systems.is_empty() { "-".into() } else { d.ci_systems.join(", ") },
        if d.scripts.is_empty() { "-".into() } else { d.scripts.join(", ") },
        if d.entrypoints.is_empty() { "-".into() } else { d.entrypoints.join(", ") },
        report.inventory.len(),
        report.files_skipped_binary,
        report.files_skipped_limits,
    ))
}

fn cmd_analyse(report: &AnalysisReport, json: bool, out: &Path) -> Result<String, String> {
    let written = maybe_write_artifacts(report, out)?;
    if json {
        return Ok(serde_json::to_string_pretty(&report.to_json()).map_err(|e| e.to_string())?);
    }
    let mut s = String::from("Findings (by severity):\n");
    for f in &report.findings {
        s.push_str(&format!(
            "  {} [{:<7}] {:<16} {:<28} {}\n",
            f.id,
            f.severity.label(),
            f.dependency.label(),
            f.state.label(),
            f.description
        ));
    }
    if report.findings.is_empty() {
        s.push_str("  none\n");
    }
    s.push_str(&format!(
        "\nArtefacts written under {}/\n",
        written[0].parent().unwrap().display()
    ));
    Ok(s)
}

fn cmd_explain(report: &AnalysisReport, finding_id: &str, json: bool) -> Result<String, String> {
    // Route through the ELCI capability facade rather than direct access.
    let mut registry = CapabilityRegistry::new();
    registry
        .register(Box::new(FindingsProvider::new(report.findings.clone())))
        .map_err(|e| e.to_string())?;
    let value = registry
        .invoke("findings.get", &json!({ "id": finding_id }))
        .map_err(|_| format!("finding `{}` not found", finding_id))?;
    if json {
        let mut alternatives = serde_json::Value::Null;
        if let Some(alts) = report.alternatives.get(finding_id) {
            alternatives = serde_json::to_value(alts).map_err(|e| e.to_string())?;
        }
        return Ok(serde_json::to_string_pretty(&json!({
            "finding": value,
            "alternatives": alternatives,
        }))
        .map_err(|e| e.to_string())?);
    }
    let finding: edwardian_core::Finding =
        serde_json::from_value(value).map_err(|e| e.to_string())?;
    let mut s = format!(
        "{} [{}] {}\nDependency: {} | State: {}\n",
        finding.id,
        finding.severity.label(),
        finding.description,
        finding.dependency.label(),
        finding.state.label()
    );
    if let Some(hint) = &finding.remediation_hint {
        s.push_str(&format!("Hint: {}\n", hint));
    }
    s.push_str("Evidence:\n");
    for e in &finding.evidence {
        s.push_str(&format!(
            "  {} {}:{}:{} ({} conf {:.2}): {}\n",
            e.id,
            e.location.path,
            e.location.line,
            e.location.column,
            e.detector,
            e.confidence,
            e.observation
        ));
    }
    if let Some(alts) = report.alternatives.get(finding_id) {
        s.push_str("Ranked alternatives (decision hierarchy order):\n");
        for (i, a) in alts.iter().enumerate() {
            s.push_str(&format!(
                "  {}. {} [{}] cost {} risk {} — {}\n",
                i + 1,
                a.name,
                a.strategy.label(),
                a.integration_cost,
                a.operational_risk,
                a.rationale
            ));
        }
    }
    Ok(s)
}

fn cmd_alternatives(report: &AnalysisReport, json: bool) -> Result<String, String> {
    if json {
        return Ok(
            serde_json::to_string_pretty(&report.alternatives_json()).map_err(|e| e.to_string())?
        );
    }
    if report.alternatives.is_empty() {
        return Ok("No capabilities require alternatives.\n".to_string());
    }
    let mut s = String::new();
    for (fid, alts) in &report.alternatives {
        s.push_str(&format!("{}:\n", fid));
        for (i, a) in alts.iter().enumerate() {
            s.push_str(&format!(
                "  {}. {} ({}) — {}\n",
                i + 1,
                a.name,
                a.strategy.label(),
                a.rationale
            ));
        }
    }
    Ok(s)
}

fn cmd_readiness(report: &AnalysisReport, json: bool, out: &Path) -> Result<String, String> {
    let written = maybe_write_artifacts(report, out)?;
    if json {
        return Ok(serde_json::to_string_pretty(&report.readiness_json()).map_err(|e| e.to_string())?);
    }
    let mut s = edwardian_engine::format_readiness_console(report);
    if report.readiness.status != edwardian_core::ReadinessStatus::Ready {
        let blockers: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Blocker)
            .collect();
        if !blockers.is_empty() {
            s.push_str("\nBlocking findings:\n");
            for f in blockers {
                s.push_str(&format!("  {} {}\n", f.id, f.description));
            }
        }
    }
    s.push_str(&format!(
        "\nArtefacts written under {}/\n",
        written[0].parent().unwrap().display()
    ));
    Ok(s)
}

fn cmd_directive(report: &AnalysisReport, json: bool) -> Result<String, String> {
    if json {
        return Ok(serde_json::to_string_pretty(&report.directives_json()).map_err(|e| e.to_string())?);
    }
    if report.directives.is_empty() {
        return Ok("No directives generated.\n".to_string());
    }
    let mut s = String::new();
    for d in &report.directives {
        s.push_str(&format!(
            "{} ({}) {}\n  state: {} → {}\n  components: {}\n  evidence: {}\n  remediation: {}\n  validation: {}\n  depends-on: {}\n",
            d.id,
            d.priority.label(),
            d.objective,
            d.current_state.label(),
            d.target_state.label(),
            d.affected_components.join(", "),
            d.evidence_ids.join(", "),
            d.remediation,
            d.validation_plan.join("; "),
            if d.dependencies.is_empty() { "-".into() } else { d.dependencies.join(", ") },
        ));
    }
    Ok(s)
}

fn cmd_propose(report: &AnalysisReport, json: bool) -> Result<String, String> {
    if json {
        return Ok(serde_json::to_string_pretty(&report.proposals_json()).map_err(|e| e.to_string())?);
    }
    if report.proposals.is_empty() {
        return Ok("No proposals generated.\n".to_string());
    }
    let mut s = String::new();
    for p in &report.proposals {
        s.push_str(&format!(
            "{} ({}, ~{} days) {}\n  current: {}\n  required: {}\n  architecture: {}\n  interface: {}\n  invariant: {}\n  risk: {}\n",
            p.id,
            p.capability,
            p.estimated_effort_days,
            p.state.label(),
            p.current_impl,
            p.required_impl,
            p.recommended_architecture,
            p.required_interface,
            p.compatibility_invariant,
            p.risk
        ));
    }
    Ok(s)
}

fn cmd_validate(report: &AnalysisReport, json: bool) -> Result<String, String> {
    let mut problems = edwardian_engine::validate_report(report);
    for d in &report.directives {
        if d.priority == DirectivePriority::P0 && d.validation_plan.len() < 3 {
            problems.push(format!("P0 directive {} needs at least 3 validation steps", d.id));
        }
    }
    let ok = problems.is_empty();
    if json {
        return Ok(serde_json::to_string_pretty(&json!({
            "valid": ok,
            "problems": problems,
            "directives_checked": report.directives.len(),
            "findings_checked": report.findings.len(),
        }))
        .map_err(|e| e.to_string())?);
    }
    if ok {
        Ok(format!(
            "Validation passed: {} findings and {} directives are structurally complete (static check only; nothing was executed).\n",
            report.findings.len(),
            report.directives.len()
        ))
    } else {
        let mut s = format!("Validation failed with {} problem(s):\n", problems.len());
        for p in &problems {
            s.push_str(&format!("  - {}\n", p));
        }
        Err(s)
    }
}

fn cmd_export(report: &AnalysisReport, out: &Path, json: bool) -> Result<String, String> {
    let written = maybe_write_artifacts(report, out)?;
    if json {
        let files: Vec<_> = written
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        return Ok(serde_json::to_string_pretty(&json!({ "written": files }))
            .map_err(|e| e.to_string())?);
    }
    let mut s = format!("Wrote {} artefacts to {}/:\n", written.len(), out.display());
    for p in &written {
        s.push_str(&format!("  {}\n", p.display()));
    }
    Ok(s)
}

fn cmd_daemon(
    root: &Path,
    config: &edwardian_engine::PipelineConfig,
    interval: u64,
    once: bool,
    json: bool,
) -> Result<(), String> {
    use std::io::Write;
    let mut daemon = edwardian_daemon::Daemon::new(root.to_path_buf(), config.clone());
    loop {
        let output = daemon.cycle().map_err(|e| format!("daemon cycle failed: {}", e))?;
        let mut stdout = std::io::stdout().lock();
        for event in &output.events {
            if json {
                writeln!(stdout, "{}", event.to_json_line()).map_err(|e| e.to_string())?;
            } else {
                writeln!(stdout, "[cycle {}] {}", event.cycle, event.kind.summary())
                    .map_err(|e| e.to_string())?;
            }
        }
        if !once && !json {
            writeln!(
                stdout,
                "[cycle {}] {} ({}% , blockers {})",
                output.cycle,
                output.readiness.status.label(),
                output.readiness.overall,
                output.readiness.blocker_count
            )
            .map_err(|e| e.to_string())?;
        }
        stdout.flush().map_err(|e| e.to_string())?;
        drop(stdout);
        if once {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
    }
}

fn cmd_release(
    report: &AnalysisReport,
    root: &Path,
    out: &Path,
    mode: &ReleaseMode,
    json: bool,
) -> Result<(), String> {
    match mode {
        ReleaseMode::Standalone => {
            let r = edwardian_release::standalone(report, root, out)
                .map_err(|e| format!("standalone release failed: {}", e))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?);
            } else {
                println!(
                    "Standalone fork at {}: {} files copied, {} transform(s) applied, {} manual item(s) remaining",
                    r.fork_dir,
                    r.files_copied,
                    r.transforms.len(),
                    r.manual_work.len()
                );
                for t in &r.transforms {
                    println!("  {} {}: {}", t.transform_id, t.file, t.change);
                }
            }
            Ok(())
        }
        ReleaseMode::Compatible { branch_name, no_git } => {
            let r = edwardian_release::compatible::compatible(
                report,
                root,
                out,
                branch_name.as_deref(),
                *no_git,
            )
            .map_err(|e| format!("compatible release failed: {}", e))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?);
            } else if r.nothing_to_do {
                println!("nothing to do: {}", r.note);
            } else {
                println!(
                    "Compatible release (via {}): branch `{}`, {} proposal(s), {} dep(s), {} path(s): {}",
                    r.applied_via,
                    r.branch,
                    r.proposals,
                    r.deps,
                    r.written_paths.len(),
                    r.note
                );
                for p in &r.written_paths {
                    println!("  {p}");
                }
            }
            Ok(())
        }
    }
}

#[allow(dead_code)]
fn _io_error_to_string(e: io::Error) -> String {
    e.to_string()
}
