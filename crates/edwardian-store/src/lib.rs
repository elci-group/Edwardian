//! Microsoft Store compliance checks — a strictly ADVISORY layer.
//!
//! Store checks never emit findings, severities, directives, or proposals;
//! they cannot affect readiness scoring or daemon events. They are
//! informational guidance for maintainers who opt into Store distribution.

use edwardian_core::{Evidence, Location, Platform, PlatformDependency};
use edwardian_engine::{AnalysisReport, PipelineConfig, inventory};
use serde::Serialize;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreStatus {
    Met,
    NotMet,
    Unknown,
}

impl StoreStatus {
    pub fn label(self) -> &'static str {
        match self {
            StoreStatus::Met => "met",
            StoreStatus::NotMet => "not-met",
            StoreStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StoreCheck {
    pub id: String,
    pub name: String,
    pub status: StoreStatus,
    pub detail: String,
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StoreReport {
    pub target: Platform,
    pub checks: Vec<StoreCheck>,
}

impl StoreReport {
    pub fn count(&self, status: StoreStatus) -> usize {
        self.checks.iter().filter(|c| c.status == status).collect::<Vec<_>>().len()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "target": self.target,
            "advisory": true,
            "summary": {
                "total": self.checks.len(),
                "met": self.count(StoreStatus::Met),
                "not_met": self.count(StoreStatus::NotMet),
                "unknown": self.count(StoreStatus::Unknown),
            },
            "checks": self.checks,
        })
    }
}

#[derive(Debug)]
struct FileData {
    path: String,
    content: String,
}

fn load_files(root: &Path, target: Platform) -> io::Result<Vec<FileData>> {
    let config = PipelineConfig { target, ..PipelineConfig::default() };
    let (inv, _b, _l) = inventory(root, &config)?;
    let mut out = Vec::new();
    for rec in inv {
        if let Ok(content) = fs::read_to_string(root.join(&rec.path)) {
            out.push(FileData { path: rec.path, content });
        }
    }
    Ok(out)
}

fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// First deterministic (file, line, column) match of any token.
fn find_token<'a>(files: &'a [FileData], tokens: &[&str]) -> Option<(&'a FileData, usize, usize, &'a str)> {
    for f in files {
        for (line_no, line) in f.content.lines().enumerate() {
            let lowered = lower(line);
            for token in tokens {
                if let Some(i) = lowered.find(token) {
                    let matched = line.get(i..i + token.len()).unwrap_or("");
                    return Some((f, line_no + 1, i + 1, matched));
                }
            }
        }
    }
    None
}

fn evidence(check_id: &str, m: &(&FileData, usize, usize, &str), detector: &str) -> Evidence {
    let (f, line, col, token) = m;
    Evidence::file_scan(
        format!("{}-E1", check_id),
        Location::new(f.path.clone(), *line, *col),
        format!("matched `{}`", token),
        0.8,
        detector,
    )
}

fn cargo_toml(files: &[FileData]) -> Option<&FileData> {
    files.iter().find(|f| f.path == "Cargo.toml")
}

fn package_field<'a>(cargo: &'a FileData, field: &str) -> Option<&'a str> {
    for line in cargo.content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(field) {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v.trim().trim_matches('"'));
            }
        }
    }
    None
}

/// First file whose PATH matches any token (installer/project extensions).
fn find_path<'a>(files: &'a [FileData], tokens: &[&str]) -> Option<&'a FileData> {
    files
        .iter()
        .find(|f| tokens.iter().any(|t| lower(&f.path).contains(t)))
}

fn check_packaging(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-001";
    let tokens = ["msix", "cargo-wix", "innosetup", "inno setup", "nsis", "electron-builder", "winres", "windows-metadata"];
    let path_tokens = [".wxs", ".wixproj", ".iss", ".nsi"];
    let m = find_token(files, &tokens).map(|(f, line, col, tok)| {
        (f, line, col, tok, "content")
    }).or_else(|| {
        find_path(files, &path_tokens).map(|f| (f, 1usize, 1usize, "installer project file", "path"))
    });
    let (status, detail) = match &m {
        Some((f, _, _, tok, where_)) => (
            StoreStatus::Met,
            format!("packaging tooling detected (`{}` in {} via {})", tok, f.path, where_),
        ),
        None => (
            StoreStatus::NotMet,
            "Store submission requires MSIX packaging (Desktop Bridge); none detected.".to_string(),
        ),
    };
    StoreCheck {
        id: ID.to_string(),
        name: "MSIX packaging".to_string(),
        status,
        detail,
        evidence: m.as_ref().map(|(f, line, col, tok, _)| {
            Evidence::file_scan(
                format!("{}-E1", ID),
                Location::new(f.path.clone(), *line, *col),
                format!("matched `{}`", tok),
                0.8,
                "store.packaging",
            )
        }),
    }
}

fn check_signing(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-002";
    let tokens = ["signtool", "azure trusted signing", "trusted-signing", "thumbprint", ".pfx", "codesign"];
    let m = find_token(files, &tokens);
    let (status, detail) = match &m {
        Some((f, _, _, tok)) => (
            StoreStatus::Met,
            format!("signing configuration detected (`{}` in {})", tok, f.path),
        ),
        None => (
            StoreStatus::NotMet,
            "no code-signing configuration detected; Store submissions must be signed".to_string(),
        ),
    };
    StoreCheck {
        id: ID.to_string(),
        name: "Code signing".to_string(),
        status,
        detail,
        evidence: m.as_ref().map(|mm| evidence(ID, mm, "store.signing")),
    }
}

fn check_privacy(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-003";
    let privacy = find_token(files, &["privacy"]);
    let url = find_token(files, &["homepage", "repository", "documentation", "https://", "http://"]);
    let (status, detail, ev) = match (&privacy, &url) {
        (Some((f, _, _, _)), _) => (
            StoreStatus::Met,
            format!("privacy/support reference found in {}", f.path),
            privacy.as_ref(),
        ),
        (None, Some((f, _, _, _))) => (
            StoreStatus::Unknown,
            format!("URLs present in {} but no explicit privacy reference; Store requires a privacy policy for network-using apps", f.path),
            url.as_ref(),
        ),
        (None, None) => (
            StoreStatus::NotMet,
            "no privacy policy or support URL reference found".to_string(),
            None,
        ),
    };
    StoreCheck {
        id: ID.to_string(),
        name: "Privacy policy / support URL".to_string(),
        status,
        detail,
        evidence: ev.map(|mm| evidence(ID, mm, "store.privacy")),
    }
}

fn check_elevation(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-004";
    let tokens = ["requireadministrator", "requestedexecutionlevel", " runas", "highestavailable"];
    let m = find_token(files, &tokens);
    let (status, detail) = match &m {
        Some((f, _, _, tok)) => (
            StoreStatus::NotMet,
            format!("administrator elevation evidence (`{}` in {}) — the Store forbids admin elevation", tok, f.path),
        ),
        None => (StoreStatus::Met, "no administrator elevation requirements detected".to_string()),
    };
    StoreCheck {
        id: ID.to_string(),
        name: "Administrator elevation".to_string(),
        status,
        detail,
        evidence: m.as_ref().map(|mm| evidence(ID, mm, "store.elevation")),
    }
}

fn check_background(report: &AnalysisReport, files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-005";
    let service_finding = report
        .findings
        .iter()
        .find(|f| f.dependency == PlatformDependency::Service);
    let token = find_token(
        files,
        &["currentversion\\run", "currentversion/run", "autostart", "backgroundtask"],
    );
    let (status, detail, ev): (_, _, Option<Evidence>) = match (service_finding, &token) {
        (Some(f), _) => (
            StoreStatus::NotMet,
            format!("service integration detected ({}, {}) — the Store restricts background execution; Desktop Bridge apps need brokered/approved background tasks", f.id, f.description),
            f.evidence.first().map(|e| {
                Evidence::file_scan(
                    format!("{}-E1", ID),
                    e.location.clone(),
                    format!("service finding {} evidenced here", f.id),
                    e.confidence,
                    "store.background",
                )
            }),
        ),
        (None, Some((fd, line, col, _))) => (
            StoreStatus::NotMet,
            format!("auto-start/background persistence evidence in {}:{} — the Store restricts background execution", fd.path, line),
            Some(Evidence::file_scan(
                format!("{}-E1", ID),
                Location::new(fd.path.clone(), *line, *col),
                "auto-start evidence",
                0.75,
                "store.background",
            )),
        ),
        (None, None) => (
            StoreStatus::Met,
            "no services or auto-start persistence detected".to_string(),
            None,
        ),
    };
    StoreCheck {
        id: ID.to_string(),
        name: "Auto-start / background persistence".to_string(),
        status,
        detail,
        evidence: ev,
    }
}

fn check_identity(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-006";
    let Some(cargo) = cargo_toml(files) else {
        return StoreCheck {
            id: ID.to_string(),
            name: "App identity metadata".to_string(),
            status: StoreStatus::Unknown,
            detail: "no root Cargo.toml found; cannot verify identity metadata".to_string(),
            evidence: None,
        };
    };
    let required = ["version", "description", "license"];
    let missing: Vec<&str> = required
        .iter()
        .filter(|field| package_field(cargo, field).is_none())
        .copied()
        .collect();
    let (status, detail) = if missing.is_empty() {
        (StoreStatus::Met, "Cargo.toml carries version, description and license".to_string())
    } else {
        (
            StoreStatus::NotMet,
            format!("identity metadata missing from Cargo.toml: {} (Store listing needs these)", missing.join(", ")),
        )
    };
    StoreCheck {
        id: ID.to_string(),
        name: "App identity metadata".to_string(),
        status,
        detail,
        evidence: Some(Evidence::file_scan(
            format!("{}-E1", ID),
            Location::new("Cargo.toml", 1, 1),
            "root manifest inspected for identity fields",
            0.9,
            "store.identity",
        )),
    }
}

fn check_network(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-007";
    let tokens = ["reqwest", "ureq", "\"hyper\"", "tcpstream", "httpclient", "curl::", "tokio::net"];
    let m = find_token(files, &tokens);
    let (status, detail) = match &m {
        Some((f, _, _, tok)) => (
            StoreStatus::NotMet,
            format!("network usage detected (`{}` in {}) — MSIX must declare the internetClient capability in its manifest", tok, f.path),
        ),
        None => (StoreStatus::Met, "no network client usage detected".to_string()),
    };
    StoreCheck {
        id: ID.to_string(),
        name: "Network capability declaration".to_string(),
        status,
        detail,
        evidence: m.as_ref().map(|mm| evidence(ID, mm, "store.network")),
    }
}

fn check_crash_reporting(files: &[FileData]) -> StoreCheck {
    const ID: &str = "MSC-008";
    let reporter = find_token(files, &["sentry", "crashpad", "bugsnag"]);
    match &reporter {
        None => StoreCheck {
            id: ID.to_string(),
            name: "Crash-reporting consent".to_string(),
            status: StoreStatus::Met,
            detail: "no crash reporter detected".to_string(),
            evidence: None,
        },
        Some(_) => {
            let consent = find_token(files, &["consent", "opt-out", "opt out", "privacy policy"]);
            let (status, detail) = match &consent {
                Some((f, _, _, tok)) => (
                    StoreStatus::Met,
                    format!("crash reporter paired with consent/policy reference (`{}` in {})", tok, f.path),
                ),
                None => (
                    StoreStatus::NotMet,
                    "crash reporter (sentry/crashpad/bugsnag) detected without a consent or privacy reference".to_string(),
                ),
            };
            StoreCheck {
                id: ID.to_string(),
                name: "Crash-reporting consent".to_string(),
                status,
                detail,
                evidence: reporter.as_ref().map(|mm| evidence(ID, mm, "store.crash")),
            }
        }
    }
}

/// Markdown section appended to report.md (composed by the CLI; the store
/// layer stays independent of the report crate).
pub fn render_markdown_section(store: &StoreReport) -> String {
    let mut out = String::from("\n## Microsoft Store compliance (advisory)\n\n");
    out.push_str(&format!(
        "{} of {} advisory checks met ({} not met, {} unknown). Advisory only — does not affect readiness.\n\n",
        store.count(StoreStatus::Met),
        store.checks.len(),
        store.count(StoreStatus::NotMet),
        store.count(StoreStatus::Unknown),
    ));
    out.push_str("| Check | Status | Detail |\n|---|---|---|\n");
    for c in &store.checks {
        out.push_str(&format!("| {} {} | {} | {} |\n", c.id, c.name, c.status.label(), c.detail));
    }
    out
}

/// Run all advisory checks. Reads the analysis report (never mutates it) and
/// re-walks the source with the standard bounded inventory.
pub fn run(root: &Path, report: &AnalysisReport) -> io::Result<StoreReport> {
    let files = load_files(root, report.target)?;
    let checks = vec![
        check_packaging(&files),
        check_signing(&files),
        check_privacy(&files),
        check_elevation(&files),
        check_background(report, &files),
        check_identity(&files),
        check_network(&files),
        check_crash_reporting(&files),
    ];
    Ok(StoreReport { target: report.target, checks })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_files(files: &[(&str, &str)], f: impl Fn(&[FileData])) {
        let dir = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
        let loaded = load_files(dir.path(), report.target).unwrap();
        f(&loaded);
    }

    #[test]
    fn packaging_met_and_not_met() {
        with_files(&[("Cargo.toml", "[package]\nname=\"x\"\nversion=\"1\"\n")], |fs| {
            let c = check_packaging(fs);
            assert_eq!(c.status, StoreStatus::NotMet);
            assert!(c.detail.contains("MSIX"));
            assert!(c.evidence.is_none());
        });
        with_files(&[("wix/setup.wxs", "<Wix/>\n")], |fs| {
            let c = check_packaging(fs);
            assert_eq!(c.status, StoreStatus::Met);
            assert!(c.evidence.is_some());
        });
    }

    #[test]
    fn signing_and_elevation() {
        with_files(&[("ci/build.yml", "run: signtool sign /a app.exe\n")], |fs| {
            assert_eq!(check_signing(fs).status, StoreStatus::Met);
        });
        with_files(&[("app.manifest", "<requestedExecutionLevel level=\"requireAdministrator\"/>\n")], |fs| {
            let c = check_elevation(fs);
            assert_eq!(c.status, StoreStatus::NotMet);
            assert!(c.detail.contains("forbids admin"));
        });
    }

    #[test]
    fn privacy_states() {
        with_files(&[("Cargo.toml", "[package]\nhomepage = \"https://x.dev\"\n")], |fs| {
            assert_eq!(check_privacy(fs).status, StoreStatus::Unknown);
        });
        with_files(&[("PRIVACY.md", "privacy policy\n")], |fs| {
            assert_eq!(check_privacy(fs).status, StoreStatus::Met);
        });
        with_files(&[("src/main.rs", "fn main() {}\n")], |fs| {
            assert_eq!(check_privacy(fs).status, StoreStatus::NotMet);
        });
    }

    #[test]
    fn identity_fields_reported() {
        with_files(&[("Cargo.toml", "[package]\nname=\"x\"\nversion=\"1\"\n")], |fs| {
            let c = check_identity(fs);
            assert_eq!(c.status, StoreStatus::NotMet);
            assert!(c.detail.contains("description"));
            assert!(c.detail.contains("license"));
        });
        with_files(
            &[("Cargo.toml", "[package]\nname=\"x\"\nversion=\"1\"\ndescription=\"d\"\nlicense=\"MIT\"\n")],
            |fs| assert_eq!(check_identity(fs).status, StoreStatus::Met),
        );
    }

    #[test]
    fn network_and_crash_reporting() {
        with_files(&[("Cargo.toml", "[dependencies]\nreqwest = \"0.12\"\n")], |fs| {
            let c = check_network(fs);
            assert_eq!(c.status, StoreStatus::NotMet);
            assert!(c.detail.contains("internetClient"));
        });
        with_files(&[("src/main.rs", "fn main() { sentry::init(); }\n"), ("PRIVACY.md", "consent\n")], |fs| {
            assert_eq!(check_crash_reporting(fs).status, StoreStatus::Met);
        });
        with_files(&[("src/main.rs", "fn main() { sentry::init(); }\n")], |fs| {
            assert_eq!(check_crash_reporting(fs).status, StoreStatus::NotMet);
        });
    }

    #[test]
    fn background_uses_engine_findings() {
        let dir = tempfile::tempdir().unwrap();
        edwardian_test::linux_only_repo(dir.path()).unwrap();
        let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
        let files = load_files(dir.path(), report.target).unwrap();
        let c = check_background(&report, &files);
        assert_eq!(c.status, StoreStatus::NotMet);
        assert!(c.detail.contains("service"));
        // Portable repo: nothing detected -> Met.
        let dir2 = tempfile::tempdir().unwrap();
        edwardian_test::portable_repo(dir2.path()).unwrap();
        let r2 = edwardian_engine::run(dir2.path(), &PipelineConfig::default()).unwrap();
        let f2 = load_files(dir2.path(), r2.target).unwrap();
        assert_eq!(check_background(&r2, &f2).status, StoreStatus::Met);
    }

    #[test]
    fn full_run_is_advisory_and_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        edwardian_test::linux_only_repo(dir.path()).unwrap();
        let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
        let before_findings = report.findings.len();
        let r1 = run(dir.path(), &report).unwrap();
        let r2 = run(dir.path(), &report).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1.checks.len(), 8);
        assert_eq!(r1.count(StoreStatus::Met) + r1.count(StoreStatus::NotMet) + r1.count(StoreStatus::Unknown), 8);
        for c in &r1.checks {
            assert!(c.id.starts_with("MSC-"));
            assert!(!c.detail.is_empty());
        }
        // Independence: the analysis report is untouched.
        assert_eq!(report.findings.len(), before_findings);
    }
}
