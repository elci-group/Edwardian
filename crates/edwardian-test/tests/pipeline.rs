use edwardian_core::{Platform, PlatformDependency, ReadinessStatus, Severity};
use edwardian_engine::PipelineConfig;

fn run_repo(build: fn(&std::path::Path) -> std::io::Result<()>) -> edwardian_engine::AnalysisReport {
    let dir = tempfile::tempdir().unwrap();
    build(dir.path()).unwrap();
    edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap()
}

#[test]
fn linux_only_repo_is_blocked_with_blockers_and_proposals() {
    let report = run_repo(edwardian_test::linux_only_repo);

    assert_eq!(report.readiness.status, ReadinessStatus::Blocked);
    assert!(
        report.readiness.blocker_count >= 2,
        "expected multiple blockers, got {} (findings: {:?})",
        report.readiness.blocker_count,
        report.findings.iter().map(|f| (&f.id, &f.description)).collect::<Vec<_>>()
    );

    // Every material finding carries evidence with a real location.
    for f in &report.findings {
        assert!(!f.evidence.is_empty(), "finding {} has no evidence", f.id);
        for e in &f.evidence {
            assert!(!e.location.path.is_empty());
            assert!(e.location.line >= 1);
            assert!(e.confidence > 0.0 && e.confidence <= 1.0);
            assert!(e.id.starts_with("EWD-"));
            assert!(f.id.starts_with("FND-"));
        }
    }

    // Specific unix-isms are found with the right classification.
    let has = |needle: &str| {
        report
            .findings
            .iter()
            .any(|f| f.description.contains(needle))
    };
    assert!(has("systemd"));
    assert!(has("absolute unix shell"));
    assert!(has("inotify"));
    assert!(has("UnixListener"));
    assert!(has("Makefile"));

    let inotify_finding = report
        .findings
        .iter()
        .find(|f| f.description.contains("inotify"))
        .expect("inotify finding");
    assert_eq!(inotify_finding.dependency, PlatformDependency::Kernel);

    // Directives exist, are well-formed, and P0s exist for blockers.
    assert!(!report.directives.is_empty());
    assert!(report.directives.iter().any(|d| d.priority == edwardian_core::DirectivePriority::P0));
    for d in &report.directives {
        assert!(d.validation_plan_is_complete(), "directive {} incomplete", d.id);
        assert!(d.validation_plan.iter().any(|s| s.contains("Windows")));
    }

    // The fs-watch capability gets a proposal with the full proposal shape.
    let proposal = report
        .proposals
        .iter()
        .find(|p| p.capability == "fs-watch")
        .expect("fs-watch proposal");
    assert!(proposal.required_interface.contains("FileWatcher"));
    assert!(!proposal.compatibility_invariant.is_empty());
    assert!(proposal.estimated_effort_days > 0);

    // The inotify finding has ranked alternatives led by the notify crate.
    let alts = report
        .alternatives
        .get(&inotify_finding.id)
        .expect("alternatives for inotify finding");
    assert_eq!(alts[0].name, "notify crate");
}

#[test]
fn portable_repo_is_ready() {
    let report = run_repo(edwardian_test::portable_repo);
    assert_eq!(report.readiness.status, ReadinessStatus::Ready);
    assert_eq!(report.readiness.overall, 100);
    assert_eq!(report.readiness.blocker_count, 0);
    assert!(report.findings.is_empty(), "unexpected findings: {:?}", report.findings);
    assert!(report.directives.is_empty());
    assert!(report.proposals.is_empty());
}

#[test]
fn git_invocation_is_tooling_not_blocker() {
    let report = run_repo(edwardian_test::git_invocation_repo);
    let git = report
        .findings
        .iter()
        .find(|f| f.description.contains("git"))
        .expect("git finding");
    assert_eq!(git.dependency, PlatformDependency::Tooling);
    assert!(git.severity < Severity::Blocker);
    assert_eq!(git.state, edwardian_core::CompatibilityState::Portable);
    assert_eq!(report.readiness.blocker_count, 0);
    assert_eq!(report.readiness.status, ReadinessStatus::Ready);
    // No alternative resolution is required for a portable tool.
    assert!(!report.alternatives.contains_key(&git.id));
}

#[test]
fn discovery_identifies_layout() {
    let report = run_repo(edwardian_test::linux_only_repo);
    let d = &report.discovery;
    assert!(d.package_managers.contains(&"cargo".to_string()));
    assert!(d.package_managers.contains(&"Makefile".to_string()));
    assert!(d.scripts.contains(&"helper.sh".to_string()));
    assert!(d.entrypoints.contains(&"src/main.rs".to_string()));
}

#[test]
fn bounded_walk_skips_vcs_and_heavy_files() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    edwardian_test::write(dir.path(), ".git/config", "[core]\nrepositoryformatversion = 0\n").unwrap();
    edwardian_test::write(dir.path(), "node_modules/dep/index.js", "module.exports = {};\n").unwrap();
    let big = "x".repeat(1024 * 1024 + 10);
    edwardian_test::write(dir.path(), "big.txt", &big).unwrap();
    // Symlink escape must not be followed.
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc", dir.path().join("escape-link")).unwrap();

    let config = PipelineConfig::default();
    let report = edwardian_engine::run(dir.path(), &config).unwrap();
    let paths: Vec<&str> = report.inventory.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.iter().all(|p| !p.starts_with(".git/")));
    assert!(paths.iter().all(|p| !p.starts_with("node_modules/")));
    assert!(!paths.contains(&"big.txt"));
    #[cfg(unix)]
    assert!(paths.iter().all(|p| !p.starts_with("escape-link")));
    assert!(report.files_skipped_limits >= 1);
}

#[test]
fn windows_path_literals_are_target_aware() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    edwardian_test::write(
        dir.path(),
        "src/paths.rs",
        "let win = \"C:\\\\Users\\\\x\";\nlet unc = \"\\\\\\\\srv\\\\share\";\n",
    )
    .unwrap();

    // Target Windows: drive/UNC literals are informational only.
    let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
    let win = report
        .findings
        .iter()
        .find(|f| f.description.contains("drive-letter"))
        .expect("drive-letter finding");
    assert_eq!(win.severity, edwardian_core::Severity::Info);
    assert_eq!(win.state, edwardian_core::CompatibilityState::WindowsCompatible);
    assert!(report.readiness.status != edwardian_core::ReadinessStatus::Blocked);

    // Target Linux: the same literals are real portability evidence.
    let config = PipelineConfig {
        target: Platform::Linux,
        ..PipelineConfig::default()
    };
    let report = edwardian_engine::run(dir.path(), &config).unwrap();
    let win = report
        .findings
        .iter()
        .find(|f| f.description.contains("drive-letter"))
        .unwrap();
    assert_eq!(win.severity, edwardian_core::Severity::Major);
    assert!(report
        .findings
        .iter()
        .any(|f| f.description.contains("UNC")));
}

#[test]
fn unix_fs_semantics_and_case_collisions_surface_in_engine() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    edwardian_test::write(
        dir.path(),
        "src/install.rs",
        "use std::os::unix::fs::PermissionsExt;\n\
         fn f() {\n\
             std::os::unix::fs::symlink(a, b).unwrap();\n\
             std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();\n\
         }\n",
    )
    .unwrap();
    edwardian_test::write(dir.path(), "src/Config.rs", "pub const A: u8 = 1;\n").unwrap();
    edwardian_test::write(dir.path(), "src/config.rs", "pub const B: u8 = 2;\n").unwrap();

    let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.description.contains("symlink") && f.severity == edwardian_core::Severity::Major));
    assert!(report
        .findings
        .iter()
        .any(|f| f.description.contains("0o755")));
    let collision = report
        .findings
        .iter()
        .find(|f| f.description.contains("collision"))
        .expect("collision finding");
    assert_eq!(collision.evidence[0].location.path, "src");
    assert_eq!(collision.evidence[0].source, edwardian_core::EvidenceSource::RepoLayout);
    // Case collision is a Major hazard on the (default) Windows target.
    assert_eq!(collision.severity, edwardian_core::Severity::Major);
}

#[test]
fn non_windows_target_also_works() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    let config = PipelineConfig {
        target: Platform::MacOs,
        ..PipelineConfig::default()
    };
    let report = edwardian_engine::run(dir.path(), &config).unwrap();
    assert_eq!(report.readiness.status, ReadinessStatus::Ready);
    assert_eq!(report.target, Platform::MacOs);
}
