use edwardian_engine::PipelineConfig;
use edwardian_store::StoreStatus;

#[test]
fn store_checks_never_affect_readiness_or_findings() {
    // The independence regression guard: for both fixtures, readiness status,
    // overall percentage, blocker count, findings, directives and proposals
    // must be identical whether or not store checks run afterwards.
    for build in [edwardian_test::linux_only_repo, edwardian_test::portable_repo] {
        let dir = tempfile::tempdir().unwrap();
        build(dir.path()).unwrap();
        let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
        let baseline = (
            report.readiness.status,
            report.readiness.overall,
            report.readiness.blocker_count,
            report.findings.len(),
            report.directives.len(),
            report.proposals.len(),
        );
        let store = edwardian_store::run(dir.path(), &report).unwrap();
        let after = (
            report.readiness.status,
            report.readiness.overall,
            report.readiness.blocker_count,
            report.findings.len(),
            report.directives.len(),
            report.proposals.len(),
        );
        assert_eq!(baseline, after, "store checks must not mutate the analysis");
        assert_eq!(store.checks.len(), 8);
        let json = store.to_json();
        assert_eq!(json["advisory"], true);
        assert_eq!(json["summary"]["total"], 8);
        assert!(json["summary"]["met"].as_u64().unwrap()
            + json["summary"]["not_met"].as_u64().unwrap()
            + json["summary"]["unknown"].as_u64().unwrap()
            == 8);
        // Store check ids must not collide with finding/evidence id spaces.
        for c in &store.checks {
            assert!(c.id.starts_with("MSC-"));
        }
    }
}

#[test]
fn store_checks_do_not_appear_in_manual_work_or_daemon_events() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(dir.path()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
    let store = edwardian_store::run(dir.path(), &report).unwrap();

    // Standalone manifest: no store-only content leaks into MANUAL WORK.
    let rel = edwardian_release::standalone(&report, dir.path(), out.path()).unwrap();
    for m in &rel.manual_work {
        assert!(!m.what.contains("MSIX") && !m.what.contains("Store"));
    }

    // Daemon cycle: baseline events contain no store check kinds.
    let mut daemon = edwardian_daemon::Daemon::new(dir.path().to_path_buf(), PipelineConfig::default());
    let c1 = daemon.cycle().unwrap();
    for e in &c1.events {
        let name = e.kind.name();
        assert!(!name.contains("store") && !name.contains("msc"));
    }
    let _ = store;
}

#[test]
fn store_ready_fixture_shows_several_checks_met() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    // Rich packaging/signing/metadata surface.
    edwardian_test::write(
        dir.path(),
        "Cargo.toml",
        "[package]\nname = \"storeapp\"\nversion = \"1.2.3\"\ndescription = \"app\"\nlicense = \"MIT\"\nhomepage = \"https://example.com\"\nrepository = \"https://example.com/repo\"\n",
    )
    .unwrap();
    edwardian_test::write(dir.path(), "wix/installer.wxs", "<Wix xmlns=\"x\">\n</Wix>\n").unwrap();
    edwardian_test::write(
        dir.path(),
        ".github/workflows/release.yml",
        "jobs:\n  sign:\n    run: signtool sign /tr http://timestamp /a app.msix\n",
    )
    .unwrap();
    edwardian_test::write(dir.path(), "PRIVACY.md", "We respect your privacy.\n").unwrap();

    let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
    assert_eq!(report.readiness.status, edwardian_core::ReadinessStatus::Ready);
    let store = edwardian_store::run(dir.path(), &report).unwrap();
    let get = |id: &str| store.checks.iter().find(|c| c.id == id).unwrap();
    assert_eq!(get("MSC-001").status, StoreStatus::Met, "{}", get("MSC-001").detail);
    assert_eq!(get("MSC-002").status, StoreStatus::Met, "{}", get("MSC-002").detail);
    assert_eq!(get("MSC-003").status, StoreStatus::Met, "{}", get("MSC-003").detail);
    assert_eq!(get("MSC-004").status, StoreStatus::Met, "{}", get("MSC-004").detail);
    assert_eq!(get("MSC-006").status, StoreStatus::Met, "{}", get("MSC-006").detail);
    assert_eq!(get("MSC-007").status, StoreStatus::Met, "{}", get("MSC-007").detail);
    assert_eq!(get("MSC-008").status, StoreStatus::Met, "{}", get("MSC-008").detail);
    assert!(store.count(StoreStatus::Met) >= 6);
}

#[test]
fn store_artifact_and_markdown_section_shape() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(dir.path()).unwrap();
    let report = edwardian_engine::run(dir.path(), &PipelineConfig::default()).unwrap();
    let store = edwardian_store::run(dir.path(), &report).unwrap();
    let md = edwardian_store::render_markdown_section(&store);
    assert!(md.contains("## Microsoft Store compliance (advisory)"));
    assert!(md.contains("advisory checks met"));
    // Evidence ids are deterministic per check.
    for c in &store.checks {
        if let Some(e) = &c.evidence {
            assert!(e.id.starts_with(&format!("{}-E", c.id)), "{}", e.id);
        }
    }
}
