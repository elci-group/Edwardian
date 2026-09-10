use edwardian_core::ReadinessStatus;
use edwardian_daemon::{Daemon, EventKind};
use edwardian_engine::PipelineConfig;

fn kinds(output: &edwardian_daemon::CycleOutput) -> Vec<&str> {
    output.events.iter().map(|e| e.kind.name()).collect()
}

#[test]
fn incremental_cycles_emit_stable_events() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(dir.path()).unwrap();

    let mut daemon = Daemon::new(dir.path().to_path_buf(), PipelineConfig::default());

    // Cycle 1: baseline. The initial population is reported as file_added /
    // finding_added so event-log consumers can reconstruct full state, and
    // the baseline status is established.
    let c1 = daemon.cycle().unwrap();
    assert_eq!(c1.cycle, 1);
    assert!(
        kinds(&c1).iter().filter(|k| **k == "file_added").count() >= 5,
        "baseline should enumerate files: {:?}",
        c1.events
    );
    let baseline = c1
        .events
        .iter()
        .find_map(|e| match &e.kind {
            EventKind::StatusChanged { from, .. } => Some(from.clone()),
            _ => None,
        })
        .expect("baseline status_changed");
    assert_eq!(baseline, "UNKNOWN");
    assert_eq!(c1.readiness.status, ReadinessStatus::Blocked);
    let baseline_overall = c1.readiness.overall;

    // Record ids of pre-existing findings for the stability check.
    let ids_before: Vec<(String, String)> = c1
        .findings
        .iter()
        .map(|f| (f.description.clone(), f.id.clone()))
        .collect();
    assert!(c1.findings.iter().all(|f| f.has_material_evidence()));

    // Mutate: add an absolute /bin/bash invocation to helper.sh (a file that
    // previously had no shell-path finding, so this is a genuine add).
    let helper = dir.path().join("helper.sh");
    let mut content = std::fs::read_to_string(&helper).unwrap();
    content.push_str("\n/bin/bash -c \"deploy\"\n");
    std::fs::write(&helper, content).unwrap();

    let c2 = daemon.cycle().unwrap();
    assert_eq!(c2.cycle, 2);
    let k = kinds(&c2);
    assert!(k.contains(&"file_changed"), "events: {k:?}");
    assert!(
        c2.events.iter().any(|e| matches!(
            &e.kind,
            EventKind::FileChanged { path, .. } if path == "helper.sh"
        )),
        "events: {:?}",
        c2.events
    );
    let added: Vec<&EventKind> = c2
        .events
        .iter()
        .map(|e| &e.kind)
        .filter(|k| matches!(k, EventKind::FindingAdded { .. }))
        .collect();
    assert_eq!(added.len(), 1, "expected exactly one finding_added: {added:?}");
    let added_bash = added.iter().any(|k| matches!(
        k,
        EventKind::FindingAdded { description, severity, .. }
            if description.contains("absolute unix shell") && severity == "blocker"
    ));
    assert!(added_bash, "finding_added should be the bash blocker: {added:?}");
    // Readiness must react: either the score moved or the status flipped.
    assert!(
        k.contains(&"readiness_changed") || k.contains(&"status_changed"),
        "events: {k:?}"
    );
    assert!(c2.readiness.overall <= baseline_overall);

    // Ids of pre-existing (unchanged-evidence) findings stay stable.
    let ids_after: Vec<(String, String)> = c2
        .findings
        .iter()
        .map(|f| (f.description.clone(), f.id.clone()))
        .collect();
    for (desc, id) in &ids_before {
        if desc.contains("Makefile") || desc.contains("systemd") {
            let after = ids_after
                .iter()
                .find(|(d, _)| d == desc)
                .unwrap_or_else(|| panic!("finding vanished: {desc}"));
            assert_eq!(after.1, *id, "id drifted for {desc}");
        }
    }

    // Delete the systemd unit file: file_removed + finding_removed.
    std::fs::remove_file(dir.path().join("linuxdaemon.service")).unwrap();
    let c3 = daemon.cycle().unwrap();
    assert!(kinds(&c3).contains(&"file_removed"), "events: {:?}", c3.events);
    let removed_systemd = c3.events.iter().any(|e| matches!(
        &e.kind,
        EventKind::FindingRemoved { description, .. } if description.contains("systemd")
    ));
    assert!(removed_systemd, "events: {:?}", c3.events);
    assert!(kinds(&c3).contains(&"readiness_changed") || kinds(&c3).contains(&"status_changed"));

    // Deleting the whole repo: everything vanishes, readiness recovers.
    std::fs::remove_dir_all(dir.path()).unwrap();
    std::fs::create_dir(dir.path()).unwrap();
    let c4 = daemon.cycle().unwrap();
    assert!(c4.findings.is_empty(), "findings: {:?}", c4.findings);
    assert_eq!(c4.readiness.status, ReadinessStatus::Ready);
    assert!(kinds(&c4).contains(&"status_changed"));
    let to_ready = c4.events.iter().any(|e| matches!(
        &e.kind,
        EventKind::StatusChanged { to, .. } if to == "READY"
    ));
    assert!(to_ready, "events: {:?}", c4.events);
}

#[test]
fn case_collision_arrives_and_leaves_via_inventory_scan() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    let mut daemon = Daemon::new(dir.path().to_path_buf(), PipelineConfig::default());
    let c1 = daemon.cycle().unwrap();
    assert!(c1.findings.is_empty());

    // Add two files differing only by case -> inventory-level finding appears.
    edwardian_test::write(dir.path(), "docs/Readme.md", "# A\n").unwrap();
    edwardian_test::write(dir.path(), "docs/readme.md", "# B\n").unwrap();
    let c2 = daemon.cycle().unwrap();
    let collision = c2
        .findings
        .iter()
        .find(|f| f.description.contains("collision"))
        .expect("collision finding");
    assert_eq!(collision.evidence[0].location.path, "docs");
    let added = c2.events.iter().any(|e| matches!(
        &e.kind,
        EventKind::FindingAdded { description, .. } if description.contains("collision")
    ));
    assert!(added, "events: {:?}", c2.events);

    // Rename one file -> collision finding disappears without a file event
    // for the surviving file (its content hash is unchanged).
    std::fs::remove_file(dir.path().join("docs/readme.md")).unwrap();
    let c3 = daemon.cycle().unwrap();
    assert!(!c3.findings.iter().any(|f| f.description.contains("collision")));
    let removed = c3.events.iter().any(|e| matches!(
        &e.kind,
        EventKind::FindingRemoved { description, .. } if description.contains("collision")
    ));
    assert!(removed, "events: {:?}", c3.events);
}

#[test]
fn stable_content_produces_no_events() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(dir.path()).unwrap();
    let mut daemon = Daemon::new(dir.path().to_path_buf(), PipelineConfig::default());
    daemon.cycle().unwrap();
    // Touch nothing: second cycle must be silent.
    let c2 = daemon.cycle().unwrap();
    assert!(c2.events.is_empty(), "events: {:?}", c2.events);
}

#[test]
fn new_file_addition_emits_file_added_and_finding_added() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();
    let mut daemon = Daemon::new(dir.path().to_path_buf(), PipelineConfig::default());
    daemon.cycle().unwrap();

    edwardian_test::write(dir.path(), "extra.sh", "#!/bin/sh\necho hi\n").unwrap();
    let c2 = daemon.cycle().unwrap();
    assert!(c2.events.iter().any(|e| matches!(
        &e.kind,
        EventKind::FileAdded { path, .. } if path == "extra.sh"
    )));
    assert!(c2.events.iter().any(|e| matches!(
        &e.kind,
        EventKind::FindingAdded { description, .. } if description.contains("shebang")
    )));
}
