use edwardian_engine::PipelineConfig;
use std::path::Path;

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, rel: String, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(base.join(&rel)).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let r = if rel.is_empty() { name.clone() } else { format!("{}/{}", rel, name) };
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(base, r, out);
            } else if ft.is_file() {
                out.push((r, std::fs::read(e.path()).unwrap()));
            }
        }
    }
    walk(dir, String::new(), &mut out);
    out.sort();
    out
}

#[test]
fn standalone_fork_copies_transforms_and_manifests_manual_work() {
    let src = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(src.path()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let report = edwardian_engine::run(src.path(), &PipelineConfig::default()).unwrap();

    let r = edwardian_release::standalone(&report, src.path(), out.path()).unwrap();

    let fork = out.path().join("standalone-fork");
    assert!(fork.is_dir());
    assert_eq!(r.files_copied, 6, "fork files: {:?}", r.fork_dir);
    // Every source file landed in the fork.
    assert!(fork.join("src/main.rs").is_file());
    assert!(fork.join("helper.sh").is_file());

    // T1 injected cfg(windows) deps: notify for fs-watch, service-manager for
    // systemd, interprocess for unix sockets.
    let cargo = std::fs::read_to_string(fork.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("[target.'cfg(windows)'.dependencies]"), "{cargo}");
    assert!(cargo.contains("notify = \"8\""), "{cargo}");
    assert!(cargo.contains("service-manager = \"0.8\""), "{cargo}");
    assert!(cargo.contains("interprocess = \"2\""), "{cargo}");
    assert_eq!(r.transforms.iter().filter(|t| t.transform_id == "T1").count(), 4);
    // Every transform records evidence ids that exist in the report.
    let evidence_ids: std::collections::HashSet<&str> = report
        .findings
        .iter()
        .flat_map(|f| f.evidence.iter().map(|e| e.id.as_str()))
        .collect();
    for t in &r.transforms {
        assert!(!t.evidence_ids.is_empty());
        assert!(t.evidence_ids.iter().all(|e| evidence_ids.contains(e.as_str())));
    }

    // Manifest lists manual work for the bash and systemd blockers, with
    // evidence ids; the fs-watch major is resolved by the notify transform
    // and must NOT appear.
    let md = std::fs::read_to_string(fork.join("EDWARDIAN-FORK.md")).unwrap();
    assert!(md.contains("## MANUAL WORK"));
    let bash = r.manual_work.iter().find(|m| m.what.contains("absolute unix shell")).unwrap();
    assert!(bash.why.contains("blocker"));
    assert!(bash.location.contains("src/main.rs"));
    assert!(!bash.evidence_ids.is_empty());
    assert!(!bash.validation.is_empty());
    assert!(r.manual_work.iter().any(|m| m.what.contains("systemd")));
    assert!(!r.manual_work.iter().any(|m| m.what.contains("inotify")));
    // Sorted deterministically by finding id.
    let ids: Vec<&str> = r.manual_work.iter().map(|m| m.finding_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    // Manifest mentions the evidence ids of the manual items.
    for m in &r.manual_work {
        for e in &m.evidence_ids {
            assert!(md.contains(e.as_str()), "manifest missing evidence {e}");
        }
    }

    // The fork is re-analysable.
    let re = edwardian_engine::run(&fork, &PipelineConfig::default()).unwrap();
    assert!(re.inventory.len() >= 7); // 6 copied + EDWARDIAN-FORK.md
}

#[test]
fn compatible_fallback_writes_branch_content_and_leaves_source_untouched() {
    let src = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(src.path()).unwrap();
    let before = snapshot(src.path());
    let out = tempfile::tempdir().unwrap();
    let report = edwardian_engine::run(src.path(), &PipelineConfig::default()).unwrap();

    let r = edwardian_release::compatible::compatible(&report, src.path(), out.path(), None, true).unwrap();
    assert_eq!(r.applied_via, "fallback");
    assert_eq!(r.branch, "edwardian/compat-windows");
    assert_eq!(r.proposals, 1);
    assert!(r.deps >= 1);

    let dir = out.path().join("compat-branch");
    let trait_src = std::fs::read_to_string(dir.join("src/platform/fs_watch.rs")).unwrap();
    assert!(trait_src.contains("pub trait FileWatcher"));
    assert!(trait_src.contains("use std::path::Path;"));
    let mod_src = std::fs::read_to_string(dir.join("src/platform/mod.rs")).unwrap();
    assert!(mod_src.contains("#[cfg(unix)]"));
    assert!(mod_src.contains("#[cfg(windows)]"));
    assert!(mod_src.contains("pub mod fs_watch;"));
    let win = std::fs::read_to_string(dir.join("src/platform/fs_watch_windows.rs")).unwrap();
    assert!(win.contains("unimplemented!(\"EWP-001"));
    let cargo = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("[target.'cfg(windows)'.dependencies]"), "{cargo}");
    let manifest = std::fs::read_to_string(dir.join("EDWARDIAN-COMPAT.md")).unwrap();
    assert!(manifest.contains("EWP-001"));
    assert!(manifest.contains("Validation plan"));
    // Exactly the declared paths were added to the mirror.
    for p in &r.written_paths {
        assert!(dir.join(p).exists(), "missing {p}");
    }

    // Original tree byte-identical.
    assert_eq!(before, snapshot(src.path()));
}

#[test]
fn compatible_git_branch_adds_and_commits_without_touching_main() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("git unavailable; skipping");
        return;
    }
    let src = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(src.path()).unwrap();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(src.path())
            .output()
            .unwrap()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.name", "test"]);
    git(&["config", "user.email", "test@example.com"]);
    assert!(git(&["add", "-A"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    let original_cargo = std::fs::read_to_string(src.path().join("Cargo.toml")).unwrap();

    let report = edwardian_engine::run(src.path(), &PipelineConfig::default()).unwrap();
    let r = edwardian_release::compatible::compatible(&report, src.path(), src.path(), Some("edwardian/test-branch"), false).unwrap();
    assert_eq!(r.applied_via, "git", "note: {:?}", r.note);
    assert_eq!(r.branch, "edwardian/test-branch");

    // Branch exists and contains exactly the new paths + Cargo.toml.
    let branch = String::from_utf8(git(&["rev-parse", "--abbrev-ref", "HEAD"]).stdout).unwrap();
    assert_eq!(branch.trim(), "edwardian/test-branch");
    let tree = String::from_utf8(git(&["ls-tree", "-r", "--name-only", "HEAD"]).stdout).unwrap();
    for p in &r.written_paths {
        assert!(tree.lines().any(|l| l == p), "commit missing {p}\n{tree}");
    }
    let changed = String::from_utf8(git(&["show", "--name-only", "--format=", "HEAD"]).stdout).unwrap();
    let changed: Vec<&str> = changed.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(changed.len(), r.written_paths.len(), "commit touched: {changed:?}");
    let msg = String::from_utf8(git(&["log", "-1", "--format=%s"]).stdout).unwrap();
    assert_eq!(msg.trim(), "edwardian: windows compatibility scaffolding (1 proposals, 4 deps)");

    // Main branch untouched after checkout back.
    assert!(git(&["checkout", "-q", "main"]).status.success());
    let cargo_now = std::fs::read_to_string(src.path().join("Cargo.toml")).unwrap();
    assert_eq!(cargo_now, original_cargo);
    assert!(!src.path().join("src/platform").exists());
}

#[test]
fn portable_repo_release_is_a_noop() {
    let src = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(src.path()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let report = edwardian_engine::run(src.path(), &PipelineConfig::default()).unwrap();

    let r = edwardian_release::standalone(&report, src.path(), out.path()).unwrap();
    assert!(r.transforms.is_empty());
    assert!(r.manual_work.is_empty());
    assert!(out.path().join("standalone-fork/EDWARDIAN-FORK.md").is_file());

    let c = edwardian_release::compatible::compatible(&report, src.path(), out.path(), None, true).unwrap();
    assert!(c.nothing_to_do);
    assert!(c.note.contains("nothing to do"));
}
